"""
Secrets Detection & Rotation Engine
Finds hardcoded secrets in files/git history with entropy + pattern matching,
then plans a rotation workflow (AWS, GitHub, Slack, OpenAI, generic Vault).

Modes:
  python engine.py scan <path>           # detect secrets in a file or directory
  python engine.py git <repo>            # scan full git history for leaked secrets
  python engine.py rotate <findings.json># generate rotation runbook per secret kind

Author: Mohith Vasamsetti (CyberEnthusiastic)
"""
import os
import re
import sys
import json
import math
import argparse
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from dataclasses import dataclass, asdict, field
from typing import List, Dict, Optional

from report_generator import generate_html


# -------------------------------------------------------------
# Secret patterns (extends Trufflehog / Gitleaks patterns)
# -------------------------------------------------------------
SECRET_RULES = [
    {"id": "AWS-AKID", "name": "AWS Access Key ID",
     "pattern": r"\b(AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b",
     "severity": "CRITICAL", "entropy_min": 0, "provider": "aws",
     "rotate_doc": "AWS IAM console / aws iam create-access-key + delete old key"},
    {"id": "AWS-SECRET", "name": "AWS Secret Access Key",
     "pattern": r"(?i)aws.{0,20}?(?:secret|sk).{0,20}?['\"]([A-Za-z0-9/+=]{40})['\"]",
     "severity": "CRITICAL", "entropy_min": 3.5, "provider": "aws",
     "rotate_doc": "Rotate via aws iam update-access-key; invalidate old key immediately"},
    {"id": "GH-PAT", "name": "GitHub PAT (classic)",
     "pattern": r"\bghp_[A-Za-z0-9]{36}\b",
     "severity": "CRITICAL", "entropy_min": 3.5, "provider": "github",
     "rotate_doc": "Revoke at github.com/settings/tokens; create new PAT with least-scope"},
    {"id": "GH-PAT-FG", "name": "GitHub PAT (fine-grained)",
     "pattern": r"\bgithub_pat_[A-Za-z0-9_]{82}\b",
     "severity": "CRITICAL", "entropy_min": 4.0, "provider": "github",
     "rotate_doc": "Revoke at github.com/settings/tokens?type=beta; rotate with shortened TTL"},
    {"id": "GH-OAUTH", "name": "GitHub OAuth token",
     "pattern": r"\bgho_[A-Za-z0-9]{36}\b",
     "severity": "CRITICAL", "entropy_min": 3.5, "provider": "github",
     "rotate_doc": "Revoke OAuth app at github.com/settings/applications"},
    {"id": "SLACK-BOT", "name": "Slack Bot/User token",
     "pattern": r"\bxox[baprs]-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{20,}\b",
     "severity": "HIGH", "entropy_min": 3.5, "provider": "slack",
     "rotate_doc": "api.slack.com/apps/<app>/general -> reinstall to workspace to rotate"},
    {"id": "OPENAI", "name": "OpenAI API Key",
     "pattern": r"\bsk-[A-Za-z0-9]{48}\b",
     "severity": "HIGH", "entropy_min": 3.8, "provider": "openai",
     "rotate_doc": "platform.openai.com/account/api-keys -> revoke + create new"},
    {"id": "GCP-SVC", "name": "Google Cloud Service Account Key",
     "pattern": r"\"private_key_id\"\s*:\s*\"[a-f0-9]{40}\"",
     "severity": "CRITICAL", "entropy_min": 0, "provider": "gcp",
     "rotate_doc": "gcloud iam service-accounts keys create/delete"},
    {"id": "GOOGLE-API", "name": "Google API Key",
     "pattern": r"\bAIza[0-9A-Za-z_-]{35}\b",
     "severity": "HIGH", "entropy_min": 3.5, "provider": "google",
     "rotate_doc": "console.cloud.google.com/apis/credentials -> regenerate key"},
    {"id": "PEM-KEY", "name": "Private key (PEM block)",
     "pattern": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
     "severity": "CRITICAL", "entropy_min": 0, "provider": "generic",
     "rotate_doc": "Generate new keypair; replace on all hosts; add old pubkey to revoke list"},
    {"id": "STRIPE", "name": "Stripe API Key",
     "pattern": r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{24,}\b",
     "severity": "CRITICAL", "entropy_min": 3.5, "provider": "stripe",
     "rotate_doc": "dashboard.stripe.com/apikeys -> roll key"},
    {"id": "TWILIO", "name": "Twilio Account SID",
     "pattern": r"\bAC[a-f0-9]{32}\b",
     "severity": "MEDIUM", "entropy_min": 3.0, "provider": "twilio",
     "rotate_doc": "console.twilio.com -> change Auth Token"},
    {"id": "SENDGRID", "name": "SendGrid API Key",
     "pattern": r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b",
     "severity": "HIGH", "entropy_min": 4.0, "provider": "sendgrid",
     "rotate_doc": "app.sendgrid.com/settings/api_keys -> delete + recreate"},
    {"id": "JWT", "name": "JSON Web Token",
     "pattern": r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b",
     "severity": "MEDIUM", "entropy_min": 3.8, "provider": "generic",
     "rotate_doc": "Invalidate in auth server; rotate signing key if token was admin"},
    {"id": "GENERIC-PW", "name": "Hardcoded password assignment",
     "pattern": r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"]([^'\"\s]{8,})['\"]",
     "severity": "HIGH", "entropy_min": 3.0, "provider": "generic",
     "rotate_doc": "Move to secret manager; force reset; rotate any derived secrets"},
    {"id": "BEARER", "name": "Hardcoded Bearer token",
     "pattern": r"(?:Authorization|authorization)\s*[:=]\s*['\"]?Bearer\s+[A-Za-z0-9_\-\.=]{20,}",
     "severity": "HIGH", "entropy_min": 3.5, "provider": "generic",
     "rotate_doc": "Revoke token at issuing auth server; rotate client credential"},
    {"id": "DATABASE-URL", "name": "Database URL with embedded password",
     "pattern": r"\b(?:mysql|postgres|mongodb|redis)://[^\s:'\"]+:[^@\s'\"]{6,}@[^\s'\"]+\b",
     "severity": "HIGH", "entropy_min": 3.0, "provider": "generic",
     "rotate_doc": "Rotate DB user password; update connection strings via secret manager"},
]


SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", "dist", "build", "out", ".idea", ".vscode"}
SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".pdf", ".zip", ".tar", ".gz",
            ".mp3", ".mp4", ".wav", ".exe", ".dll", ".so", ".bin", ".class", ".jar",
            ".pyc", ".pyo", ".woff", ".woff2", ".ttf"}

# Tokens near the match (within the same line) that indicate a placeholder.
# These are CASE-SENSITIVE substrings; we also require them to appear outside
# the secret match itself (not baked into a live-looking token).
ALLOW_MARKERS = ("placeholder", "YOUR-KEY-HERE", "xxxxxxxx", "replace-me",
                 "dummy-secret", "fake-only", "test-only-", "DO-NOT-USE")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    from collections import Counter
    cnt = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in cnt.values())


@dataclass
class Finding:
    id: str
    name: str
    severity: str
    provider: str
    file: str
    line: int
    match: str
    entropy: float
    confidence: float
    risk_score: float
    rotate_doc: str
    commit: str = ""
    author: str = ""


def risk_score(rule: dict, entropy: float, in_history: bool, confidence: float) -> float:
    base = 60 * confidence
    sev_bonus = {"CRITICAL": 20, "HIGH": 12, "MEDIUM": 6, "LOW": 0}.get(rule["severity"], 0)
    ent_bonus = min(10, max(0, (entropy - 3.0) * 5))
    hist_bonus = 5 if in_history else 0
    return round(min(100.0, base + sev_bonus + ent_bonus + hist_bonus), 1)


def _is_allowlisted(s: str) -> bool:
    return any(m.lower() in s.lower() for m in ALLOW_MARKERS)


def scan_line(line: str, path: str, line_no: int, in_history: bool = False,
              commit: str = "", author: str = "") -> List[Finding]:
    findings: List[Finding] = []
    for rule in SECRET_RULES:
        for m in re.finditer(rule["pattern"], line):
            match = m.group(0)
            if _is_allowlisted(match):
                continue
            # compute entropy on the "secret-like" portion
            sec = m.group(1) if m.groups() else match
            ent = shannon_entropy(sec)
            if ent < rule.get("entropy_min", 0):
                continue
            confidence = 0.85 if rule["id"] in ("PEM-KEY", "JWT", "GENERIC-PW") else 0.95
            findings.append(Finding(
                id=rule["id"], name=rule["name"], severity=rule["severity"],
                provider=rule["provider"], file=path, line=line_no,
                match=match[:120], entropy=round(ent, 2),
                confidence=confidence,
                risk_score=risk_score(rule, ent, in_history, confidence),
                rotate_doc=rule["rotate_doc"],
                commit=commit, author=author,
            ))
    return findings


def scan_file(p: Path) -> List[Finding]:
    if p.suffix in SKIP_EXT:
        return []
    try:
        text = p.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return []
    findings = []
    for i, line in enumerate(text.splitlines(), 1):
        if len(line) > 4000:
            continue  # skip minified blobs
        findings.extend(scan_line(line, str(p), i))
    return findings


def scan_path(target: Path) -> List[Finding]:
    if target.is_file():
        return scan_file(target)
    findings: List[Finding] = []
    for p in target.rglob("*"):
        if not p.is_file():
            continue
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        findings.extend(scan_file(p))
    return findings


# -------------------------------------------------------------
# Git history scanner
# -------------------------------------------------------------
def scan_git(repo_path: str) -> List[Finding]:
    findings: List[Finding] = []
    try:
        proc = subprocess.run(
            ["git", "-C", repo_path, "log", "--all", "-p", "-U0",
             "--pretty=format:--COMMIT-- %H %an"],
            capture_output=True, text=True, timeout=180
        )
    except FileNotFoundError:
        print("[x] git not found on PATH", file=sys.stderr); return []
    except subprocess.TimeoutExpired:
        print("[!] git log timed out - scanning captured output so far", file=sys.stderr)
        return []

    output = proc.stdout or ""
    commit = ""
    author = ""
    path = ""
    line_no = 0
    for raw in output.splitlines():
        if raw.startswith("--COMMIT--"):
            parts = raw.split(" ", 2)
            commit = parts[1] if len(parts) > 1 else ""
            author = parts[2] if len(parts) > 2 else ""
            continue
        if raw.startswith("diff --git "):
            m = re.search(r"b/(.+)$", raw)
            path = m.group(1) if m else ""
            continue
        if raw.startswith("@@"):
            m = re.search(r"\+(\d+)", raw)
            line_no = int(m.group(1)) if m else 0
            continue
        if raw.startswith("+") and not raw.startswith("+++"):
            new_findings = scan_line(raw[1:], path, line_no, in_history=True,
                                      commit=commit, author=author)
            findings.extend(new_findings)
            line_no += 1
    return findings


# -------------------------------------------------------------
# Rotation planner
# -------------------------------------------------------------
ROTATION_STEPS = {
    "aws": [
        "1. Inventory who uses this key (CloudTrail LookupEvents + Splunk/Athena for last 30 days).",
        "2. Create a NEW IAM access key via `aws iam create-access-key --user-name <user>`.",
        "3. Deploy the new key to your secret manager (AWS Secrets Manager, Vault, Doppler).",
        "4. Update the application config to read the new secret; redeploy.",
        "5. Monitor CloudTrail to confirm only the new key is in use.",
        "6. Inactivate (not delete) the old key: `aws iam update-access-key --status Inactive`.",
        "7. Wait 7 days watching for any code still referencing the old key.",
        "8. Delete the old key: `aws iam delete-access-key`.",
    ],
    "github": [
        "1. Identify scopes granted to the exposed token (GitHub audit log).",
        "2. Create a replacement token with minimum scope + 90-day expiry.",
        "3. Update secret in the consuming system (Actions, CI server, local dev).",
        "4. Revoke the leaked token: github.com/settings/tokens.",
        "5. Audit any repo/org actions taken with the old token since leak.",
    ],
    "openai": [
        "1. Visit platform.openai.com/account/api-keys.",
        "2. Create a new API key with the same label + rate-limit tier.",
        "3. Replace the secret in your app (env var / Vault / Parameter Store).",
        "4. Delete the leaked key from the OpenAI dashboard.",
        "5. Review usage dashboard for unexpected spend in the last 7 days.",
    ],
    "slack": [
        "1. Identify the app and its permissions in api.slack.com/apps.",
        "2. Re-install the app to the workspace; this issues a new token.",
        "3. Update the secret manager and redeploy consumers.",
        "4. Revoke the old token explicitly if workspace settings allow.",
    ],
    "gcp": [
        "1. gcloud iam service-accounts keys list --iam-account=<sa>",
        "2. gcloud iam service-accounts keys create new-key.json --iam-account=<sa>",
        "3. Deploy the new key JSON to your secret manager (Secret Manager / Vault).",
        "4. Validate services are using the new key (Cloud Logging).",
        "5. gcloud iam service-accounts keys delete <OLD_KEY_ID>",
    ],
    "google": [
        "1. Identify the project + API restrictions in console.cloud.google.com/apis/credentials.",
        "2. Regenerate the key; deploy to the secret manager.",
        "3. Apply HTTP referrer / IP restrictions to the new key.",
        "4. Revoke the old key after switchover.",
    ],
    "stripe": [
        "1. dashboard.stripe.com/apikeys -> create a new restricted key.",
        "2. Update app config / webhook processors.",
        "3. Roll (deactivate) the old key from the dashboard.",
        "4. Confirm no failed charges in the next 24h.",
    ],
    "twilio": [
        "1. console.twilio.com -> Account -> API keys and tokens.",
        "2. Change Auth Token; copy the new one.",
        "3. Update secret manager + redeploy SMS/voice services.",
        "4. The old token is invalid immediately.",
    ],
    "sendgrid": [
        "1. app.sendgrid.com/settings/api_keys -> create a new API key.",
        "2. Update the mailing service secret.",
        "3. Delete the old API key.",
    ],
    "generic": [
        "1. Classify the secret (what does it grant access to?).",
        "2. Rotate at the issuing system (DB password, OAuth provider, etc.).",
        "3. Push the new value to your secret manager.",
        "4. Redeploy consumers; confirm no fallback to the old value.",
        "5. Review access logs for unauthorized use during the leak window.",
        "6. Remove the secret from git history: `git filter-repo --path <file>` + force-push.",
    ],
}


def plan_rotation(findings: List[Finding]) -> Dict:
    by_provider: Dict[str, List[Finding]] = {}
    for f in findings:
        by_provider.setdefault(f.provider, []).append(f)
    out = {"generated_at": datetime.now(timezone.utc).isoformat(), "plans": []}
    for prov, items in sorted(by_provider.items()):
        out["plans"].append({
            "provider": prov,
            "secret_count": len(items),
            "steps": ROTATION_STEPS.get(prov, ROTATION_STEPS["generic"]),
            "secrets": [{"file": i.file, "line": i.line, "id": i.id, "match": i.match} for i in items],
        })
    return out


# -------------------------------------------------------------
# Summary + reports
# -------------------------------------------------------------
def build_summary(findings):
    by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    by_provider = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        by_provider[f.provider] = by_provider.get(f.provider, 0) + 1
    return {
        "tool": "Secrets Detection & Rotation Engine",
        "version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_findings": len(findings),
        "by_severity": by_sev,
        "by_provider": by_provider,
    }


def print_report(summary, findings):
    print("=" * 60)
    print("  Secrets Detection & Rotation Engine v1.0")
    print("=" * 60)
    print(f"[*] Total secrets  : {summary['total_findings']}")
    print(f"[*] By severity    : {summary['by_severity']}")
    print(f"[*] By provider    : {summary['by_provider']}")
    print()
    for f in sorted(findings, key=lambda x: -x.risk_score)[:20]:
        print(f"[{f.severity}] {f.name}  (provider: {f.provider})")
        loc = f"{f.file}:{f.line}" + (f"  (commit {f.commit[:8]} by {f.author})" if f.commit else "")
        print(f"   {loc}  (entropy={f.entropy}, risk={f.risk_score})")
        print(f"   > {f.match}")
        print()


def main():
    ap = argparse.ArgumentParser(description="Secrets Detection & Rotation Engine")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("scan", help="scan a file or directory")
    sp.add_argument("target")
    sp.add_argument("-o", "--output", default="reports/secrets_report.json")
    sp.add_argument("--html", default="reports/secrets_report.html")

    sp = sub.add_parser("git", help="scan entire git history")
    sp.add_argument("repo")
    sp.add_argument("-o", "--output", default="reports/secrets_git_report.json")
    sp.add_argument("--html", default="reports/secrets_git_report.html")

    sp = sub.add_parser("rotate", help="generate rotation runbook from findings JSON")
    sp.add_argument("findings_json")
    sp.add_argument("-o", "--output", default="reports/rotation_plan.json")

    args = ap.parse_args()

    if args.cmd == "scan":
        target = Path(args.target)
        if not target.exists():
            print(f"[x] Not found: {target}", file=sys.stderr); sys.exit(1)
        findings = scan_path(target)
    elif args.cmd == "git":
        findings = scan_git(args.repo)
    elif args.cmd == "rotate":
        raw = json.loads(Path(args.findings_json).read_text(encoding="utf-8"))
        findings_dicts = raw.get("findings", [])
        findings = [Finding(**{k: v for k, v in d.items() if k in Finding.__dataclass_fields__})
                    for d in findings_dicts]
        plan = plan_rotation(findings)
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(plan, fh, indent=2)
        # pretty print
        print("=" * 60); print("  Rotation Plan"); print("=" * 60)
        for plan_item in plan["plans"]:
            print(f"\n[{plan_item['provider'].upper()}]  {plan_item['secret_count']} secret(s)")
            for step in plan_item["steps"]:
                print(f"   {step}")
        print(f"\n[*] Written: {args.output}")
        return

    summary = build_summary(findings)
    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump({"summary": summary, "findings": [asdict(f) for f in findings]}, fh, indent=2)
    generate_html(summary, findings, args.html)
    print_report(summary, findings)
    print(f"[*] JSON report: {args.output}")
    print(f"[*] HTML report: {args.html}")


if __name__ == "__main__":
    try:
        from license_guard import verify_license
        verify_license()
    except Exception:
        pass
    main()
