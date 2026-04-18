"""HTML report generator for the Secrets Detection & Rotation Engine."""
import os
from html import escape


def generate_html(summary: dict, findings: list, output_path: str):
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    sev_colors = {"CRITICAL": "#ff3b30", "HIGH": "#ff9500", "MEDIUM": "#ffcc00", "LOW": "#34c759"}

    rows = []
    for i, f in enumerate(sorted(findings, key=lambda x: -x.risk_score)):
        color = sev_colors.get(f.severity, "#888")
        history_tag = f"<span class='pill'>commit {escape(f.commit[:8])} &middot; {escape(f.author)}</span>" if f.commit else ""
        rows.append(f"""
        <div class="finding" data-severity="{f.severity}">
          <div class="fhead" onclick="toggleFinding({i})">
            <span class="sev" style="background:{color}">{f.severity}</span>
            <span class="fname">{escape(f.name)}</span>
            <span class="prov">{escape(f.provider)}</span>
            <span class="score">risk {f.risk_score}</span>
            <span class="chev">&#9656;</span>
          </div>
          <div class="fbody" id="fbody-{i}">
            <div class="row"><b>File:</b> <code>{escape(f.file)}:{f.line}</code> {history_tag}</div>
            <div class="row"><b>Rule:</b> {f.id} &nbsp; <b>Entropy:</b> {f.entropy} &nbsp; <b>Confidence:</b> {f.confidence}</div>
            <div class="row"><b>Match:</b> <code>{escape(f.match)}</code></div>
            <div class="row"><b>Rotation:</b> {escape(f.rotate_doc)}</div>
          </div>
        </div>
        """)

    by_sev = summary["by_severity"]
    by_prov = summary["by_provider"]
    prov_pills = "".join([f"<span class='pill big'>{escape(p)} : {c}</span>" for p, c in sorted(by_prov.items())])
    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Secrets Detection Report</title>
<style>
  :root {{ color-scheme: dark; }}
  body {{ background:#0d1117; color:#e6edf3; font-family:ui-sans-serif,system-ui,"Segoe UI",Roboto,sans-serif; margin:0; padding:24px; }}
  h1 {{ margin:0 0 8px; }}
  .meta {{ color:#8b949e; margin-bottom:20px; font-size:13px; }}
  .cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:12px; margin-bottom:16px; }}
  .card {{ background:#161b22; border:1px solid #30363d; border-radius:8px; padding:14px; }}
  .card .n {{ font-size:28px; font-weight:700; }}
  .card .l {{ color:#8b949e; font-size:12px; text-transform:uppercase; letter-spacing:.5px; }}
  .provs {{ display:flex; gap:6px; flex-wrap:wrap; margin:8px 0 20px; }}
  .pill {{ background:#21262d; border:1px solid #30363d; color:#8b949e; padding:2px 8px; border-radius:10px; font-size:11px; }}
  .pill.big {{ font-size:13px; padding:4px 12px; color:#e6edf3; }}
  .finding {{ background:#161b22; border:1px solid #30363d; border-radius:8px; margin-bottom:10px; }}
  .fhead {{ padding:10px 14px; cursor:pointer; display:flex; align-items:center; gap:10px; }}
  .fhead:hover {{ background:#1f242c; }}
  .sev {{ display:inline-block; color:#fff; padding:2px 8px; border-radius:4px; font-size:11px; font-weight:700; }}
  .fname {{ flex:1; }}
  .prov {{ color:#58a6ff; font-size:12px; }}
  .score {{ color:#8b949e; font-size:12px; }}
  .fbody {{ display:none; padding:0 14px 14px; border-top:1px solid #30363d; }}
  .fbody.open {{ display:block; }}
  .row {{ margin:6px 0; font-size:13px; }}
  code {{ background:#0d1117; border:1px solid #30363d; padding:1px 6px; border-radius:4px; font-size:12px; word-break:break-all; }}
  .foot {{ color:#8b949e; margin-top:24px; font-size:12px; text-align:center; }}
</style></head><body>
  <h1>Secrets Detection &amp; Rotation Report</h1>
  <div class="meta">Generated {escape(summary["generated_at"])} &middot; {summary["total_findings"]} secrets found</div>
  <div class="cards">
    <div class="card"><div class="n" style="color:#ff3b30">{by_sev.get("CRITICAL",0)}</div><div class="l">Critical</div></div>
    <div class="card"><div class="n" style="color:#ff9500">{by_sev.get("HIGH",0)}</div><div class="l">High</div></div>
    <div class="card"><div class="n" style="color:#ffcc00">{by_sev.get("MEDIUM",0)}</div><div class="l">Medium</div></div>
    <div class="card"><div class="n" style="color:#34c759">{by_sev.get("LOW",0)}</div><div class="l">Low</div></div>
  </div>
  <div class="provs">{prov_pills}</div>
  {''.join(rows)}
  <div class="foot">Secrets Detection &amp; Rotation Engine &middot; CyberEnthusiastic</div>
<script>
  function toggleFinding(i){{
    var el = document.getElementById('fbody-'+i);
    if(el) el.classList.toggle('open');
  }}
</script>
</body></html>"""
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html)
