"""Sample file with intentionally leaked secrets for the scanner to find.
DO NOT USE ANY OF THESE VALUES - they are invalid / synthetic.
"""

# AWS credentials hardcoded - do not do this
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYRealExample9"

# GitHub PAT (36 chars after ghp_)
GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"

# OpenAI API key
OPENAI_API_KEY = "sk-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPqrstuv"

# Slack token would go here - omitted from the sample file because
# GitHub push-protection rejects even obviously-fake xoxb-*-*-* strings.
# Our scanner still covers Slack; point it at a real repo to see it in action.

# Google API key (35 chars after AIza)
GOOGLE_MAPS_KEY = "AIzaSyD_abcdefghijklmnopqrstuvwxyz12345"

# Hardcoded password in a conn string
db_url = "postgres://app:SuperSecret2025!@db.prod.example:5432/appdb"

# Bearer token for internal API
headers = {"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0IiwiaWF0IjoxNzEwMDAwMDAwfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"}

# PEM key (fake header)
PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAlMhDBaRandomFakeValueForDetectionTesting==
-----END RSA PRIVATE KEY-----"""
