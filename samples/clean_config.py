"""Clean config - reads secrets from env / secret manager."""
import os

AWS_ACCESS_KEY_ID = os.environ["AWS_ACCESS_KEY_ID"]
GITHUB_TOKEN = os.environ["GITHUB_TOKEN"]
OPENAI_API_KEY = os.environ["OPENAI_API_KEY"]

# These are placeholders explicitly tagged so the scanner skips them
EXAMPLE_AWS_KEY = "AKIAYOURKEYHEREEXAMPLE"  # replace-me
