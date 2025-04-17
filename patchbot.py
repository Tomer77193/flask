# --- patchbot.py (full with duplicate‐alert guard) ----------------------------
import os
import re
import sys
import json
import subprocess
import requests

from pathlib import Path
from github import Github

OWNER = "Tomer77193"      # your GitHub username
REPO  = "flask"           # your repo name

GH_TOKEN = os.environ["GH_TOKEN"]
g        = Github(GH_TOKEN)
rep      = g.get_repo(f"{OWNER}/{REPO}")

# 1. Fetch all open Dependabot alerts
alerts = requests.get(
    f"https://api.github.com/repos/{OWNER}/{REPO}/dependabot/alerts",
    headers={
        "Authorization": f"Bearer {GH_TOKEN}",
        "Accept":        "application/vnd.github+json"
    }
).json()

if not alerts:
    sys.exit("No open Dependabot alerts found")

# track which (package, safe_version) pairs we've already handled
seen = set()

# Helper to extract the patched version from an advisory
def extract_safe_version(advisory: dict) -> str | None:
    # 1) Top‑level first_patched_version
    fpv = advisory.get("first_patched_version", {})
    if isinstance(fpv, dict) and fpv.get("identifier"):
        return fpv["identifier"]
    # 2) Nested vulnerabilities list
    for vuln in advisory.get("vulnerabilities", []):
        id_ = vuln.get("first_patched_version", {}).get("identifier")
        if id_:
            return id_
    # 3) Fallback: parse the "< version" string
    rng = (
        advisory.get("vulnerable_versions") or
        advisory.get("vulnerable_version_range") or ""
    )
    m = re.search(r"<\s*([0-9A-Za-z][0-9A-Za-z.\-]*)", rng)
    return m.group(1) if m else None

# 2. Loop through each alert and open one PR per unique bump
for alert in alerts:
    pkg      = alert["dependency"]["package"]["name"]
    adv      = alert["security_advisory"]
    manifest = alert["dependency"]["manifest_path"]  # full path from alert

    safe = extract_safe_version(adv)
    if not safe:
        print(f"⚠️  No patched version found for {pkg}, skipping")
        continue

    key = (pkg, safe)
    if key in seen:
        print(f"ℹ️  Already bumped {pkg} → {safe}, skipping duplicate alert")
        continue
    seen.add(key)

    print(f"▶️  Fixing {pkg} → {safe} in {manifest}")

    path = Path(manifest)
    if not path.exists():
        print(f"⚠️  Manifest {manifest!r} not found, skipping")
        continue

    # 2a. Patch pip‐style requirements.txt
    if manifest.endswith(".txt"):
        text = path.read_text(encoding="utf-8")
        text = re.sub(
            rf"{pkg}==[0-9A-Za-z.\-]+",
            f"{pkg}=={safe}",
            text
        )
        path.write_text(text, encoding="utf-8")

    # 2b. Patch npm‐style package.json
    elif manifest.endswith(".json"):
        data = json.loads(path.read_text(encoding="utf-8"))
        changed = False
        for sec in ("dependencies", "devDependencies"):
            if sec in data and pkg in data[sec]:
                data[sec][pkg] = safe
                changed = True
        if not changed:
            print(f"⚠️  {pkg} not found in {manifest}, skipping")
            continue
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

    else:
        print(f"⚠️  Unsupported manifest type: {manifest}, skipping")
        continue

    # 3. Commit & push a new branch
    branch = f"patchbot/{pkg}-{safe}"
    subprocess.check_call(["git", "checkout", "-B", branch])

    # set the CI bot’s identity
    subprocess.check_call([
        "git", "config", "--global",
        "user.email", "patchbot@users.noreply.github.com"
    ])
    subprocess.check_call([
        "git", "config", "--global",
        "user.name",  "Patch‑Bot"
    ])

    # stage exactly the file we updated
    subprocess.check_call(["git", "add", manifest])

    # skip if no actual diff
    diff = subprocess.run(
        ["git", "diff", "--cached", "--quiet"], check=False
    )
    if diff.returncode == 0:
        print(f"ℹ️  No changes in {manifest}, skipping PR")
        subprocess.check_call(["git", "checkout", "main"])
        continue

    subprocess.check_call([
        "git", "commit", "-m",
        f"chore: bump {pkg} to {safe}"
    ])
    subprocess.check_call([
        "git", "push", "-u", "origin", branch
    ])

    # 4. Open the pull request on GitHub
    pr = rep.create_pull(
        title = f"chore: bump {pkg} to {safe}",
        body  = "Automated fix by **Patch‑Bot**",
        head  = branch,
        base  = "main",
    )
    print("✅ Pull‑request created:", pr.html_url)
# -------------------------------------------------------------------------------
