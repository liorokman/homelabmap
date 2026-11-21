#!/usr/bin/env python3
"""Render deploy/cosmos-compose.json with values from ../.env.

Every <PLACEHOLDER> must have a value in .env (empty is allowed for optional
ones), so a typo fails loudly instead of deploying a literal "<...>".
Writes deploy/cosmos-compose.rendered.json (gitignored: it holds secrets).
"""
import json
import pathlib
import re
import sys

here = pathlib.Path(__file__).resolve().parent
env_path = here.parent / ".env"

OPTIONAL = {
    "HOMELABMAP_OIDC_CLIENT_SECRET", "HOMELABMAP_OIDC_ALLOWED_GROUPS", "HOMELABMAP_OIDC_PROVIDER_NAME", "TZ",
    "HOMELABMAP_UNIFI_URL", "HOMELABMAP_UNIFI_API_KEY", "HOMELABMAP_UNIFI_INSECURE_TLS",
    "HOMELABMAP_PVE_URL", "HOMELABMAP_PVE_TOKEN_ID", "HOMELABMAP_PVE_TOKEN_SECRET", "HOMELABMAP_PVE_INSECURE_TLS",
    "HOMELABMAP_COSMOS_URL", "HOMELABMAP_COSMOS_TOKEN",
}


def load_env(path):
    env = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        v = v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
            v = v[1:-1]
        env[k.strip()] = v
    return env


def main():
    env = load_env(env_path)
    template = (here / "cosmos-compose.json").read_text()
    names = sorted(set(re.findall(r"<([A-Z0-9_]+)>", template)))
    missing = [n for n in names if n not in env and n not in OPTIONAL]
    empty_required = [n for n in names if n not in OPTIONAL and n in env and env[n] == ""]
    if missing or empty_required:
        sys.exit(f"render.py: set these in {env_path}: {', '.join(missing + empty_required)}")
    if len(env.get("HOMELABMAP_AGENT_TOKEN", "")) < 32:
        sys.exit("render.py: HOMELABMAP_AGENT_TOKEN must be at least 32 characters")

    def sub(m):
        # JSON-escape the value; strip the surrounding quotes json.dumps adds.
        return json.dumps(env.get(m.group(1), ""))[1:-1]

    rendered = re.sub(r"<([A-Z0-9_]+)>", sub, template)
    doc = json.loads(rendered)  # must still be valid JSON
    # Drop optional settings left empty, so the apps see them as unset.
    for svc in doc["services"].values():
        svc["environment"] = [e for e in svc["environment"] if not e.endswith("=")]
    out = here / "cosmos-compose.rendered.json"
    out.write_text(json.dumps(doc, indent=2) + "\n")
    out.chmod(0o600)
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
