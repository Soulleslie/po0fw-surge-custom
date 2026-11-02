#!/usr/bin/env python3
"""Keep the four Surge script URLs pinned to the released script commit."""

import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/po0-firewall-whitelist.js"
MODULE = ROOT / "surge/po0-firewall-whitelist.sgmodule"
SCRIPT_NAMES = ("po0-fw-cron", "po0-fw-event", "po0-fw-start", "po0-fw-panel")
URL = re.compile(
    r"https://raw\.githubusercontent\.com/Soulleslie/po0fw-surge-custom/"
    r"([0-9a-f]{40})/scripts/po0-firewall-whitelist\.js"
)


def git(*args):
    result = subprocess.run(
        ("git", *args), cwd=ROOT, capture_output=True, text=False, check=False
    )
    if result.returncode:
        message = result.stderr.decode("utf-8", "replace").strip()
        raise ValueError(message or "git " + " ".join(args) + " failed")
    return result.stdout


def module_refs():
    text = MODULE.read_text(encoding="utf-8")
    refs = []
    for name in SCRIPT_NAMES:
        lines = [line for line in text.splitlines() if line.startswith(name + " = ")]
        if len(lines) != 1:
            raise ValueError(f"expected exactly one {name} script line")
        paths = re.findall(r"(?:^|,)script-path=([^,\s]+)", lines[0])
        if len(paths) != 1:
            raise ValueError(f"expected exactly one script-path for {name}")
        match = URL.fullmatch(paths[0])
        if not match:
            raise ValueError(f"unexpected script URL for {name}: {paths[0]}")
        refs.append(match.group(1))
    if len(set(refs)) != 1:
        raise ValueError("Surge cron, events, and panel use different script commits")
    return text, refs[0]


def validate_ref(ref):
    released = git("show", f"{ref}:scripts/po0-firewall-whitelist.js")
    if released != SCRIPT.read_bytes():
        raise ValueError(
            f"Surge pins {ref}, but its script differs from scripts/po0-firewall-whitelist.js"
        )
    git("merge-base", "--is-ancestor", ref, "HEAD")


def main():
    if len(sys.argv) == 2 and sys.argv[1] == "check":
        _, ref = module_refs()
        validate_ref(ref)
        print(f"Surge release sync OK: {ref}")
    elif len(sys.argv) == 3 and sys.argv[1] == "pin":
        new_ref = git("rev-parse", "--verify", sys.argv[2] + "^{commit}").decode().strip()
        if not re.fullmatch(r"[0-9a-f]{40}", new_ref):
            raise ValueError("pin requires a commit SHA")
        validate_ref(new_ref)
        text, old_ref = module_refs()
        if old_ref == new_ref:
            print(f"Surge already pins {new_ref}")
            return
        # Replace only the exact version segment in the three validated URLs.
        old_path = f"/{old_ref}/scripts/po0-firewall-whitelist.js"
        new_path = f"/{new_ref}/scripts/po0-firewall-whitelist.js"
        if text.count(old_path) != len(SCRIPT_NAMES):
            raise ValueError("expected four pinned script paths in the module")
        MODULE.write_text(text.replace(old_path, new_path), encoding="utf-8")
        print(f"Updated Surge script pin: {old_ref} -> {new_ref}")
    else:
        raise ValueError("usage: surge-release.py check | pin <script-commit>")


if __name__ == "__main__":
    try:
        main()
    except ValueError as exc:
        print(f"Surge release sync failed: {exc}", file=sys.stderr)
        sys.exit(1)
