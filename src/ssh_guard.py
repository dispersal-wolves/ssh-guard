"""Audit OpenSSH server policy and install a validated hardening drop-in."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path


DEFAULT_CONFIG = Path("C:/ProgramData/ssh/sshd_config") if os.name == "nt" else Path("/etc/ssh/sshd_config")
DEFAULT_DROPIN = Path("C:/ProgramData/ssh/sshd_config.d/99-dispersal-wolves.conf") if os.name == "nt" else Path("/etc/ssh/sshd_config.d/99-dispersal-wolves.conf")

POLICY = {
    "permitrootlogin": ("no", "Root login should be disabled."),
    "passwordauthentication": ("no", "Prefer public-key authentication."),
    "kbdinteractiveauthentication": ("no", "Disable keyboard-interactive authentication."),
    "pubkeyauthentication": ("yes", "Public-key authentication should remain available."),
    "x11forwarding": ("no", "Disable X11 forwarding unless it is required."),
    "permitemptypasswords": ("no", "Empty passwords must never be accepted."),
}

HARDENED_DROPIN = """# Managed by Dispersal Wolves SSH Guard
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PermitEmptyPasswords no
X11Forwarding no
MaxAuthTries 4
LoginGraceTime 60
"""


@dataclass(frozen=True)
class Finding:
    key: str
    status: str
    actual: str
    expected: str
    guidance: str


def parse_config(path: Path, visited: set[Path] | None = None) -> dict[str, str]:
    visited = visited or set()
    resolved = path.resolve()
    if resolved in visited:
        return {}
    visited.add(resolved)
    settings: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return settings
    for raw in lines:
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        key, _, value = line.partition(" ")
        normalized = key.lower()
        if normalized == "match":
            break
        if normalized == "include":
            pattern = Path(value.strip())
            if not pattern.is_absolute():
                pattern = path.parent / pattern
            for included in sorted(pattern.parent.glob(pattern.name)):
                for child_key, child_value in parse_config(included, visited).items():
                    settings.setdefault(child_key, child_value)
            continue
        settings.setdefault(normalized, value.strip().lower())
    return settings


def effective_settings(config: Path) -> dict[str, str]:
    sshd = shutil.which("sshd")
    if sshd:
        process = subprocess.run([sshd, "-T", "-f", str(config)], capture_output=True, text=True, check=False)
        if process.returncode == 0:
            return parse_effective_output(process.stdout)
    return parse_config(config)


def parse_effective_output(text: str) -> dict[str, str]:
    settings: dict[str, str] = {}
    for line in text.splitlines():
        key, _, value = line.strip().partition(" ")
        if key and value:
            settings[key.lower()] = value.strip().lower()
    return settings


def audit(settings: dict[str, str]) -> list[Finding]:
    findings = []
    for key, (expected, guidance) in POLICY.items():
        actual = settings.get(key, "unset")
        findings.append(Finding(key, "pass" if actual == expected else "warn", actual, expected, guidance))
    max_auth = settings.get("maxauthtries", "unset")
    try:
        auth_ok = int(max_auth) <= 4
    except ValueError:
        auth_ok = False
    findings.append(Finding("maxauthtries", "pass" if auth_ok else "warn", max_auth, "4 or fewer", "Limit repeated authentication attempts."))
    return findings


def validate(config: Path) -> tuple[bool, str]:
    sshd = shutil.which("sshd")
    if not sshd:
        return False, "sshd is unavailable; refusing to install an unvalidated configuration"
    process = subprocess.run([sshd, "-t", "-f", str(config)], capture_output=True, text=True, check=False)
    return process.returncode == 0, (process.stdout + process.stderr).strip()


def install_dropin(config: Path, destination: Path, confirmed: bool) -> tuple[bool, str]:
    if not confirmed:
        return False, "Use --yes after reviewing the generated policy."
    destination.parent.mkdir(parents=True, exist_ok=True)
    backup: Path | None = None
    if destination.exists():
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup = destination.with_suffix(destination.suffix + f".{stamp}.bak")
        shutil.copy2(destination, backup)
    destination.write_text(HARDENED_DROPIN, encoding="utf-8", newline="\n")
    valid, message = validate(config)
    if valid:
        remaining = [item.key for item in audit(effective_settings(config)) if item.status != "pass"]
        if not remaining:
            return True, f"Installed {destination}"
        valid = False
        message = "drop-in was not effective for: " + ", ".join(remaining)
    if backup:
        shutil.copy2(backup, destination)
    else:
        destination.unlink(missing_ok=True)
    return False, f"Validation failed and the change was rolled back: {message}"


def command_audit(args: argparse.Namespace) -> int:
    if not args.config.exists():
        print(f"SSH server configuration not found: {args.config}", file=sys.stderr)
        return 2
    findings = audit(effective_settings(args.config))
    if args.format == "json":
        print(json.dumps({"schema": "dispersal-wolves/ssh-guard/v1", "findings": [asdict(item) for item in findings]}, indent=2))
    else:
        for item in findings:
            print(f"[{item.status.upper():4}] {item.key}: {item.actual} (recommended: {item.expected})")
    return 1 if args.strict and any(item.status != "pass" for item in findings) else 0


def command_render(_: argparse.Namespace) -> int:
    print(HARDENED_DROPIN, end="")
    return 0


def command_apply(args: argparse.Namespace) -> int:
    success, message = install_dropin(args.config, args.destination, args.yes)
    print(message, file=sys.stdout if success else sys.stderr)
    return 0 if success else 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    audit_parser = subparsers.add_parser("audit", help="Audit the effective SSH server policy")
    audit_parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    audit_parser.add_argument("--format", choices=("text", "json"), default="text")
    audit_parser.add_argument("--strict", action="store_true")
    audit_parser.set_defaults(func=command_audit)
    render_parser = subparsers.add_parser("render", help="Print the hardened drop-in")
    render_parser.set_defaults(func=command_render)
    apply_parser = subparsers.add_parser("apply", help="Install and validate the hardened drop-in")
    apply_parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    apply_parser.add_argument("--destination", type=Path, default=DEFAULT_DROPIN)
    apply_parser.add_argument("--yes", action="store_true", help="Confirm installation after reviewing the policy")
    apply_parser.set_defaults(func=command_apply)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
