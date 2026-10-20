#!/usr/bin/env python3
"""TLS certificate expiry checker (Python standard library only).

Reads a small YAML-subset config (domains.yml), opens a TLS connection to every
host, reads the leaf certificate (expiry, issuer, SANs), classifies each host
and writes a console table plus report.json / report.md.

Status rules (whole days left, rounded down):
    expired, handshake failure or failed trust check -> failed
    days_left <= critical_days (default 7)           -> critical
    days_left <= warn_days     (default 30)          -> warning
    otherwise                                        -> ok

Exit code: 0 healthy, 1 if any host is critical/failed (or warning with
--fail-on warning), 2 on config errors.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import socket
import ssl
import sys
import tempfile
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

OK, WARNING, CRITICAL, FAILED = "ok", "warning", "critical", "failed"
SEVERITY = {OK: 0, WARNING: 1, CRITICAL: 2, FAILED: 3}
EMOJI = {OK: "🟢", WARNING: "🟡", CRITICAL: "🔴", FAILED: "⛔"}


# --------------------------------------------------------------------------- #
# Config parsing (tiny YAML subset so we need no third-party packages)
# --------------------------------------------------------------------------- #
class ConfigError(ValueError):
    pass


@dataclass
class HostSpec:
    host: str
    port: int = 443
    verify: bool = True  # also check chain + hostname; False for self-signed/internal


@dataclass
class Config:
    hosts: list[HostSpec]
    warn_days: int = 30
    critical_days: int = 7
    timeout: float = 10.0


_HOST_KEYS = {"host", "port", "verify"}


def _scalar(value: str):
    v = value.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        return v[1:-1]
    if v.lower() in ("true", "yes"):
        return True
    if v.lower() in ("false", "no"):
        return False
    if re.fullmatch(r"-?\d+", v):
        return int(v)
    return v


def _strip_comment(line: str) -> str:
    if line.strip().startswith("#"):
        return ""
    return re.sub(r"\s+#.*$", "", line).rstrip()


def parse_config(text: str) -> Config:
    """Parse the supported YAML subset. See README for the format."""
    settings: dict = {"warn_days": 30, "critical_days": 7, "timeout": 10.0}
    entries: list[tuple[dict, bool]] = []  # (entry, came_from_plain_scalar)
    in_hosts = False
    current: dict | None = None

    for n, raw in enumerate(text.splitlines(), 1):
        line = _strip_comment(raw)
        if not line.strip():
            continue
        body = line.strip()
        indented = line[0] in " \t"

        if not indented and not body.startswith("-"):
            key, sep, val = body.partition(":")
            key = key.strip()
            if not sep:
                raise ConfigError(f"line {n}: expected 'key: value', got {body!r}")
            if key == "hosts":
                if val.strip():
                    raise ConfigError(f"line {n}: 'hosts:' must be followed by a list")
                in_hosts, current = True, None
            elif key in settings:
                in_hosts = False
                parsed = _scalar(val)
                if isinstance(parsed, bool) or not isinstance(parsed, (int, str)):
                    raise ConfigError(f"line {n}: {key} must be a number")
                try:
                    settings[key] = float(parsed) if key == "timeout" else int(parsed)
                except ValueError:
                    raise ConfigError(f"line {n}: {key} must be a number") from None
            else:
                raise ConfigError(f"line {n}: unknown setting {key!r}")
            continue

        if not in_hosts:
            raise ConfigError(f"line {n}: list item outside of 'hosts:'")

        if body.startswith("-"):
            item = body[1:].strip()
            if not item:
                raise ConfigError(f"line {n}: empty list item")
            m = re.match(r"^(host|port|verify)\s*:\s*(.*)$", item)
            if m:
                current = {m.group(1): _scalar(m.group(2))}
                entries.append((current, False))
            else:
                current = {"host": str(_scalar(item))}
                entries.append((current, True))
        else:
            m = re.match(r"^(\w+)\s*:\s*(.*)$", body)
            if not m or current is None:
                raise ConfigError(f"line {n}: cannot parse {body!r}")
            if m.group(1) not in _HOST_KEYS:
                raise ConfigError(f"line {n}: unknown host option {m.group(1)!r}")
            current[m.group(1)] = _scalar(m.group(2))

    hosts: list[HostSpec] = []
    for entry, plain in entries:
        host = entry.get("host")
        if not host or not isinstance(host, str):
            raise ConfigError(f"host entry without a 'host': {entry}")
        port = entry.get("port", 443)
        if plain and "port" not in entry and host.count(":") == 1:
            host, _, port_s = host.partition(":")
            if not port_s.isdigit():
                raise ConfigError(f"bad port in {entry['host']!r}")
            port = int(port_s)
        if not isinstance(port, int) or isinstance(port, bool) or not 0 < port < 65536:
            raise ConfigError(f"invalid port for {host}: {port!r}")
        verify = entry.get("verify", True)
        if not isinstance(verify, bool):
            raise ConfigError(f"'verify' for {host} must be true or false")
        hosts.append(HostSpec(host=host, port=port, verify=verify))

    if not hosts:
        raise ConfigError("no hosts configured")
    if settings["critical_days"] >= settings["warn_days"]:
        raise ConfigError("critical_days must be smaller than warn_days")
    return Config(hosts=hosts, **settings)


def load_config(path: str | os.PathLike) -> Config:
    return parse_config(Path(path).read_text(encoding="utf-8"))


# --------------------------------------------------------------------------- #
# Certificate retrieval
# --------------------------------------------------------------------------- #
@dataclass
class Result:
    host: str
    port: int
    status: str
    days_left: int | None = None
    not_after: str | None = None
    issuer: str | None = None
    sans: list[str] = field(default_factory=list)
    error: str | None = None


def fetch_der(host: str, port: int, timeout: float) -> bytes:
    """Fetch the leaf certificate WITHOUT validating it.

    We want the expiry date even when the cert is expired or self-signed, which
    a verifying handshake would refuse to give us. Trust is checked separately.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
    if not der:
        raise ssl.SSLError("server presented no certificate")
    return der


def decode_der(der: bytes) -> dict:
    """Decode a DER cert into the same dict shape as SSLSocket.getpeercert().

    The stdlib only exposes a decoder for files, via a private helper that has
    been stable for many Python versions (it is what CPython's own tests use).
    """
    pem = ssl.DER_cert_to_PEM_cert(der)
    fd, path = tempfile.mkstemp(suffix=".pem")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(pem)
        return ssl._ssl._test_decode_cert(path)  # type: ignore[attr-defined]
    finally:
        os.unlink(path)


def _rdn_get(rdns, name: str) -> str | None:
    for rdn in rdns or ():
        for key, value in rdn:
            if key == name:
                return value
    return None


def issuer_name(info: dict) -> str:
    cn = _rdn_get(info.get("issuer"), "commonName")
    org = _rdn_get(info.get("issuer"), "organizationName")
    if cn and org and cn != org:
        return f"{cn} ({org})"
    return cn or org or "unknown"


def verify_trust(host: str, port: int, timeout: float) -> str | None:
    """Full verification (chain + hostname). Returns an error string or None."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return None
    except ssl.SSLCertVerificationError as exc:
        return exc.verify_message or str(exc)
    except (OSError, ssl.SSLError) as exc:
        return str(exc) or type(exc).__name__


def classify(days_left: int, warn_days: int, critical_days: int, expired: bool = False) -> str:
    if expired:
        return FAILED
    if days_left <= critical_days:
        return CRITICAL
    if days_left <= warn_days:
        return WARNING
    return OK


def check_host(spec: HostSpec, warn_days: int = 30, critical_days: int = 7,
               timeout: float = 10.0, retries: int = 1,
               now: datetime | None = None) -> Result:
    now = now or datetime.now(timezone.utc)
    base = dict(host=spec.host, port=spec.port)

    der, last_exc = None, None
    for attempt in range(retries + 1):
        try:
            der = fetch_der(spec.host, spec.port, timeout)
            break
        except (OSError, ssl.SSLError) as exc:
            last_exc = exc
            if attempt < retries:
                time.sleep(1)
    if der is None:
        msg = str(last_exc) or type(last_exc).__name__
        return Result(**base, status=FAILED, error=f"handshake failure: {msg}")

    try:
        info = decode_der(der)
        expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(info["notAfter"]), tz=timezone.utc)
    except Exception as exc:  # noqa: BLE001 - report any parse problem as a failure
        return Result(**base, status=FAILED, error=f"could not parse certificate: {exc}")

    remaining = (expires - now).total_seconds()
    days_left = int(remaining / 86400)  # truncates toward zero: 3.9 -> 3, -5.2 -> -5
    sans = [v for k, v in info.get("subjectAltName", ()) if k in ("DNS", "IP Address")]
    status = classify(days_left, warn_days, critical_days, expired=remaining <= 0)
    error = f"certificate expired {abs(days_left)} day(s) ago" if remaining <= 0 else None

    if status != FAILED and spec.verify:
        trust_err = verify_trust(spec.host, spec.port, timeout)
        if trust_err:
            status, error = FAILED, f"trust check failed: {trust_err}"

    return Result(**base, status=status, days_left=days_left,
                  not_after=expires.strftime("%Y-%m-%d %H:%M:%S UTC"),
                  issuer=issuer_name(info), sans=sans, error=error)


def run_checks(cfg: Config, retries: int = 1, now: datetime | None = None) -> list[Result]:
    with ThreadPoolExecutor(max_workers=min(16, len(cfg.hosts))) as pool:
        futures = [pool.submit(check_host, h, cfg.warn_days, cfg.critical_days,
                               cfg.timeout, retries, now) for h in cfg.hosts]
        return [f.result() for f in futures]


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #
def overall_status(results: list[Result]) -> str:
    return max((r.status for r in results), key=SEVERITY.get, default=OK)


def summary_counts(results: list[Result]) -> dict[str, int]:
    c = Counter(r.status for r in results)
    return {s: c.get(s, 0) for s in (FAILED, CRITICAL, WARNING, OK)}


def sorted_results(results: list[Result]) -> list[Result]:
    return sorted(results, key=lambda r: (-SEVERITY[r.status],
                                          r.days_left if r.days_left is not None else -10**6,
                                          r.host))


def _days_cell(r: Result) -> str:
    return "–" if r.days_left is None else str(r.days_left)


def _sans_cell(r: Result, limit: int = 3) -> str:
    if not r.sans:
        return "–"
    shown = ", ".join(r.sans[:limit])
    return shown + (f" (+{len(r.sans) - limit})" if len(r.sans) > limit else "")


def render_text(results: list[Result]) -> str:
    rows = [("HOST", "DAYS", "STATUS", "EXPIRES", "ISSUER")]
    for r in sorted_results(results):
        rows.append((f"{r.host}:{r.port}", _days_cell(r), r.status.upper(),
                     r.not_after or "–", r.issuer or "–"))
    widths = [max(len(row[i]) for row in rows) for i in range(5)]
    lines = ["  ".join(c.ljust(w) for c, w in zip(row, widths)).rstrip() for row in rows]
    for r in sorted_results(results):
        if r.error:
            lines.append(f"  ! {r.host}:{r.port} - {r.error}")
    return "\n".join(lines)


def render_markdown(results: list[Result], warn_days: int, critical_days: int,
                    generated_at: datetime | None = None) -> str:
    generated_at = generated_at or datetime.now(timezone.utc)
    overall = overall_status(results)
    counts = summary_counts(results)
    parts = [f"{n} {name}" for name, n in counts.items() if n]
    out = [f"## {EMOJI[overall]} TLS certificate check: " + ", ".join(parts), "",
           "| Host | Days left | Status | Expires | Issuer | SANs |",
           "|------|----------:|--------|---------|--------|------|"]
    for r in sorted_results(results):
        out.append(f"| `{r.host}:{r.port}` | {_days_cell(r)} | {EMOJI[r.status]} {r.status} | "
                   f"{r.not_after or '–'} | {(r.issuer or '–').replace('|', '/')} | {_sans_cell(r)} |")
    problems = [r for r in sorted_results(results) if r.error]
    if problems:
        out += ["", "### Details", ""]
        out += [f"- `{r.host}:{r.port}`: {r.error}" for r in problems]
    out += ["", f"_Checked {generated_at.strftime('%Y-%m-%d %H:%M UTC')} · "
                f"warning ≤ {warn_days} days · critical ≤ {critical_days} days_"]
    return "\n".join(out) + "\n"


def write_reports(out_dir: Path, results: list[Result], warn_days: int,
                  critical_days: int) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)
    payload = {
        "generated_at": now.isoformat(timespec="seconds"),
        "overall": overall_status(results),
        "counts": summary_counts(results),
        "thresholds": {"warn_days": warn_days, "critical_days": critical_days},
        "results": [asdict(r) for r in sorted_results(results)],
    }
    (out_dir / "report.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    (out_dir / "report.md").write_text(render_markdown(results, warn_days, critical_days, now),
                                       encoding="utf-8")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Check TLS certificate expiry for a list of hosts.")
    p.add_argument("--config", default="domains.yml", help="path to domains.yml")
    p.add_argument("--out", default="reports", help="directory for report.json / report.md")
    p.add_argument("--warn-days", type=int, help="override warn_days from config")
    p.add_argument("--critical-days", type=int, help="override critical_days from config")
    p.add_argument("--timeout", type=float, help="connect/handshake timeout in seconds")
    p.add_argument("--retries", type=int, default=1, help="extra connection attempts (default 1)")
    p.add_argument("--fail-on", choices=("critical", "warning"), default="critical",
                   help="lowest severity that makes the exit code non-zero (default: critical)")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    try:
        cfg = load_config(args.config)
    except (OSError, ConfigError) as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2
    if args.warn_days is not None:
        cfg.warn_days = args.warn_days
    if args.critical_days is not None:
        cfg.critical_days = args.critical_days
    if args.timeout is not None:
        cfg.timeout = args.timeout
    if cfg.critical_days >= cfg.warn_days:
        print("config error: critical_days must be smaller than warn_days", file=sys.stderr)
        return 2

    results = run_checks(cfg, retries=args.retries)
    print(render_text(results))
    counts = summary_counts(results)
    print("\n" + ", ".join(f"{n} {name}" for name, n in counts.items()))
    write_reports(Path(args.out), results, cfg.warn_days, cfg.critical_days)

    failing = {CRITICAL, FAILED} if args.fail_on == "critical" else {WARNING, CRITICAL, FAILED}
    return 1 if any(r.status in failing for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
