#!/usr/bin/env python3
"""Local-first passive privacy audit toolkit. No deletion or login attempts."""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import email
import hashlib
import html
import ipaddress
import json
import mailbox
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from email import policy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import yaml

ROOT = Path(os.environ.get("PRIVACY_CENTER_HOME", Path.home() / "privacy-center"))
CONFIG = ROOT / "config" / "identity.yml"
RESULTS = ROOT / "results"
SUPPORTED = {".jpg", ".jpeg", ".png", ".pdf", ".docx", ".mp4"}
SENSITIVE_TAGS = {
    "GPSLatitude", "GPSLongitude", "GPSPosition", "GPSAltitude", "GPSCoordinates",
    "CameraSerialNumber", "SerialNumber", "InternalSerialNumber", "LensSerialNumber",
    "Model", "Make", "Author", "Creator", "CreatorTool", "Software", "Producer",
    "LastModifiedBy", "Company", "CreateDate", "ModifyDate", "MediaCreateDate",
    "TrackCreateDate", "FileCreateDate", "FileModifyDate", "UserComment",
}


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def secure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path, 0o700)
    return path


def write_json(path: Path, value) -> None:
    secure_dir(path.parent)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")
    os.chmod(path, 0o600)


def write_csv(path: Path, rows: list[dict], fields: list[str]) -> None:
    secure_dir(path.parent)
    with path.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    os.chmod(path, 0o600)


def load_identity() -> dict:
    data = yaml.safe_load(CONFIG.read_text()) or {}
    return {k: data.get(k, [] if k != "full_name" else "") for k in
            ("full_name", "alternative_names", "usernames", "emails", "phone_numbers", "domains")}


def run(cmd: list[str], timeout: int = 300, check: bool = False,
        cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, text=True, capture_output=True, timeout=timeout,
                          check=check, cwd=cwd)


def username_audit(username: str) -> Path:
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", username):
        raise SystemExit("Invalid username characters")
    stamp = dt.datetime.now().strftime("%Y%m%dT%H%M%S")
    outdir = secure_dir(RESULTS / "usernames" / f"{username}-{stamp}")
    rows: list[dict] = []
    sherlock = ROOT / "tools" / "sherlock" / "bin" / "sherlock"
    if sherlock.exists():
        # Sherlock 0.16 writes CSV output as <username>.csv in its working directory.
        raw = outdir / f"{username}.csv"
        proc = run([str(sherlock), username, "--print-found", "--no-color",
                    "--csv"], timeout=900, cwd=outdir)
        (outdir / "sherlock.stderr.txt").write_text(proc.stderr[-20000:])
        if raw.exists():
            with raw.open(newline="", errors="replace") as fh:
                for item in csv.DictReader(fh):
                    url = item.get("url_user") or item.get("url") or item.get("url_main") or ""
                    status = item.get("status") or item.get("exists") or "found"
                    rows.append({"platform": item.get("name") or item.get("site_name") or "unknown",
                                 "URL": url, "status": status, "username": username,
                                 "confidence": "medium (automated HTTP heuristic)"})
    maigret = ROOT / "tools" / "maigret" / "bin" / "maigret"
    if maigret.exists():
        raw_json = outdir / "maigret.json"
        proc = run([str(maigret), username, "--json", "simple", "--folderoutput", str(outdir),
                    "--no-autoupdate", "--no-recursion", "--no-extracting", "--no-progressbar"],
                   timeout=900)
        (outdir / "maigret.stderr.txt").write_text(proc.stderr[-20000:])
        candidates = sorted(outdir.glob("report_*.json")) + ([raw_json] if raw_json.exists() else [])
        for candidate in candidates[:1]:
            try:
                data = json.loads(candidate.read_text())
                for platform, item in data.items():
                    if isinstance(item, dict) and item.get("url_user"):
                        status_data = item.get("status", {})
                        normalized_status = (status_data.get("status", "claimed")
                                             if isinstance(status_data, dict)
                                             else str(status_data or "claimed"))
                        rows.append({"platform": platform, "URL": item["url_user"],
                                     "status": normalized_status, "username": username,
                                     "confidence": "medium (automated HTTP heuristic)"})
            except Exception:
                pass
    dedup = {(r["platform"], r["URL"]): r for r in rows}
    write_csv(outdir / "summary.csv", list(dedup.values()),
              ["platform", "URL", "status", "username", "confidence"])
    write_json(outdir / "run.json", {"identifier_type": "username", "identifier": username,
                                      "checked_at": now(), "login_attempts": False,
                                      "result_count": len(dedup)})
    return outdir


def http_status(url: str) -> int | None:
    try:
        req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "privacy-center/1.0"})
        with urllib.request.urlopen(req, timeout=12) as response:
            return response.status
    except urllib.error.HTTPError as exc:
        return exc.code
    except Exception:
        return None


def email_audit(address: str) -> Path:
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", address):
        raise SystemExit("Invalid email address")
    stamp = dt.datetime.now().strftime("%Y%m%dT%H%M%S")
    outdir = secure_dir(RESULTS / "emails" / f"audit-{stamp}")
    digest = hashlib.md5(address.strip().lower().encode(), usedforsecurity=False).hexdigest()
    gravatar_url = f"https://www.gravatar.com/avatar/{digest}?d=404"
    gravatar_status = http_status(gravatar_url)
    report = {
        "checked_at": now(), "email_sha256": hashlib.sha256(address.lower().encode()).hexdigest(),
        "gravatar": {"exposed": gravatar_status == 200, "status": gravatar_status,
                     "url": gravatar_url if gravatar_status == 200 else None},
        "search_queries_for_manual_review": [
            f'"{address}"', f'"{address}" site:github.com', f'"{address}" site:gitlab.com',
            f'"{address}" (profile OR contact OR author)'],
        "github_public_commit_search": [], "hibp": {"status": "not_checked", "breaches": []},
        "notes": ["Search engines are documented for manual review; this tool does not scrape result pages."]
    }
    if shutil.which("gh") and run(["gh", "auth", "status"], timeout=20).returncode == 0:
        query = urllib.parse.quote(f'"{address}"')
        proc = run(["gh", "api", f"search/commits?q={query}", "-H", "Accept: application/vnd.github+json"], timeout=60)
        if proc.returncode == 0:
            try:
                for item in json.loads(proc.stdout).get("items", [])[:100]:
                    report["github_public_commit_search"].append({
                        "repository": item.get("repository", {}).get("full_name"),
                        "url": item.get("html_url"), "sha": item.get("sha", "")[:12]})
            except Exception as exc:
                report["notes"].append(f"GitHub commit result parse error: {exc}")
    hibp_key = os.environ.get("HIBP_API_KEY")
    if hibp_key:
        url = "https://haveibeenpwned.com/api/v3/breachedaccount/" + urllib.parse.quote(address) + "?truncateResponse=false"
        req = urllib.request.Request(url, headers={"hibp-api-key": hibp_key, "user-agent": "privacy-center/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=20) as response:
                breaches = json.load(response)
            report["hibp"] = {"status": "checked", "breaches": [
                {k: b.get(k) for k in ("Name", "Title", "BreachDate", "AddedDate", "DataClasses", "IsVerified")}
                for b in breaches]}
        except urllib.error.HTTPError as exc:
            report["hibp"]["status"] = "no_breach" if exc.code == 404 else f"http_{exc.code}"
    else:
        report["hibp"]["status"] = "skipped: set HIBP_API_KEY only in the process environment"
    write_json(outdir / "report.json", report)
    return outdir


def github_audit() -> Path:
    if not shutil.which("gh") or run(["gh", "auth", "status"], timeout=20).returncode:
        raise SystemExit("GitHub CLI is not authenticated")
    outdir = secure_dir(RESULTS / "github" / dt.datetime.now().strftime("%Y%m%dT%H%M%S"))
    def api(path: str):
        proc = run(["gh", "api", path], timeout=180)
        if proc.returncode: return None
        try: return json.loads(proc.stdout)
        except Exception: return None
    profile = api("user") or {}
    repos = api("user/repos?per_page=100&affiliation=owner") or []
    gists = api("gists?per_page=100") or []
    keys = api("user/keys?per_page=100") or []
    emails = api("user/emails") or []
    secret_counts = []
    for repo in repos:
        if repo.get("owner", {}).get("login") != profile.get("login"): continue
        alerts = api(f"repos/{repo['full_name']}/secret-scanning/alerts?state=open&per_page=100")
        secret_counts.append({"repository": repo["full_name"],
                              "open_alert_count": len(alerts) if isinstance(alerts, list) else None,
                              "availability": "available" if isinstance(alerts, list) else "unavailable/not enabled"})
    report = {
        "checked_at": now(), "account": profile.get("login"),
        "profile_public_fields": {k: profile.get(k) for k in ("name", "company", "blog", "location", "email", "bio", "twitter_username")},
        "emails": [{"email": e.get("email"), "primary": e.get("primary"), "verified": e.get("verified"),
                    "visibility": e.get("visibility")} for e in emails],
        "public_repositories": [{"name": r.get("full_name"), "url": r.get("html_url"),
                                 "fork": r.get("fork"), "archived": r.get("archived"),
                                 "pushed_at": r.get("pushed_at")} for r in repos if not r.get("private")],
        "public_gists": [{"id": g.get("id"), "url": g.get("html_url"), "public": g.get("public"),
                          "updated_at": g.get("updated_at")} for g in gists if g.get("public")],
        "ssh_key_metadata": [{"id": k.get("id"), "title": k.get("title"), "created_at": k.get("created_at")}
                             for k in keys],
        "secret_scanning": secret_counts,
        "recommendations": ["Use a noreply commit email where public attribution is unnecessary.",
                            "Review old forks, archived repositories and public gists manually; nothing was deleted.",
                            "Rotate any valid secret represented by an open alert before removing it from history."]
    }
    write_json(outdir / "report.json", report)
    return outdir


def iter_files(target: Path):
    if target.is_file():
        if target.suffix.lower() in SUPPORTED: yield target
    elif target.is_dir():
        for path in target.rglob("*"):
            if path.is_file() and path.suffix.lower() in SUPPORTED: yield path


def metadata_audit(target: Path) -> Path:
    if not shutil.which("exiftool"): raise SystemExit("exiftool is not installed")
    files = list(iter_files(target.expanduser().resolve()))
    outdir = secure_dir(RESULTS / "metadata" / dt.datetime.now().strftime("%Y%m%dT%H%M%S"))
    rows = []
    for path in files:
        proc = run(["exiftool", "-j", "-G1", "-a", "-s", str(path)], timeout=120, check=True)
        metadata = json.loads(proc.stdout)
        if not isinstance(metadata, list) or len(metadata) != 1 or not isinstance(metadata[0], dict):
            raise ValueError("Invalid ExifTool metadata response")
        metadata = metadata[0]
        if any(key.split(":")[-1] == "Error" for key in metadata):
            raise ValueError("ExifTool could not inspect the file")
        risks = {k: v for k, v in metadata.items() if k.split(":")[-1] in SENSITIVE_TAGS or
                 any(word in k.lower() for word in ("gps", "serial", "author", "creator", "software"))}
        rows.append({"file": str(path), "risk_count": len(risks), "risks": risks})
    write_json(outdir / "report.json", {"checked_at": now(), "target": str(target), "files": rows})
    return outdir


def sanitize_metadata(target: Path) -> Path:
    if not shutil.which("exiftool"): raise SystemExit("exiftool is not installed")
    source = target.expanduser().resolve()
    destination = secure_dir(ROOT / "sanitized" / dt.datetime.now().strftime("%Y%m%dT%H%M%S"))
    for path in iter_files(source):
        relative = Path(path.name) if source.is_file() else path.relative_to(source)
        output = destination / relative
        output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, output)
        run(["exiftool", "-overwrite_original", "-all=", str(output)], timeout=180)
        if output.suffix.lower() == ".pdf" and shutil.which("qpdf"):
            rewritten = output.with_suffix(".rewritten.pdf")
            if run(["qpdf", "--linearize", str(output), str(rewritten)], timeout=180).returncode == 0:
                rewritten.replace(output)
    metadata_audit(destination)
    return destination


ACCOUNT_PATTERNS = re.compile(r"welcome|verify|verification|account (created|creation)|confirm your (email|account)|password reset|subscription confirmed|thanks for signing up", re.I)


def email_export_audit(target: Path) -> Path:
    source = target.expanduser().resolve(); rows = []
    messages = mailbox.mbox(source) if source.is_file() and source.suffix.lower() == ".mbox" else None
    iterable = messages if messages is not None else (email.message_from_binary_file(p.open("rb"), policy=policy.default)
               for p in source.rglob("*.eml") if p.is_file())
    for msg in iterable:
        subject = str(msg.get("subject", "")); sender = str(msg.get("from", "")); date = str(msg.get("date", ""))
        if ACCOUNT_PATTERNS.search(subject):
            rows.append({"service_guess": sender, "subject": subject, "date": date,
                         "category": ACCOUNT_PATTERNS.search(subject).group(0)})
    outdir = secure_dir(RESULTS / "email-exports" / dt.datetime.now().strftime("%Y%m%dT%H%M%S"))
    write_csv(outdir / "account-candidates.csv", rows, ["service_guess", "subject", "date", "category"])
    return outdir


def scoreboard() -> dict:
    accounts_path = ROOT / "data" / "accounts.csv"
    accounts = list(csv.DictReader(accounts_path.open())) if accounts_path.exists() else []
    brokers = list(csv.DictReader((ROOT / "data" / "data-brokers.csv").open()))
    metadata_risks = 0; exposed_emails = 0; breaches = 0; profile_urls: set[str] = set()
    for path in (RESULTS / "metadata").glob("*/report.json"):
        try: metadata_risks += sum(int(x.get("risk_count", 0)) for x in json.loads(path.read_text()).get("files", []))
        except Exception: pass
    for path in (RESULTS / "emails").glob("*/report.json"):
        try:
            item = json.loads(path.read_text()); exposed_emails += int(bool(item.get("gravatar", {}).get("exposed")))
            breaches += len(item.get("hibp", {}).get("breaches", []))
        except Exception: pass
    latest_username_reports: dict[str, tuple[float, Path]] = {}
    for path in (RESULTS / "usernames").glob("*/summary.csv"):
        username = path.parent.name.rsplit("-", 1)[0]
        candidate = (path.stat().st_mtime, path)
        if username not in latest_username_reports or candidate[0] > latest_username_reports[username][0]:
            latest_username_reports[username] = candidate
    for _, path in latest_username_reports.values():
        try:
            profile_urls.update(row.get("URL", "") for row in csv.DictReader(path.open())
                                if row.get("URL"))
        except Exception: pass
    return {"known_accounts": len(accounts), "deleted_accounts": sum(x.get("deleted", "").lower() in ("yes","true","1") for x in accounts),
            "public_profiles": len(profile_urls), "exposed_emails": exposed_emails, "known_breaches": breaches,
            "public_phone_occurrences": 0, "metadata_risks": metadata_risks,
            "outstanding_gdpr_requests": sum(x.get("request_sent", "").lower() in ("yes","true","1") and x.get("deleted", "").lower() not in ("yes","true","1") for x in brokers)}


def dashboard(bind: str | None, port: int) -> None:
    token_path = ROOT / "config" / "dashboard.token"
    if not token_path.exists(): token_path.write_text(secrets.token_urlsafe(24)); os.chmod(token_path, 0o600)
    token = token_path.read_text().strip()
    if not bind:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try: probe.connect(("192.0.2.1", 9)); bind = probe.getsockname()[0]
        finally: probe.close()
    try:
        bind_ip = ipaddress.ip_address(bind)
    except ValueError as exc:
        raise SystemExit("Dashboard --bind must be a numeric LAN or loopback address") from exc
    if not (bind_ip.is_private or bind_ip.is_loopback or bind_ip.is_link_local):
        raise SystemExit("Refusing to bind the privacy dashboard to a public address")
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            if query.get("token", [""])[0] != token:
                self.send_response(403); self.end_headers(); return
            cards = "".join(f"<article><strong>{html.escape(k.replace('_',' ').title())}</strong><span>{v}</span></article>" for k,v in scoreboard().items())
            body = f"<!doctype html><meta name=viewport content='width=device-width'><title>Privacy Center</title><style>body{{font:16px system-ui;background:#0b1220;color:#eaf1ff;max-width:1000px;margin:3rem auto;padding:1rem}}main{{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:1rem}}article{{background:#15233b;padding:1.3rem;border-radius:14px}}strong,span{{display:block}}span{{font-size:2rem;color:#7dd3fc;margin-top:.5rem}}small{{color:#9fb2cc}}</style><h1>Local Privacy Center</h1><small>Generated locally {html.escape(now())}; no cloud upload.</small><main>{cards}</main>"
            payload = body.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
            self.end_headers()
            self.wfile.write(payload)
        def log_message(self, *_): pass
    print(f"Dashboard: http://{bind}:{port}/?token={token}")
    ThreadingHTTPServer((bind, port), Handler).serve_forever()


def audit_all() -> None:
    identity = load_identity(); completed = []
    for value in identity["usernames"]: completed.append(str(username_audit(value)))
    for value in identity["emails"]: completed.append(str(email_audit(value)))
    if shutil.which("gh") and run(["gh", "auth", "status"], timeout=20).returncode == 0:
        completed.append(str(github_audit()))
    print(json.dumps({"completed": completed, "identifiers_present": {k: len(v) if isinstance(v,list) else bool(v) for k,v in identity.items()}}, indent=2))


def main():
    os.umask(0o077); secure_dir(RESULTS)
    parser = argparse.ArgumentParser(prog="privacy-audit", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("username"); p.add_argument("value")
    p = sub.add_parser("email"); p.add_argument("value")
    sub.add_parser("github")
    p = sub.add_parser("metadata"); p.add_argument("path", type=Path)
    p = sub.add_parser("metadata-sanitize"); p.add_argument("path", type=Path)
    p = sub.add_parser("email-export"); p.add_argument("path", type=Path)
    p = sub.add_parser("dashboard"); p.add_argument("--bind"); p.add_argument("--port", type=int, default=8765)
    sub.add_parser("all")
    args = parser.parse_args()
    result = None
    if args.command == "username": result = username_audit(args.value)
    elif args.command == "email": result = email_audit(args.value)
    elif args.command == "github": result = github_audit()
    elif args.command == "metadata": result = metadata_audit(args.path)
    elif args.command == "metadata-sanitize": result = sanitize_metadata(args.path)
    elif args.command == "email-export": result = email_export_audit(args.path)
    elif args.command == "dashboard": return dashboard(args.bind, args.port)
    elif args.command == "all": return audit_all()
    if result: print(result)


if __name__ == "__main__": main()
