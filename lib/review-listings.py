#!/usr/bin/env python3
"""Audit every service in awesome-privacy.yml.

Checks:
- url-reachable: homepage URL does not 404
- https-url: homepage URL uses HTTPS
- icon-reachable: icon URL does not 404
- description-len: description is 50 to 280 chars (over 420 escalates to warn)
- opensource-github: openSource listings include a repo link (error); not open source is noted (info)
- duplicate-url: no URL appears in more than one listing
- androidApp-valid: androidApp is a package name, not a URL
- iosApp-valid: iosApp is a valid App Store URL with an app id
- subreddit-exists: subreddit page exists on reddit.com
- tosdr-valid: tosdrId still resolves on tosdr.org
- discord-invite-valid: Discord invite code is still valid
- github-exists: github repo is accessible (needs token)
- github-archived: github repo is not archived (needs token)
- github-activity: github repo was pushed recently (needs token)
- github-license: github repo has a license (needs token)
- github-fork: github repo is not a fork (needs token)
- security-advisories: no open unpatched CVEs (needs API_TOKEN)
- android-trackers: android app has few trackers (1 info, 2+ warn) (needs API_TOKEN)
- ios-app: iOS app exists, is maintained and rated (missing/stale/low-rating warn) (needs API_TOKEN)
- degoogled-compat: android app works on de-googled android (needs API_TOKEN)
- privacy-grade: tosdr privacy grade is B or better (C info, D/E warn) (needs API_TOKEN)

Findings have three severities: error (must fix), warn (should review), info (FYI).
HTTP 403/406/429 (and 404 on known bot-blocking hosts such as play.google.com) on
reachability checks means the probe was rate-limited or blocked, not that the resource is
missing, so it is logged during the run but left out of the results.

Exit codes:
    1 when pass rate drops below FAIL_PASS_RATE or errors exceed FAIL_MAX_ERRORS (5)
    2 you didn't run the script right / something else fucked up
    0 everything is amazing

Flags:
- --save-json PATH: save a JSON report to this file
- --save-markdown PATH: save a markdown report to this file (for GH Actions summaries)
- --category / --section / --service: narrow to one entry
- --only / --skip: pick or drop checks by name
- --severity {all,warn,error}: filter findings
- --max-workers N: parallel workers (default 8)
- --timeout N: HTTP timeout in seconds (default 10)
- --token: GitHub token, else $GITHUB_TOKEN
- --no-color: disable ANSI colors
- --list-checks: list checks and exit
- -v / -q: verbose or quiet logging
"""

import argparse
import json
import logging
import os
import re
import signal
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from threading import Lock, local
from time import monotonic
from typing import Callable, Iterable
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import utils
except ImportError as exc:
    print(f"ERROR: missing dependency ({exc}). Run `make install_lib_deps`.", file=sys.stderr)
    sys.exit(2)

MIN_DESC = 50
MAX_DESC = 280
MAX_DESC_HARD = 420
DEFAULT_WORKERS = 8
DEFAULT_TIMEOUT = 10

# github-activity age bands (days since last push). Order matters: most severe first.
ACTIVITY_BANDS = (
    (365 * 8, "error"),
    (365 * 3, "warn"),
    (365,     "info"),
)

SEVERITIES = ("error", "warn", "info")
_SEV_COLOR = {"error": "red", "warn": "yellow", "info": "cyan"}
_SEV_EMOJI = {"error": "🔴", "warn": "🟠", "info": "🟡"}
_SOFT_HTTP = {403, 406, 429}
_SOFT_404_HOSTS = {"play.google.com"}
_PKG_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$")

FAIL_PASS_RATE = 95.0
FAIL_MAX_ERRORS = 5


@dataclass
class Entry:
    category: str
    section: str
    service: dict

    @property
    def name(self):
        return self.service.get("name", "")


@dataclass
class Finding:
    category: str
    section: str
    service: str
    check: str
    severity: str
    message: str


@dataclass
class Context:
    token: str
    timeout: int
    api_token: str = ""
    url_occurrences: dict = field(default_factory=dict)
    repo_cache: dict = field(default_factory=dict)
    security_cache: dict = field(default_factory=dict)
    android_cache: dict = field(default_factory=dict)
    privacy_cache: dict = field(default_factory=dict)
    ios_cache: dict = field(default_factory=dict)
    repo_lock: Lock = field(default_factory=Lock)
    _sessions: local = field(default_factory=local)

    @property
    def session(self):
        """Per-thread session, since a requests.Session is not safe to share across threads."""
        session = getattr(self._sessions, "value", None)
        if session is None:
            session = utils.make_session()
            self._sessions.value = session
        return session


@dataclass
class CheckSpec:
    name: str
    scope: str
    needs_github: bool
    needs_api: bool
    fn: Callable
    doc: str


CHECKS: dict[str, CheckSpec] = {}


def check(name, *, scope="service", needs_github=False, needs_api=False):
    def deco(fn):
        CHECKS[name] = CheckSpec(
            name, scope, needs_github, needs_api, fn, (fn.__doc__ or "").strip()
        )
        return fn
    return deco


def _finding(entry: Entry, check_name: str, severity: str, message: str) -> Finding:
    return Finding(entry.category, entry.section, entry.name, check_name, severity, message)


def _normalize_url(url: str) -> str:
    return (url or "").strip().rstrip("/").lower()


def _get_repo(entry: Entry, ctx: Context):
    owner, repo = utils.parse_github_field(entry.service.get("github"))
    if not owner:
        return None
    key = f"{owner}/{repo}"
    with ctx.repo_lock:
        if key in ctx.repo_cache:
            return ctx.repo_cache[key]
    data = utils.fetch_repo(owner, repo, ctx.token, session=ctx.session)
    with ctx.repo_lock:
        ctx.repo_cache[key] = data
    return data


def _get_security_report(entry: Entry, ctx: Context):
    owner, repo = utils.parse_github_field(entry.service.get("github"))
    if not owner:
        return None
    key = f"{owner}/{repo}"
    with ctx.repo_lock:
        if key in ctx.security_cache:
            return ctx.security_cache[key]
    data = utils.fetch_security_report(owner, repo, ctx.api_token,
                                       session=ctx.session, label=entry.name)
    with ctx.repo_lock:
        ctx.security_cache[key] = data
    return data


def _get_android(entry: Entry, ctx: Context):
    pkg = entry.service.get("androidApp")
    if not pkg:
        return None
    with ctx.repo_lock:
        if pkg in ctx.android_cache:
            return ctx.android_cache[pkg]
    data = utils.fetch_android_app(pkg, ctx.api_token, session=ctx.session, label=entry.name)
    with ctx.repo_lock:
        ctx.android_cache[pkg] = data
    return data


def _get_privacy(entry: Entry, ctx: Context):
    tid = entry.service.get("tosdrId")
    if not tid:
        return None
    key = str(tid)
    with ctx.repo_lock:
        if key in ctx.privacy_cache:
            return ctx.privacy_cache[key]
    data = utils.fetch_privacy(tid, ctx.api_token, session=ctx.session, label=entry.name)
    with ctx.repo_lock:
        ctx.privacy_cache[key] = data
    return data


def _get_ios(entry: Entry, ctx: Context):
    """Return (report, http_status) for the listing's iOS app, both None if no valid id."""
    app_id = utils.ios_app_id(entry.service.get("iosApp"))
    if not app_id:
        return None, None
    with ctx.repo_lock:
        if app_id in ctx.ios_cache:
            return ctx.ios_cache[app_id]
    result = utils.fetch_ios(entry.service.get("iosApp"), ctx.api_token,
                             session=ctx.session, label=entry.name, return_status=True)
    with ctx.repo_lock:
        ctx.ios_cache[app_id] = result
    return result


def _reachability_finding(entry, check_name, field, url, default_sev, ctx):
    ok, status = utils.check_url(url, ctx.session, ctx.timeout)
    if ok:
        return None
    host = urlparse(url).netloc.lower()
    if status in _SOFT_HTTP or (status == 404 and host in _SOFT_404_HOSTS):
        # Rate-limited or bot-blocked probe, inconclusive so log it but do not report
        logging.info("%s for %s inconclusive (HTTP %s) possibly just rate-limited/blocked", check_name, url, status)
        return None
    detail = f"{url} returned HTTP {status}" if status else f"{url} could not be reached"
    return _finding(entry, check_name, default_sev, f"{field} is unreachable, {detail}")


@check("url-reachable")
def _url_reachable(entry: Entry, ctx: Context) -> Iterable[Finding]:
    """Homepage URL must not 404."""
    url = entry.service.get("url")
    if url:
        f = _reachability_finding(entry, "url-reachable", "url", url, "error", ctx)
        if f:
            yield f


@check("https-url")
def _https_url(entry: Entry, ctx: Context) -> Iterable[Finding]:
    """Homepage URL must use HTTPS."""
    url = entry.service.get("url", "")
    if url and not url.startswith("https://"):
        yield _finding(entry, "https-url", "warn", f"url is not HTTPS: {url}")


@check("icon-reachable")
def _icon_reachable(entry: Entry, ctx: Context) -> Iterable[Finding]:
    """Icon URL must not 404."""
    icon = entry.service.get("icon")
    if icon:
        f = _reachability_finding(entry, "icon-reachable", "icon", icon, "warn", ctx)
        if f:
            yield f


@check("description-len")
def _description_len(entry: Entry, ctx: Context) -> Iterable[Finding]:
    """Description length within 50 to 280 characters (over 420 escalates to warn)."""
    length = len((entry.service.get("description") or "").strip())
    if length < MIN_DESC:
        yield _finding(entry, "description-len", "warn",
                       f"description is {length} chars (min {MIN_DESC})")
    elif length > MAX_DESC_HARD:
        yield _finding(entry, "description-len", "warn",
                       f"description is {length} chars (max {MAX_DESC_HARD})")
    elif length > MAX_DESC:
        yield _finding(entry, "description-len", "info",
                       f"description is {length} chars (target {MIN_DESC} to {MAX_DESC})")


@check("opensource-github")
def _opensource_github(entry: Entry, ctx: Context) -> Iterable[Finding]:
    """openSource: true needs a repo link (error); not open source is noted (info)."""
    svc = entry.service
    has_repo = svc.get("github") or svc.get("codeberg") or svc.get("git")
    if svc.get("openSource") is True and not has_repo:
        yield _finding(entry, "opensource-github", "error",
                       "marked openSource but missing a repository link ")
    elif svc.get("openSource") is False or not has_repo:
        reason = "openSource is false" if svc.get("openSource") is False else "no repository linked"
        yield _finding(entry, "opensource-github", "info",
                       f"not open source ({reason})")


@check("androidApp-valid")
def _android_app_valid(entry: Entry, ctx: Context) -> Iterable[Finding]:
    """androidApp must be a package name like com.example.app, not a URL."""
    val = entry.service.get("androidApp")
    if val and not _PKG_RE.match(val):
        yield _finding(entry, "androidApp-valid", "warn",
                       f"androidApp {val} is not a package name (expected com.example.app)")


@check("iosApp-valid")
def _iosapp_valid(entry: Entry, ctx: Context) -> Iterable[Finding]:
    """iosApp must be an App Store URL with an app id."""
    url = entry.service.get("iosApp")
    if url and not utils.ios_app_id(url):
        yield _finding(entry, "iosApp-valid", "warn",
                       f"iosApp {url} is not a valid App Store URL (expected .../idNNNN)")


@check("subreddit-exists")
def _subreddit_exists(entry: Entry, ctx: Context) -> Iterable[Finding]:
    """Subreddit page must exist."""
    name = (entry.service.get("subreddit") or "").strip()
    if not name:
        return
    url = f"https://old.reddit.com/r/{name}"
    f = _reachability_finding(entry, "subreddit-exists", f"r/{name}", url, "info", ctx)
    if f:
        yield f


@check("tosdr-valid")
def _tosdr_valid(entry: Entry, ctx: Context) -> Iterable[Finding]:
    """tosdrId must still resolve on tosdr.org."""
    tid = entry.service.get("tosdrId")
    if not tid:
        return
    url = f"https://tosdr.org/en/service/{tid}"
    ok, status = utils.check_url(url, ctx.session, ctx.timeout)
    if not ok:
        detail = f"HTTP {status}" if status else "not reachable"
        yield _finding(entry, "tosdr-valid", "info",
                       f"tosdrId {tid} did not validate ({detail})")


@check("discord-invite-valid")
def _discord_invite_valid(entry: Entry, ctx: Context) -> Iterable[Finding]:
    """Discord invite code must still be valid."""
    code = (entry.service.get("discordInvite") or "").strip()
    if not code:
        return
    url = f"https://discord.com/api/v10/invites/{code}"
    ok, status = utils.check_url(url, ctx.session, ctx.timeout)
    if not ok:
        detail = f"HTTP {status}" if status else "not reachable"
        yield _finding(entry, "discord-invite-valid", "info",
                       f"discord invite {code} invalid or expired ({detail})")


@check("github-exists", needs_github=True)
def _github_exists(entry: Entry, ctx: Context) -> Iterable[Finding]:
    """GitHub repo must be accessible."""
    gh = entry.service.get("github")
    if not gh:
        return
    owner, repo = utils.parse_github_field(gh)
    if not owner:
        yield _finding(entry, "github-exists", "warn",
                       f"github field {gh} is not in owner/repo form")
        return
    if _get_repo(entry, ctx) is None:
        yield _finding(entry, "github-exists", "error",
                       f"repo {owner}/{repo} not accessible (deleted, private, or API error)")


@check("github-archived", needs_github=True)
def _github_archived(entry: Entry, ctx: Context) -> Iterable[Finding]:
    """GitHub repo must not be archived."""
    if utils.repo_is_archived(_get_repo(entry, ctx)):
        yield _finding(entry, "github-archived", "error", "repository is archived on GitHub")


@check("github-fork", needs_github=True)
def _github_fork(entry: Entry, ctx: Context) -> Iterable[Finding]:
    """GitHub repo should not be a fork."""
    data = _get_repo(entry, ctx)
    if utils.repo_is_fork(data):
        parent = (data.get("parent") or {}).get("full_name")
        suffix = f" of {parent}" if parent else ""
        yield _finding(entry, "github-fork", "warn", f"repository is a fork{suffix}")


@check("github-activity", needs_github=True)
def _github_activity(entry: Entry, ctx: Context) -> Iterable[Finding]:
    """GitHub repo has been pushed to recently (info at 1y, warn at 3y, error at 8y)."""
    age = utils.repo_pushed_days_ago(_get_repo(entry, ctx))
    if age is None:
        return
    for threshold, sev in ACTIVITY_BANDS:
        if age >= threshold:
            yield _finding(entry, "github-activity", sev, f"last push {age} days ago")
            return


@check("github-license", needs_github=True)
def _github_license(entry: Entry, ctx: Context) -> Iterable[Finding]:
    """GitHub repo must have a declared license."""
    data = _get_repo(entry, ctx)
    if data and not utils.repo_has_license(data):
        yield _finding(entry, "github-license", "warn", "repository has no declared license")


@check("security-advisories", needs_api=True)
def _security_advisories(entry: Entry, ctx: Context) -> Iterable[Finding]:
    """No open unpatched CVEs (low/medium warn, high/critical error)."""
    if not entry.service.get("github"):
        return
    low_med, high_crit = utils.unpatched_advisories(_get_security_report(entry, ctx))
    if high_crit:
        yield _finding(entry, "security-advisories", "error",
                       f"{high_crit} open high/critical "
                       f"advisor{'ies' if high_crit != 1 else 'y'}")
    if low_med:
        yield _finding(entry, "security-advisories", "warn",
                       f"{low_med} open low/medium "
                       f"advisor{'ies' if low_med != 1 else 'y'}")


@check("android-trackers", needs_api=True)
def _android_trackers(entry: Entry, ctx: Context) -> Iterable[Finding]:
    """Android app has few trackers (1 info, 2+ warn)."""
    if not entry.service.get("androidApp"):
        return
    count = utils.tracker_count(_get_android(entry, ctx))
    if not count:
        return
    sev = "info" if count == 1 else "warn"
    yield _finding(entry, "android-trackers", sev,
                   f"Android app reports {count} tracker{'s' if count != 1 else ''}")


@check("ios-app", needs_api=True)
def _ios_app(entry: Entry, ctx: Context) -> Iterable[Finding]:
    """iOS app exists, is maintained and rated (missing/stale/<2 stars warn)."""
    if not utils.ios_app_id(entry.service.get("iosApp")):
        return
    report, status = _get_ios(entry, ctx)
    if status == 404:
        yield _finding(entry, "ios-app", "warn",
                       "iOS app not found on the App Store (may have been removed)")
        return
    days = utils.ios_days_since_update(report)
    if days is not None and days >= 365:
        yield _finding(entry, "ios-app", "warn",
                       f"iOS app not updated in over a year (last release {days} days ago)")
    rating, count = utils.ios_rating(report)
    if count and rating is not None and rating < 2:
        yield _finding(entry, "ios-app", "warn",
                       f"iOS app is rated below 2 stars ({rating:.1f} from {count:,} ratings)")


@check("degoogled-compat", needs_api=True)
def _degoogled_compat(entry: Entry, ctx: Context) -> Iterable[Finding]:
    """Android app works on de-Googled Android (broken warn, limited info)."""
    if not entry.service.get("androidApp"):
        return
    status = utils.degoogled_status(_get_android(entry, ctx))
    if status == "broken":
        yield _finding(entry, "degoogled-compat", "warn",
                       "Android app is broken on de-Googled Android")
    elif status == "bronze":
        yield _finding(entry, "degoogled-compat", "info",
                       "Android app has limited de-Googled support")


@check("privacy-grade", needs_api=True)
def _privacy_grade(entry: Entry, ctx: Context) -> Iterable[Finding]:
    """ToS;DR privacy grade is B or better (C info, D/E warn)."""
    if not entry.service.get("tosdrId"):
        return
    grade = utils.privacy_grade(_get_privacy(entry, ctx))
    if grade == "C":
        yield _finding(entry, "privacy-grade", "info", "privacy policy has minor concerns")
    elif grade in ("D", "E"):
        yield _finding(entry, "privacy-grade", "warn", f"privacy policy has major issues (graded: {grade})")


@check("duplicate-url", scope="global")
def _duplicate_url(entries, ctx: Context) -> Iterable[Finding]:
    """No two listings share the same homepage URL."""
    in_scope = {(e.category, e.section, e.name) for e in entries}
    for url, matches in ctx.url_occurrences.items():
        if len(matches) <= 1:
            continue
        for me in matches:
            if (me.category, me.section, me.name) not in in_scope:
                continue
            others = [e for e in matches if e is not me]
            shown = ", ".join(f"{e.category} > {e.section}: {e.name}" for e in others[:2])
            if len(others) > 2:
                shown += f" (+{len(others) - 2} more)"
            yield _finding(me, "duplicate-url", "warn",
                           f"URL {url} also used by {shown}")


_interrupted = False


def _install_sigint():
    def handler(signum, frame):
        global _interrupted
        if _interrupted:
            raise KeyboardInterrupt
        _interrupted = True
        logging.warning("Interrupt received, finishing in-flight checks (Ctrl-C again to abort)")
    signal.signal(signal.SIGINT, handler)


def build_context(args, data, token, api_token):
    ctx = Context(
        token=token,
        timeout=args.timeout,
        api_token=api_token,
    )
    for cat, sec, svc in utils.iter_services(data):
        url = _normalize_url(svc.get("url"))
        if url:
            ctx.url_occurrences.setdefault(url, []).append(Entry(cat, sec, svc))
    return ctx


def changed_service_keys(ref, head):
    """Return {(category, section, name)} for services added or modified vs a git ref."""
    from yaml_diff import build_index, diff_index, load_yaml_at_ref
    base = load_yaml_at_ref(ref)
    if base is None:
        logging.error("Could not read awesome-privacy.yml at git ref %s", ref)
        sys.exit(2)
    added, _, modified = diff_index(build_index(base, 3), build_index(head, 3))
    return set(added) | {k for k, _ in modified}


def filter_entries(data, args):
    for cat, sec, svc in utils.iter_services(data):
        if args.category and args.category.lower() != cat.lower():
            continue
        if args.section and args.section.lower() != sec.lower():
            continue
        if args.service and args.service.lower() != svc.get("name", "").lower():
            continue
        yield Entry(cat, sec, svc)


def _run_one(entry, enabled, ctx):
    findings = []
    for name in enabled:
        spec = CHECKS[name]
        if spec.scope != "service":
            continue
        try:
            findings.extend(spec.fn(entry, ctx) or [])
        except Exception as exc:
            logging.warning("check %s on %s failed: %s", name, entry.name, exc)
    return findings


def _run_global(enabled, entries, ctx):
    findings = []
    for name in enabled:
        spec = CHECKS[name]
        if spec.scope != "global":
            continue
        try:
            findings.extend(spec.fn(entries, ctx) or [])
        except Exception as exc:
            logging.warning("global check %s failed: %s", name, exc)
    return findings


def run_checks(entries, enabled, ctx, workers):
    findings = []
    total = len(entries)
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(_run_one, e, enabled, ctx): e for e in entries}
        for i, fut in enumerate(as_completed(futures), start=1):
            if _interrupted:
                ex.shutdown(wait=False, cancel_futures=True)
                break
            try:
                findings.extend(fut.result())
            except Exception as exc:
                logging.warning("worker error: %s", exc)
            if i % 25 == 0 or i == total:
                logging.info("Progress: %d/%d services reviewed", i, total)
    findings.extend(_run_global(enabled, entries, ctx))
    return findings


def _sev_color(severity, colors):
    return colors[_SEV_COLOR.get(severity, "yellow")]


def _compute_summary(findings, entries, enabled, elapsed):
    n_services = len(entries)
    total_checks = n_services * len(enabled)
    failed = {(f.category, f.section, f.service, f.check) for f in findings}
    passed_checks = total_checks - len(failed)
    pass_rate = (passed_checks / total_checks * 100) if total_checks else 100.0
    services_with_findings = {(f.category, f.section, f.service) for f in findings}
    return {
        "services_scanned": n_services,
        "services_passed": n_services - len(services_with_findings),
        "total_checks": total_checks,
        "passed_checks": passed_checks,
        "pass_rate": round(pass_rate, 1),
        "findings": len(findings),
        "errors": sum(1 for f in findings if f.severity == "error"),
        "warnings": sum(1 for f in findings if f.severity == "warn"),
        "info": sum(1 for f in findings if f.severity == "info"),
        "elapsed_seconds": round(elapsed, 2),
    }


_SUMMARY_ROWS = (("errors", "error"), ("warnings", "warn"), ("info", "info"))


def _summary(s, colors):
    parts = ", ".join(
        colors[_SEV_COLOR[sev]](f"{s[key]} {key}") if s[key] else f"0 {key}"
        for key, sev in _SUMMARY_ROWS
    )
    return "\n".join([
        colors["bold"]("Summary"),
        "-------",
        f"{s['services_scanned']} listings scanned "
        f"({s['total_checks']} checks, {s['pass_rate']:.1f}% pass rate)",
        f"{s['findings']} findings ({parts})",
        f"{s['services_passed']} listings passed all checks",
        f"Took {s['elapsed_seconds']:.1f}s",
    ])


def _markdown_summary(s):
    return "\n".join([
        "### Summary",
        "",
        f"- ℹ️ {s['services_scanned']} listings scanned "
        f"({s['total_checks']} checks, {s['pass_rate']:.1f}% pass rate)",
        f"- ⚠️ {s['findings']} findings "
        f"({s['errors']} errors, {s['warnings']} warnings, {s['info']} info)",
        f"- ✅ {s['services_passed']} listings passed all checks",
        f"- ⏱️ Triggered at {s['triggered_at']}, took {s['elapsed_seconds']:.1f}s",
    ])


def render_list(findings, colors, summary):
    lines = ["", colors["bold"]("Findings"), "--------"]
    if not findings:
        lines.append(colors["green"]("✓ All services passed."))
    grouped: dict = {}
    for f in findings:
        grouped.setdefault((f.category, f.section, f.service), []).append(f)
    for (cat, sec, name), items in grouped.items():
        lines.append(f"{colors['bold'](name)}  {colors['dim'](f'({cat} > {sec})')}")
        for f in items:
            badge = _sev_color(f.severity, colors)(f"[{f.severity.upper():<5}]")
            lines.append(f"  {badge} {colors['cyan'](f.check.ljust(20))} {f.message}")
        lines.append("")
    lines.append(_summary(summary, colors))
    return "\n".join(lines)


def render_json(findings, colors, summary):
    return json.dumps(
        {"summary": summary, "findings": [asdict(f) for f in findings]},
        indent=2,
    )


_MD_URL_RE = re.compile(r"https?://[^\s)\]]+")
_URL_TRAIL = ".,;:!?"


def _md_message(msg, url_limit=42):
    def shorten(m):
        url = m.group()
        trail = ""
        while url and url[-1] in _URL_TRAIL:
            trail = url[-1] + trail
            url = url[:-1]
        label = url if len(url) <= url_limit else url[:url_limit - 3] + "..."
        return f"[`{label}`]({url}){trail}"
    return _MD_URL_RE.sub(shorten, msg)


def render_markdown(findings, colors, summary):
    def cell(s):
        return str(s).replace("|", "\\|").replace("\n", " ")

    lines = []

    lines += ["# Awesome Privacy Auto Checks", ""]

    need_review = summary["findings"] - summary["errors"]
    lines += [
        f"_Ran {summary['total_checks']} checks across {summary['services_scanned']} "
        f"listings, with a {summary['pass_rate']:.1f}% pass rate._",
        f"_{summary['errors']} issues require action, plus another {need_review} "
        f"findings need reviewing._",
        "",
    ]

    errors = [f for f in findings if f.severity == "error"]
    if errors:
        lines += ["### Critical Issues", ""]
        for f in errors:
            lines.append(
                f"- {_SEV_EMOJI[f.severity]} **{cell(f.service)}** - "
                f"{_md_message(cell(f.message))}"
            )
        lines.append("")

    lines += [
        "---",
        "",
        "### Full Issue List",
        "",
        "| Service | Review Required |",
        "|---|---|",
    ]
    grouped: dict = {}
    for f in findings:
        grouped.setdefault((f.category, f.section, f.service), []).append(f)
    for (cat, sec, name), items in grouped.items():
        review = "<br>".join(
            f"{_SEV_EMOJI[f.severity]} {_md_message(cell(f.message))}"
            for f in items
        )
        link = f"https://awesome-privacy.xyz/{utils.slugify(cat)}/{utils.slugify(sec)}/{utils.slugify(name)}"
        lines.append(
            f"| **{cell(name)}** [↗]({link})<br>"
            f"<sup>{cell(cat)} > {cell(sec)}</sup> | {review} |"
        )
    lines += ["", "---", "", _markdown_summary(summary)]
    lines += [
        "",
        "> [!IMPORTANT]",
        "> The automated checks can produce false positives, fail to include real issues, and does not "
        "take the context of the listings into account. Careful human review is needed!",
        ""
    ]
    return "\n".join(lines)


def _csv(s):
    return [x.strip() for x in s.split(",") if x.strip()]


def parse_args():
    p = argparse.ArgumentParser(
        description="Review all listings in awesome-privacy.yml against our criteria.",
    )
    p.add_argument("--save-json", metavar="PATH", help="save a JSON report to this file")
    p.add_argument("--save-markdown", metavar="PATH",
                   help="save a markdown report to this file (for GH Actions summaries)")
    p.add_argument("--category", help="filter to a single category")
    p.add_argument("--section", help="filter to a single section")
    p.add_argument("--service", help="filter to a single service")
    p.add_argument("--changed-since", metavar="REF",
                   help="only review services added or modified vs this git ref (e.g. main)")
    p.add_argument("--only", type=_csv, default=[], help="comma-separated checks to run")
    p.add_argument("--skip", type=_csv, default=[], help="comma-separated checks to skip")
    p.add_argument("--severity", choices=["all", "warn", "error"], default="all")
    p.add_argument("--max-workers", type=int, default=DEFAULT_WORKERS)
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    p.add_argument("--token", help="GitHub token (else $GITHUB_TOKEN)")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--list-checks", action="store_true", help="list available checks and exit")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("-q", "--quiet", action="store_true")
    return p.parse_args()


def resolve_enabled(only, skip):
    unknown = [n for n in only + skip if n not in CHECKS]
    if unknown:
        logging.error("Unknown check(s): %s. Available: %s",
                      ", ".join(unknown), ", ".join(CHECKS))
        sys.exit(2)
    enabled = list(only) if only else list(CHECKS)
    return [n for n in enabled if n not in skip]


def filter_severity(findings, level):
    if level == "error":
        return [f for f in findings if f.severity == "error"]
    if level == "warn":
        return [f for f in findings if f.severity in ("warn", "error")]
    return findings


def main():
    _install_sigint()
    args = parse_args()
    utils.setup_logging("DEBUG" if args.verbose else "WARNING" if args.quiet else "INFO")
    colors = utils.make_colors(enabled=False if args.no_color else None)

    if args.list_checks:
        for name, spec in CHECKS.items():
            tag = colors["dim"](" (needs GITHUB_TOKEN)") if spec.needs_github else ""
            tag += colors["dim"](" (needs API_TOKEN)") if spec.needs_api else ""
            print(f"  {colors['cyan'](name.ljust(22))} {spec.doc}{tag}")
        return

    enabled = resolve_enabled(args.only, args.skip)
    token = args.token or os.environ.get("GITHUB_TOKEN", "")
    api_token = os.environ.get("API_TOKEN", "")

    # A targeted review (single entry/diff) runs external checks unauthenticated, as probz won't hit rate limit
    targeted = bool(args.service or args.category or args.section or args.changed_since)

    if not token:
        gh_checks = [n for n in enabled if CHECKS[n].needs_github]
        if gh_checks and not targeted:
            logging.warning(
                "GITHUB_TOKEN not set, skipping GitHub checks (%s) for a full review. "
                "Export GITHUB_TOKEN, or narrow with --service/--category/--changed-since.",
                ", ".join(gh_checks),
            )
            enabled = [n for n in enabled if not CHECKS[n].needs_github]
        elif gh_checks:
            logging.info("GITHUB_TOKEN not set, running GitHub checks unauthenticated (may be rate-limited)")

    if not api_token:
        api_checks = [n for n in enabled if CHECKS[n].needs_api]
        if api_checks and not targeted:
            logging.warning(
                "API_TOKEN not set, skipping API checks (%s) for a full review. "
                "Export API_TOKEN, or narrow the review to run them.",
                ", ".join(api_checks),
            )
            enabled = [n for n in enabled if not CHECKS[n].needs_api]
        elif api_checks:
            logging.info("API_TOKEN not set, running API checks unauthenticated (may be rate-limited)")

    if not enabled:
        logging.error("No checks to run after filters.")
        sys.exit(2)

    try:
        data = utils.load_yaml()
    except FileNotFoundError:
        logging.error("awesome-privacy.yml not found at %s", utils.DATA_PATH)
        sys.exit(2)
    except Exception as exc:
        logging.error("Failed to parse awesome-privacy.yml: %s", exc)
        sys.exit(2)

    entries = list(filter_entries(data, args))
    if args.changed_since:
        keys = changed_service_keys(args.changed_since, data)
        entries = [e for e in entries if (e.category, e.section, e.name) in keys]
        if not entries:
            logging.info("No added or modified services since %s, nothing to review",
                         args.changed_since)
            return
    if not entries:
        logging.error("No services matched filters (category=%s, section=%s, service=%s)",
                      args.category, args.section, args.service)
        sys.exit(2)

    ctx = build_context(args, data, token, api_token)
    logging.info("Reviewing %d service(s) with %d check(s): %s",
                 len(entries), len(enabled), ", ".join(enabled))

    triggered_at = datetime.now(timezone.utc)
    start = monotonic()
    findings = run_checks(entries, enabled, ctx, args.max_workers)
    elapsed = monotonic() - start

    summary = _compute_summary(findings, entries, enabled, elapsed)
    summary["triggered_at"] = triggered_at.strftime("%Y-%m-%d %H:%M UTC")
    display = filter_severity(findings, args.severity)
    display.sort(key=lambda f: (f.category, f.section, f.service, f.check))

    print(render_list(display, colors, summary))

    for path, renderer in (
        (args.save_json, render_json),
        (args.save_markdown, render_markdown),
    ):
        if not path:
            continue
        try:
            with open(path, "w") as f:
                f.write(renderer(display, colors, summary) + "\n")
            logging.info("Wrote %s", path)
        except OSError as exc:
            logging.warning("Could not write %s: %s", path, exc)

    fail = summary["pass_rate"] < FAIL_PASS_RATE or summary["errors"] > FAIL_MAX_ERRORS
    sys.exit(1 if fail else 0)


if __name__ == "__main__":
    main()
