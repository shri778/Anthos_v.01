import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
from pathlib import Path

# =========================
# EDIT YOUR ALLOWED TARGETS HERE
# Only domains you own or bug bounty in-scope domains
# =========================
SCOPES = [
    "example.com",
    "api.example.com",
]

USER_AGENT = "ArenaReconBot/minimal-2file-passive-recon"
REQUEST_DELAY_SECONDS = 0.15
MAX_WAYBACK_URLS = 300
MAX_JS_FILES = 15
MAX_REPORTED_ITEMS = 20

BASE_DIR = Path(".").resolve()
STATE_FILE = BASE_DIR / "state.json"
RESULTS_FILE = BASE_DIR / "results.md"

ANTI_BOT_SIGNATURES = {
    "prove_not_robot": [
        "prove you are not a robot",
        "prove you are human",
    ],
    "verify_human": [
        "verify you are human",
        "verify that you are human",
    ],
    "captcha": [
        "captcha",
        "hcaptcha",
        "recaptcha",
        "turnstile",
        "cf-turnstile",
    ],
    "cloudflare_challenge": [
        "attention required",
        "just a moment",
        "checking your browser",
        "enable javascript and cookies to continue",
        "cf-chl-",
        "__cf_bm",
    ],
}

INTERESTING_PARAM_KEYWORDS = [
    "redirect", "url", "next", "return", "dest",
    "file", "path", "download", "image",
    "token", "code", "state", "email", "user", "id",
    "callback", "debug", "admin",
]

INTERESTING_PATH_KEYWORDS = [
    "api", "graphql", "admin", "upload", "debug", "internal",
    "export", "oauth", "auth", "login", "reset", "backup",
    "config", "private", "v1", "v2",
]

PATH_REGEX = re.compile(r'["\']((?:/|https?://)[^"\'\s]{1,180})["\']')
_last_request_at = 0.0


def throttle():
    global _last_request_at
    now = time.time()
    wait = REQUEST_DELAY_SECONDS - (now - _last_request_at)
    if wait > 0:
        time.sleep(wait)
    _last_request_at = time.time()


def normalize_scope_domain(value: str) -> str:
    value = value.strip()
    if not value:
        return ""
    if value.startswith("http://") or value.startswith("https://"):
        return urllib.parse.urlparse(value).netloc.lower().strip()
    return value.lower().strip().strip("/")


def load_scope():
    return sorted(set(filter(None, [normalize_scope_domain(x) for x in SCOPES])))


def same_domain(url: str, domain: str) -> bool:
    try:
        host = urllib.parse.urlparse(url).netloc.lower()
        if not host:
            return True
        return host == domain or host.endswith("." + domain)
    except Exception:
        return False


def build_https_url(domain: str, path: str) -> str:
    return urllib.parse.urljoin(f"https://{domain}/", path)


def detect_anti_bot_signals(text: str, headers: dict) -> list:
    blob = (text or "")[:300000].lower()
    if headers:
        blob += "\n" + "\n".join(f"{k}: {v}" for k, v in headers.items()).lower()

    found = []
    for name, phrases in ANTI_BOT_SIGNATURES.items():
        if any(p in blob for p in phrases):
            found.append(name)
    return sorted(set(found))


def alert_identity(alert: dict) -> str:
    return f"{alert.get('url','')}|{alert.get('status','unknown')}|{','.join(alert.get('matches', []))}"


def add_alert(alerts: list, url: str, status, matches: list):
    if not matches:
        return
    alert = {
        "url": url,
        "status": status if status is not None else "unknown",
        "matches": sorted(set(matches)),
    }
    keys = {alert_identity(x) for x in alerts}
    if alert_identity(alert) not in keys:
        alerts.append(alert)
        print(f"::warning::Anti-bot detected at {url} status={alert['status']} signals={','.join(alert['matches'])}")


def get_text(url: str, timeout: int = 20, alerts: list | None = None) -> str:
    throttle()
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    status = None
    headers = {}
    text = ""

    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            status = getattr(response, "status", None)
            headers = dict(response.headers.items())
            text = response.read().decode("utf-8", "ignore")
    except urllib.error.HTTPError as exc:
        status = exc.code
        headers = dict(exc.headers.items())
        try:
            text = exc.read().decode("utf-8", "ignore")
        except Exception:
            text = ""
    except Exception:
        return ""

    if alerts is not None:
        add_alert(alerts, url, status, detect_anti_bot_signals(text, headers))
    return text


class HTMLCollector(HTMLParser):
    def __init__(self):
        super().__init__()
        self.scripts = []
        self.links = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "script" and attrs.get("src"):
            self.scripts.append(attrs["src"])
        if tag == "a" and attrs.get("href"):
            self.links.append(attrs["href"])


def extract_from_robots(domain: str, alerts: list) -> set:
    text = get_text(f"https://{domain}/robots.txt", alerts=alerts)
    found = set()
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        if not value:
            continue
        if key in {"allow", "disallow"} and value.startswith("/"):
            found.add(build_https_url(domain, value))
        elif key == "sitemap":
            if value.startswith("http://") or value.startswith("https://"):
                found.add(value)
            elif value.startswith("/"):
                found.add(build_https_url(domain, value))
    return found


def parse_xml_locs(xml_text: str) -> list:
    out = []
    if not xml_text:
        return out
    try:
        root = ET.fromstring(xml_text)
    except Exception:
        return out
    for el in root.iter():
        if el.tag.endswith("loc") and el.text:
            out.append(el.text.strip())
    return out


def collect_sitemaps(domain: str, extra_candidates, alerts: list) -> set:
    candidates = {f"https://{domain}/sitemap.xml"}
    candidates.update(extra_candidates)
    found = set()
    for candidate in list(candidates)[:10]:
        low = candidate.lower()
        if not low.endswith(".xml") and "sitemap" not in low:
            continue
        xml_text = get_text(candidate, alerts=alerts)
        if not xml_text:
            continue
        found.add(candidate)
        for loc in parse_xml_locs(xml_text):
            found.add(loc)
    return found


def collect_wayback(domain: str) -> set:
    base = "https://web.archive.org/cdx/search/cdx"
    query = urllib.parse.urlencode({
        "url": f"*.{domain}/*",
        "output": "json",
        "fl": "original",
        "collapse": "urlkey",
        "limit": str(MAX_WAYBACK_URLS),
    })
    raw = get_text(f"{base}?{query}", timeout=30)
    if not raw:
        return set()
    try:
        data = json.loads(raw)
        return {str(row[0]) for row in data[1:] if row}
    except Exception:
        return set()


def collect_homepage(domain: str, alerts: list):
    html = get_text(f"https://{domain}/", alerts=alerts)
    if not html:
        return set(), set(), set()

    parser = HTMLCollector()
    try:
        parser.feed(html)
    except Exception:
        pass

    scripts = set()
    links = set()
    endpoints = set()

    for src in parser.scripts[:MAX_JS_FILES]:
        full = urllib.parse.urljoin(f"https://{domain}/", src)
        if same_domain(full, domain):
            scripts.add(full)

    for href in parser.links[:200]:
        full = urllib.parse.urljoin(f"https://{domain}/", href)
        if same_domain(full, domain):
            links.add(full)

    for js_url in sorted(scripts):
        js = get_text(js_url, timeout=25, alerts=alerts)
        if not js:
            continue
        for match in PATH_REGEX.findall(js):
            candidate = urllib.parse.urljoin(f"https://{domain}/", match)
            if same_domain(candidate, domain):
                if any(k in candidate.lower() for k in INTERESTING_PATH_KEYWORDS):
                    endpoints.add(candidate)

    return scripts, links, endpoints


def score_url(url: str):
    parsed = urllib.parse.urlparse(url)
    low = url.lower()
    hits = []
    score = 0

    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    for key in params:
        key = key.lower()
        for kw in INTERESTING_PARAM_KEYWORDS:
            if kw in key:
                score += 2
                hits.append(f"param:{kw}")

    for kw in INTERESTING_PATH_KEYWORDS:
        if kw in low:
            score += 1
            hits.append(f"path:{kw}")

    if parsed.query:
        score += 1
        hits.append("has_params")

    if any(ext in low for ext in [".bak", ".old", ".zip", ".tar", ".gz", ".env", ".sql"]):
        score += 2
        hits.append("sensitive_ext")

    return score, sorted(set(hits))


def load_state():
    if not STATE_FILE.exists():
        return {}
    try:
        data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_state(state: dict):
    STATE_FILE.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")


def render_results(domains, findings, old_state):
    lines = [
        "# Recon results",
        "",
        "Passive recon only. Legal scope only.",
        "Anti-bot/CAPTCHA pages are flagged if detected.",
        f"_Updated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}_",
        "",
    ]

    for domain in domains:
        current = findings.get(domain, {}).get("urls", [])
        old_urls = set(old_state.get(domain, {}).get("urls", []))
        new_items = [u for u in current if u not in old_urls]

        current_alerts = findings.get(domain, {}).get("alerts", [])
        old_alert_ids = {
            alert_identity(x)
            for x in old_state.get(domain, {}).get("alerts", [])
            if isinstance(x, dict)
        }
        new_alerts = [x for x in current_alerts if alert_identity(x) not in old_alert_ids]

        ranked = []
        for url in current:
            score, hits = score_url(url)
            if score > 0:
                ranked.append((score, hits, url))
        ranked.sort(key=lambda x: (-x[0], x[2]))

        lines.append(f"## {domain}")
        lines.append(f"- total collected: {len(current)}")
        lines.append(f"- new since last run: {len(new_items)}")
        lines.append(f"- anti-bot alerts: {len(current_alerts)}")

        if new_items:
            lines.append("- new items:")
            for url in new_items[:MAX_REPORTED_ITEMS]:
                lines.append(f"  - {url}")

        if new_alerts:
            lines.append("- new anti-bot alerts:")
            for alert in new_alerts[:MAX_REPORTED_ITEMS]:
                lines.append(f"  - {alert['url']}  status={alert['status']}  signals={','.join(alert['matches'])}")

        if current_alerts:
            lines.append("- anti-bot / captcha pages detected:")
            for alert in current_alerts[:MAX_REPORTED_ITEMS]:
                lines.append(f"  - {alert['url']}  status={alert['status']}  signals={','.join(alert['matches'])}")

        if ranked:
            lines.append("- interesting URLs:")
            for score, hits, url in ranked[:MAX_REPORTED_ITEMS]:
                lines.append(f"  - [{score}] {url}  keywords={','.join(hits)}")

        lines.append("")

    return "\n".join(lines)


def main():
    domains = load_scope()
    if not domains:
        RESULTS_FILE.write_text("# Recon results\n\nNo domains configured.\n", encoding="utf-8")
        print("No domains configured in SCOPES.")
        return

    old_state = load_state()
    new_state = {}

    for domain in domains:
        print(f"[+] scanning {domain}")
        found = set()
        alerts = []

        robot_items = extract_from_robots(domain, alerts)
        found.update(robot_items)

        sitemap_items = collect_sitemaps(domain, robot_items, alerts)
        found.update(sitemap_items)

        wayback_items = collect_wayback(domain)
        found.update(url for url in wayback_items if same_domain(url, domain))

        script_urls, link_urls, endpoint_urls = collect_homepage(domain, alerts)
        found.update(script_urls)
        found.update(link_urls)
        found.update(endpoint_urls)

        cleaned = sorted(
            url for url in found
            if url.startswith("http://") or url.startswith("https://")
        )

        new_state[domain] = {
            "urls": cleaned,
            "alerts": alerts,
        }

    save_state(new_state)
    RESULTS_FILE.write_text(render_results(domains, new_state, old_state), encoding="utf-8")
    print("[+] done")
    print("[+] wrote results.md and state.json")


if __name__ == "__main__":
    main()
