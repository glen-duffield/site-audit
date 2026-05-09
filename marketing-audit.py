#!/usr/bin/env python3
"""
Marketing audit — public-site checks across multiple product domains.

Usage:
    python3 marketing-audit.py

Output:
    marketing-audit-report.html (saved next to this script)

What it checks (per domain):
    1.  HTTPS + valid SSL cert
    2.  robots.txt exists and isn't accidentally blocking everything
    3.  sitemap.xml exists and is referenced in robots.txt
    4.  Canonical URL set
    5.  Custom 404 page
    6.  Title tag (length 30-60)
    7.  Meta description (length 120-160)
    8.  Single H1 per page
    9.  Heading hierarchy (no skipped levels)
    10. Image alt text
    11. OpenGraph tags (og:title, og:description, og:image, og:url)
    12. og:image loads
    13. Twitter card tag
    14. LinkedIn-ready (uses og: tags)
    15. Schema/JSON-LD present
    16. Schema parses cleanly
    17. Page weight under 2 MB
    18. Mobile viewport meta
    19. Favicon
    20. Security headers (HSTS, X-Content-Type-Options, Referrer-Policy)

Edit DOMAINS below to add/remove sites.
No external Python packages required — uses stdlib only.
"""

import json
import re
import ssl
import socket
import time
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime, timezone
from html.parser import HTMLParser
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# Domains are loaded from audit-config.json (next to this script).
# To add/remove sites, edit that JSON — or use the cowork artifact's add-domain UI.
# Falls back to this hardcoded list if audit-config.json is missing.
_FALLBACK_DOMAINS = [
    "agenticintelligence.co.nz",
    "adiso.co.nz",
    "xos.co.nz",
    "buildfoundry.co.nz",
    "workable.co.nz",
    "takeoffqs.com",
    "trafficsense.co.nz",
    "trafficsense.com.au",
]


def load_domains():
    config_path = Path(__file__).resolve().parent / "audit-config.json"
    if not config_path.exists():
        print(f"audit-config.json not found at {config_path} — using fallback list.")
        return _FALLBACK_DOMAINS
    try:
        with open(config_path) as fh:
            cfg = json.load(fh)
        domains = []
        for brand in cfg.get("brands", []):
            for d in brand.get("domains", []):
                if d and d not in domains:
                    domains.append(d)
        if not domains:
            print("audit-config.json has no domains — using fallback list.")
            return _FALLBACK_DOMAINS
        return domains
    except Exception as e:
        print(f"Couldn't parse audit-config.json ({e}) — using fallback list.")
        return _FALLBACK_DOMAINS


DOMAINS = load_domains()

UA = "Mozilla/5.0 (compatible; AgenticAuditBot/1.0; +https://agenticintelligence.co.nz)"
TIMEOUT = 15


# ---------- Lightweight HTML parser (stdlib only) ----------

class SiteParser(HTMLParser):
    """Walks the homepage HTML and pulls out everything our 20 checks need."""

    def __init__(self):
        super().__init__()
        self.title = None
        self._in_title = False
        self.meta = []          # list of dicts of attributes
        self.links = []         # list of dicts of attributes
        self.headings = []      # list of (level:int, text:str)
        self._heading_stack = []  # current open heading
        self._current_text = []
        self.imgs = []          # list of dicts of attributes
        self.json_ld = []       # raw JSON-LD strings
        self._in_json_ld = False
        self._json_ld_buf = []
        self.html_attrs = {}    # attributes on the <html> tag

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "html":
            self.html_attrs = a
        if tag == "title":
            self._in_title = True
            self._current_text = []
        elif tag == "meta":
            self.meta.append(a)
        elif tag == "link":
            self.links.append(a)
        elif tag == "img":
            self.imgs.append(a)
        elif tag in ("h1", "h2", "h3", "h4", "h5", "h6"):
            self._heading_stack.append((int(tag[1]), []))
        elif tag == "script" and a.get("type") == "application/ld+json":
            self._in_json_ld = True
            self._json_ld_buf = []

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False
            self.title = "".join(self._current_text).strip() or None
        elif tag in ("h1", "h2", "h3", "h4", "h5", "h6") and self._heading_stack:
            level, parts = self._heading_stack.pop()
            self.headings.append((level, "".join(parts).strip()))
        elif tag == "script" and self._in_json_ld:
            self._in_json_ld = False
            self.json_ld.append("".join(self._json_ld_buf))

    def handle_data(self, data):
        if self._in_title:
            self._current_text.append(data)
        if self._heading_stack:
            self._heading_stack[-1][1].append(data)
        if self._in_json_ld:
            self._json_ld_buf.append(data)


# ---------- Fetching ----------

def fetch(url, method="GET", timeout=TIMEOUT):
    req = urllib.request.Request(url, headers={"User-Agent": UA}, method=method)
    try:
        start = time.time()
        with urllib.request.urlopen(req, timeout=timeout) as r:
            content = r.read() if method == "GET" else b""
            return {
                "ok": True, "status": r.status, "url": r.geturl(),
                "headers": dict(r.headers), "content": content,
                "text": content.decode(r.headers.get_content_charset() or "utf-8", errors="replace"),
                "elapsed_ms": int((time.time() - start) * 1000),
            }
    except urllib.error.HTTPError as e:
        return {
            "ok": True, "status": e.code, "url": e.url, "headers": dict(e.headers or {}),
            "content": b"", "text": "", "error": str(e),
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}


def head_check(url):
    """HEAD request to check if a URL exists. Falls back to GET if HEAD blocked."""
    r = fetch(url, method="HEAD", timeout=8)
    if r.get("ok") and r.get("status") in (405, 501):
        r = fetch(url, method="GET", timeout=8)
    return r


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Stop urllib from auto-following redirects so we can see the first response."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def head_no_redirect(url, timeout=10):
    """HEAD request without following redirects.
    Returns first-hop status (e.g. 301) and the Location header it points at.
    Falls back to GET if HEAD is rejected.
    """
    opener = urllib.request.build_opener(_NoRedirectHandler())
    for method in ("HEAD", "GET"):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA}, method=method)
            with opener.open(req, timeout=timeout) as r:
                return {
                    "ok": True,
                    "status": r.status,
                    "url": r.geturl(),
                    "location": r.headers.get("Location"),
                    "headers": dict(r.headers),
                }
        except urllib.error.HTTPError as e:
            # Server returned 3xx/4xx/5xx. For us this is a valid response, not an error.
            # 405/501 = method not allowed → retry with GET.
            if e.code in (405, 501) and method == "HEAD":
                continue
            return {
                "ok": True,
                "status": e.code,
                "url": e.url,
                "location": (e.headers or {}).get("Location") if e.headers else None,
                "headers": dict(e.headers or {}),
            }
        except Exception as e:
            if method == "HEAD":
                continue  # try GET
            return {"ok": False, "error": str(e)}
    return {"ok": False, "error": "Both HEAD and GET failed"}


def check_ssl(host):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                return {"ok": True, "expires": cert.get("notAfter", "?")}
    except Exception as e:
        return {"ok": False, "error": str(e)}


# ---------- Check helpers ----------

def result(status, msg, fix="", view=None, external_url=None):
    """status is one of: pass | warn | fail | skip
    view: optional URL/list to preview as image in a modal
    external_url: optional URL the dashboard should render as an Open ↗ link"""
    r = {"status": status, "message": msg, "fix": fix}
    if view:
        r["view"] = view
    if external_url:
        r["external_url"] = external_url
    return r


def result_with_view(status, msg, fix="", view=None, external_url=None):
    """Backwards-compatible alias."""
    return result(status, msg, fix=fix, view=view, external_url=external_url)


_GTM_CONTAINER_CACHE = {}

def detect_linkedin_via_gtm(gtm_id):
    """Fetch the public GTM container script and look for LinkedIn Insight signals.
    Returns dict with 'found' (bool), 'partner_id' (str|None), 'signals' (list[str]).
    Cached per gtm_id within a single audit run to avoid duplicate fetches.
    Most reliable when the GTM container has 'LinkedIn Insight' template tags configured.
    Has false positive risk (template references) and false negative risk (heavy obfuscation)."""
    if gtm_id in _GTM_CONTAINER_CACHE:
        return _GTM_CONTAINER_CACHE[gtm_id]
    try:
        url = f"https://www.googletagmanager.com/gtm.js?id={gtm_id}"
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=10) as r:
            content = r.read().decode("utf-8", errors="replace")
    except Exception:
        _GTM_CONTAINER_CACHE[gtm_id] = {"found": False}
        return _GTM_CONTAINER_CACHE[gtm_id]

    signals = []
    partner_id = None

    # Direct partner ID assignment pattern
    m = re.search(r'_linkedin_partner_id["\']?\s*[:=]\s*["\']?(\d{4,8})', content)
    if m:
        partner_id = m.group(1)
        signals.append(f"_linkedin_partner_id={partner_id}")

    # snap.licdn.com is the LinkedIn Insight delivery domain
    if "snap.licdn.com" in content or "licdn.com/li.lms-analytics" in content:
        signals.append("snap.licdn.com reference")

    # GTM tag template ID for LinkedIn Insight (usually cvt_NN_NN-tied)
    if re.search(r'\"LinkedIn[^\"]{0,30}Insight', content, re.IGNORECASE):
        signals.append("LinkedIn Insight tag name")
    if re.search(r'(?i)linkedin[_\s]*insight[_\s]*tag', content):
        signals.append("LinkedIn Insight Tag string")

    res = {"found": bool(signals), "partner_id": partner_id, "signals": signals}
    _GTM_CONTAINER_CACHE[gtm_id] = res
    return res


def lookup_spf_dmarc(domain):
    """Returns (spf_record_or_None, dmarc_record_or_None) using Cloudflare DNS-over-HTTPS.
    No external Python deps required."""
    def _query(name):
        try:
            url = f"https://cloudflare-dns.com/dns-query?name={name}&type=TXT"
            req = urllib.request.Request(url, headers={"Accept": "application/dns-json"})
            with urllib.request.urlopen(req, timeout=8) as r:
                data = json.loads(r.read().decode("utf-8", errors="replace"))
            answers = data.get("Answer", [])
            return [a.get("data", "").strip('"') for a in answers if a.get("type") == 16]
        except Exception:
            return []

    spf = None
    for txt in _query(domain):
        if txt.lower().startswith("v=spf1"):
            spf = txt
            break
    dmarc = None
    for txt in _query(f"_dmarc.{domain}"):
        if txt.lower().startswith("v=dmarc1"):
            dmarc = txt
            break
    return spf, dmarc


_PLACEHOLDER_PATTERNS = [
    "lorem ipsum",
    "dolor sit amet",
    "consectetur adipiscing",
    "lipsum",
    "[placeholder]",
    "placeholder text",
    "insert text here",
    "your tagline here",
    "your headline here",
    "untitled",
    " todo ",
    ">todo<",
    "fixme",
    "xxx xxx",
]

def detect_placeholder_text(html):
    """Returns a set of placeholder patterns found in the HTML body text (case-insensitive).
    Strips script/style content first to avoid matching code comments."""
    # Strip script + style tags
    cleaned = re.sub(r"<script[^>]*>.*?</script>", " ", html, flags=re.DOTALL | re.IGNORECASE)
    cleaned = re.sub(r"<style[^>]*>.*?</style>", " ", cleaned, flags=re.DOTALL | re.IGNORECASE)
    # Strip remaining tags so we look at text content
    text = re.sub(r"<[^>]+>", " ", cleaned).lower()
    found = set()
    for p in _PLACEHOLDER_PATTERNS:
        if p.lower() in text:
            found.add(p.strip().strip("[]"))
    return found


def get_meta(parser, key, attr="name"):
    for m in parser.meta:
        if m.get(attr, "").lower() == key.lower() and m.get("content"):
            return m["content"].strip()
    return None


def get_meta_property(parser, prop):
    return get_meta(parser, prop, attr="property")


# ---------- Stack + tracking detection ----------

def detect_stack(html, headers, domain):
    """Returns dict with framework/css/cdn/cms/registrar + evidence list."""
    out = {"framework": None, "css": None, "cdn": None, "cms": None, "registrar": None, "evidence": []}
    h = {k.lower(): v for k, v in (headers or {}).items()}

    # ----- Hosting / CDN (response headers) -----
    server = h.get("server", "")
    if "cf-ray" in h or "cloudflare" in server.lower():
        out["cdn"] = "Cloudflare"
        out["evidence"].append(f"cf-ray header / Server: {server[:50]}")
    elif "x-vercel-id" in h or "vercel" in server.lower():
        out["cdn"] = "Vercel"
        out["evidence"].append("x-vercel-id header")
    elif "x-nf-request-id" in h or "netlify" in server.lower():
        out["cdn"] = "Netlify"
        out["evidence"].append("x-nf-request-id header")
    elif "github.com" in server.lower():
        out["cdn"] = "GitHub Pages"
        out["evidence"].append(f"Server: {server}")
    elif "x-amz-cf-id" in h or "cloudfront" in server.lower():
        out["cdn"] = "AWS CloudFront"
        out["evidence"].append("x-amz-cf-id header")
    elif "x-served-by" in h and "fastly" in (h.get("x-served-by", "")).lower():
        out["cdn"] = "Fastly"
        out["evidence"].append("Fastly x-served-by")
    elif "webflow" in server.lower():
        out["cdn"] = "Webflow"
        out["evidence"].append(f"Server: {server}")
    elif "replit" in server.lower():
        out["cdn"] = "Replit"
        out["evidence"].append(f"Server: {server}")
    elif server:
        out["cdn"] = server.split(",")[0].strip()[:40]
        out["evidence"].append(f"Server: {server[:60]}")

    # ----- Framework -----
    if "__NEXT_DATA__" in html or "/_next/" in html:
        out["framework"] = "Next.js (React)"
        out["evidence"].append("__NEXT_DATA__ / _next paths")
    elif "__NUXT__" in html or "/_nuxt/" in html:
        out["framework"] = "Nuxt (Vue)"
        out["evidence"].append("__NUXT__ / _nuxt paths")
    elif "astro-island" in html or "/_astro/" in html:
        out["framework"] = "Astro"
        out["evidence"].append("astro-island / _astro paths")
    elif "__remixContext" in html:
        out["framework"] = "Remix (React)"
    elif "___gatsby" in html or "gatsby-" in html.lower()[:5000]:
        out["framework"] = "Gatsby (React)"
    elif "/_app/immutable/" in html:
        out["framework"] = "SvelteKit"
        out["evidence"].append("_app/immutable paths")
    elif re.search(r'data-v-[0-9a-f]{8}', html):
        out["framework"] = "Vue"
        out["evidence"].append("data-v-* attributes")
    elif "react-dom" in html.lower() or "_reactRootContainer" in html:
        out["framework"] = "React"
    elif re.search(r'svelte-[0-9a-z]{6}', html):
        out["framework"] = "Svelte"
    # No JS framework signals — leave as None (= plain HTML)

    # ----- CSS framework -----
    # Tailwind: many utility-class patterns. Heuristic: look for at least 5 distinct utility patterns.
    tw_indicators = re.findall(r'class="[^"]*\b(?:flex|grid|hidden|block|absolute|relative|md:|sm:|lg:|xl:|2xl:|hover:|focus:|dark:)[^"]*"', html)
    if len(tw_indicators) >= 5:
        out["css"] = "Tailwind CSS"
        out["evidence"].append(f"~{len(tw_indicators)} Tailwind-style classes")
    elif "bootstrap" in html.lower()[:50000]:
        out["css"] = "Bootstrap"
        out["evidence"].append("Bootstrap reference")

    # ----- CMS / builder -----
    if "/wp-content/" in html or "wp-json" in html:
        out["cms"] = "WordPress"
        out["evidence"].append("/wp-content/ paths")
    elif "data-wf-page" in html or "data-wf-site" in html or "webflow.com" in html.lower()[:30000]:
        out["cms"] = "Webflow"
        out["evidence"].append("data-wf-page attributes")
    elif "framerusercontent.com" in html or "data-framer-" in html:
        out["cms"] = "Framer"
        out["evidence"].append("framerusercontent.com")
    elif "static1.squarespace.com" in html or "Squarespace-" in str(headers):
        out["cms"] = "Squarespace"
        out["evidence"].append("Squarespace asset host")
    elif "cdn.shopify.com" in html:
        out["cms"] = "Shopify"
        out["evidence"].append("cdn.shopify.com")

    # ----- Registrar (RDAP via rdap.org) -----
    out["registrar"] = lookup_registrar(domain)

    return out


def lookup_registrar(domain):
    """Use rdap.org to find the registrar. Returns string or None."""
    try:
        url = f"https://rdap.org/domain/{domain}"
        req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": UA})
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read().decode("utf-8", errors="replace"))
        # Walk entities, find registrar role
        for ent in data.get("entities", []):
            roles = ent.get("roles", [])
            if "registrar" in roles:
                # Try to pull the org name from vcardArray
                vc = ent.get("vcardArray")
                if vc and len(vc) > 1 and isinstance(vc[1], list):
                    for entry in vc[1]:
                        if isinstance(entry, list) and len(entry) >= 4 and entry[0] == "fn":
                            return entry[3]
                # Fall back to handle
                return ent.get("handle") or ent.get("publicIds", [{}])[0].get("identifier")
    except Exception:
        return None
    return None


def detect_tracking(html):
    """Returns dict of installed trackers (each as {installed, id, evidence})."""
    out = {}

    # GA4: look for G-XXXXXXXX
    m = re.search(r'gtag\(\s*["\']config["\'],\s*["\'](G-[A-Z0-9]+)', html) or \
        re.search(r'googletagmanager\.com/gtag/js\?id=(G-[A-Z0-9]+)', html)
    if m:
        out["ga4"] = {"installed": True, "id": m.group(1), "evidence": "gtag config"}
    else:
        out["ga4"] = {"installed": False}

    # GTM
    m = re.search(r'googletagmanager\.com/gtm\.js\?id=(GTM-[A-Z0-9]+)', html) or \
        re.search(r'GTM-[A-Z0-9]{6,}', html)
    if m:
        # Extract just the GTM-XXX portion
        gid = re.search(r'GTM-[A-Z0-9]+', m.group(0)).group(0)
        out["gtm"] = {"installed": True, "id": gid, "evidence": "gtm.js script"}
    else:
        out["gtm"] = {"installed": False}

    # PostHog
    if "posthog-js" in html or "app.posthog.com/static/array.js" in html or re.search(r'posthog\.init\s*\(', html):
        out["posthog"] = {"installed": True, "id": None, "evidence": "posthog script"}
    else:
        out["posthog"] = {"installed": False}

    # LinkedIn Insight Tag — check static HTML first, then peek inside GTM container if present
    m = re.search(r'_linkedin_partner_id\s*=\s*["\']?(\d+)', html)
    if m:
        out["linkedin_insight"] = {"installed": True, "id": m.group(1), "evidence": "_linkedin_partner_id"}
    elif "snap.licdn.com/li.lms-analytics" in html:
        out["linkedin_insight"] = {"installed": True, "id": None, "evidence": "snap.licdn.com script"}
    elif out.get("gtm", {}).get("installed"):
        # Peek inside the GTM container script
        gid = out["gtm"]["id"]
        gtm_li = detect_linkedin_via_gtm(gid)
        if gtm_li.get("found"):
            out["linkedin_insight"] = {
                "installed": True,
                "id": gtm_li.get("partner_id"),
                "evidence": f"detected inside GTM container ({gid})",
            }
        else:
            out["linkedin_insight"] = {"installed": False}
    else:
        out["linkedin_insight"] = {"installed": False}

    # Meta Pixel
    m = re.search(r'fbq\(\s*["\']init["\'],\s*["\'](\d+)', html)
    if m:
        out["meta_pixel"] = {"installed": True, "id": m.group(1), "evidence": "fbq init"}
    elif "connect.facebook.net" in html and "fbevents" in html:
        out["meta_pixel"] = {"installed": True, "id": None, "evidence": "fbevents.js"}
    else:
        out["meta_pixel"] = {"installed": False}

    # Search Console verification meta — checked separately from parser
    return out


def detect_gsc_verification(parser, domain=None):
    """Detect Google Search Console verification via:
       1. <meta name="google-site-verification" ...>
       2. DNS TXT record (google-site-verification=...)
    Returns {installed: bool, id: str|None, evidence: str|None}"""
    # Method 1: meta tag
    for m in parser.meta:
        if m.get("name", "").lower() == "google-site-verification":
            return {"installed": True, "id": (m.get("content") or "")[:20] + "…", "evidence": "<meta> tag"}

    # Method 2: DNS TXT record
    if domain:
        try:
            url = f"https://cloudflare-dns.com/dns-query?name={domain}&type=TXT"
            req = urllib.request.Request(url, headers={"Accept": "application/dns-json"})
            with urllib.request.urlopen(req, timeout=8) as r:
                data = json.loads(r.read().decode("utf-8", errors="replace"))
            for a in data.get("Answer", []):
                if a.get("type") != 16:
                    continue
                txt = a.get("data", "").strip('"')
                if txt.startswith("google-site-verification="):
                    token = txt[len("google-site-verification="):]
                    return {"installed": True, "id": token[:20] + "…", "evidence": "DNS TXT record"}
        except Exception:
            pass

    return {"installed": False}


# ---------- The audit ----------

def audit_domain(domain):
    out = {
        "domain": domain,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "checks": {},
    }

    https_url = f"https://{domain}"
    page = fetch(https_url)

    # 1. HTTPS + SSL
    if not page["ok"]:
        out["checks"]["1_https_ssl"] = result(
            "fail", f"Site unreachable: {page.get('error', 'unknown error')}",
            "Confirm DNS resolves and the SSL cert is installed on apex + www.",
        )
        for k in ("2_robots", "3_sitemap", "4_canonical", "5_404", "6_title", "7_meta_desc",
                  "8_h1", "9_heading_hierarchy", "10_alt_text", "11_og_tags", "12_og_image",
                  "13_twitter_card", "14_linkedin_preview", "15_schema_present",
                  "16_schema_valid", "17_page_weight", "18_viewport", "19_favicon",
                  "20_security_headers", "21_apex_www_redirect", "22_http_https_redirect",
                  "23_html_lang", "24_meta_robots", "25_email_dns", "26_placeholder_text",
                  "27_linkedin_insight"):
            out["checks"][k] = result("skip", "Skipped — site unreachable")
        out["stack"] = {"framework": None, "css": None, "cdn": None, "cms": None,
                        "registrar": lookup_registrar(domain), "evidence": []}
        out["tracking"] = {}
        out["score"] = compute_score(out["checks"])
        return out

    ssl_info = check_ssl(domain)
    if ssl_info["ok"]:
        # Compute days until expiry — warn at <30, fail at <7
        from datetime import datetime as _dt
        days_left = None
        try:
            exp_str = ssl_info.get("expires", "")
            # OpenSSL format: "Aug  1 01:58:26 2026 GMT" — strip the timezone label
            # (strptime's %Z is unreliable across platforms) and treat as UTC.
            clean = exp_str.replace(" GMT", "").replace(" UTC", "").strip()
            exp_dt = _dt.strptime(clean, "%b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)
            days_left = (exp_dt - _dt.now(timezone.utc)).days
        except Exception:
            pass
        if days_left is None:
            out["checks"]["1_https_ssl"] = result("pass", f"HTTPS works. Cert expires {ssl_info['expires']}")
        elif days_left < 0:
            out["checks"]["1_https_ssl"] = result(
                "fail", f"SSL cert EXPIRED {abs(days_left)} days ago",
                "Renew the cert immediately. Cloudflare and Let's Encrypt offer free auto-renewing certs.",
            )
        elif days_left < 7:
            out["checks"]["1_https_ssl"] = result(
                "fail", f"SSL cert expires in {days_left} days ({ssl_info['expires']})",
                "Renew now — fewer than 7 days left.",
            )
        elif days_left < 30:
            out["checks"]["1_https_ssl"] = result(
                "warn", f"SSL cert expires in {days_left} days ({ssl_info['expires']})",
                "Schedule renewal — under a month remaining.",
            )
        else:
            out["checks"]["1_https_ssl"] = result(
                "pass", f"HTTPS works. Cert expires in {days_left} days ({ssl_info['expires']})"
            )
    else:
        out["checks"]["1_https_ssl"] = result(
            "warn", f"HTTPS reachable but SSL cert info failed: {ssl_info['error']}"
        )

    parser = SiteParser()
    try:
        parser.feed(page["text"])
    except Exception:
        pass  # malformed HTML — we'll keep what we got

    final_url = page["url"]
    parsed = urllib.parse.urlparse(final_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    # 2. robots.txt — also extracts any Sitemap: URLs declared inside
    sitemap_urls_from_robots = []
    robots_url = f"{base}/robots.txt"
    robots = fetch(robots_url)
    if robots.get("ok") and robots.get("status") == 200 and robots.get("text"):
        text = robots["text"]
        if re.search(r"(?im)^\s*Disallow:\s*/\s*$", text) and not re.search(r"(?im)^\s*Allow:", text):
            out["checks"]["2_robots"] = result(
                "warn", "robots.txt blocks all crawlers",
                "Remove blanket Disallow: / unless this is intentional.",
                external_url=robots_url,
            )
        else:
            out["checks"]["2_robots"] = result("pass", f"robots.txt found ({len(text)} bytes)",
                                                external_url=robots_url)
        # Extract every Sitemap: line — there can be multiple
        for m in re.finditer(r"(?im)^\s*Sitemap:\s*(\S+)\s*$", text):
            sitemap_urls_from_robots.append(m.group(1).strip())
    else:
        out["checks"]["2_robots"] = result(
            "warn", "No robots.txt at /robots.txt",
            "Add a robots.txt to control crawler behaviour and reference your sitemap.",
        )

    # 3. sitemap.xml — robots.txt declarations win, then fall back to common locations
    sitemap_found = None
    candidates = list(sitemap_urls_from_robots)  # honour what robots.txt says first
    for fallback in (
        f"{base}/sitemap.xml",
        f"{base}/sitemap-index.xml",   # Yoast / WordPress with hyphen
        f"{base}/sitemap_index.xml",   # underscore variant
        f"{base}/wp-sitemap.xml",      # WordPress 5.5+ default
        f"{base}/sitemap.xml.gz",      # gzipped sitemaps
    ):
        if fallback not in candidates:
            candidates.append(fallback)

    for loc in candidates:
        s = fetch(loc)
        if s.get("ok") and s.get("status") == 200:
            body_start = (s.get("text", "") or "")[:300]
            # Accept either XML or a sitemap index (urlset/sitemapindex)
            if "<" in body_start or loc.endswith(".gz"):
                sitemap_found = loc
                break

    if sitemap_found:
        if sitemap_found in sitemap_urls_from_robots:
            out["checks"]["3_sitemap"] = result("pass", f"Sitemap at {sitemap_found} (referenced in robots.txt)",
                                                 external_url=sitemap_found)
        elif sitemap_urls_from_robots:
            # robots.txt declared sitemaps but none worked — odd
            out["checks"]["3_sitemap"] = result(
                "warn", f"Sitemap at {sitemap_found}; robots.txt declares others that didn't load",
                f"Check the Sitemap: lines in robots.txt are reachable. Found: {', '.join(sitemap_urls_from_robots)}.",
                external_url=sitemap_found,
            )
        else:
            out["checks"]["3_sitemap"] = result(
                "warn", f"Sitemap at {sitemap_found} but not referenced in robots.txt",
                f"Add 'Sitemap: {sitemap_found}' to robots.txt.",
                external_url=sitemap_found,
            )
    else:
        out["checks"]["3_sitemap"] = result(
            "fail", "No sitemap.xml found",
            "Generate /sitemap.xml (or /sitemap-index.xml) and reference it in robots.txt.",
        )

    # 4. Canonical
    canonical = next((l.get("href") for l in parser.links if l.get("rel", "").lower() == "canonical" and l.get("href")), None)
    if canonical:
        if canonical.rstrip("/") in (final_url.rstrip("/"), base):
            out["checks"]["4_canonical"] = result("pass", f"Canonical: {canonical}")
        else:
            out["checks"]["4_canonical"] = result(
                "warn", f"Canonical points elsewhere: {canonical}",
                "Confirm this is intentional — usually canonical should match the live URL.",
            )
    else:
        out["checks"]["4_canonical"] = result(
            "warn", "No canonical link tag",
            f"Add <link rel='canonical' href='{base}/'> to prevent duplicate-content issues.",
        )

    # 5. Custom 404
    rand = f"/this-page-does-not-exist-{int(time.time())}"
    test_404_url = base + rand
    nf = fetch(test_404_url)
    if nf.get("ok"):
        if nf.get("status") == 404:
            text_l = (nf.get("text", "") or "").lower()
            looks_branded = len(nf.get("text") or "") > 600 and any(k in text_l for k in ("404", "not found", "page", "home"))
            if looks_branded:
                out["checks"]["5_404"] = result("pass", "Custom 404 page (status 404)", external_url=test_404_url)
            else:
                out["checks"]["5_404"] = result(
                    "warn", "404 status but page is minimal",
                    "Design a branded 404 with navigation back to key pages.",
                    external_url=test_404_url,
                )
        elif nf.get("status") == 200:
            out["checks"]["5_404"] = result(
                "fail", "Missing pages return HTTP 200 (soft 404)",
                "Configure server/framework to return proper 404 status codes.",
                external_url=test_404_url,
            )
        else:
            out["checks"]["5_404"] = result("warn", f"Unexpected status: {nf.get('status')}",
                                             external_url=test_404_url)
    else:
        out["checks"]["5_404"] = result("warn", "Could not test 404 behaviour")

    # 6. Title
    title = parser.title
    if title:
        if 30 <= len(title) <= 60:
            out["checks"]["6_title"] = result("pass", f"Title ({len(title)} chars): {title}")
        elif len(title) < 30:
            out["checks"]["6_title"] = result("warn", f"Title short ({len(title)} chars): {title}",
                                              "Aim for 30-60 chars including brand name.")
        else:
            out["checks"]["6_title"] = result("warn", f"Title long ({len(title)} chars): {title}",
                                              "Trim to 60 chars or it'll truncate in search results.")
    else:
        out["checks"]["6_title"] = result("fail", "No <title> tag", "Add a descriptive page title.")

    # 7. Meta description (now includes the actual text)
    desc = get_meta(parser, "description")
    if desc:
        if 120 <= len(desc) <= 160:
            out["checks"]["7_meta_desc"] = result("pass", f"({len(desc)} chars): {desc}")
        elif len(desc) < 120:
            out["checks"]["7_meta_desc"] = result("warn", f"Short ({len(desc)} chars): {desc}",
                                                  "Expand to 120-160 chars for better SERP display.")
        else:
            out["checks"]["7_meta_desc"] = result("warn", f"Long ({len(desc)} chars): {desc}",
                                                  "Trim to 160 chars to avoid truncation.")
    else:
        out["checks"]["7_meta_desc"] = result(
            "fail", "No meta description",
            "Add <meta name='description' content='...'> with a 120-160 char summary.",
        )

    # 8. H1
    h1s = [(l, t) for l, t in parser.headings if l == 1]
    if len(h1s) == 1:
        if h1s[0][1]:
            out["checks"]["8_h1"] = result("pass", f"One H1: {h1s[0][1][:80]}")
        else:
            out["checks"]["8_h1"] = result("warn", "Empty H1 tag", "Add descriptive H1 text.")
    elif not h1s:
        out["checks"]["8_h1"] = result("fail", "No H1 tag",
                                       "Add a single H1 with your primary page topic.")
    else:
        out["checks"]["8_h1"] = result(
            "warn", f"{len(h1s)} H1 tags",
            "Use only one H1 per page; downgrade extras to H2.",
        )

    # 9. Heading hierarchy
    levels = [l for l, _ in parser.headings]
    skipped = []
    last = 0
    for lvl in levels:
        if last and lvl > last + 1:
            skipped.append(f"h{last}->h{lvl}")
        last = lvl
    if not levels:
        out["checks"]["9_heading_hierarchy"] = result("warn", "No headings on page")
    elif skipped:
        out["checks"]["9_heading_hierarchy"] = result(
            "warn", f"Skipped levels: {', '.join(skipped[:3])}",
            "Avoid jumping levels (e.g. h1->h3); use sequential headings.",
        )
    else:
        out["checks"]["9_heading_hierarchy"] = result("pass", f"{len(levels)} headings, hierarchy clean")

    # 10. Alt text
    if not parser.imgs:
        out["checks"]["10_alt_text"] = result("warn", "No images on homepage")
    else:
        missing = [i for i in parser.imgs if "alt" not in i]
        decorative = [i for i in parser.imgs if "alt" in i and not (i.get("alt") or "").strip()]
        if missing:
            srcs = [i.get("src", "?")[:50] for i in missing[:3]]
            out["checks"]["10_alt_text"] = result(
                "fail", f"{len(missing)}/{len(parser.imgs)} images missing alt attribute",
                f"Add alt='' for decorative or alt='description' for content. Examples: {', '.join(srcs)}",
            )
        else:
            out["checks"]["10_alt_text"] = result(
                "pass", f"All {len(parser.imgs)} images have alt attributes ({len(decorative)} marked decorative)"
            )

    # 11. OG tags
    og_required = ("og:title", "og:description", "og:image", "og:url")
    og_found = {k: get_meta_property(parser, k) for k in og_required}
    missing_og = [k for k, v in og_found.items() if not v]
    if not missing_og:
        out["checks"]["11_og_tags"] = result("pass", "All 4 core OG tags present")
    else:
        out["checks"]["11_og_tags"] = result(
            "fail", f"Missing OG tags: {', '.join(missing_og)}",
            "Add OpenGraph tags so links shared on LinkedIn/FB/Slack render with image and copy.",
        )

    # 12. og:image
    og_img = og_found.get("og:image")
    if og_img:
        if not og_img.startswith("http"):
            og_img = urllib.parse.urljoin(base, og_img)
        chk = head_check(og_img)
        if chk.get("ok") and chk.get("status") == 200:
            ctype = chk.get("headers", {}).get("Content-Type", "")
            if "image" in ctype.lower():
                out["checks"]["12_og_image"] = result_with_view("pass", f"og:image loads ({ctype})", view=og_img)
            else:
                out["checks"]["12_og_image"] = result_with_view("warn", f"og:image returned non-image content-type: {ctype}", view=og_img)
        else:
            out["checks"]["12_og_image"] = result(
                "fail", "og:image URL doesn't load",
                f"Fix the og:image URL: {og_img}",
            )
    else:
        out["checks"]["12_og_image"] = result(
            "fail", "No og:image",
            "Add og:image with a 1200x630 PNG/JPG.",
        )

    # 13. Twitter card
    tc = get_meta(parser, "twitter:card")
    if tc:
        if tc == "summary_large_image":
            out["checks"]["13_twitter_card"] = result("pass", f"twitter:card = {tc}")
        else:
            out["checks"]["13_twitter_card"] = result(
                "warn", f"twitter:card = {tc}",
                "Consider 'summary_large_image' for richer link previews.",
            )
    else:
        out["checks"]["13_twitter_card"] = result(
            "warn", "No twitter:card tag",
            "Add <meta name='twitter:card' content='summary_large_image'>.",
        )

    # 14. LinkedIn preview (OG-based)
    if og_found.get("og:title") and og_found.get("og:description") and og_found.get("og:image"):
        out["checks"]["14_linkedin_preview"] = result("pass", "LinkedIn-ready (uses OG tags)")
    else:
        out["checks"]["14_linkedin_preview"] = result(
            "fail", "LinkedIn preview will be incomplete",
            "LinkedIn uses og:title, og:description, og:image — set all three.",
        )

    # 15. Schema present + 16. Schema valid
    if parser.json_ld:
        types = []
        valid = 0
        for s in parser.json_ld:
            try:
                data = json.loads(s.strip())
                if isinstance(data, dict):
                    t = data.get("@type", "?")
                    types.append(t if isinstance(t, str) else str(t))
                elif isinstance(data, list):
                    for it in data:
                        if isinstance(it, dict):
                            types.append(str(it.get("@type", "?")))
                valid += 1
            except Exception:
                pass
        out["checks"]["15_schema_present"] = result(
            "pass", f"JSON-LD schema found: {', '.join(sorted(set(types[:5]))) or 'unknown'}"
        )
        if valid == len(parser.json_ld):
            out["checks"]["16_schema_valid"] = result(
                "pass", f"All {len(parser.json_ld)} JSON-LD blocks parse cleanly"
            )
        else:
            out["checks"]["16_schema_valid"] = result(
                "warn", f"{len(parser.json_ld) - valid} JSON-LD block(s) failed to parse",
                "Validate at validator.schema.org.",
            )
    else:
        out["checks"]["15_schema_present"] = result(
            "warn", "No JSON-LD structured data",
            "Add Organization or WebSite schema for richer search results.",
        )
        out["checks"]["16_schema_valid"] = result("skip", "No schema to validate")

    # 17. Page weight
    size = len(page["content"])
    mb = size / (1024 * 1024)
    if mb < 1:
        out["checks"]["17_page_weight"] = result("pass", f"Homepage HTML: {size / 1024:.0f} KB")
    elif mb < 2:
        out["checks"]["17_page_weight"] = result("pass", f"Homepage: {mb:.2f} MB")
    elif mb < 5:
        out["checks"]["17_page_weight"] = result(
            "warn", f"Homepage: {mb:.2f} MB",
            "Compress images, defer JS, audit fonts. Aim under 2 MB.",
        )
    else:
        out["checks"]["17_page_weight"] = result(
            "fail", f"Homepage: {mb:.2f} MB",
            "Heavy page. Run PageSpeed Insights and trim.",
        )

    # 18. Viewport
    vp = get_meta(parser, "viewport")
    if vp and "width=device-width" in vp:
        out["checks"]["18_viewport"] = result("pass", "Mobile viewport set")
    else:
        out["checks"]["18_viewport"] = result(
            "fail", "No mobile viewport meta",
            "Add <meta name='viewport' content='width=device-width, initial-scale=1'>.",
        )

    # 19. Favicon + apple-touch + manifest + theme color
    def _resolve(u):
        if not u:
            return None
        return u if u.startswith("http") else urllib.parse.urljoin(base, u)

    # apple-touch-icon entries first (more specific match), then exclude from generic icon list
    apple = [l for l in parser.links if "apple-touch-icon" in l.get("rel", "").lower()]
    icon_links = [l for l in parser.links
                  if "icon" in l.get("rel", "").lower()
                  and "apple-touch-icon" not in l.get("rel", "").lower()
                  and "mask-icon" not in l.get("rel", "").lower()]
    mask_icon = next((l for l in parser.links if "mask-icon" in l.get("rel", "").lower()), None)
    manifest = next((l for l in parser.links if "manifest" in l.get("rel", "").lower()), None)
    theme_color = get_meta(parser, "theme-color")

    # Build assets list for "view" links in the dashboard
    view_assets = []
    for a in apple:
        u = _resolve(a.get("href"))
        if u:
            sz = a.get("sizes", "")
            view_assets.append({"label": f"apple-touch-icon{' ' + sz if sz else ''}", "url": u})
    for a in icon_links:
        u = _resolve(a.get("href"))
        if u:
            sz = a.get("sizes", "")
            view_assets.append({"label": f"favicon{' ' + sz if sz else ''}", "url": u})
    if mask_icon:
        u = _resolve(mask_icon.get("href"))
        if u:
            view_assets.append({"label": "Safari mask-icon", "url": u})

    # Compose the message + status
    parts = []
    if icon_links:
        parts.append(f"{len(icon_links)} icon link(s)")
    if apple:
        parts.append("apple-touch-icon")
    if manifest:
        parts.append("web manifest")
    if mask_icon:
        parts.append("mask-icon")
    if theme_color:
        parts.append(f"theme-color {theme_color}")

    if (icon_links or apple) and apple and (manifest or theme_color):
        out["checks"]["19_favicon"] = result_with_view("pass", ", ".join(parts), view=view_assets or None)
    elif (icon_links or apple) and apple:
        out["checks"]["19_favicon"] = result_with_view(
            "pass", ", ".join(parts) + " (consider adding manifest + theme-color for fuller PWA support)",
            view=view_assets or None,
        )
    elif icon_links and not apple:
        # Has favicon but no apple-touch — mobile home screen shortcuts won't have a nice icon
        out["checks"]["19_favicon"] = result_with_view(
            "warn", ", ".join(parts) + " — no apple-touch-icon",
            "Add <link rel='apple-touch-icon' href='/apple-touch-icon.png'> (180×180 PNG) for iOS home screen.",
            view=view_assets or None,
        )
    else:
        fav = head_check(base + "/favicon.ico")
        if fav.get("ok") and fav.get("status") == 200:
            out["checks"]["19_favicon"] = result_with_view(
                "warn", "favicon.ico exists but no <link> tags",
                "Add <link rel='icon'> + apple-touch-icon. Use realfavicongenerator.net to generate a full set.",
                view=[{"label": "favicon.ico", "url": base + "/favicon.ico"}],
            )
        else:
            out["checks"]["19_favicon"] = result(
                "fail", "No favicon at all",
                "Add favicon.ico + <link rel='icon'> + apple-touch-icon. Use realfavicongenerator.net to generate a full set.",
            )

    # 20. Security headers
    h_lower = {k.lower(): v for k, v in page["headers"].items()}
    expected = {
        "strict-transport-security": "HSTS",
        "x-content-type-options": "X-Content-Type-Options",
        "referrer-policy": "Referrer-Policy",
    }
    present = [name for k, name in expected.items() if k in h_lower]
    missing = [name for k, name in expected.items() if k not in h_lower]
    if not missing:
        out["checks"]["20_security_headers"] = result("pass", "All 3 core security headers set")
    elif present:
        out["checks"]["20_security_headers"] = result(
            "warn", f"Has: {', '.join(present)}. Missing: {', '.join(missing)}",
            "Add missing headers via Cloudflare Transform Rules or origin server.",
        )
    else:
        out["checks"]["20_security_headers"] = result(
            "fail", f"Missing: {', '.join(missing)}",
            "Add HSTS, X-Content-Type-Options: nosniff, Referrer-Policy via Cloudflare or origin.",
        )

    # 21. Apex/www redirect consistency
    # Strip leading "www." from the requested domain to find the apex form
    apex = domain[4:] if domain.startswith("www.") else domain
    www = "www." + apex
    apex_resp = head_no_redirect(f"https://{apex}")
    www_resp = head_no_redirect(f"https://{www}")
    apex_status = apex_resp.get("status")
    www_status = www_resp.get("status")
    apex_loc = (apex_resp.get("location") or "").lower()
    www_loc = (www_resp.get("location") or "").lower()
    redirect_codes = (301, 302, 307, 308)
    # Determine the "live" canonical version (the one others redirect to)
    live_url = None
    if apex_status == 200 and www_status in redirect_codes and apex in www_loc:
        live_url = f"https://{apex}"
        out["checks"]["21_apex_www_redirect"] = result(
            "pass", f"www → apex ({www_status} redirect). Live URL: {apex}"
        )
    elif www_status == 200 and apex_status in redirect_codes and www in apex_loc:
        live_url = f"https://{www}"
        out["checks"]["21_apex_www_redirect"] = result(
            "pass", f"apex → www ({apex_status} redirect). Live URL: {www}"
        )
    elif apex_status == 200 and www_status == 200:
        out["checks"]["21_apex_www_redirect"] = result(
            "warn", "Both apex and www serve content — split brain",
            "Pick one as canonical and 301 the other to it. Otherwise Google may split SEO signal.",
        )
    elif apex_status in redirect_codes and www_status in redirect_codes:
        out["checks"]["21_apex_www_redirect"] = result(
            "warn", f"Both apex and www redirect (apex→{apex_loc[:60]}, www→{www_loc[:60]})",
            "Unusual — usually one version is the live one. Inspect the redirect chain.",
        )
    elif apex_status == 200 and not www_resp.get("ok"):
        out["checks"]["21_apex_www_redirect"] = result(
            "warn", "Apex serves content but www unreachable",
            "Add a 301 redirect from www → apex so visitors typing www. don't see an error.",
        )
    elif www_status == 200 and not apex_resp.get("ok"):
        out["checks"]["21_apex_www_redirect"] = result(
            "warn", "www serves content but apex unreachable",
            "Add a 301 redirect from apex → www so visitors typing the bare domain don't see an error.",
        )
    else:
        out["checks"]["21_apex_www_redirect"] = result(
            "warn", f"Inconclusive: apex={apex_status}, www={www_status}",
        )

    # 22. HTTP → HTTPS redirect (also no-redirect-follow)
    http_resp = head_no_redirect(f"http://{apex}")
    if http_resp.get("ok"):
        if http_resp.get("status") in redirect_codes:
            target = http_resp.get("location") or ""
            if target.startswith("https://"):
                out["checks"]["22_http_https_redirect"] = result(
                    "pass", f"http:// → {target}"
                )
            else:
                out["checks"]["22_http_https_redirect"] = result(
                    "warn", f"http:// redirects but not to https: {target}",
                    "Redirect target should be the https version of the page.",
                )
        elif http_resp.get("status") == 200:
            out["checks"]["22_http_https_redirect"] = result(
                "fail", "http:// serves content directly (no redirect to https)",
                "Force HTTPS at your CDN. Cloudflare: SSL/TLS → Edge Certificates → toggle 'Always Use HTTPS'.",
            )
        else:
            out["checks"]["22_http_https_redirect"] = result(
                "warn", f"http:// returned status {http_resp.get('status')}",
            )
    else:
        out["checks"]["22_http_https_redirect"] = result(
            "warn", "Could not test http:// (port 80 may be closed)",
            "Confirm port 80 listens and 301-redirects to https://.",
        )
    # Cross-check canonical vs live URL
    if live_url and canonical:
        c = canonical.rstrip("/")
        l = live_url.rstrip("/")
        if c != l:
            # Downgrade canonical check to fail if it disagrees with the redirect direction
            out["checks"]["4_canonical"] = result(
                "fail", f"Canonical disagrees with redirect direction: canonical={canonical}, live={live_url}",
                f"Either change canonical to {live_url}/, or flip the redirect direction.",
            )

    # 23. HTML lang attribute
    lang = (parser.html_attrs or {}).get("lang", "").strip()
    if not lang:
        out["checks"]["23_html_lang"] = result(
            "fail", "No lang attribute on <html>",
            "Add <html lang=\"en\"> (or your language code) for screen readers + search engines.",
        )
    elif len(lang) < 2 or len(lang) > 10:
        out["checks"]["23_html_lang"] = result(
            "warn", f"Unusual lang value: '{lang}'",
            "Use a BCP 47 code like 'en', 'en-NZ', 'fr', etc.",
        )
    else:
        out["checks"]["23_html_lang"] = result("pass", f"lang=\"{lang}\"")

    # 24. Meta robots noindex check
    robots_meta = get_meta(parser, "robots")
    x_robots = h_lower.get("x-robots-tag", "")
    combined = f"{robots_meta or ''} {x_robots}".lower()
    if "noindex" in combined:
        source = "X-Robots-Tag header" if "noindex" in x_robots.lower() else "<meta name='robots'>"
        out["checks"]["24_meta_robots"] = result(
            "fail", f"Page is set to noindex via {source} ({robots_meta or x_robots})",
            "Remove 'noindex' unless this page genuinely shouldn't appear in search. Common cause: staging config shipped to production.",
        )
    elif robots_meta and "nofollow" in robots_meta.lower():
        out["checks"]["24_meta_robots"] = result(
            "warn", f"Page uses nofollow: {robots_meta}",
            "nofollow tells search engines not to follow links from this page. Confirm intentional.",
        )
    elif robots_meta:
        out["checks"]["24_meta_robots"] = result("pass", f"robots: {robots_meta}")
    else:
        out["checks"]["24_meta_robots"] = result("pass", "No restrictive robots directive (default = index, follow)")

    # 25. Email DNS hygiene (SPF + DMARC) — uses Cloudflare DNS-over-HTTPS
    spf, dmarc = lookup_spf_dmarc(apex)
    if spf and dmarc:
        out["checks"]["25_email_dns"] = result(
            "pass", f"SPF + DMARC both present (DMARC: {dmarc[:60]}{'…' if len(dmarc) > 60 else ''})"
        )
    elif spf and not dmarc:
        out["checks"]["25_email_dns"] = result(
            "warn", "SPF present but no DMARC record",
            "Add DMARC by creating a TXT record at _dmarc.{domain} with at minimum: v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com",
        )
    elif dmarc and not spf:
        out["checks"]["25_email_dns"] = result(
            "warn", "DMARC present but no SPF record",
            "Add SPF by creating a TXT record on the apex domain like: v=spf1 include:_spf.google.com ~all (include your email provider)",
        )
    else:
        out["checks"]["25_email_dns"] = result(
            "warn", "No SPF or DMARC records found",
            "If this domain sends ANY email, add SPF + DMARC TXT records. Otherwise spammers can spoof email 'from' your domain.",
        )

    # 26. Placeholder text (Lorem ipsum, TODO, Untitled, etc)
    detected = detect_placeholder_text(page["text"])
    if not detected:
        out["checks"]["26_placeholder_text"] = result("pass", "No placeholder text detected")
    elif any(k in detected for k in ("lorem ipsum", "lipsum", "consectetur adipiscing", "dolor sit amet")):
        out["checks"]["26_placeholder_text"] = result(
            "fail", f"Lorem ipsum found ({', '.join(sorted(detected))})",
            "Replace placeholder text with real copy.",
        )
    else:
        out["checks"]["26_placeholder_text"] = result(
            "warn", f"Placeholder markers found: {', '.join(sorted(detected))}",
            "These often indicate forgotten dummy content. Confirm intentional or replace.",
        )

    # 27. LinkedIn Insight Tag (for B2B retargeting + LinkedIn Ads attribution)
    li_match = re.search(r'_linkedin_partner_id\s*=\s*["\']?(\d+)', page["text"])
    has_licdn_script = "snap.licdn.com/li.lms-analytics" in page["text"]
    # Match GTM either via the gtm.js URL OR a bare GTM-XXX reference (covers inline snippet installs)
    gtm_id_match = (re.search(r"googletagmanager\.com/gtm\.js\?id=(GTM-[A-Z0-9]+)", page["text"])
                    or re.search(r"\b(GTM-[A-Z0-9]{6,})\b", page["text"]))

    if li_match:
        out["checks"]["27_linkedin_insight"] = result(
            "pass", f"LinkedIn Insight Tag installed directly (partner ID: {li_match.group(1)})"
        )
    elif has_licdn_script:
        out["checks"]["27_linkedin_insight"] = result(
            "pass", "LinkedIn Insight Tag installed directly (script detected)"
        )
    elif gtm_id_match:
        # Try to peek inside the GTM container
        gtm_id = gtm_id_match.group(1)
        gtm_li = detect_linkedin_via_gtm(gtm_id)
        if gtm_li.get("found"):
            pid = gtm_li.get("partner_id")
            sig = ", ".join(gtm_li.get("signals", [])[:2])
            out["checks"]["27_linkedin_insight"] = result(
                "pass",
                f"LinkedIn Insight Tag detected inside GTM container ({gtm_id})"
                + (f" — partner ID {pid}" if pid else "")
                + (f". Signals: {sig}" if sig else "")
            )
        else:
            out["checks"]["27_linkedin_insight"] = result(
                "warn", f"GTM detected ({gtm_id}) but no LinkedIn Insight signals in container",
                "Add LinkedIn Insight via GTM → New Tag → Tag Type: 'LinkedIn Insight'. Get the partner ID from LinkedIn Campaign Manager → Account Assets → Insight Tag. Skip this check if you don't run LinkedIn Ads.",
            )
    else:
        out["checks"]["27_linkedin_insight"] = result(
            "warn", "LinkedIn Insight Tag not detected (no GTM either)",
            "For B2B sites: install via GTM (recommended) — Tag Type: 'LinkedIn Insight'. Get the partner ID from LinkedIn Campaign Manager → Account Assets → Insight Tag.",
        )

    # Store the resolved live URL so the dashboard can show e.g. "→ Live: www.x.com" when there's a redirect
    if live_url:
        out["live_url"] = live_url

    # Stack + tracking detection (informational, not part of the score)
    try:
        out["stack"] = detect_stack(page["text"], page.get("headers", {}), domain)
    except Exception as e:
        out["stack"] = {"error": str(e)}
    try:
        tracking = detect_tracking(page["text"])
        tracking["gsc_verification"] = detect_gsc_verification(parser, apex)
        out["tracking"] = tracking
    except Exception as e:
        out["tracking"] = {"error": str(e)}

    out["score"] = compute_score(out["checks"])
    return out


def compute_score(checks):
    p = sum(1 for c in checks.values() if c["status"] == "pass")
    w = sum(1 for c in checks.values() if c["status"] == "warn")
    f = sum(1 for c in checks.values() if c["status"] == "fail")
    sk = sum(1 for c in checks.values() if c["status"] == "skip")
    total = len(checks) - sk
    pct = round((p / total) * 100) if total else 0
    return {"pass": p, "warn": w, "fail": f, "skip": sk, "total": total, "percent": pct}


# ---------- HTML report ----------

CHECK_LABELS = {
    "1_https_ssl": ("Discoverability", "HTTPS + SSL cert"),
    "2_robots": ("Discoverability", "robots.txt"),
    "3_sitemap": ("Discoverability", "sitemap.xml"),
    "4_canonical": ("Discoverability", "Canonical URL"),
    "5_404": ("Discoverability", "Custom 404 page"),
    "6_title": ("On-page SEO", "Title tag"),
    "7_meta_desc": ("On-page SEO", "Meta description"),
    "8_h1": ("On-page SEO", "Single H1"),
    "9_heading_hierarchy": ("On-page SEO", "Heading hierarchy"),
    "10_alt_text": ("On-page SEO", "Image alt text"),
    "11_og_tags": ("Social sharing", "OpenGraph tags"),
    "12_og_image": ("Social sharing", "og:image loads"),
    "13_twitter_card": ("Social sharing", "Twitter card"),
    "14_linkedin_preview": ("Social sharing", "LinkedIn preview"),
    "15_schema_present": ("Structured data", "Schema present"),
    "16_schema_valid": ("Structured data", "Schema valid"),
    "17_page_weight": ("Performance + trust", "Page weight"),
    "18_viewport": ("Performance + trust", "Mobile viewport"),
    "19_favicon": ("Performance + trust", "Favicon"),
    "20_security_headers": ("Performance + trust", "Security headers"),
}


def render_html(report):
    generated = report["generated_at"]
    cards_html = ""
    for r in report["results"]:
        cards_html += render_card(r)
    return REPORT_TEMPLATE.replace("{{GENERATED}}", generated).replace("{{CARDS}}", cards_html)


def render_card(r):
    s = r.get("score") or {}
    domain = r["domain"]
    pct = s.get("percent", 0)
    band = "ok" if pct >= 80 else "warn" if pct >= 50 else "bad"

    # Group checks by section
    sections = {}
    for key, check in r["checks"].items():
        section, label = CHECK_LABELS.get(key, ("Other", key))
        sections.setdefault(section, []).append((label, check))

    sections_html = ""
    for section, items in sections.items():
        rows = ""
        for label, check in items:
            status = check["status"]
            msg = html_escape(check.get("message", ""))
            fix = html_escape(check.get("fix", ""))
            fix_html = f'<div class="fix">{fix}</div>' if fix else ""
            rows += f'''
                <tr class="row {status}">
                    <td class="dot"><span class="status {status}">{status}</span></td>
                    <td><strong>{html_escape(label)}</strong><div class="msg">{msg}</div>{fix_html}</td>
                </tr>'''
        sections_html += f'''
            <div class="section">
                <h3>{html_escape(section)}</h3>
                <table>{rows}</table>
            </div>'''

    return f'''
        <details class="card {band}" open>
            <summary>
                <div class="domain">
                    <span class="name">{html_escape(domain)}</span>
                    <span class="score {band}">{pct}%</span>
                </div>
                <div class="meta">
                    <span class="pill pass">{s.get("pass", 0)} pass</span>
                    <span class="pill warn">{s.get("warn", 0)} warn</span>
                    <span class="pill fail">{s.get("fail", 0)} fail</span>
                    {f'<span class="pill skip">{s.get("skip", 0)} skip</span>' if s.get("skip", 0) else ''}
                </div>
            </summary>
            <div class="body">{sections_html}</div>
        </details>
    '''


def html_escape(s):
    if s is None:
        return ""
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;").replace("'", "&#39;"))


REPORT_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Marketing audit report</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
:root {
    --bg: #fafaf7;
    --card: #ffffff;
    --ink: #1a1a1a;
    --muted: #6b6b66;
    --line: #e8e6e0;
    --pass: #2d7a4f;
    --pass-bg: #e8f5ee;
    --warn: #b86d00;
    --warn-bg: #fdf3e3;
    --fail: #b8392f;
    --fail-bg: #fbe9e7;
    --skip: #888;
    --skip-bg: #efefea;
    color-scheme: light;
}
* { box-sizing: border-box; }
body {
    margin: 0; padding: 32px 20px; background: var(--bg); color: var(--ink);
    font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
}
.container { max-width: 1100px; margin: 0 auto; }
header { margin-bottom: 28px; }
h1 { font-size: 26px; margin: 0 0 6px; font-weight: 600; letter-spacing: -0.01em; }
.sub { color: var(--muted); font-size: 14px; }
.cards { display: flex; flex-direction: column; gap: 14px; }
.card {
    background: var(--card); border: 1px solid var(--line); border-radius: 10px;
    overflow: hidden;
}
.card summary {
    list-style: none; cursor: pointer; padding: 18px 22px;
    display: flex; align-items: center; justify-content: space-between; gap: 16px;
}
.card summary::-webkit-details-marker { display: none; }
.card .domain { display: flex; align-items: baseline; gap: 14px; min-width: 0; }
.card .name { font-size: 17px; font-weight: 600; }
.card .score {
    font-size: 22px; font-weight: 700; padding: 2px 10px; border-radius: 6px;
    font-variant-numeric: tabular-nums;
}
.card .score.ok  { background: var(--pass-bg); color: var(--pass); }
.card .score.warn { background: var(--warn-bg); color: var(--warn); }
.card .score.bad { background: var(--fail-bg); color: var(--fail); }
.card .meta { display: flex; gap: 6px; flex-wrap: wrap; }
.pill {
    font-size: 12px; padding: 3px 9px; border-radius: 999px; font-weight: 500;
    font-variant-numeric: tabular-nums;
}
.pill.pass { background: var(--pass-bg); color: var(--pass); }
.pill.warn { background: var(--warn-bg); color: var(--warn); }
.pill.fail { background: var(--fail-bg); color: var(--fail); }
.pill.skip { background: var(--skip-bg); color: var(--skip); }
.card .body { padding: 0 22px 18px; border-top: 1px solid var(--line); }
.section { margin-top: 18px; }
.section h3 {
    font-size: 13px; font-weight: 600; text-transform: uppercase;
    letter-spacing: 0.06em; color: var(--muted); margin: 0 0 6px;
}
.section table { width: 100%; border-collapse: collapse; }
.section td { padding: 10px 0; border-top: 1px solid var(--line); vertical-align: top; }
.section td:first-child { width: 70px; padding-right: 8px; }
.status {
    display: inline-block; padding: 2px 8px; border-radius: 4px;
    font-size: 11px; font-weight: 600; text-transform: uppercase;
    letter-spacing: 0.04em;
}
.status.pass { background: var(--pass-bg); color: var(--pass); }
.status.warn { background: var(--warn-bg); color: var(--warn); }
.status.fail { background: var(--fail-bg); color: var(--fail); }
.status.skip { background: var(--skip-bg); color: var(--skip); }
.msg { color: var(--ink); margin-top: 2px; font-size: 14px; }
.fix {
    color: var(--muted); margin-top: 4px; font-size: 13px;
    border-left: 2px solid var(--line); padding-left: 10px;
}
footer { margin-top: 28px; color: var(--muted); font-size: 13px; text-align: center; }
</style>
</head>
<body>
<div class="container">
    <header>
        <h1>Marketing audit</h1>
        <div class="sub">Generated {{GENERATED}}</div>
    </header>
    <div class="cards">{{CARDS}}</div>
    <footer>20 checks per domain. Re-run weekly with <code>python3 marketing-audit.py</code>.</footer>
</div>
</body>
</html>
"""


# ---------- Main ----------

def load_overrides():
    """Returns dict of domain -> {check_key: override} from audit-config.json.
    Override values can be either a string (treated as new pass message) or
    a dict {status: ..., note: ...} for more control."""
    config_path = Path(__file__).resolve().parent / "audit-config.json"
    if not config_path.exists():
        return {}
    try:
        cfg = json.loads(config_path.read_text())
        return cfg.get("overrides", {}) or {}
    except Exception:
        return {}


def apply_overrides(result, overrides_for_domain):
    """Apply manual overrides to a domain's check results.
    Each overridden check keeps a record of what the auto-detection found, so
    the dashboard can show 'manually verified' alongside the original auto status."""
    if not overrides_for_domain:
        return result
    for check_key, override in overrides_for_domain.items():
        if check_key not in result.get("checks", {}):
            continue
        original = result["checks"][check_key]
        if isinstance(override, dict):
            new_status = override.get("status", "pass")
            note = override.get("note", "Manually verified")
        elif isinstance(override, str):
            new_status = "pass"
            note = override
        else:
            continue
        result["checks"][check_key] = {
            "status": new_status,
            "message": note,
            "fix": "",
            "overridden": True,
            "auto_status": original.get("status"),
            "auto_message": original.get("message"),
        }
    # Re-compute score after overrides
    result["score"] = compute_score(result["checks"])
    return result


def main():
    print(f"Auditing {len(DOMAINS)} domains...")
    overrides = load_overrides()
    if overrides:
        print(f"  ({sum(len(v) for v in overrides.values())} manual override(s) loaded)")
    results = []
    with ThreadPoolExecutor(max_workers=4) as ex:
        futures = {ex.submit(audit_domain, d): d for d in DOMAINS}
        for f in as_completed(futures):
            d = futures[f]
            try:
                r = f.result()
                # Apply overrides for this domain (if any)
                r = apply_overrides(r, overrides.get(d, {}))
                results.append(r)
                s = r["score"]
                print(f"  {d}: {s['pass']}/{s['total']} ({s['percent']}%) — "
                      f"{s['fail']} fail, {s['warn']} warn")
            except Exception as e:
                print(f"  {d}: ERROR — {e}")

    # Sort to match input order
    results.sort(key=lambda r: DOMAINS.index(r["domain"]))

    report = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "results": results,
    }

    out_dir = Path(__file__).resolve().parent
    out_html = out_dir / "marketing-audit-report.html"
    out_json = out_dir / "marketing-audit-data.json"
    out_history = out_dir / "audit-history.json"
    out_dashboard = out_dir / "marketing-audit-dashboard.html"
    template_path = out_dir / "audit-dashboard-template.html"
    config_path = out_dir / "audit-config.json"

    out_html.write_text(render_html(report), encoding="utf-8")
    out_json.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")

    # Append today's snapshot to audit-history.json (one entry per domain per day).
    # Re-running on the same day overwrites that day's entry.
    history = {"domains": {}}
    if out_history.exists():
        try:
            history = json.loads(out_history.read_text())
            if "domains" not in history:
                history = {"domains": {}}
        except Exception:
            history = {"domains": {}}
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    for r in results:
        domain = r["domain"]
        s = r.get("score") or {}
        snapshot = {
            "date": today,
            "percent": s.get("percent"),
            "pass": s.get("pass"),
            "warn": s.get("warn"),
            "fail": s.get("fail"),
        }
        existing = [x for x in history["domains"].get(domain, []) if x.get("date") != today]
        existing.append(snapshot)
        existing.sort(key=lambda x: x.get("date", ""))
        history["domains"][domain] = existing
    out_history.write_text(json.dumps(history, indent=2), encoding="utf-8")

    # Bake the rich dashboard (sparklines, filters, stack, tracking) if the template exists
    if template_path.exists() and config_path.exists():
        try:
            template = template_path.read_text(encoding="utf-8")
            config_data = json.loads(config_path.read_text(encoding="utf-8"))
            cfg_js = json.dumps(config_data, ensure_ascii=False).replace("</", "<\\/")
            data_js = json.dumps(report, ensure_ascii=False, default=str).replace("</", "<\\/")
            hist_js = json.dumps(history, ensure_ascii=False).replace("</", "<\\/")
            baked = (template
                     .replace("__CONFIG_JSON__", cfg_js)
                     .replace("__DATA_JSON__", data_js)
                     .replace("__HISTORY_JSON__", hist_js))
            out_dashboard.write_text(baked, encoding="utf-8")
            print(f"Dashboard: {out_dashboard}")
        except Exception as e:
            print(f"Couldn't bake dashboard ({e})")
    else:
        print(f"Dashboard template not found at {template_path} — skipping rich dashboard.")

    print(f"\nReport: {out_html}")
    print(f"Raw data: {out_json}")
    print(f"History: {out_history}")


if __name__ == "__main__":
    main()
