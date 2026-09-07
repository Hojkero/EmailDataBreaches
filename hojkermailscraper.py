#!/usr/bin/env python3
#  .--..--..--..--..--..--..--..--..--. 
# / .. \.. \.. \.. \.. \.. \.. \.. \.. \
# \ \/\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ \/ /
#  \/ /`--'`--'`--'`--'`--'`--'`--'\/ / 
#  / /\                            / /\ 
# / /\ \ ╦ ╦┌─┐ ┬┬┌─┌─┐┬─┐        / /\ \
# \ \/ / ╠═╣│ │ │├┴┐├┤ ├┬┘        \ \/ /
#  \/ /  ╩ ╩└─┘└┘┴ ┴└─┘┴└─         \/ / 
#  / /\  ╔═╗┌┬┐┌─┐┬┬               / /\ 
# / /\ \ ║╣ │││├─┤││              / /\ \
# \ \/ / ╚═╝┴ ┴┴ ┴┴┴─┘            \ \/ /
#  \/ /  ╔╗ ┬─┐┌─┐┌─┐┌─┐┬ ┬┌─┐┌─┐  \/ / 
#  / /\  ╠╩╗├┬┘├┤ ├─┤│  ├─┤├┤ └─┐  / /\ 
# / /\ \ ╚═╝┴└─└─┘┴ ┴└─┘┴ ┴└─┘└─┘ / /\ \
# \ \/ /                          \ \/ /
#  \/ /                            \/ / 
#  / /\.--..--..--..--..--..--..--./ /\ 
# / /\ \.. \.. \.. \.. \.. \.. \.. \/\ \
# \ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `' /
#  `--'`--'`--'`--'`--'`--'`--'`--'`--' 
import sys, os, re, json, time, random, string, hashlib, smtplib, shutil
import subprocess, urllib.parse, argparse, concurrent.futures as cf
import math
from datetime import datetime, timezone
from collections import OrderedDict

try:
    import requests, dns.resolver
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.columns import Columns
    from rich.text import Text
    from rich.rule import Rule
    from rich.align import Align
    from rich.progress import (Progress, SpinnerColumn, TextColumn,
                               BarColumn, TimeElapsedColumn)
    from rich import box
    import socks  # noqa: F401  PySocks — required for Tor proxying
except ImportError as _e:
    sys.exit("Missing deps. Run:  pip install requests dnspython rich PySocks python-whois")

console = Console()
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")
EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
ONION_RE = re.compile(r"[a-z2-7]{16,56}\.onion", re.I)
KEYFILE  = os.path.expanduser("~/.hojker_keys.json")
DBFILE   = os.path.expanduser("~/.hojkermailscraper/hojkermailscraper.db")
TIMEOUT  = 15
SHOW_PASSWORDS = False

# ══════════════════════════════════════════════════════════════════════════
#  HASH IDENTIFICATION
# ══════════════════════════════════════════════════════════════════════════
HASH_PATTERNS = OrderedDict([
    ("bcrypt",     re.compile(r'^\$2[aby]?\$\d{1,2}\$.{53}$')),
    ("argon2",     re.compile(r'^\$argon2(id|i|d)\$')),
    ("md5_crypt",  re.compile(r'^\$1\$')),
    ("sha256_crypt", re.compile(r'^\$5\$')),
    ("sha512_crypt", re.compile(r'^\$6\$')),
    ("scrypt",     re.compile(r'^\$scrypt\$')),
    ("NTLM",       re.compile(r'^[a-fA-F0-9]{32}$')),
    ("SHA1",       re.compile(r'^[a-fA-F0-9]{40}$')),
    ("SHA256",     re.compile(r'^[a-fA-F0-9]{64}$')),
    ("SHA384",     re.compile(r'^[a-fA-F0-9]{96}$')),
    ("SHA512",     re.compile(r'^[a-fA-F0-9]{128}$')),
    ("MD5",        re.compile(r'^[a-fA-F0-9]{32}$')),
    ("MySQL4.1+",  re.compile(r'^\*[a-fA-F0-9]{40}$')),
    ("Drupal7",    re.compile(r'^\$S\$[a-zA-Z0-9/.]{52}$')),
    ("Wordpress",  re.compile(r'^\$P\$[a-zA-Z0-9/.]{34}$')),
    ("phpBB3",     re.compile(r'^\$H\$[a-zA-Z0-9/.]{34}$')),
    ("vBulletin",  re.compile(r'^[a-zA-Z0-9]{32}:[a-zA-Z0-9]{32}$')),
    ("django",     re.compile(r'^pbkdf2_(sha256|sha1)_\d+\$')),
])

KNOWN_HASH_LABELS = {
    "bcrypt": "bcrypt (strong)",
    "argon2": "Argon2 (strong)",
    "scrypt": "scrypt (strong)",
    "sha256_crypt": "SHA-256 crypt (moderate)",
    "sha512_crypt": "SHA-512 crypt (moderate)",
    "md5_crypt": "MD5 crypt (weak)",
    "SHA512": "SHA-512 hex (moderate)",
    "SHA256": "SHA-256 hex (moderate)",
    "SHA384": "SHA-384 hex (moderate)",
    "SHA1": "SHA-1 hex (weak)",
    "MD5": "MD5 hex (weak)",
    "NTLM": "NTLM (weak)",
    "MySQL4.1+": "MySQL 4.1+ (weak)",
    "Drupal7": "Drupal 7 (strong)",
    "Wordpress": "WordPress (moderate)",
    "phpBB3": "phpBB3 (moderate)",
    "vBulletin": "vBulletin (weak)",
    "django": "Django PBKDF2 (strong)",
}

def identify_hash(value):
    if not value or not isinstance(value, str):
        return None, None
    v = value.strip()
    for name, pattern in HASH_PATTERNS.items():
        if pattern.match(v):
            return name, KNOWN_HASH_LABELS.get(name, name)
    return None, None

def is_likely_hash(v):
    if not v or not isinstance(v, str):
        return False
    v = v.strip()
    if identify_hash(v)[0]:
        return True
    if 28 <= len(v) <= 128 and all(c in '0123456789abcdefABCDEF' for c in v):
        return True
    if v.startswith('$') and any(v.startswith(p) for p in ('$2', '$5', '$6', '$1$', '$H$', '$P$', '$S$', '$argon')):
        return True
    return False

# ══════════════════════════════════════════════════════════════════════════
#  PASSWORD STRENGTH ANALYSIS
# ══════════════════════════════════════════════════════════════════════════
def analyze_password_strength(password):
    if not password or not isinstance(password, str):
        return {"score": 0, "label": "N/A", "color": "grey50", "details": []}
    score = 0
    details = []
    length = len(password)
    if length >= 8: score += 10
    if length >= 12: score += 10
    if length >= 16: score += 10
    if length >= 20: score += 5
    if length < 6:
        score -= 10
        details.append("very short")
    has_lower = bool(re.search(r'[a-z]', password))
    has_upper = bool(re.search(r'[A-Z]', password))
    has_digit = bool(re.search(r'[0-9]', password))
    has_special = bool(re.search(r'[^a-zA-Z0-9]', password))
    charset_size = (26 if has_lower else 0) + (26 if has_upper else 0) + \
                   (10 if has_digit else 0) + (32 if has_special else 0)
    score += min(15, charset_size // 4)
    if has_lower: details.append("lowercase")
    if has_upper: details.append("uppercase")
    if has_digit: details.append("digits")
    if has_special: details.append("special")
    common_patterns = [
        r'(.)\1{2,}',
        r'(012|123|234|345|456|567|678|789|890)',
        r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)',
        r'(qwerty|asdf|zxcv|password|123456|admin|letmein|welcome)',
        r'^(pass|pwd|pw)',
    ]
    penalty = 0
    for pat in common_patterns:
        if re.search(pat, password, re.I):
            penalty += 15
            details.append("common pattern")
            break
    score -= penalty
    entropy = math.log2(max(1, charset_size ** min(length, 20))) if charset_size > 0 else 0
    if entropy > 60: score += 10
    if entropy > 80: score += 10
    details.append(f"~{entropy:.0f} bits entropy")
    score = max(0, min(100, score))
    if score >= 80:
        label, color = "STRONG", "bright_green"
    elif score >= 60:
        label, color = "MODERATE", "bright_yellow"
    elif score >= 40:
        label, color = "WEAK", "bright_red"
    elif score >= 20:
        label, color = "VERY WEAK", "red"
    else:
        label, color = "CRITICAL", "bold red"
    return {"score": score, "label": label, "color": color, "details": details}

# ══════════════════════════════════════════════════════════════════════════
#  CREDENTIAL EXTRACTION
# ══════════════════════════════════════════════════════════════════════════
def extract_passwords_from_text(text):
    found = set()
    if not text:
        return found
    patterns = [
        re.compile(r'(?:password|passwd|pwd|pass|secret|token|key|auth)\s*[:=]\s*(\S{3,64})', re.I),
        re.compile(r'(?:password|passwd|pwd|pass|secret|token|key|auth)\s*["\']?\s*[:=]\s*["\']([^"\']{3,64})["\']', re.I),
        re.compile(r'"(?:password|passwd|pwd|pass|secret|token|key|auth)"\s*:\s*"([^"]{3,64})"', re.I),
    ]
    for p in patterns:
        for m in p.finditer(text):
            val = m.group(1).strip().strip("\"'")
            if val and len(val) >= 3 and not val.lower() in ('null', 'none', 'undefined', 'true', 'false', 'empty'):
                found.add(val)
    return found

class CredentialStore:
    def __init__(self):
        self.credentials = []
        self.hashes = []
        self.secrets = []
        self._seen = set()

    def _key(self, cred):
        return hash((cred.get('password', ''), cred.get('source', '')))

    def add(self, entry):
        k = self._key(entry)
        if k in self._seen:
            return
        self._seen.add(k)
        pwd = entry.get('password', '')
        hash_type, hash_label = identify_hash(pwd)
        if hash_type:
            entry['hash_type'] = hash_type
            entry['hash_label'] = hash_label
            self.hashes.append(entry)
        else:
            strength = analyze_password_strength(pwd)
            entry['strength'] = strength
            if pwd and not is_likely_hash(pwd):
                self.credentials.append(entry)
            else:
                self.hashes.append(entry)

    def add_text_secrets(self, text, source):
        for pwd in extract_passwords_from_text(text):
            self.add({'password': pwd, 'source': source, 'type': 'plaintext'})

    def total(self):
        return len(self.credentials) + len(self.hashes) + len(self.secrets)

    def plaintext_count(self):
        return len(self.credentials)

    def hash_count(self):
        return len(self.hashes)

# ══════════════════════════════════════════════════════════════════════════
#  HTTP HELPERS
# ══════════════════════════════════════════════════════════════════════════
def make_session(tor=False, timeout=TIMEOUT):
    s = requests.Session()
    s.headers.update({"User-Agent": UA, "Accept-Language": "en-US,en;q=0.9",
                      "Accept": "application/json, text/html, */*"})
    if tor:
        s.proxies = {"http": "socks5h://127.0.0.1:9050",
                     "https": "socks5h://127.0.0.1:9050"}
    s._timeout = timeout
    return s

def http_get(s, url, tries=3, **kw):
    uas = [UA, UA.replace("Chrome/124.0", "Chrome/120.0"),
           "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/125.0"]
    kw["timeout"] = kw.pop("timeout", getattr(s, "_timeout", TIMEOUT))
    last = None
    for i in range(tries):
        try:
            s.headers["User-Agent"] = random.choice(uas)
            return s.get(url, **kw)
        except Exception as e:
            last = e
            time.sleep(0.4 * (2 ** i) + random.random() * 0.3)
    raise last if last else ConnectionError(url)

def http_post(s, url, tries=2, **kw):
    kw["timeout"] = kw.pop("timeout", getattr(s, "_timeout", TIMEOUT))
    last = None
    for i in range(tries):
        try:
            return s.post(url, **kw)
        except Exception as e:
            last = e
            time.sleep(0.5 * (2 ** i))
    raise last if last else ConnectionError(url)

# ══════════════════════════════════════════════════════════════════════════
#  AUTOMATIC TOR SERVICE MANAGER
# ══════════════════════════════════════════════════════════════════════════
TOR_HOST = "127.0.0.1"
TOR_PORT = 9050
TOR_DATADIR = os.path.expanduser("~/.blackoutx_tor")
TOR_CFG = os.path.expanduser("~/.blackoutx_torrc")

def _socks_port_open(port=TOR_PORT, host=TOR_HOST):
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((host, port))
        s.close()
        return True
    except Exception:
        return False

def tor_running(port=TOR_PORT):
    if _socks_port_open(port):
        try:
            s = requests.Session()
            s.proxies = {"http": f"socks5h://127.0.0.1:{port}",
                         "https": f"socks5h://127.0.0.1:{port}"}
            r = s.get("https://check.torproject.org/api/ip", timeout=6)
            if r.status_code == 200:
                return True
        except Exception:
            pass
        return True
    return False

def _tor_bootstrapped(datadir=TOR_DATADIR):
    try:
        with open(os.path.join(datadir, "tor.log"), "r",
                  errors="ignore") as f:
            return "Bootstrapped 100%" in f.read()
    except Exception:
        return False

def ensure_tor(quiet=False):
    if tor_running(TOR_PORT):
        if not quiet:
            console.print("  [bright_green]✔ Tor circuit already live "
                          f"({TOR_HOST}:{TOR_PORT})[/]")
        return True
    if not quiet:
        console.print("  [bright_yellow]⚡ Tor not detected — starting tor daemon…[/]")
    try:
        for lk in ("lock", "control"):
            p = os.path.join(TOR_DATADIR, lk)
            if os.path.exists(p):
                os.remove(p)
    except Exception:
        pass
    os.makedirs(TOR_DATADIR, exist_ok=True)
    try:
        with open(TOR_CFG, "w") as f:
            f.write(
                f"SOCKSPort {TOR_HOST}:{TOR_PORT}\n"
                f"ControlPort {TOR_HOST}:9051\n"
                f"DataDirectory {TOR_DATADIR}\n"
                f"Log notice file {TOR_DATADIR}/tor.log\n"
                f"RunAsDaemon 1\n")
    except Exception:
        pass
    try:
        with open(os.path.join(TOR_DATADIR, "tor.log"), "a",
                  errors="ignore") as lf:
            subprocess.Popen(["tor", "-f", TOR_CFG],
                             stdout=lf, stderr=lf,
                             start_new_session=True,
                             stdin=subprocess.DEVNULL)
    except Exception:
        pass
    deadline = time.time() + 40
    while time.time() < deadline:
        if _socks_port_open(TOR_PORT):
            if not quiet:
                console.print("  [bright_green]✔ Tor bootstrapped — "
                              "onion routing ACTIVE[/]")
            return True
        if _tor_bootstrapped():
            if not quiet:
                console.print("  [bright_green]✔ Tor bootstrapped — "
                              "onion routing ACTIVE[/]")
            return True
        time.sleep(2)
    if not quiet:
        console.print("  [bright_red]✘ Tor could not start. Install it: "
                      "apt install tor[/]")
    return False

# ══════════════════════════════════════════════════════════════════════════
#  API KEY VAULT
# ══════════════════════════════════════════════════════════════════════════
SUPPORTED_KEYS = {
    "shodan":        "https://account.shodan.io            — free: domain + host intel",
    "hibp":          "https://haveibeenpwned.com/API/Key — full breach corpus w/ data classes",
    "hunter_io":     "https://hunter.io/api-keys         — free: 25 verifies/mo",
    "intelx":        "https://intelx.io                  — free: dark web + dumps + pastes",
    "emailrep":      "https://emailrep.io/key            — free: lifts rate limit",
    "github_token":  "https://github.com/settings/tokens — free: commit/code search",
    "leakcheck":     "https://leakcheck.io               — breach search (demo: no key)",
    "google_cse":    "https://developers.google.com/custom-search/v1/overview — free 100/day",
    "dehashed":      "https://dehashed.com               — paid breach corpus",
    "snusbase":      "https://snusbase.com               — paid breach corpus",
    "breachdirectory":"https://rapidapi.com/rock7r/breachdirectory — free trial",
    "serpapi":       "https://serpapi.com                — search API (dorks)",
    "rapidapi":      "https://rapidapi.com/hub — facebook/instagram/linkedin/scrapeninja social search",
}

def load_keys():
    if os.path.exists(KEYFILE):
        try:
            return json.load(open(KEYFILE))
        except Exception:
            return {}
    return {}

def save_keys(keys):
    json.dump(keys, open(KEYFILE, "w"), indent=2)
    try:
        os.chmod(KEYFILE, 0o600)
    except Exception:
        pass

def key_menu():
    keys = load_keys()
    t = Table(title="[bright_cyan]⚙  A P I   K E Y   V A U L T[/]",
              box=box.DOUBLE, border_style="bright_cyan", header_style="bold")
    t.add_column("Service", style="bold bright_white", width=18)
    t.add_column("Status", width=12)
    t.add_column("Where to get it (most have free tiers)", style="grey50")
    for svc, desc in SUPPORTED_KEYS.items():
        st = "[bright_green]✔ ACTIVE" if keys.get(svc) else "[grey50]○ not set"
        t.add_row(svc, st, desc)
    console.print(Align.center(t))
    svc = console.input("\n  [bright_cyan]service to set/replace (blank = back):[/] ").strip()
    if not svc:
        return
    if svc not in SUPPORTED_KEYS:
        console.print(f"  [bright_red]✘ unknown service '{svc}'[/]")
        return
    val = console.input("  [bright_cyan]API key:[/] ").strip()
    if val:
        keys[svc] = val
        save_keys(keys)
        console.print(f"  [bright_green]✔ {svc} saved → {KEYFILE} (chmod 600)[/]")
    elif svc in keys:
        del keys[svc]
        save_keys(keys)
        console.print(f"  [bright_yellow]– {svc} key removed[/]")

# ══════════════════════════════════════════════════════════════════════════
#  LAYER 1 — EMAIL ORACLES (prove the email is registered)
# ══════════════════════════════════════════════════════════════════════════
def email_oracles(s, email):
    def p_twitter():
        r = http_get(s, "https://api.twitter.com/i/users/email_available",
                     params={"email": email}, tries=1)
        return r.json().get("taken") is True
    def p_spotify():
        r = http_get(s, "https://www.spotify.com/api/signup/check-email",
                     params={"email": email}, tries=1)
        return r.json().get("status") in (0, 3)
    def p_adobe():
        r = http_get(s, "https://api.adobe.com/ims/check/v6/email",
                     params={"email": email}, tries=1)
        return r.json().get("valid") is True
    def p_bitmoji():
        return http_get(s,
                        f"https://api.bitmoji.com/account/identifier?email={email}",
                        tries=1).status_code == 200
    def p_duolingo():
        return bool(http_get(s, "https://www.duolingo.com/2017-06-30/users",
                             params={"email": email},
                             tries=1).json().get("users"))
    def p_github():
        r = http_get(s, "https://api.github.com/search/users",
                     params={"q": f'"{email}" in:email', "per_page": 3},
                     tries=1)
        return [u["html_url"] for u in r.json().get("items", [])]
    def p_gravatar():
        md5 = hashlib.md5(email.lower().encode()).hexdigest()
        r = http_get(s, f"https://www.gravatar.com/{md5}.json", tries=1)
        return bool((r.json().get("entry") or [{}])[0])
    def p_keybase():
        r = http_get(s, "https://keybase.io/_/api/1.0/user/lookup.json",
                     params={"email": email}, tries=1).json()
        them = r.get("them") or {}
        return them.get("profile", {}).get("username") if them.get("id") else None
    def p_npm():
        r = http_get(s, "https://registry.npmjs.org/-/v1/search",
                     params={"text": email, "size": 5}, tries=1).json()
        return [o["package"]["name"] for o in r.get("objects", [])][:4]
    def p_imgur():
        r = http_get(s, "https://api.imgur.com/3/account/validateemail",
                     params={"email": email}, tries=1)
        return r.status_code == 200
    def p_pinterest():
        r = http_get(s, "https://www.pinterest.com/resource/UserResource/get/",
                     params={"source_url": "/", "data": json.dumps(
                         {"options": {"email": email, "fields": "id"}})},
                     tries=1)
        return r.status_code == 200 and email.lower() in r.text.lower()
    def p_patreon():
        r = http_get(s, "https://www.patreon.com/api/exists",
                     params={"email": email}, tries=1)
        return r.json().get("exists") is True
    def p_discord():
        r = http_get(s, "https://discord.com/api/v9/auth/register",
                     data={"email": email}, tries=1)
        return r.status_code == 400 and "email" in r.text.lower()

    battery = [
        ("X / Twitter", "social",    p_twitter),
        ("Spotify",     "media",     p_spotify),
        ("Adobe",       "cloud",     p_adobe),
        ("Bitmoji",     "social",    p_bitmoji),
        ("Duolingo",    "education", p_duolingo),
        ("GitHub",      "developer", p_github),
        ("Gravatar",    "identity",  p_gravatar),
        ("Keybase",     "identity",  p_keybase),
        ("npm",         "developer", p_npm),
        ("Imgur",       "media",     p_imgur),
        ("Patreon",     "creator",   p_patreon),
        ("Discord",     "social",    p_discord),
    ]
    hits = []
    with cf.ThreadPoolExecutor(max_workers=12) as ex:
        futs = {ex.submit(fn): (name, cat) for name, cat, fn in battery}
        for f in cf.as_completed(futs):
            name, cat = futs[f]
            try:
                res = f.result()
                if isinstance(res, list) and res:
                    hits.append({"platform": name, "category": cat,
                                 "confidence": "HIGH",
                                 "detail": ", ".join(map(str, res))})
                elif isinstance(res, str) and res:
                    hits.append({"platform": name, "category": cat,
                                 "confidence": "HIGH", "detail": f"user: {res}"})
                elif res is True:
                    hits.append({"platform": name, "category": cat,
                                 "confidence": "HIGH",
                                 "detail": "email registered"})
            except Exception:
                continue
    return hits

# ══════════════════════════════════════════════════════════════════════════
#  LAYER 2 — USERNAME SWEEP: social · creator · adult · gaming · dev
# ══════════════════════════════════════════════════════════════════════════
def username_candidates(email):
    local = email.split("@")[0]
    base = re.sub(r"[^a-z0-9._\-]", "", local.lower())
    cands = {base, base.replace(".", ""), base.replace(".", "_"),
             base.replace(".", "-")}
    if "." in base:
        cands.add(base.split(".")[0])
    m = re.match(r"^(.*?)(\d{1,4})$", base.replace(".", ""))
    if m and len(m.group(1)) >= 3:
        cands.add(m.group(1))
    return sorted(c for c in cands if len(c) >= 3)[:6]

USER_PLATFORMS = [
    ("Instagram",  "social",    "https://www.instagram.com/{u}/",
     lambda c, t: c == 200 and "Page Not Found" not in t),
    ("TikTok",     "social",    "https://www.tiktok.com/@{u}",
     lambda c, t: c == 200 and "Couldn't find this account" not in t),
    ("X / Twitter","social",    "https://x.com/{u}",
     lambda c, t: c == 200 and "doesn't exist" not in t and "doesn't exist" not in t),
    ("Reddit",     "social",    "https://www.reddit.com/user/{u}/about.json",
     lambda c, t: c == 200),
    ("Telegram",   "social",    "https://t.me/{u}",
     lambda c, t: c == 200 and "tgme_page_title" in t),
    ("Pinterest",  "social",    "https://www.pinterest.com/{u}/",
     lambda c, t: c == 200 and "Sorry!" not in t),
    ("Tumblr",     "social",    "https://{u}.tumblr.com",
     lambda c, t: c == 200 and "Whatever you were looking for" not in t),
    ("Medium",     "social",    "https://medium.com/@{u}",
     lambda c, t: c == 200),
    ("Mastodon",   "social",    "https://mastodon.social/@{u}",
     lambda c, t: c == 200 and "not found" not in t.lower()),
    ("Threads",    "social",    "https://www.threads.net/@{u}",
     lambda c, t: c == 200 and "Sorry, this page isn't available" not in t),
    ("VK",         "social",    "https://vk.com/{u}",
     lambda c, t: c == 200 and "page not found" not in t.lower()
                  and ("Профиль" in t or "profile" in t.lower())
                  and "deleted" not in t.lower()),
    ("Flickr",     "media",     "https://www.flickr.com/people/{u}",
     lambda c, t: c == 200 and "This page is private or does not exist" not in t),
    ("Vimeo",      "media",     "https://vimeo.com/{u}",
     lambda c, t: c == 200 and "Sorry, we couldn" not in t),
    ("SoundCloud", "media",     "https://soundcloud.com/{u}",
     lambda c, t: c == 200 and "We can't find that user" not in t),
    ("Dailymotion","media",     "https://www.dailymotion.com/{u}",
     lambda c, t: c == 200 and "not found" not in t.lower()),
    ("Twitch",     "media",     "https://m.twitch.tv/{u}",
     lambda c, t: c == 200 and "not found" not in t.lower()),
    ("Patreon",    "creator",   "https://www.patreon.com/{u}",
     lambda c, t: c == 200 and "This page could not be found" not in t),
    ("Steam",      "gaming",    "https://steamcommunity.com/id/{u}",
     lambda c, t: c == 200 and "specified profile could not be found" not in t),
    ("Xbox Gamertag","gaming",  "https://xboxgamertag.com/search/{u}",
     lambda c, t: c == 200),
    ("GitHub",     "developer", "https://github.com/{u}",
     lambda c, t: c == 200),
    ("GitLab",     "developer", "https://gitlab.com/{u}",
     lambda c, t: c == 200 and "Page not found" not in t),
    ("OnlyFans",   "adult",     "https://onlyfans.com/{u}",
     lambda c, t: c == 200 and ("postsCount" in t or "canReceiveChatMessage" in t)),
    ("Fansly",     "adult",     "https://fansly.com/{u}",
     lambda c, t: c == 200 and "Page Not Found" not in t),
    ("XVideos",    "adult",     "https://www.xvideos.com/profiles/{u}",
     lambda c, t: c == 200 and "not found" not in t.lower()),
    ("Pornhub",    "adult",     "https://www.pornhub.com/users/{u}",
     lambda c, t: c == 200 and "Page Not Found" not in t),
    ("RedGifs",    "adult",     "https://www.redgifs.com/users/{u}",
     lambda c, t: c == 200 and "not found" not in t.lower()),
    ("Snapchat",   "social",    "https://www.snapchat.com/add/{u}",
     lambda c, t: c == 200 and "couldn&#x27;t find" not in t.lower() and "We couldn't find the page" not in t),
]

def _probe_bluesky(s, u):
    try:
        r = http_get(s, "https://public.api.bsky.app/xrpc/"
                        "com.atproto.identity.resolveHandle",
                     params={"handle": u}, tries=1)
        if r.status_code == 200:
            return {"platform": "Bluesky", "category": "social",
                    "confidence": "MEDIUM (username match)",
                    "username": u, "detail": f"https://bsky.app/profile/{u}"}
    except Exception:
        pass
    return None

def social_sweep(s, email):
    cands = username_candidates(email)
    def probe(platform, cat, tmpl, check, u):
        if check is None:
            return _probe_bluesky(s, u) if platform == "Bluesky" else None
        url = tmpl.format(u=u)
        try:
            r = http_get(s, url, tries=2,
                         headers={"User-Agent": UA,
                                  "Referer": "https://www.google.com/"})
            if check(r.status_code, r.text):
                return {"platform": platform, "category": cat,
                        "confidence": "MEDIUM (username match)",
                        "username": u, "detail": url}
        except Exception:
            return None
        return None
    try:
        hits = email_oracles(s, email)
    except Exception:
        hits = []
    with cf.ThreadPoolExecutor(max_workers=12) as ex:
        futs = [ex.submit(probe, p, c, t, ck, u)
                for (p, c, t, ck) in USER_PLATFORMS for u in cands]
        for f in cf.as_completed(futs):
            r = f.result()
            if r:
                hits.append(r)
    best = {}
    for h in hits:
        cur = best.get(h["platform"])
        if (not cur or (h["confidence"].startswith("HIGH")
                        and not cur["confidence"].startswith("HIGH"))):
            best[h["platform"]] = h
    ordered = list(best.values())
    ordered.sort(key=lambda a: ({"adult": 0, "social": 1}.get(a["category"], 2),
                                a["platform"].lower()))
    return ordered, cands

def mod_registrations(s, email, keys):
    accounts, cands = social_sweep(s, email)
    if keys.get("hunter_io"):
        try:
            r = http_get(s, "https://api.hunter.io/v2/email-verifier",
                         params={"email": email,
                                 "api_key": keys["hunter_io"]}).json()
            d = r.get("data", {})
            accounts.append({"platform": "Hunter.io verify", "category": "intel",
                             "confidence": str(d.get("status", "?")).upper(),
                             "detail": f"score={d.get('score')} "
                                       f"sources={d.get('sources')}"})
        except Exception:
            pass
    return (bool(accounts), {"total_found": len(accounts),
                             "username_variants": cands, "accounts": accounts})

# ══════════════════════════════════════════════════════════════════════════
#  BREACH / DUMP MODULES — maximum corpora for maximum coverage
# ══════════════════════════════════════════════════════════════════════════
def mod_breaches(s, email, keys, cred_store=None):
    out = {"corpora": [], "breaches": [], "data_classes": [], "metadata": []}
    # XposedOrNot (free, keyless)
    try:
        j = http_get(s, f"https://api.xposedornot.com/v1/check-email/{email}").json()
        br = (j.get("breaches") or {}).get("exposed", [])
        if br:
            out["corpora"].append("XposedOrNot")
            for b in br:
                if isinstance(b, dict):
                    out["breaches"].append(b.get("name") or b.get("Name") or str(b))
                    cls = b.get("data_classes") or b.get("DataClasses") or []
                    out["data_classes"] += cls if isinstance(cls, list) else [cls]
                else:
                    out["breaches"].append(str(b))
    except Exception:
        pass
    # HIBP (key)
    if keys.get("hibp"):
        try:
            r = http_get(s, f"https://haveibeenpwned.com/api/v3/"
                            f"breachedaccount/{urllib.parse.quote(email)}",
                         params={"truncateResponse": "false"},
                         headers={"hibp-api-key": keys["hibp"],
                                  "user-agent": "HojkerBlackoutX"}, tries=2)
            if r.status_code == 200:
                out["corpora"].append("HIBP")
                for b in r.json():
                    out["breaches"].append(b["Name"])
                    out["data_classes"] += b.get("DataClasses", [])
                    out["metadata"].append({"breach": b["Name"],
                                            "breach_date": b.get("BreachDate"),
                                            "pwn_count": b.get("PwnCount"),
                                            "description": (b.get("Description") or "")[:160]})
        except Exception:
            pass
    # Scylla.so (free, keyless) — EXTRACT PASSWORDS
    try:
        r = http_get(s, "https://scylla.so/search",
                     params={"q": f'email:"{email}"'}, tries=1, timeout=20)
        if r.status_code == 200 and isinstance(r.json(), list):
            rows = r.json()[:60]
            seen = set()
            for it in rows:
                merged = {**((it.get("fields") or {}) if isinstance(it, dict) else {}),
                          **({} if not isinstance(it, dict) else {k: v for k, v in it.items() if k != "fields"})}
                src = merged.get("breach_source") or merged.get("source") \
                    or merged.get("database_name") or "scylla"
                sname = str(src)
                if sname in seen:
                    continue
                seen.add(sname)
                out["corpora"].append("Scylla")
                out["breaches"].append(sname)
                out["metadata"].append({
                    "breach": sname,
                    "has_password": bool(merged.get("password") or merged.get("hash") or merged.get("hashed_password")),
                    "has_name": bool(merged.get("name")),
                    "username": merged.get("username"),
                })
                # EXTRACT CREDENTIALS
                if cred_store:
                    pwd = merged.get("password") or merged.get("hash") or merged.get("hashed_password")
                    if pwd:
                        cred_store.add({
                            "password": str(pwd),
                            "source": f"Scylla/{sname}",
                            "type": "plaintext" if not is_likely_hash(str(pwd)) else "hash",
                            "username": merged.get("username", ""),
                            "email": email,
                        })
                    for field in ("login", "username", "name"):
                        val = merged.get(field)
                        if val and isinstance(val, str) and "@" in val and val.lower() != email.lower():
                            out["metadata"][-1].setdefault("associated_emails", []).append(val)
    except Exception:
        pass
    # LeakCheck (public/demo)
    try:
        j = http_get(s, "https://leakcheck.io/api/public",
                     params={"check": email}, tries=1, timeout=20).json()
        if j.get("success"):
            out["corpora"].append("LeakCheck")
            n = int(j.get("found", 0))
            if n:
                out["breaches"].append(f"LeakCheck ({n} records / "
                                       f"{len(j.get('sources', []))} sources)")
                out["data_classes"].append("password" if n else "")
    except Exception:
        pass
    # Dehashed (key) — EXTRACT PASSWORDS
    if keys.get("dehashed"):
        try:
            import base64 as _b64
            auth = _b64.b64encode(
                (keys.get("dehashed_email", "") + ":" + keys["dehashed"]).encode()
                if keys.get("dehashed_email") else
                (":0".encode())).decode()
            r = http_get(s, "https://api.dehashed.com/search",
                         params={"query": f"email:{email}", "size": "25"},
                         headers={"Accept": "application/json",
                                  "Authorization": f"Basic {auth}"},
                         tries=1, timeout=20)
            if r.status_code == 200:
                j = r.json()
                out["corpora"].append("Dehashed")
                for rec in (j.get("entries") or [])[:15]:
                    db_name = rec.get('database_name') or 'dehashed'
                    has_pwd = type(rec.get('password')) is not type(None)
                    out["breaches"].append(
                        f"{db_name} ({'pwd' if has_pwd else 'no-pwd'})")
                    if cred_store and rec.get("password"):
                        cred_store.add({
                            "password": str(rec["password"]),
                            "source": f"Dehashed/{db_name}",
                            "type": "plaintext",
                            "username": rec.get("username", ""),
                            "email": email,
                            "name": rec.get("name", ""),
                        })
        except Exception:
            pass
    # Snusbase (key) — EXTRACT PASSWORDS
    if keys.get("snusbase"):
        try:
            r = http_post(s, "https://api.snusbase.com/data/search",
                          headers={"Auth": keys["snusbase"],
                                   "Content-Type": "application/json"},
                          json={"terms": [email], "types": ["email"]},
                          tries=1, timeout=20)
            if r.status_code == 200:
                j = r.json()
                results = (j.get("results") or {}).get("email") or []
                if results:
                    out["corpora"].append("Snusbase")
                    for rec in results[:15]:
                        db_name = rec.get('database') or 'snusbase'
                        has_pwd = bool(rec.get('password'))
                        out["breaches"].append(
                            f"{db_name} ({'pwd' if has_pwd else 'no-pwd'})")
                        if cred_store and rec.get("password"):
                            cred_store.add({
                                "password": str(rec["password"]),
                                "source": f"Snusbase/{db_name}",
                                "type": "plaintext",
                                "username": rec.get("username", ""),
                                "email": email,
                            })
        except Exception:
            pass
    out["breaches"] = sorted(set(out["breaches"]))
    out["data_classes"] = sorted(set(out["data_classes"]))[:24]
    out["total_breaches"] = len(out["breaches"])
    out["corpora"] = sorted(set(out["corpora"]))
    return (bool(out["breaches"]), out)

def mod_breachdeep(s, email, keys, cred_store=None):
    out = {"secondary_breaches": [], "data_classes": [], "domain_exposures": [],
           "credential_mentions": 0}
    domain = email.split("@")[1]
    # emailrep.io (free, keyless)
    try:
        r = http_get(s, f"https://emailrep.io/{urllib.parse.quote(email)}",
                     timeout=20).json()
        if r.get("status") == "ok":
            d = r.get("details") or {}
            if d.get("data_breach"):
                for k in ("password", "passwords", "credentials", "hash",
                          "premium_password", "bcrypt_hash", "history"):
                    if d.get(k):
                        out["data_classes"].append(k)
                if d.get("credentials_leaked"):
                    out["credential_mentions"] += 1
                out["secondary_breaches"].append("emailrep.io flagged breach+leak")
            out["domain_exposures"].append(
                f"emailrep: pwn_count={d.get('pwn_count')} "
                f"breach={d.get('data_breach')} leak={d.get('credentials_leaked')}")
    except Exception as ex:
        out["breachdeep_emailrep_error"] = type(ex).__name__
    # BreachDirectory public (no key, pending-status)
    try:
        r = http_get(s, f"https://api.breachdirectory.org/1/search/email",
                     params={"query": email, "type": "email"},
                     tries=1, timeout=20)
        j = r.json()
        if j.get("success") and j.get("result"):
            n = len(j.get("result", []))
            out["secondary_breaches"].append(f"BreachDirectory ({n} entries)")
            out["data_classes"].append("password" if any(
                x.get("password") for x in j.get("result", [])) else "")
            out["credential_mentions"] += (1 if n else 0)
            if cred_store:
                for rec in j.get("result", [])[:20]:
                    pwd = rec.get("password")
                    if pwd:
                        cred_store.add({
                            "password": str(pwd),
                            "source": "BreachDirectory",
                            "type": "plaintext" if not is_likely_hash(str(pwd)) else "hash",
                            "username": rec.get("username", ""),
                            "email": email,
                        })
    except Exception:
        pass
    # Google-cache dork scan for public credential mentions
    for q in (f'"{email}" password', f'"{email}" breach',
              f'"{email}" leak db'):
        try:
            rr = http_get(s, "https://www.google.com/search",
                          params={"q": q, "num": "5"},
                          headers={"User-Agent": UA}, tries=1, timeout=18)
            if email.lower() in rr.text.lower():
                out["credential_mentions"] += 1
                out["domain_exposures"].append(f"web-cache: '{q[:24]}'")
        except Exception:
            continue
    # XposedOrNot domain aggregate
    try:
        rr = http_get(s, "https://api.xposedornot.com/v1/check-domains/" + domain,
                      timeout=20)
        if rr.status_code == 200 and isinstance(rr.json(), dict):
            dj = rr.json()
            n = len(dj.get("domains") or dj.get("breaches") or [])
            if n:
                out["domain_exposures"].append(f"XposedOrNot domain: {domain} ({n})")
    except Exception:
        pass
    out["data_classes"] = sorted(set(out["data_classes"]))[:15]
    total = len(out["secondary_breaches"]) + out["credential_mentions"]
    return (total > 0, out)

# ══════════════════════════════════════════════════════════════════════════
def mod_breachdirectory(s, email, keys, cred_store=None):
    out = {"breaches": [], "entries": 0, "data_classes": [], "hashes": [],
           "metadata": []}
    key = keys.get("breachdirectory") or keys.get("rapidapi")
    if not key:
        out["status"] = "no rapidapi key configured"
        return (False, out)
    try:
        r = http_get(s, "https://breachdirectory.p.rapidapi.com/",
                     params={"func": "auto", "term": email},
                     headers={"x-rapidapi-key": key,
                              "x-rapidapi-host": "breachdirectory.p.rapidapi.com"},
                     timeout=25)
        if r.status_code != 200:
            out["status"] = f"HTTP {r.status_code}"
            return (False, out)
        body = r.json()
        rows = body.get("result") if body.get("success") else None
        if not isinstance(rows, list) or not rows:
            return (False, out)
        out["entries"] = len(rows)
        seen = set()
        for rec in rows[:40]:
            if not isinstance(rec, dict):
                continue
            sname = str(rec.get("breach") or rec.get("source") or "breachdirectory")
            if sname in seen:
                continue
            seen.add(sname)
            out["breaches"].append(sname)
            pwd = rec.get("plain") or rec.get("password2") or rec.get("password")
            is_hash = rec.get("hash") in (True, 1, "1", "true", 1) or (
                pwd and is_likely_hash(str(pwd)))
            for h in ("md5", "sha1", "sha256"):
                if rec.get(h):
                    out["hashes"].append(h)
            out["metadata"].append({
                "breach": sname,
                "type": rec.get("type", ""),
                "lines": rec.get("lines", ""),
                "username": rec.get("username", ""),
                "has_password": bool(pwd),
                "password_type": "hash" if is_hash else "plaintext",
            })
            if cred_store and pwd:
                cred_store.add({
                    "password": str(pwd),
                    "source": f"BreachDirectory/{sname}",
                    "type": "hash" if is_hash else "plaintext",
                    "username": rec.get("username", ""),
                    "email": email,
                })
        out["hashes"] = list(dict.fromkeys(out["hashes"]))[:6]
        out["data_classes"] = sorted(set(out["hashes"]))
        return (len(out["breaches"]) > 0, out)
    except Exception as exx:
        out["error"] = type(exx).__name__
        return (False, out)

def mod_dumps_pastes(s, email, keys, tor=False, cred_store=None):
    out = {"paste_hits": [], "dump_references": [], "password_mentions": 0,
           "sources": []}
    # psbdmp — EXTRACT PASSWORDS FROM PASTE TEXT
    try:
        r = http_get(s, "https://psbdmp.ws/api/v3/search/" +
                     urllib.parse.quote(email), timeout=20).json()
        entries = r.get("data") or []
        if isinstance(entries, list):
            for e in entries[:25]:
                pid = e.get("id") if isinstance(e, dict) else e
                url = f"https://psbdmp.ws/api/view/{pid}"
                entry = {"paste_id": pid, "url": url}
                try:
                    body = http_get(s, url, timeout=15).json()
                    txt = str(body.get("data", body.get("text", "")))
                    if email.lower() in txt.lower():
                        entry["email_present"] = True
                        if re.search(r"(password|passwd|pwd|pass)\s*[:=]", txt, re.I):
                            entry["password_field_nearby"] = True
                            out["password_mentions"] += 1
                        out["paste_hits"].append(entry)
                        if cred_store:
                            cred_store.add_text_secrets(txt, f"psbdmp/{pid}")
                except Exception:
                    out["paste_hits"].append(entry)
            if entries:
                out["sources"].append(f"psbdmp.ws ({len(entries)} candidate pastes)")
    except Exception as ex:
        out["psbdmp_error"] = type(ex).__name__
    # IntelX (free key)
    if keys.get("intelx"):
        try:
            r = http_post(s, "https://2.intelx.io/intelligent/search",
                          json={"term": email, "maxcrawls": 100, "media": 0},
                          headers={"x-key": keys["intelx"]}).json()
            recs = r.get("records") or []
            out["dump_references"] = [
                {"record_id": x.get("id"), "type": x.get("mediah"),
                 "name": x.get("name")} for x in recs[:20]]
            out["sources"].append(f"IntelX ({len(recs)} records)")
        except Exception as ex:
            out["intelx_error"] = type(ex).__name__
    # HIBP pastes (key)
    if keys.get("hibp"):
        try:
            r = http_get(s, f"https://haveibeenpwned.com/api/v3/"
                            f"pasteaccount/{urllib.parse.quote(email)}",
                         headers={"hibp-api-key": keys["hibp"],
                                  "user-agent": "HojkerBlackoutX"}, tries=2)
            if r.status_code == 200:
                for p in r.json():
                    out["paste_hits"].append({
                        "paste_id": p.get("Id"),
                        "url": p.get("Source") or p.get("Title") or "hibp-paste",
                        "password_field_nearby": (p.get("Title") or "").lower() in
                        ("password", "credentials", "dump"),
                    })
                    if str(p.get("Title", "")).lower() in ("password", "credentials", "dump"):
                        out["password_mentions"] += 1
                out["sources"].append("HIBP pastes")
        except Exception:
            pass
    total = len(out["paste_hits"]) + len(out["dump_references"])
    return (total > 0, {**out, "total_hits": total})

def mod_darkweb(s, email, keys, tor=False, quiet=False):
    out = {"hits": [], "onions": [], "darkweb_emails": [], "via_tor": tor}
    dw = make_session(tor=tor, timeout=30)
    for q in (email, email.split("@")[0]):
        try:
            r = http_get(dw, "https://ahmia.fi/search/", params={"q": q}, tries=2)
            if email.lower() in r.text.lower():
                out["hits"].append(f"Ahmia onion index (query={q})")
            out["onions"] += list(dict.fromkeys(ONION_RE.findall(r.text)))[:10]
            out["darkweb_emails"] += [e for e in EMAIL_RE.findall(r.text)
                                      if e.lower() == email.lower()]
        except Exception as ex:
            out["error"] = type(ex).__name__ + (" — Tor unreachable" if tor else "")
            break
    out["onions"] = list(dict.fromkeys(out["onions"]))[:10]
    return (bool(out["hits"] or out["darkweb_emails"]), out)

# ══════════════════════════════════════════════════════════════════════════
#  OTHER MODULES
# ══════════════════════════════════════════════════════════════════════════
def mod_hudsonrock(s, email, keys):
    r = http_get(s, "https://cavalier.hudsonrock.com/api/json/v2/"
                    "osint-tools/search-by-email",
                 params={"email": email}).json()
    st = r.get("stealers") or []
    return (bool(st), {"infostealer_infection": bool(st), "machines": len(st),
                       "summary": (r.get("message") or "")[:250]})

def mod_emailrep(s, email, keys):
    hdrs = {"Key": keys["emailrep"]} if keys.get("emailrep") else {}
    r = http_get(s, f"https://emailrep.io/{urllib.parse.quote(email)}",
                 headers=hdrs).json()
    if r.get("status") == "fail":
        return (False, {"error": r.get("reason", "rate limited")})
    d = r.get("details") or {}
    return (True, {"reputation": r.get("reputation"), "suspicious": r.get("suspicious"),
                   "blacklisted": r.get("blacklisted"),
                   "credentials_leaked": d.get("credentials_leaked"),
                   "data_breach": d.get("data_breach"),
                   "pwn_count": d.get("pwn_count"),
                   "profiles_on": r.get("profiles")})

def mod_shodan(s, email, keys):
    if not keys.get("shodan"):
        return (False, {"note": "no Shodan key — set via menu [k] / --keys"})
    domain = email.split("@")[1]
    try:
        r = http_get(s, "https://api.shodan.io/dns/domain/" + domain,
                     params={"key": keys["shodan"]}).json()
        subs = sorted(r.get("subdomains", []))[:12]
    except Exception as ex:
        return (False, {"error": type(ex).__name__})
    hosts = []
    for sub in subs[:5]:
        host = f"{sub}.{domain}"
        try:
            h = http_get(s, f"https://api.shodan.io/shodan/host/{host}",
                         params={"key": keys["shodan"]}, tries=1).json()
            hosts.append({"host": host, "ports": h.get("ports", []),
                          "org": h.get("org"),
                          "vulns": list((h.get("vulns") or {}).keys())[:5]})
        except Exception:
            continue
    return (bool(hosts), {"domain": domain, "subdomains": subs,
                          "exposed_hosts": hosts})

def mod_github(s, email, keys):
    hdrs = ({"Authorization": f"token {keys['github_token']}"}
            if keys.get("github_token") else {})
    out = {"users": [], "commit_repos": [], "names": []}
    try:
        r = http_get(s, "https://api.github.com/search/users",
                     params={"q": email, "per_page": 5}, headers=hdrs).json()
        out["users"] = [u["html_url"] for u in r.get("items", [])[:5]]
    except Exception:
        pass
    try:
        r = http_get(s, "https://api.github.com/search/commits",
                     params={"q": f"author-email:{email}", "per_page": 5},
                     headers={**hdrs,
                              "Accept": "application/vnd.github.cloak-preview+json"}).json()
        for c in r.get("items", [])[:5]:
            out["commit_repos"].append(c["repository"]["full_name"])
            n = (c.get("commit", {}).get("author") or {}).get("name")
            if n:
                out["names"].append(n)
    except Exception:
        pass
    return (bool(out["users"] or out["commit_repos"]), out)

def mod_gravatar(s, email, keys):
    md5 = hashlib.md5(email.lower().encode()).hexdigest()
    out = {"gravatar_url": None, "libravatar_url": None, "profile": None,
           "display_name": None}
    try:
        r = http_get(s, f"https://www.gravatar.com/{md5}.json", tries=1)
        if r.status_code == 200:
            ent = (r.json().get("entry") or [{}])[0]
            out["gravatar_url"] = f"https://www.gravatar.com/{md5}"
            out["display_name"] = ent.get("displayName")
            out["profile"] = {
                "name": ent.get("name"),
                "about": (ent.get("aboutMe") or "")[:120],
                "urls": [u.get("value") for u in (ent.get("urls") or [])][:5],
            }
    except Exception:
        pass
    try:
        lr = http_get(s, f"https://www.libravatar.org/avatar/{md5}?d=404",
                      tries=1, stream=True)
        if lr.status_code == 200:
            out["libravatar_url"] = f"https://www.libravatar.org/avatar/{md5}"
    except Exception:
        pass
    return (bool(out["display_name"] or out["profile"]), out)

def mod_keybase(s, email, keys):
    try:
        r = http_get(s, "https://keybase.io/_/api/1.0/user/lookup.json",
                     params={"email": email}, tries=2).json()
        them = r.get("them") or {}
        if not them.get("id"):
            return (False, {})
        profile = them.get("profile") or {}
        return (True, {
            "username": profile.get("username"),
            "full_name": profile.get("full_name"),
            "keybase_url": f"https://keybase.io/{profile.get('username')}",
            "pgp_fingerprints": [k.get("key_fingerprint")
                                 for k in (them.get("public_keys") or {}).get(
                                     "primary", {}).get("all_bundles", [])][:3],
        })
    except Exception as ex:
        return (False, {"error": type(ex).__name__})

def mod_pgp(s, email, keys):
    found = []
    for host in ("https://keyserver.ubuntu.com", "https://keys.openpgp.org"):
        try:
            j = http_get(s, f"{host}/pks/lookup",
                         params={"op": "index", "search": email,
                                 "fingerprint": "on"},
                         headers={"Accept": "application/json"}, tries=1).json()
            found += [{"fingerprint": k.get("fingerprint"),
                       "uids": (k.get("uids") or k.get("userid") or "") if isinstance(k.get("uids"), str) else k.get("uids"),
                       "server": host.split("//")[1]}
                      for k in (j.get("keys") or [])]
        except Exception:
            continue
    return (bool(found), {"pgp_keys": found, "verified_identity": bool(found)})

def mod_dns(s, email, keys):
    domain = email.split("@")[1]
    res = dns.resolver.Resolver()
    res.timeout = 5
    res.lifetime = 8
    out = {"domain": domain}
    for rt, key in [("MX", "mx"), ("A", "a"), ("NS", "ns"), ("TXT", "txt")]:
        try:
            out[key] = sorted(str(r) for r in res.resolve(domain, rt))[:4]
        except Exception:
            out[key] = []
    for txt, key in [(domain, "spf"), (f"_dmarc.{domain}", "dmarc")]:
        try:
            out[key] = " ".join(str(r) for r in res.resolve(txt, "TXT"))[:160]
        except Exception:
            out[key] = None
    out["mail_server_live"] = bool(out["mx"])
    return (True, out)

def mod_whois(s, email, keys):
    try:
        import whois as w
        d = w.whois(email.split("@")[1])
        emails = d.get("emails") or []
        if isinstance(emails, str):
            emails = [emails]
        return (True, {"registrar": d.get("registrar"),
                       "created": str(d.get("creation_date", ""))[:10],
                       "expires": str(d.get("expiration_date", ""))[:10],
                       "privacy_protected": "privacy" in str(emails).lower()
                       or not d.get("name"),
                       "whois_emails": [e for e in emails if EMAIL_RE.match(str(e))]})
    except Exception as ex:
        return (False, {"error": type(ex).__name__})

def mod_wayback(s, email, keys):
    domain = email.split("@")[1]
    try:
        r = http_get(s, "https://web.archive.org/cdx/search/cdx",
                     params={"url": f"*.{domain}", "output": "json",
                             "collapse": "urlkey", "limit": "100"}).json()
        rows = r[1:] if isinstance(r, list) else []
        return (True, {"snapshots": len(rows),
                       "sample_pages": [row[2] for row in rows[:6]]})
    except Exception as ex:
        return (False, {"error": type(ex).__name__})

def mod_securitytxt(s, email, keys):
    domain = email.split("@")[1]
    out = {"security_txt_on_domain": None, "contacts": [], "hint": ""}
    for url in (f"https://{domain}/.well-known/security.txt",
                f"https://{domain}/security.txt",
                f"http://{domain}/.well-known/security.txt"):
        try:
            r = http_get(s, url, tries=1, timeout=10)
            if r.status_code == 200:
                out["security_txt_on_domain"] = url
                out["contacts"] += EMAIL_RE.findall(r.text)[:10]
                out["hint"] = r.text[:200]
                break
        except Exception:
            continue
    return (bool(out["security_txt_on_domain"]), out)

def mod_subdomain(s, email, keys):
    domain = email.split("@")[1]
    subs = set()
    out = {"domain": domain, "subdomains": [], "sources": []}
    try:
        r = http_get(s, "https://crt.sh/?q=%25." + domain + "&output=json",
                     tries=2, timeout=25)
        if r.status_code == 200 and r.text.strip().startswith("["):
            for row in r.json():
                for nm in (row.get("name_value") or "").split("\n"):
                    nm = nm.strip().lstrip("*.")
                    if nm.endswith(domain) and nm != domain:
                        subs.add(nm)
        out["sources"].append("crt.sh")
    except Exception:
        pass
    try:
        r = http_get(s, f"https://api.hackertarget.com/hostsearch/?q={domain}",
                     tries=2, timeout=20)
        if r.status_code == 200 and "error" not in r.text.lower()[:20]:
            for line in r.text.splitlines():
                host = line.split(",")[0].strip()
                if host.endswith(domain) and host != domain:
                    subs.add(host)
            out["sources"].append("HackerTarget")
    except Exception:
        pass
    out["subdomains"] = sorted(subs)[:30]
    return (bool(out["subdomains"]), out)

def mod_package(s, email, keys):
    out = {"packages": [], "maintainers": [], "sources": []}
    try:
        r = http_get(s, "https://registry.npmjs.org/-/v1/search",
                     params={"text": email, "size": 10}, tries=1).json()
        for o in r.get("objects", [])[:8]:
            p = o.get("package", {})
            out["packages"].append(p.get("name"))
            out["maintainers"] += [m.get("username") for m in
                                   p.get("maintainers", [])][:4]
        out["sources"].append("npm registry")
    except Exception:
        pass
    try:
        r = http_get(s, "https://pypi.org/pypi/" + email.split("@")[0] +
                     "/json", tries=1)
        if r.status_code == 200:
            out["packages"].append(email.split("@")[0])
            out["sources"].append("PyPI")
    except Exception:
        pass
    out["packages"] = sorted(set(out["packages"]))[:12]
    out["maintainers"] = sorted(set(out["maintainers"]))[:12]
    return (bool(out["packages"] or out["maintainers"]), out)

def mod_verify_smtp(s, email, keys):
    domain = email.split("@")[1]
    res = dns.resolver.Resolver()
    res.timeout = 5
    try:
        mx = sorted((int(x.preference), str(x.exchange).rstrip("."))
                    for x in res.resolve(domain, "MX"))
    except Exception:
        return (False, {"mx_live": False, "note": "no MX — cannot receive mail"})
    def rcpt(addr, host):
        try:
            with smtplib.SMTP(host, 25, timeout=12) as srv:
                srv.ehlo("hojker.local")
                try:
                    srv.starttls()
                    srv.ehlo("hojker.local")
                except Exception:
                    pass
                srv.mail("probe@hojker.local")
                code, _ = srv.rcpt(addr)
                return code in (250, 251)
        except Exception:
            return None
    rnd = "no-such-user-" + "".join(random.choices(string.ascii_lowercase, k=16))
    try:
        catch_all = rcpt(f"{rnd}@{domain}", mx[0][1])
        ok = rcpt(email, mx[0][1])
    except Exception:
        return (True, {"mx_live": True, "primary_mx": mx[0][1],
                       "verdict": "⚠ server refused SMTP probes"})
    verdict = ("✔ DELIVERABLE — mailbox confirmed live" if ok and not catch_all else
               "⚠ CATCH-ALL domain — inconclusive" if catch_all else
               "? UNVERIFIABLE — server refused probes" if ok is None else
               "✘ MAILBOX DOES NOT EXIST")
    return (True, {"mx_live": True, "primary_mx": mx[0][1],
                   "catch_all": catch_all, "verdict": verdict})

def mod_google_dork(s, email, keys):
    out = {"dork_hits": [], "count": 0}
    queries = [
        f'"{email}"',
        f'"{email}" -onion',
        f'"{email}" site:github.com',
        f'"{email}" password',
        f'"{email}" "phone" OR "address"',
    ]
    if keys.get("google_cse"):
        try:
            for q in queries:
                r = http_get(s, "https://www.googleapis.com/customsearch/v1",
                             params={"key": keys["google_cse"],
                                     "cx": keys.get("google_cse_cx", ""),
                                     "q": q}, tries=1, timeout=15)
                if r.status_code == 200:
                    items = r.json().get("items") or []
                    out["dork_hits"] += [{"q": q[:28], "title": it.get("title")[:60],
                                          "link": it.get("link")[:120]}
                                         for it in items[:3]]
        except Exception as ex:
            out["cse_error"] = type(ex).__name__
    out["count"] = len(out["dork_hits"])
    return (bool(out["count"]), out)

# ══════════════════════════════════════════════════════════════════════════
#  ONLYFANS ACCOUNT HUNT (search-engine handle discovery + dork probe)
# ══════════════════════════════════════════════════════════════════════════
def _engine_html(s, url, params, timeout=20):
    try:
        r = http_get(s, url, params=params, headers={"User-Agent": UA},
                     timeout=timeout, tries=1)
        if r.status_code == 200:
            return r.text or ""
    except Exception:
        pass
    return ""

def _of_handles_from(text):
    handles = []
    for m in re.finditer(
            r"onlyfans\.com/(?!(auth|signin|signup|join|login|media|api2|v[0-9]|search)/)"
            r"[a-z0-9_]{3,40}", text.lower()):
        h = m.group(0).split("onlyfans.com/", 1)[-1]
        if h.endswith((".jpg", ".png", ".webp", ".gif", ".css", ".js")):
            continue
        if h not in handles:
            handles.append(h)
    return handles

def mod_onlyfans(s, email, keys):
    out = {"email": email, "of_handles": [], "dork_hits": [], "engines": []}
    cands = username_candidates(email)
    queries = [f'onlyfans.com/{c}' for c in cands]
    queries += [f'"{email}" onlyfans', f'onlyfans "{email}"']
    seen_h, seen_hit = set(), set()
    for q in queries[:8]:
        for eng, url in (("ddg", "https://html.duckduckgo.com/html/"),
                         ("bing", "https://www.bing.com/search")):
            txt = _engine_html(s, url, {"q": q})
            if not txt:
                continue
            if eng not in out["engines"]:
                out["engines"].append(eng)
            for h in _of_handles_from(txt):
                if h not in seen_h:
                    seen_h.add(h)
                    out["of_handles"].append(h)
            for href in re.findall(r'<a[^>]+href="([^"]*onlyfans\.com[^"]+)"', txt)[:3]:
                if href in seen_hit:
                    continue
                seen_hit.add(href)
                lbl = ""
                m = re.search(r'<a[^>]+href="' + re.escape(href) + r'"[^>]*>([^<]{1,80})', txt)
                if m:
                    lbl = " ".join(m.group(1).split())
                out["dork_hits"].append({"q": q[:26], "engine": eng,
                                         "label": lbl[:50], "link": href[:140]})
    out["of_handles"] = out["of_handles"][:12]
    out["direct_probe"] = {}
    if cands:
        try:
            rr = http_get(s, f"https://onlyfans.com/{cands[0]}",
                          headers={"User-Agent": UA,
                                   "Accept": "text/html,application/xhtml+xml",
                                   "Accept-Language": "en-US,en;q=0.9"},
                          timeout=20, tries=1)
            out["direct_probe"]["handle"] = cands[0]
            out["direct_probe"]["http"] = rr.status_code
            if rr.status_code == 200:
                mm = (re.search(r'"username":"([a-z0-9_]+)"', rr.text)
                      or re.search(r'<title>([^<]{3,60})</title>', rr.text))
                if mm:
                    out["direct_probe"]["page_name"] = " ".join(mm.group(1).split())
        except Exception:
            pass
    out["count"] = len(out["of_handles"]) + len(out["dork_hits"])
    return (bool(out["of_handles"] or out["dork_hits"]), out)

# ══════════════════════════════════════════════════════════════════════════
#  RAPIDAPI SOCIAL SEARCH (rapidapi.com — social account discovery)
#  key: set with menu [k] / --keys → service: rapidapi
# ══════════════════════════════════════════════════════════════════════════
def _rp_json(r):
    try:
        return r.json()
    except Exception:
        return {}

def _rp_scalars(obj, depth=0):
    if depth > 6:
        return []
    if isinstance(obj, dict):
        out = []
        for v in obj.values():
            out += _rp_scalars(v, depth + 1)
        return out
    if isinstance(obj, list):
        out = []
        for v in obj:
            out += _rp_scalars(v, depth + 1)
        return out
    if obj is not None:
        return [str(obj)]
    return []

def _rp_first(obj, *keys):
    for k in keys:
        if isinstance(obj, dict) and obj.get(k) not in (None, ""):
            return obj.get(k)
    return None

def mod_rapidapi_social(s, email, keys):
    key = (keys or {}).get("rapidapi")
    if not key:
        return (False, {"note": "no RapidAPI key — set with menu [k] / --keys ⚙",
                        "services": "facebook · instagram · linkedin · scrapeninja"})
    out = {"services": [], "profiles": [], "context_hits": [], "errors": []}
    email_l = email.lower()
    cands = username_candidates(email)
    urls_seen = set()

    def push_profile(platform, handle, url, extra=None):
        if not handle and not url:
            return
        key_ = (url or handle or "").lower()
        if key_ in urls_seen:
            return
        urls_seen.add(key_)
        p = {"platform": platform, "handle": handle or "?", "url": url or ""}
        if extra:
            p["detail"] = {k: v for k, v in list(extra.items())[:8] if v not in (None, "")}
        out["profiles"].append(p)

    def probe(service, url, method="GET", **kw):
        hdrs = {"x-rapidapi-key": key,
                "x-rapidapi-host": {"facebook": "facebook-scraper3.p.rapidapi.com",
                                    "instagram-looter": "instagram-looter2.p.rapidapi.com",
                                    "instagram-scraper": "instagram-scraper-stable-api.p.rapidapi.com",
                                    "linkedin": "li-data-scraper.p.rapidapi.com",
                                    "scrapeninja": "scrapeninja.p.rapidapi.com"}[service]}
        kw["headers"] = {**(kw.get("headers") or {}), **hdrs}
        kw.setdefault("timeout", 25)
        fn = http_get if method == "GET" else http_post
        try:
            r = fn(s, url, tries=1, **kw)
        except Exception as ex:
            out["errors"].append(f"{service}: {type(ex).__name__}")
            out["services"].append(service)
            return None, None
        out["services"].append(service)
        if r.status_code != 200:
            out["errors"].append(f"{service}: HTTP {r.status_code}")
            return r.status_code, None
        return r.status_code, _rp_json(r)

    for u in cands[:3]:
        st, body = probe("instagram-looter",
                         "https://instagram-looter2.p.rapidapi.com/search",
                         params={"query": u})
        if st == 200 and body:
            items = (body.get("data") or body.get("result") or
                     body.get("items") or body.get("users") or body)
            if isinstance(items, dict):
                items = [items]
            for it in (items if isinstance(items, list) else []):
                if not isinstance(it, dict):
                    continue
                handle = (_rp_first(it, "username", "userName", "user", "handle")
                          or (it.get("user_info") or {}).get("username")
                          or (it.get("user") or {}).get("username"))
                url = _rp_first(it, "url", "profile_pic_url", "profile_url")
                if not url and handle:
                    url = f"https://www.instagram.com/{handle}/"
                push_profile("Instagram", str(handle) if handle else u, url,
                             {"query": u, "full_name": _rp_first(it, "full_name", "fullName"),
                              "followers": _rp_first(it, "followers", "edge_followed_by")})
                if not handle:
                    out["context_hits"].append(
                        {"service": "Instagram Looter", "query": u,
                         "snippet": str({k: v for k, v in it.items() if isinstance(v, str)})[:220]})

    st, body = probe("instagram-scraper",
                     "https://instagram-scraper-stable-api.p.rapidapi.com"
                     "/get_ig_user_followers_v2.php",
                     method="POST", data={"username_or_url": f"https://www.instagram.com/{cands[0]}/",
                                          "data": "following_and_followers", "amount": "12",
                                          "pagination_token": ""})
    if st == 200 and body:
        for sub in (body.get("data") or body.get("result") or body.get("response") or [body]):
            if isinstance(sub, dict) and ("username" in sub or "pk" in sub):
                h = sub.get("username") or sub.get("user") or cands[0]
                push_profile("Instagram", h,
                             f"https://www.instagram.com/{h}/",
                             {"rel": "following/followers", "full_name": sub.get("full_name")})

    st, body = probe("facebook",
                     "https://facebook-scraper3.p.rapidapi.com/profile/following",
                     params={"username": cands[0]})
    if st == 200:
        if isinstance(body, dict):
            for rel in (body.get("following") or body.get("data") or body.get("results") or []):
                if isinstance(rel, dict):
                    nm = rel.get("username") or rel.get("name")
                    if nm:
                        push_profile("Facebook", nm, rel.get("url") or rel.get("profile_pic") or "",
                                     {"rel": "fb following"})
        elif body:
            out["context_hits"].append(
                {"service": "Facebook Scraper3", "query": cands[0],
                 "snippet": str(body)[:220]})

    li_url = f"https://www.linkedin.com/in/{cands[0]}/"
    st, body = probe("linkedin",
                     "https://li-data-scraper.p.rapidapi.com/get-profile-data-by-url",
                     params={"url": li_url})
    if st == 200 and isinstance(body, dict):
        name = (_rp_first(body, "full_name", "fullName", "name")
                or ((body.get("profile") or {}).get("full_name")))
        if name:
            push_profile("LinkedIn", cands[0], li_url,
                         {"headline": _rp_first(body, "headline", "headlineUrl"),
                          "location": _rp_first(body, "location", "countryFullName"),
                          "followers": _rp_first(body, "followers", "connections")})

    st, body = probe("scrapeninja",
                     "https://scrapeninja.p.rapidapi.com/v2/scrape-js",
                     method="POST",
                     json={"url": f'https://www.bing.com/search?q="{email_l}"',
                           "geo": "us", "timeout": 15, "screenshot": False})
    if st == 200:
        hay = " ".join(_rp_scalars(body))[:12000]
        if re.search(re.escape(email_l), hay):
            out["context_hits"].append(
                {"service": "ScrapeNinja (Bing)", "query": email_l,
                 "snippet": "email referenced on indexed page"})
        for url_m in list(dict.fromkeys(re.findall(
                r'https?://(?:www\.)?'
                r'(?:instagram|facebook|twitter|linkedin|tiktok|reddit|x)\.com/[^\s"\\<>]+',
                hay)))[:6]:
            out["context_hits"].append(
                {"service": "ScrapeNinja (Bing)", "query": email_l,
                 "snippet": url_m[:220]})

    out["services"] = list(dict.fromkeys(out["services"]))
    out["errors"] = list(dict.fromkeys(out["errors"]))[:6]
    out["profile_count"] = len(out["profiles"])
    out["context_count"] = len(out["context_hits"])
    found = bool(out["profiles"] or out["context_hits"])
    return (found, out)

# ══════════════════════════════════════════════════════════════════════════
#  ANALYSIS
# ══════════════════════════════════════════════════════════════════════════
def name_consensus(results):
    names = {}
    for n in (results.get("GITHUB") or {}).get("names") or []:
        names.setdefault(str(n).lower(), set()).add("github")
    for n in (results.get("KEYBASE") or {}).get("full_name") or []:
        names.setdefault(str(n).lower(), set()).add("keybase")
    if (results.get("GRAVATAR") or {}).get("display_name"):
        names.setdefault(str((results.get("GRAVATAR") or {}).get("display_name")).lower(),
                         set()).add("gravatar")
    for e in (results.get("WHOIS") or {}).get("whois_emails") or []:
        if EMAIL_RE.match(str(e)):
            names.setdefault(str(e).lower(), set()).add("whois")
    if (results.get("PGP KEYS") or {}).get("verified_identity"):
        names.setdefault("pgp-verified", set()).add("pgp")
    return {"confirmed": [n for n, ss in names.items() if len(ss) >= 3],
            "probable":  [n for n, ss in names.items() if len(ss) == 2],
            "possible":  [n for n, ss in names.items() if len(ss) == 1][:8]}

def risk_score(results):
    score, drivers = 0, []
    hr = results.get("INFOSTEALER LOGS") or {}
    if hr.get("infostealer_infection"):
        score += 40
        drivers.append("Infostealer infection")
    br = results.get("BREACH CORPUS") or {}
    if br.get("total_breaches"):
        score += min(25, br["total_breaches"] * 3)
        drivers.append(f"{br['total_breaches']} breaches")
    xl = results.get("BREACH DEEP") or {}
    if xl.get("credential_mentions"):
        score += min(20, xl["credential_mentions"] * 6)
        drivers.append(f"{xl['credential_mentions']} credential/paste mention(s)")
    if xl.get("secondary_breaches"):
        score += 5
        drivers.append("deep breach corpus hit")
    bd = results.get("BREACH DIRECTORY") or {}
    if bd.get("breaches"):
        score += min(15, len(bd["breaches"]) * 4)
        drivers.append(f"breach-directory hit ({len(bd['breaches'])})")
    dp = results.get("DUMPS & PASTES") or {}
    if dp.get("password_mentions"):
        score += 20
        drivers.append(f"{dp['password_mentions']} paste(s) w/ password fields")
    elif dp.get("total_hits"):
        score += 10
        drivers.append(f"{dp['total_hits']} dump/paste references")
    er = results.get("REPUTATION") or {}
    if er.get("credentials_leaked"):
        score += 20
        drivers.append("Credentials leaked (emailrep)")
    if er.get("blacklisted"):
        score += 10
        drivers.append("Blacklisted")
    dw = results.get("DARK WEB") or {}
    if dw.get("darkweb_emails") or dw.get("hits"):
        score += 25
        drivers.append("Found on dark web")
    reg = results.get("REGISTRATIONS") or {}
    adult = [a for a in (reg.get("accounts") or [])
             if a.get("category") == "adult"]
    if adult:
        score += 10
        drivers.append(f"{len(adult)} adult-platform matches")
    score = min(100, score)
    band = ("CRITICAL" if score >= 70 else "HIGH" if score >= 40 else
            "MEDIUM" if score >= 20 else "LOW")
    return {"score": score, "band": band, "drivers": drivers}

# ══════════════════════════════════════════════════════════════════════════
#  VISUAL DESIGN — ENHANCED v8
# ══════════════════════════════════════════════════════════════════════════
BANNER = r"""
 .--..--..--..--..--..--..--..--..--. 
/ .. \.. \.. \.. \.. \.. \.. \.. \.. \
\ \/\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ \/ /
 \/ /`--'`--'`--'`--'`--'`--'`--'\/ / 
 / /\                            / /\ 
/ /\ \ ╦ ╦┌─┐ ┬┬┌─┌─┐┬─┐        / /\ \
\ \/ / ╠═╣│ │ │├┴┐├┤ ├┬┘        \ \/ /
 \/ /  ╩ ╩└─┘└┘┴ ┴└─┘┴└─         \/ / 
 / /\  ╔═╗┌┬┐┌─┐┬┬               / /\ 
/ /\ \ ║╣ │││├─┤││              / /\ \
\ \/ / ╚═╝┴ ┴┴ ┴┴┴─┘            \ \/ /
 \/ /  ╔╗ ┬─┐┌─┐┌─┐┌─┐┬ ┬┌─┐┌─┐  \/ / 
 / /\  ╠╩╗├┬┘├┤ ├─┤│  ├─┤├┤ └─┐  / /\ 
/ /\ \ ╚═╝┴└─└─┘┴ ┴└─┘┴ ┴└─┘└─┘ / /\ \
\ \/ /                          \ \/ /
 \/ /                            \/ / 
 / /\.--..--..--..--..--..--..--./ /\ 
/ /\ \.. \.. \.. \.. \.. \.. \.. \/\ \
\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `' /
 `--'`--'`--'`--'`--'`--'`--'`--'`--' 
"""

def frame_banner():
    console.print()
    console.print(Text(BANNER, style="bold bright_magenta"))
    console.print(Rule(style="bright_magenta", characters="═"))
    console.print()

def game_loading(target, seconds=2.6):
    from rich.live import Live
    w = 64
    console.print()
    console.print(Text(f"  ┌{'─' * w}┐", style="bright_magenta"))
    console.print(Text(f"  │{'TARGET':<20}│  {target[:40]:<40}│", style="bold bright_white"))
    console.print(Text(f"  │{'MODE':<20}│  {'FULL BLACKOUT X SWEEP':<40}│", style="bright_white"))
    console.print(Text(f"  │{'TIMESTAMP':<20}│  {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'):<40}│", style="grey50"))
    console.print(Text(f"  └{'─' * w}┘", style="bright_magenta"))
    console.print()
    frames = max(2, int(seconds * 30))
    with Live(console=console, refresh_per_second=30) as live:
        for i in range(frames + 1):
            pct = i / frames
            filled = int(pct * 48)
            bar = "█" * filled + "░" * (48 - filled)
            live.update(f"  [bold bright_magenta]⬢ LOADING ALL MODULES[/]  "
                        f"[bright_magenta]{bar}[/]  "
                        f"[bold]{int(pct * 100):3d}%[/]")
            time.sleep(seconds / frames)
    console.print("  [bold bright_green]✔ SYSTEM READY — SWEEP BEGINNING[/]")
    console.print()

def _gradient_bar(score, width=24):
    filled = int(round(score / 100 * width))
    segments = []
    for i in range(width):
        if i < filled:
            if i >= width * 0.85:
                c = "bold red"
                ch = "█"
            elif i >= width * 0.65:
                c = "bright_red"
                ch = "█"
            elif i >= width * 0.45:
                c = "bright_yellow"
                ch = "█"
            elif i >= width * 0.25:
                c = "yellow"
                ch = "█"
            else:
                c = "bright_green"
                ch = "█"
        else:
            c = "grey27"
            ch = "░"
        segments.append(f"[{c}]{ch}[/]")
    return "".join(segments)

def _kv_line(k, v, limit=175):
    vs = json.dumps(v, ensure_ascii=False, default=str) \
        if isinstance(v, (list, dict)) else str(v)
    if len(vs) > limit:
        vs = vs[:limit - 3] + "..."
    return f"  [grey50]{k:<24}[/] [white]{vs}[/]"

def _stat_box(label, value, color="bright_white"):
    return f"[bold grey50]{label}[/]\n  [bold {color}]{value}[/]"

def render_credential_panel(cred_store, show_passwords=False):
    if not cred_store or cred_store.total() == 0:
        return
    console.print()
    console.print(Rule(style="bold bright_red", title="[bold bright_red] 🔑  EXTRACTED CREDENTIALS & SECRETS [/]"))
    console.print()

    if cred_store.plaintext_count() > 0:
        t = Table(
            title=f"[bold bright_red] ● PLAINTEXT PASSWORDS — {cred_store.plaintext_count()} EXTRACTED [/]",
            box=box.HEAVY_EDGE, border_style="bright_red", header_style="bold",
            title_justify="left", show_lines=True, pad_edge=True)
        t.add_column("#", justify="right", style="grey50", width=4)
        t.add_column("PASSWORD", style="bold bright_white", min_width=20)
        t.add_column("STRENGTH", width=18)
        t.add_column("SOURCE", style="bright_cyan", min_width=18)
        t.add_column("USERNAME", style="bright_yellow", min_width=12)

        for i, c in enumerate(cred_store.credentials, 1):
            pwd = c.get("password", "")
            if show_passwords:
                display_pwd = pwd
            else:
                display_pwd = pwd[:4] + "•" * max(0, len(pwd) - 8) + pwd[-4:] if len(pwd) > 8 else "••••••••"

            strength = c.get("strength", {})
            s_color = strength.get("color", "grey50")
            s_label = strength.get("label", "N/A")
            s_details = ", ".join(strength.get("details", [])[:3])

            strength_display = f"[{s_color}]{s_label}[/]\n[grey50]{s_details}[/]"

            t.add_row(
                str(i),
                f"[bold bright_red]{display_pwd}[/]",
                strength_display,
                c.get("source", "?"),
                c.get("username", "") or c.get("email", "")[:20])
        console.print(t)
    else:
        console.print(Panel(
            "  [grey50]No plaintext passwords extracted.[/]",
            title="[bold grey50] ● PLAINTEXT PASSWORDS [/]",
            border_style="grey50", box=box.SIMPLE, padding=(0, 1)))

    if cred_store.hash_count() > 0:
        t2 = Table(
            title=f"[bold bright_yellow] ● IDENTIFIED HASHES — {cred_store.hash_count()} FOUND [/]",
            box=box.HEAVY_EDGE, border_style="bright_yellow", header_style="bold",
            title_justify="left", show_lines=True, pad_edge=True)
        t2.add_column("#", justify="right", style="grey50", width=4)
        t2.add_column("HASH VALUE", style="bright_white", min_width=20)
        t2.add_column("HASH TYPE", style="bold bright_red", width=22)
        t2.add_column("SOURCE", style="bright_cyan", min_width=18)
        t2.add_column("USERNAME", style="bright_yellow", min_width=12)

        for i, c in enumerate(cred_store.hashes, 1):
            pwd = c.get("password", "")
            if show_passwords:
                display_hash = pwd[:32] + "..." if len(pwd) > 35 else pwd
            else:
                display_hash = pwd[:8] + "..." + pwd[-4:] if len(pwd) > 15 else "••••••••"

            t2.add_row(
                str(i),
                f"[bright_white]{display_hash}[/]",
                f"[bold bright_red]{c.get('hash_label', 'Unknown')}[/]",
                c.get("source", "?"),
                c.get("username", "") or c.get("email", "")[:20])
        console.print(t2)

    total = cred_store.total()
    pt = cred_store.plaintext_count()
    ht = cred_store.hash_count()
    console.print(Panel(
        f"  [bold bright_red]TOTAL EXTRACTED[/]    [bold bright_white]{total}[/] credentials/secrets\n"
        f"  [bold bright_red]PLAINTEXT[/]          [bold bright_red]{pt}[/] passwords  •  "
        f"[bold bright_yellow]{ht}[/] hashes identified\n"
        f"  [bold bright_red]DISPLAY MODE[/]       {'[bold bright_green]FULL REVEAL[/]' if show_passwords else '[grey50]MASKED (use --show-passwords)[/]'}",
        title="[bold] 📊  CREDENTIAL SUMMARY [/]",
        border_style="bright_red", box=box.HEAVY, padding=(0, 1)))
    console.print()

def render(email, results, consensus, risk, keys, cred_store=None, show_passwords=False):
    console.print()
    n_keys = len([k for k, v in keys.items() if v])
    band_color = {"CRITICAL": "red", "HIGH": "bright_red",
                  "MEDIUM": "bright_yellow", "LOW": "bright_green"}.get(
                      risk["band"], "white")

    # HEADER PANEL
    console.print(Panel(
        f"  [bold bright_magenta]HOJKER «BLACKOUT X» v8.0 — INTELLIGENCE DASHBOARD[/]\n"
        f"  [bold bright_white]{email}[/]\n"
        f"  [grey50]25+ platforms · breaches · dumps/pastes · dark web · infra · identity · credentials[/]",
        border_style="bright_magenta", box=box.DOUBLE, padding=(0, 1)))

    reg = results.get("REGISTRATIONS") or {}
    br = results.get("BREACH CORPUS") or {}
    dp = results.get("DUMPS & PASTES") or {}
    dw = results.get("DARK WEB") or {}
    hr = results.get("INFOSTEALER LOGS") or {}
    n_reg = len(reg.get("accounts") or [])
    n_br = br.get("total_breaches", 0)
    n_dp = dp.get("total_hits", 0)
    n_dw = len(dw.get("darkweb_emails") or []) + len(dw.get("hits") or [])
    n_inf = "✔" if hr.get("infostealer_infection") else "—"
    n_cred = cred_store.total() if cred_store else 0

    # KPI SCORECARD
    kpi_body = (
        "  " + _stat_box("REGISTRATIONS", n_reg, "bright_white") + "  │"
        + _stat_box("BREACHES", n_br, "red" if n_br else "grey50") + "  │"
        + _stat_box("PASTES/DUMPS", n_dp, "bright_yellow" if n_dp else "grey50") + "  │"
        + _stat_box("DARK-WEB", n_dw, "bright_red" if n_dw else "grey50") + "  │"
        + _stat_box("INFOSTEALER", n_inf, "red" if hr.get("infostealer_infection") else "grey50") + "  │"
        + _stat_box("CREDENTIALS", n_cred, "bright_red" if n_cred else "grey50")
    )

    risk_bar = _gradient_bar(risk["score"])
    kpi = Panel(
        kpi_body +
        f"\n\n  [bold grey50]RISK SCORE[/]  {risk_bar}  [bold {band_color}]{risk['score']:3d}/100[/]",
        title=f"[bold {band_color}] ⚠  EXPOSURE SCORECARD [/]",
        border_style=band_color, box=box.HEAVY, padding=(0, 1))

    # DEFENDER'S BRIEF
    brief_lines = [
        f"  [bold]RISK LEVEL[/]   [bold {band_color}]{risk['band']} — {risk['score']}/100[/]",
        f"  [bold]DRIVERS[/]      {'; '.join(risk['drivers']) or 'none detected'}",
        f"  [bold]ACTION[/]       " + (
            "[bold red]CONTAIN NOW — rotate credentials, kill sessions, enforce hardware MFA.[/]"
            if risk["band"] == "CRITICAL" else
            "[bright_yellow]Reset passwords + enforce MFA on all exposed services.[/]"
            if risk["band"] in ("HIGH", "MEDIUM") else
            "[bright_green]Standard monitoring. No immediate action required.[/]")
    ]
    if n_cred > 0:
        brief_lines.append(f"  [bold bright_red]⚠ CREDENTIALS EXPOSED — {n_cred} secrets found in breaches[/]")
    brief = Panel("\n".join(brief_lines),
        title="[bold] 🛡  DEFENDER'S BRIEF [/]",
        border_style=band_color, box=box.ROUNDED, padding=(0, 1))

    # NAME CONSENSUS
    cons = Panel(
        ("[bright_green bold]CONFIRMED[/]  " + (", ".join(consensus["confirmed"]) or "—") + "\n"
         "[bright_yellow bold]PROBABLE [/]  " + (", ".join(consensus["probable"]) or "—") + "\n"
         "[grey50]POSSIBLE  [/]  " + (", ".join(consensus["possible"]) or "—")),
        title="[bold] 👤  NAME CONSENSUS [/]", border_style="bright_blue",
        box=box.ROUNDED, padding=(0, 1))

    console.print(kpi)
    console.print(Columns([brief, cons], equal=True, expand=True))

    # REGISTRATIONS
    accounts = reg.get("accounts") or []
    if accounts:
        cat_icon = {"social": "💬", "adult": "🔴", "media": "🎧", "creator": "🎬",
                    "developer": "⌨ ", "identity": "🪪", "cloud": "☁ ",
                    "education": "🎓", "gaming": "🎮", "intel": "🔎"}
        lines = [f"  [grey50]HIGH = email-proven · MEDIUM = username match · "
                 f"{len(reg.get('username_variants') or [])} variants derived[/]", ""]
        for i, a in enumerate(accounts, 1):
            conf = a.get("confidence", "?")
            cc = ("bright_green" if conf.startswith("HIGH") else
                  "bright_yellow" if conf.startswith("MEDIUM") else "grey50")
            icon = cat_icon.get(a.get("category"), "▪")
            det = a.get("profile") or a.get("detail") or ""
            if len(det) > 70:
                det = det[:67] + "..."
            lines.append(
                f"  [bold bright_cyan]{i:>2}.[/] {icon} [bold bright_white]"
                f"{a.get('platform', a.get('service', '?')):<18}[/]"
                f" [grey50]\\[{a.get('category', '?')}][/] [{cc}]{conf}[/]\n"
                f"       [grey50]↳[/] {det}")
        console.print(Panel("\n".join(lines),
            title=f"[bold bright_magenta] ◉ REGISTRATIONS — {len(accounts)} "
                  f"PLATFORMS FOUND [/]",
            border_style="bright_magenta", box=box.DOUBLE, padding=(0, 1)))

    # DUMPS & PASTES
    if dp.get("total_hits"):
        lines = [f"  [grey50]corpora: {', '.join(dp.get('sources') or ['psbdmp.ws'])}"
                 f" · password-field mentions: {dp.get('password_mentions', 0)}[/]", ""]
        n = 0
        for h in (dp.get("paste_hits") or []):
            n += 1
            flag = (" [bold red]⚠ password field nearby[/]"
                    if h.get("password_field_nearby") else "")
            lines.append(f"  [bold bright_cyan]{n:>2}.[/] [bold]PASTE[/] "
                         f"{h.get('paste_id')} [grey50]{h.get('url', '')}[/]{flag}")
        for dref in (dp.get("dump_references") or []):
            n += 1
            lines.append(f"  [bold bright_cyan]{n:>2}.[/] [bold]DUMP RECORD[/] "
                         f"[grey50]{json.dumps(dref)[:120]}[/]")
        console.print(Panel("\n".join(lines),
            title=f"[bold bright_red] ◉ DUMPS & PASTES — {n} EXPOSURE REFERENCES [/]",
            border_style="bright_red", box=box.DOUBLE, padding=(0, 1)))

    # MODULE PANELS
    sev = {"INFOSTEALER LOGS": "bright_red", "BREACH CORPUS": "bright_red",
           "BREACH DEEP": "bright_red", "BREACH DIRECTORY": "bright_red",
           "DARK WEB": "bright_red",
           "SHODAN": "bright_red", "REPUTATION": "bright_yellow",
           "SMTP VERIFY": "bright_green", "GITHUB": "bright_cyan",
           "GRAVATAR": "bright_cyan", "KEYBASE": "bright_cyan",
           "PGP KEYS": "bright_cyan", "DNS / MAIL": "bright_blue",
           "WHOIS": "bright_blue", "WAYBACK MACHINE": "bright_blue",
           "SUBDOMAINS": "bright_blue", "SECURITY.TXT": "bright_blue",
           "PACKAGE ECOSYSTEMS": "bright_cyan", "GOOGLE DORK": "bright_yellow",
           "RAPIDAPI SOCIAL": "bright_magenta", "ONLYFANS": "bright_magenta"}
    for mod, data in results.items():
        if mod in ("REGISTRATIONS", "DUMPS & PASTES"):
            continue
        body = "\n".join(_kv_line(k, v) for k, v in data.items())
        color = sev.get(mod, "white")
        console.print(Panel(body or f"  [grey50]no data[/]",
                            title=f"[bold {color}] {mod} [/]",
                            border_style=color, box=box.SQUARE, padding=(0, 1)))

    # BREACH TABLE
    if br.get("breaches"):
        t = Table(title=f"[bold bright_red] 💀  BREACH CORPUS — "
                        f"{br.get('total_breaches', '?')} INCIDENTS [/]",
                  box=box.DOUBLE, border_style="bright_red", header_style="bold",
                  title_justify="left")
        t.add_column("#", justify="right", style="grey50", width=4)
        t.add_column("Incident", style="bold bright_white")
        t.add_column("Source", style="bright_cyan")
        t.add_column("Data exposed", style="bright_yellow")
        dc = br.get("data_classes") or []
        for i, b in enumerate(br["breaches"][:40], 1):
            src = (br.get("corpora") or ["corpus"])
            t.add_row(str(i), str(b), ", ".join(src),
                      ", ".join(dc[:6]) if i == 1 else "")
        console.print(t)

    # CREDENTIAL PANEL
    render_credential_panel(cred_store, show_passwords)

    # BREACH TIMELINE
    breach_meta = []
    for mod_name in ("BREACH CORPUS", "BREACH DEEP"):
        mod_data = results.get(mod_name) or {}
        for m in mod_data.get("metadata") or []:
            if isinstance(m, dict) and m.get("breach_date"):
                breach_meta.append(m)
    if breach_meta:
        breach_meta.sort(key=lambda x: x.get("breach_date", ""), reverse=True)
        lines = []
        for bm in breach_meta[:12]:
            date = bm.get("breach_date", "?")
            name = bm.get("breach", "?")
            count = bm.get("pwn_count")
            count_str = f" · {count:,} accounts" if count else ""
            lines.append(f"  [grey50]│[/] [bright_white]{date}[/]  [bold bright_red]{name}[/]{count_str}")
        timeline_body = "\n".join(lines)
        console.print(Panel(
            f"  [grey50]timeline of known breach dates (newest first)[/]\n\n{timeline_body}",
            title="[bold] 📅  BREACH TIMELINE [/]",
            border_style="bright_red", box=box.ROUNDED, padding=(0, 1)))

    # EXECUTIVE SUMMARY
    total_hits = n_reg + n_br + n_dp + n_dw + int(bool(hr.get("infostealer_infection"))) + n_cred
    summary = Panel(
        f"  [bold]TOTAL SIGNALS[/]    [bright_white]{total_hits}[/] exposure indicators\n"
        f"  [bold]DOMAIN[/]           [grey50]{email.split('@')[1]}[/] · "
        f"{'[bold red]INFOSTEALER-CORRELATED[/]' if hr.get('infostealer_infection') else '[bright_green]no active stealer signal[/]'}\n"
        f"  [bold]DATA EXPOSED[/]     [grey50]{', '.join(br.get('data_classes') or []) or 'n/a'}[/]\n"
        f"  [bold]CREDENTIALS[/]      [bold bright_red]{n_cred}[/] extracted secrets · "
        f"{'[bold bright_red]PLAINTEXT PASSWORDS FOUND[/]' if (cred_store and cred_store.plaintext_count() > 0) else '[bright_green]none[/]'}\n"
        f"  [bold]VERDICT[/]          {risk['band']} exposure — see DEFENDER'S BRIEF above",
        title="[bold] 📋  EXECUTIVE SUMMARY [/]", border_style="bright_cyan",
        box=box.HEAVY, padding=(0, 1))
    console.print(summary)

    # JSON EXPORT
    path = f"report_{email.replace('@', '_at_')}.json"
    export_data = {
        "target": email,
        "risk": risk,
        "results": results,
        "generated": datetime.now(timezone.utc).isoformat(),
    }
    if cred_store:
        export_data["credentials"] = {
            "total": cred_store.total(),
            "plaintext_count": cred_store.plaintext_count(),
            "hash_count": cred_store.hash_count(),
            "credentials": [{"password": c["password"], "source": c["source"],
                              "username": c.get("username", "")}
                             for c in cred_store.credentials],
            "hashes": [{"hash": c["password"], "type": c.get("hash_label", "?"),
                         "source": c["source"], "username": c.get("username", "")}
                        for c in cred_store.hashes],
        }
    json.dump(export_data, open(path, "w"), indent=2, default=str)

    console.print(Rule(style="bright_magenta", characters="═"))
    console.print(Text(
        f"  ✔ Investigation complete  •  JSON report → {path}  •  "
        f"{cred_store.total() if cred_store else 0} credentials extracted",
        style="bold bright_green"))
    console.print()

# ══════════════════════════════════════════════════════════════════════════
#  ENGINE
# ══════════════════════════════════════════════════════════════════════════
CORE_MODULES = [
    ("INFOSTEALER LOGS", mod_hudsonrock),
    ("BREACH CORPUS",    mod_breaches),
    ("BREACH DEEP",      mod_breachdeep),
    ("BREACH DIRECTORY", mod_breachdirectory),
    ("REPUTATION",       mod_emailrep),
    ("SHODAN",           mod_shodan),
    ("GITHUB",           mod_github),
    ("KEYBASE",          mod_keybase),
    ("PGP KEYS",         mod_pgp),
    ("DNS / MAIL",       mod_dns),
    ("WAYBACK MACHINE",  mod_wayback),
    ("GRAVATAR",         mod_gravatar),
    ("SUBDOMAINS",       mod_subdomain),
    ("SECURITY.TXT",     mod_securitytxt),
    ("PACKAGE ECOSYSTEMS", mod_package),
    ("GOOGLE DORK",      mod_google_dork),
    ("RAPIDAPI SOCIAL",  mod_rapidapi_social),
    ("ONLYFANS",         mod_onlyfans),
]

def run_full(email, use_tor=True, quiet=False, show_passwords=False):
    global SHOW_PASSWORDS
    SHOW_PASSWORDS = show_passwords
    if not EMAIL_RE.match(email):
        console.print("  [bold bright_red]✘ invalid email address[/]")
        return
    keys = load_keys()
    s = make_session()
    cred_store = CredentialStore()

    if not quiet:
        game_loading(email)
    else:
        console.print(f"  [bold bright_magenta]▶ scanning {email} …[/]")

    tor_ok = ensure_tor(quiet=quiet) if use_tor else False

    results = {}
    total_tasks = len(CORE_MODULES) + 5
    with Progress(SpinnerColumn("dots12"),
                  TextColumn("[bold bright_white]{task.description}"),
                  BarColumn(bar_width=32, style="bright_magenta",
                            complete_style="bright_green"),
                  TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                  TimeElapsedColumn(), console=console, transient=True) as prog:
        t = prog.add_task("[bold bright_magenta]⬢ LOADING ALL MODULES — STANDBY", total=total_tasks)

        try:
            ok, d = mod_registrations(s, email, keys)
            d["◉ status"] = f"{d.get('total_found', 0)} platforms" if ok else "none found"
        except Exception as ex:
            d = {"◉ status": "error", "error": type(ex).__name__}
        results["REGISTRATIONS"] = d
        prog.advance(t)

        with cf.ThreadPoolExecutor(max_workers=8) as exf:
            futs = {}
            for name, fn in CORE_MODULES:
                if name in ("BREACH CORPUS", "BREACH DEEP", "BREACH DIRECTORY"):
                    futs[exf.submit(fn, s, email, keys, cred_store)] = name
                else:
                    futs[exf.submit(fn, s, email, keys)] = name
            for f in cf.as_completed(futs):
                name = futs[f]
                try:
                    ok, d = f.result()
                except Exception as exx:
                    ok, d = False, {"error": type(exx).__name__}
                d["◉ status"] = "HIT — findings found" if ok else "no findings / unreachable"
                results[name] = d
                prog.advance(t)

        try:
            ok, d = mod_dumps_pastes(s, email, keys, tor=tor_ok, cred_store=cred_store)
            d["◉ status"] = f"{d.get('total_hits', 0)} exposure references" if ok else "no exposure found"
        except Exception as exx:
            d = {"◉ status": "error", "error": type(exx).__name__}
        results["DUMPS & PASTES"] = d
        prog.advance(t)

        try:
            ok, d = mod_darkweb(make_session(tor=tor_ok, timeout=30), email, keys,
                                tor=tor_ok, quiet=quiet)
            d["◉ status"] = "HIT — dark-web exposure" if ok else "no findings" + \
                            ("" if tor_ok else " [Tor unavailable]")
        except Exception as exx:
            d = {"◉ status": "error", "error": type(exx).__name__}
        results["DARK WEB"] = d
        prog.advance(t)

        for name, fn in [("SMTP VERIFY", lambda: mod_verify_smtp(s, email, keys)),
                         ("WHOIS", lambda: mod_whois(s, email, keys))]:
            try:
                ok, d = fn()
            except Exception as exx:
                ok, d = False, {"error": type(exx).__name__}
            d["◉ status"] = "HIT — findings found" if ok else "no findings / unreachable"
            results[name] = d
            prog.advance(t)

        prog.update(t, description="[bold bright_green]✔ ALL MODULES LOADED", completed=total_tasks)

    render(email, results, name_consensus(results), risk_score(results), keys,
           cred_store, show_passwords)
    return results

# ══════════════════════════════════════════════════════════════════════════
#  MENU
# ══════════════════════════════════════════════════════════════════════════
def menu():
    frame_banner()
    while True:
        console.print(Panel(
            "  [bold bright_magenta]1[/]) [bold]FULL BLACKOUT X SWEEP[/] — everything, auto-Tor\n"
            "  [bold bright_magenta]2[/])  Registrations only — social · adult · all platforms\n"
            "  [bold bright_magenta]3[/])  Breach + dumps/pastes + dark-web sweep (auto-Tor)\n"
            "  [bold bright_magenta]4[/])  SMTP / mailbox verification\n"
            "  [bold bright_magenta]5[/])  [bold bright_red]FULL SWEEP + SHOW PASSWORDS[/] — reveal all secrets\n"
            "  [bold bright_cyan]k[/])  API key vault (Shodan · HIBP · IntelX · Hunter · more)\n"
            "  [bold]q[/])  Quit",
            title="[bold bright_magenta] ⬢  MAIN MENU [/]",
            border_style="bright_magenta", box=box.DOUBLE, padding=(0, 1)))
        ch = console.input("  [bold bright_magenta]hojker blackout ›[/] ").strip().lower()
        if ch == "q":
            console.print(Align.center(Text("  blackout complete. o7",
                                            style="bold bright_magenta")))
            return
        if ch == "k":
            key_menu()
            continue
        email = console.input("  [bold bright_cyan]target email ›[/] ").strip()
        if not email:
            continue
        keys = load_keys()
        if ch == "1":
            run_full(email, use_tor=True)
        elif ch == "2":
            try:
                ok, d = mod_registrations(make_session(), email, keys)
            except Exception as ex:
                d = {"error": type(ex).__name__}
            d["◉ status"] = f"{d.get('total_found', 0)} platforms" if ok else "none found"
            render(email, {"REGISTRATIONS": d}, name_consensus({}),
                   risk_score({}), keys)
        elif ch == "3":
            tor_ok = ensure_tor()
            out = {}
            cs = CredentialStore()
            for nm, fn in [
                ("BREACH CORPUS", lambda: mod_breaches(make_session(), email, keys, cs)),
                ("BREACH DEEP", lambda: mod_breachdeep(make_session(), email, keys, cs)),
                ("BREACH EXT", lambda: mod_dumps_pastes(make_session(), email, keys, cred_store=cs)),
                ("DARK WEB", lambda: mod_darkweb(make_session(tor=tor_ok, timeout=30),
                                                 email, keys, tor=tor_ok))]:
                try:
                    ok, d = fn()
                except Exception as ex:
                    ok, d = False, {"error": type(ex).__name__}
                d["◉ status"] = "HIT" if ok else "no findings"
                out[nm] = d
            render(email, out, name_consensus({}), risk_score(out), keys, cs)
        elif ch == "4":
            try:
                ok, d = mod_verify_smtp(make_session(), email, keys)
            except Exception as ex:
                ok, d = False, {"error": type(ex).__name__}
            d["◉ status"] = "verified" if ok else "no MX"
            render(email, {"SMTP VERIFY": d}, name_consensus({}),
                   risk_score({}), keys)
        elif ch == "5":
            run_full(email, use_tor=True, show_passwords=True)

if __name__ == "__main__":
    ap = argparse.ArgumentParser(
        description="HojkerMailScraper v8.0 «BLACKOUT X» — all-source email OSINT + credential extraction")
    ap.add_argument("email", nargs="?")
    ap.add_argument("--no-tor", action="store_true",
                    help="skip Tor / dark-web phase")
    ap.add_argument("--quiet", action="store_true",
                    help="skip cinematic loading")
    ap.add_argument("--show-passwords", action="store_true",
                    help="reveal plaintext passwords and full hash values (CAUTION)")
    ap.add_argument("--keys", action="store_true", help="open API key vault")
    a = ap.parse_args()
    if a.keys:
        frame_banner()
        key_menu()
    elif a.email:
        frame_banner()
        run_full(a.email, use_tor=not a.no_tor, quiet=a.quiet,
                 show_passwords=a.show_passwords)
    else:
        menu()

