import asyncio
import base64
import json
import re
import shutil
import time
from collections import defaultdict
from pathlib import Path

import aiohttp
from bs4 import BeautifulSoup

ROOT = Path(__file__).resolve().parent.parent
COUNTRY_DIR = ROOT / "country"
DATA_DIR = ROOT / "data"
DEAD_FILE = DATA_DIR / "dead_proxies.json"

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"}

ADDRESS_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3}:\d{1,5})")
_TEXT_PROTOCOLS = ("HTTP", "HTTPS", "SOCKS4", "SOCKS5")
CONCURRENCY = 150
TIMEOUT = 15
DATA_DIR.mkdir(parents=True, exist_ok=True)

try:
    from aiohttp_socks import ProxyConnector
    HAS_SOCKS = True
except ImportError:
    HAS_SOCKS = False
    ProxyConnector = None


def load_dead_set():
    if DEAD_FILE.exists():
        try:
            return set(json.loads(DEAD_FILE.read_text(encoding="utf-8")).get("dead", []))
        except Exception:
            return set()
    return set()


def save_dead_set(dead_set):
    DEAD_FILE.write_text(json.dumps({"dead": sorted(dead_set), "updated": time.time(), "count": len(dead_set)}, indent=2), encoding="utf-8")


async def test_proxy(address, protocol, semaphore):
    async with semaphore:
        for attempt in range(2):
            try:
                timeout = aiohttp.ClientTimeout(total=TIMEOUT)
                proto = protocol.upper()
                # Try httpbin first, fallback to ip-api for leniency
                test_urls = ["http://httpbin.org/ip", "http://ip-api.com/json"]
                for test_url in test_urls:
                    try:
                        if proto in ("SOCKS4", "SOCKS5") and HAS_SOCKS:
                            connector = ProxyConnector.from_url(f"{proto.lower()}://{address}")
                            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as s:
                                async with s.get(test_url, timeout=timeout) as resp:
                                    if resp.status == 200:
                                        return True
                        else:
                            scheme = "http" if proto in ("HTTP", "HTTPS") else proto.lower()
                            proxy_url = f"{scheme}://{address}"
                            async with aiohttp.ClientSession(timeout=timeout) as s:
                                async with s.get(test_url, proxy=proxy_url, timeout=timeout) as resp:
                                    if resp.status == 200:
                                        return True
                    except Exception:
                        continue
            except Exception:
                pass
            await asyncio.sleep(0.2 * (attempt + 1))
    return False


def load_existing_working():
    """Load previous working proxies from country/*/*.txt with their protocol/country"""
    existing = []
    if not COUNTRY_DIR.exists():
        return existing
    for cc_dir in COUNTRY_DIR.iterdir():
        if not cc_dir.is_dir():
            continue
        cc = cc_dir.name.upper()
        for proto_file in cc_dir.iterdir():
            if not proto_file.is_file():
                continue
            proto = proto_file.stem.upper()
            if proto not in _TEXT_PROTOCOLS:
                continue
            try:
                for line in proto_file.read_text(encoding="utf-8").splitlines():
                    m = ADDRESS_RE.search(line)
                    if m:
                        existing.append({"address": m.group(1), "protocol": proto, "country": cc})
            except Exception:
                continue
    return existing


def _normalize_protocol(value):
    value = str(value or "").strip().upper().replace("-", "").replace(" ", "")
    if value in ("SOCKS4|SOCKS5", "SOCKS5|SOCKS4"):
        return "SOCKS5"
    if value in _TEXT_PROTOCOLS:
        return value
    if value.startswith("HTTPS"):
        return "HTTPS"
    if value.startswith("SOCKS5"):
        return "SOCKS5"
    if value.startswith("SOCKS4"):
        return "SOCKS4"
    return "HTTP"


async def fetch(session, url, timeout=60):
    try:
        async with session.get(url, headers=UA, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
            if resp.status != 200:
                return ""
            return await resp.text()
    except Exception:
        return ""


# ---------------- Geonode JSON API ----------------

async def scrape_geonode(session):
    rows = []
    page = 1
    while page <= 10:
        url = (
            "https://proxylist.geonode.com/api/proxy-list?limit=500&page={}"
            "&sort_by=lastChecked&sort_type=desc".format(page)
        )
        try:
            data = json.loads(await fetch(session, url))
        except Exception:
            break
        items = data.get("data") or []
        if not items:
            break
        for r in items:
            ip, port = r.get("ip"), r.get("port")
            if not ip or not port:
                continue
            protos = r.get("protocols") or [r.get("protocol") or "http"]
            for p in protos:
                rows.append({"address": "{}:{}".format(ip, port), "protocol": _normalize_protocol(p), "country": ""})
        total = int(data.get("total") or 0)
        if page * 500 >= total:
            break
        page += 1
    return rows


# ---------------- ProxyScrape API (plain text per protocol) ----------------

async def scrape_proxyscrape(session):
    rows = []
    for proto in ("http", "https", "socks4", "socks5"):
        url = (
            "https://api.proxyscrape.com/v2/?request=displayproxies&protocol={}"
            "&timeout=15000&country=all&ssl=all&anonymity=all".format(proto)
        )
        text = await fetch(session, url)
        for line in text.splitlines():
            m = ADDRESS_RE.search(line)
            if m:
                rows.append({"address": m.group(1), "protocol": proto.upper(), "country": ""})
    return rows


# ---------------- free-proxy-list.net / sslproxies.org HTML table ----------------
# cols: IP | Port | Code | Country | Anonymity | Google | Https | Last Checked

def parse_fpl_table(html, default_protocol):
    rows = []
    soup = BeautifulSoup(html, "html.parser")
    table = soup.find("table")
    tbody = table.find("tbody") if table else None
    if not tbody:
        return rows
    for tr in tbody.find_all("tr"):
        tds = [td.get_text(strip=True) for td in tr.find_all("td")]
        if len(tds) < 7:
            continue
        ip, port, code = tds[0], tds[1], tds[2]
        if not re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", ip):
            continue
        https_flag = tds[6].strip().lower()
        proto = "HTTPS" if (default_protocol == "HTTPS" or https_flag == "yes") else "HTTP"
        rows.append({"address": "{}:{}".format(ip, port), "protocol": proto, "country": code.upper()})
    return rows


async def scrape_fpl_sources(session):
    out = []
    out.extend(parse_fpl_table(await fetch(session, "https://free-proxy-list.net/"), "HTTP"))
    out.extend(parse_fpl_table(await fetch(session, "https://sslproxies.org/"), "HTTPS"))
    return out


# ---------------- hidemy.name HTML table ----------------
# cols: IP | Port | Country(flag-icon-xx) | Speed | Type | Anonymity | Last

def parse_hidemy_table(html):
    rows = []
    soup = BeautifulSoup(html, "html.parser")
    table = soup.find("table")
    tbody = table.find("tbody") if table else None
    if not tbody:
        return rows
    for tr in tbody.find_all("tr"):
        tds = tr.find_all("td")
        if len(tds) < 5:
            continue
        ip = tds[0].get_text(strip=True)
        port = tds[1].get_text(strip=True)
        if not re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", ip):
            continue
        code = ""
        el = tds[2].find(class_=re.compile(r"flag-icon-[a-z]{2}"))
        if el:
            m = re.search(r"flag-icon-([a-z]{2})", " ".join(el.get("class", [])))
            if m:
                code = m.group(1).upper()
        proto = _normalize_protocol(tds[4].get_text(strip=True))
        rows.append({"address": "{}:{}".format(ip, port), "protocol": proto, "country": code})
    return rows


async def scrape_hidemy(session):
    out = []
    urls = ["https://hidemy.name/en/proxy-list/"]
    urls += ["https://hidemy.name/en/proxy-list/?start={}".format(n) for n in (64, 128, 192, 256)]
    for url in urls:
        html = await fetch(session, url)
        if not html:
            break
        found = parse_hidemy_table(html)
        out.extend(found)
        if not found:
            break
    return out


# ---------------- proxydb.net HTML table ----------------
# cols: IP(link) | Port(hidden div + link) | Type | Country(abbr ISO) | Anonymity ...

def parse_proxydb_table(html):
    rows = []
    soup = BeautifulSoup(html, "html.parser")
    table = soup.find("table")
    tbody = table.find("tbody") if table else None
    if not tbody:
        return rows
    for tr in tbody.find_all("tr"):
        tds = tr.find_all("td")
        if len(tds) < 4:
            continue
        ip = tds[0].get_text(strip=True)
        port = tds[1].get_text(strip=True)
        if not re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", ip):
            continue
        abbr = tds[3].find("abbr")
        code = abbr.get_text(strip=True).upper() if abbr else ""
        proto = _normalize_protocol(tds[2].get_text(strip=True))
        rows.append({"address": "{}:{}".format(ip, port), "protocol": proto, "country": code[:2]})
    return rows


async def scrape_proxydb(session):
    out = []
    for proto in ("http", "https", "socks4", "socks5"):
        for page in (1, 2, 3):
            url = "https://proxydb.net/?protocol={}&page={}".format(proto, page)
            html = await fetch(session, url)
            if not html:
                break
            found = parse_proxydb_table(html)
            out.extend(found)
            if len(found) < 10:
                break
    return out


# ---------------- spys.one (JS-obfuscated ports) ----------------
# port expression: document.write("<font ...>:<\/font>"+(v1^v2)+(v3^v4)...)</script>
# variables defined inline as name=digits;

SPYS_ROW_RE = re.compile(
    r"(\d{1,3}(?:\.\d{1,3}){3})[\s\S]{0,120}?"
    r'document\.write\("<font[^>]*>:<\\/font>"\+\((.+?)\)\)</script>'
)


def decode_spys_ports(html):
    ints = dict((m.group(1), int(m.group(2))) for m in re.finditer(r"([a-z0-9]+)=(\d+);", html))
    digits = {}
    for m in re.finditer(r"([a-z0-9]+)='(\d)\^[a-z0-9]+';", html):
        digits[m.group(1)] = int(m.group(2))

    def val(name):
        if name in ints:
            return ints[name]
        if name in digits:
            return digits[name]
        return 0

    results = []
    for m in SPYS_ROW_RE.finditer(html):
        ip = m.group(1)
        try:
            total = 0
            for term in ("(" + m.group(2) + ")").split("+"):
                xv = 0
                for part in term.strip().strip("()").split("^"):
                    part = part.strip()
                    if part:
                        xv ^= val(part)
                total += xv
            port = str(total)
        except Exception:
            port = ""
        if port.isdigit():
            results.append((ip, port))
    return results


# ---------------- proxynova.com (base64+chr obfuscated IPs) ----------------
IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
NOVA_SCRIPT_RE = re.compile(r"document\.write\((atob\(.*?)\)\s*</script>", re.S)
NOVA_MAP_RE = re.compile(
    r'\[\s*([\d,\s]+?)\s*\]\s*\.\s*map\(\s*\(code\)\s*=>\s*String\.fromCharCode\(code\s*-\s*(\d+)\)\s*\)\s*\.\s*join\(""\)'
)


class _NovaParser:
    def __init__(self, expr):
        self.s = expr
        self.i = 0

    def _ws(self):
        while self.i < len(self.s) and self.s[self.i] in " \n\t":
            self.i += 1

    def _term(self):
        self._ws()
        if self.s.startswith("atob(", self.i):
            j = self.s.index('"', self.i) + 1
            k = self.s.index('"', j)
            val = base64.b64decode(self.s[j:k]).decode("latin-1")
            self.i = self.s.index(")", k) + 1
            return val
        if self.s[self.i] == "[":
            j = self.s.index("]", self.i)
            nums = [int(x.strip()) for x in self.s[self.i + 1 : j].split(",") if x.strip()]
            mm = NOVA_MAP_RE.match(self.s, self.i)
            if not mm:
                raise ValueError("no map")
            off = int(mm.group(2))
            self.i = mm.end()
            return "".join(chr(n - off) for n in nums)
        if self.s[self.i] == '"':
            j = self.s.index('"', self.i + 1)
            val = self.s[self.i + 1 : j]
            self.i = j + 1
            return val
        raise ValueError("atom? " + self.s[self.i : self.i + 30])

    def _arith(self):
        mm = re.compile(r"\s*([\d\s+\-]+?)\s*(?=[,)])").match(self.s, self.i)
        if not mm:
            raise ValueError("arith?")
        self.i = mm.end()
        return eval(mm.group(1))

    def parse(self):
        val = self._term()
        while True:
            self._ws()
            if self.s.startswith(".concat(", self.i):
                self.i += 8
                val += self.parse()
                self._ws()
                if self.i < len(self.s) and self.s[self.i] == ")":
                    self.i += 1
            elif self.s.startswith(".substring(", self.i):
                self.i += 11
                a = self._arith()
                self.i += 1
                b = self._arith()
                self.i += 1
                val = val[int(a) : int(b)]
            else:
                break
        return val


def decode_nova_ips(html):
    ips = []
    for m in NOVA_SCRIPT_RE.finditer(html):
        expr = m.group(1)
        try:
            ip = _NovaParser(expr).parse()
        except Exception:
            continue
        if IPV4_RE.match(ip):
            ips.append(ip)
    return ips


async def scrape_proxynova(session):
    rows = []
    seen = set()

    def add_rows(html, default_port):
        chunks = html.split('<tr data-proxy-id=')[1:]
        count = 0
        for chunk in chunks:
            end = chunk.find("</tr>")
            block = chunk[: end if end > 0 else len(chunk)]
            ips = decode_nova_ips(block)
            if not ips:
                continue
            pm = re.search(r'href="/proxy-server-list/port-(\d+)/"', block)
            prt = pm.group(1) if pm else default_port
            for ip in ips:
                addr = "{}:{}".format(ip, prt)
                if addr not in seen:
                    seen.add(addr)
                    rows.append({"address": addr, "protocol": "HTTP", "country": ""})
                    count += 1
        return count

    for port in ("80", "8080", "3128", "8000", "8888"):
        html = await fetch(session, "https://www.proxynova.com/proxy-server-list/port-{}/".format(port))
        add_rows(html, port)

    idx = await fetch(session, "https://www.proxynova.com/proxy-server-list/")
    country_codes = sorted(set(re.findall(r"proxy-server-list/country-([a-z]{2})/", idx)))
    for cc in country_codes:
        html = await fetch(session, "https://www.proxynova.com/proxy-server-list/country-{}/".format(cc))
        if html:
            add_rows(html, "")
    return rows


# ---------------- geolocation (ip-api batch, verifies every IP) ----------------

async def geolocate_batch(session, ips):
    result = {}
    batches = [ips[i : i + 100] for i in range(0, len(ips), 100)]
    for batch in batches:
        for attempt in range(5):
            status, data = 0, None
            try:
                async with session.post(
                    "http://ip-api.com/batch",
                    json=batch,
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp:
                    status = resp.status
                    if status == 200:
                        data = await resp.json()
            except Exception:
                pass
            if isinstance(data, list):
                for entry in data:
                    if isinstance(entry, dict) and entry.get("status") == "success":
                        result[entry["query"]] = entry.get("countryCode", "").upper()
                break
            await asyncio.sleep(min(15, 3 * (attempt + 1)))
        await asyncio.sleep(1.5)
    return result


async def scrape_dinoz0rg_checked(session):
    rows = []
    base = "https://raw.githubusercontent.com/dinoz0rg/proxy-list/main/checked_proxies"
    for proto, url in (
        ("http.txt", "HTTP"),
        ("socks4.txt", "SOCKS4"),
        ("socks5.txt", "SOCKS5"),
    ):
        txt = await fetch(session, "{}/{}".format(base, proto))
        for line in txt.splitlines():
            m = ADDRESS_RE.search(line)
            if m:
                rows.append({"address": m.group(1), "protocol": url, "country": ""})
    return rows


async def scrape_noctiro(session):
    rows = []
    base = "https://raw.githubusercontent.com/noctiro/getproxy/refs/heads/master/file"
    for proto, url in (
        ("http.txt", "HTTP"),
        ("https.txt", "HTTPS"),
        ("socks4.txt", "SOCKS4"),
        ("socks5.txt", "SOCKS5"),
    ):
        txt = await fetch(session, "{}/{}".format(base, proto))
        for line in txt.splitlines():
            m = ADDRESS_RE.search(line)
            if m:
                rows.append({"address": m.group(1), "protocol": url, "country": ""})
    return rows


async def scrape_dpangestuw(session):
    rows = []
    base = "https://raw.githubusercontent.com/dpangestuw/Free-Proxy/refs/heads/main"
    for proto, url in (
        ("http_proxies.txt", "HTTP"),
        ("socks4_proxies.txt", "SOCKS4"),
        ("socks5_proxies.txt", "SOCKS5"),
    ):
        txt = await fetch(session, "{}/{}".format(base, proto))
        for line in txt.splitlines():
            m = ADDRESS_RE.search(line)
            if m:
                rows.append({"address": m.group(1), "protocol": url, "country": ""})
    return rows


async def scrape_aliilapro(session):
    rows = []
    base = "https://raw.githubusercontent.com/ALIILAPRO/Proxy/main"
    for proto, url in (
        ("http.txt", "HTTP"),
        ("socks4.txt", "SOCKS4"),
        ("socks5.txt", "SOCKS5"),
    ):
        txt = await fetch(session, "{}/{}".format(base, proto))
        for line in txt.splitlines():
            m = ADDRESS_RE.search(line)
            if m:
                rows.append({"address": m.group(1), "protocol": url, "country": ""})
    return rows


SCRAPERS = (
    scrape_geonode,
    scrape_proxyscrape,
    scrape_fpl_sources,
    scrape_hidemy,
    scrape_proxydb,
    scrape_proxynova,
    scrape_dinoz0rg_checked,
    scrape_noctiro,
    scrape_dpangestuw,
    scrape_aliilapro,
)

SOURCE_NAMES = {
    scrape_geonode: "Geonode API",
    scrape_proxyscrape: "ProxyScrape API",
    scrape_fpl_sources: "FreeProxyLists + SSLProxies",
    scrape_hidemy: "Hidemy.name",
    scrape_proxydb: "ProxyDB",
    scrape_proxynova: "ProxyNova",
    scrape_dinoz0rg_checked: "Dinoz0rg Checked Proxies",
    scrape_noctiro: "noctiro/getproxy",
    scrape_dpangestuw: "dpangestuw Free-Proxy",
    scrape_aliilapro: "ALIILAPRO/Proxy",
}


async def main():
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
        # --- Persistent working: re-validate previous working before new scrape ---
        dead_set = load_dead_set()
        existing = load_existing_working()
        print(f"[Persistent] Loaded existing working: {len(existing)}, dead: {len(dead_set)}")
        still_working = []
        if existing:
            # filter existing that may have become dead since last run (dead list updated)
            existing_filtered = [p for p in existing if p["address"] not in dead_set]
            print(f"[Persistent] Existing after dead filter: {len(existing)} -> {len(existing_filtered)}")
            if existing_filtered:
                semaphore0 = asyncio.Semaphore(CONCURRENCY)
                tasks0 = [test_proxy(p["address"], p["protocol"], semaphore0) for p in existing_filtered]
                results0 = await asyncio.gather(*tasks0)
                still_working = [p for p, ok in zip(existing_filtered, results0) if ok]
                dead_existing = [p["address"] for p, ok in zip(existing_filtered, results0) if not ok]
                print(f"[Persistent] Still working: {len(still_working)}, Dead from old: {len(dead_existing)}")
                if dead_existing:
                    dead_set.update(dead_existing)
                    save_dead_set(dead_set)
            else:
                print("[Persistent] All existing already in dead list")
        else:
            print("[Persistent] No existing working to re-validate")

        per_source = {}
        tasks = [scrape(session) for scrape in SCRAPERS]
        results = await asyncio.gather(*tasks)
        all_proxies = []
        seen = set()
        for scrape, items in zip(SCRAPERS, results):
            count = 0
            for item in items:
                key = (item["address"], item["protocol"])
                if key not in seen:
                    seen.add(key)
                    all_proxies.append(item)
                    count += 1
            per_source[SOURCE_NAMES[scrape]] = count

        # --- Validate new scraped: dead + still_working dedup -> working_new ---
        initial = len(all_proxies)
        still_addrs = {p["address"] for p in still_working}
        filtered = [p for p in all_proxies if p["address"] not in dead_set and p["address"] not in still_addrs]
        print(f"[Validate] New after dead+still_working filter: {initial} -> {len(filtered)} (removed {initial - len(filtered)})")
        working_new = []
        dead_new = []
        if filtered:
            semaphore = asyncio.Semaphore(CONCURRENCY)
            tasks_v = [test_proxy(p["address"], p["protocol"], semaphore) for p in filtered]
            results_v = await asyncio.gather(*tasks_v)
            working_new = [p for p, ok in zip(filtered, results_v) if ok]
            dead_new = [p["address"] for p, ok in zip(filtered, results_v) if not ok]
            print(f"[Validate] New Working: {len(working_new)}, Dead new: {len(dead_new)}")
            if dead_new:
                dead_set.update(dead_new)
                save_dead_set(dead_set)
            print(f"[Validate] Dead list total: {len(dead_set)}")
        else:
            print("[Validate] No new proxies to validate")

        # Merge still working + new working (dedup already)
        all_proxies = still_working + working_new
        print(f"[Merge] Total working to keep: {len(all_proxies)} (still {len(still_working)} + new {len(working_new)})")

        if not all_proxies:
            print("[Validate] No working proxies, skipping geolocate and saving empty")
            if COUNTRY_DIR.exists():
                shutil.rmtree(COUNTRY_DIR)
            COUNTRY_DIR.mkdir(parents=True, exist_ok=True)
            summary = {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "sources": sorted(per_source),
                "per_source": dict(sorted(per_source.items(), key=lambda x: -x[1])),
                "total_scraped": initial,
                "dead_filtered": initial - len(filtered) if 'filtered' in locals() else 0,
                "validated": len(filtered) if 'filtered' in locals() else 0,
                "working": 0,
                "dead_new": len(dead_new) if 'dead_new' in locals() else 0,
                "dead_total": len(dead_set),
                "geolocated": 0,
                "stored_count": 0,
                "no_country_count": 0,
                "country_count": 0,
                "protocol_counts": {},
                "country_counts": {},
            }
            (ROOT / "last_run.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
            print(json.dumps(summary, indent=2))
            return

        # Only geolocate new working (still_working already has country)
        if working_new:
            ips_new = list({p["address"].rsplit(":", 1)[0] for p in working_new})
            country_map_new = await geolocate_batch(session, ips_new)
            for p in working_new:
                cc = country_map_new.get(p["address"].rsplit(":", 1)[0])
                if cc:
                    p["country"] = cc
            print(f"[Geolocate] New working geolocated: {len(country_map_new)} / {len(working_new)}")
            # still_working keeps its existing country as-is
        else:
            print("[Geolocate] No new working to geolocate, keeping still_working as-is")

        grouped = defaultdict(set)
        protocol_counts = defaultdict(int)
        no_country_count = 0
        for p in all_proxies:
            if not p["country"]:
                no_country_count += 1
                continue
            grouped[(p["country"], p["protocol"])].add(p["address"])
            protocol_counts[p["protocol"]] += 1

        if COUNTRY_DIR.exists():
            shutil.rmtree(COUNTRY_DIR)
        COUNTRY_DIR.mkdir(parents=True, exist_ok=True)

        country_counts = defaultdict(int)
        for (cc, proto), addrs in grouped.items():
            cc_dir = COUNTRY_DIR / cc
            cc_dir.mkdir(parents=True, exist_ok=True)
            (cc_dir / "{}.txt".format(proto.lower())).write_text(
                "\n".join(sorted(addrs)) + "\n", encoding="utf-8"
            )
            country_counts[cc] += len(addrs)

        summary = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "sources": sorted(per_source),
            "per_source": dict(sorted(per_source.items(), key=lambda x: -x[1])),
            "total_scraped": initial,
            "validated": len(filtered),
            "still_working": len(still_working),
            "working_new": len(working_new),
            "working": len(all_proxies),
            "dead_new": len(dead_new),
            "dead_total": len(dead_set),
            "geolocated": len(all_proxies) - no_country_count,
            "stored_count": sum(len(addrs) for addrs in grouped.values()),
            "no_country_count": no_country_count,
            "country_count": len(country_counts),
            "protocol_counts": dict(sorted(protocol_counts.items())),
            "country_counts": dict(sorted(country_counts.items(), key=lambda x: -x[1])),
        }
        (ROOT / "last_run.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
        print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
