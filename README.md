# habibi

Free proxy aggregator — scrapes multiple public sources, verifies every proxy's country via ip-api.com, dedupes, and publishes per-country, per-protocol lists.

## Structure

```
country/
├── US/
│   ├── http.txt
│   ├── https.txt
│   ├── socks4.txt
│   └── socks5.txt
├── DE/
│   └── ...
└── ... (one folder per country)
```

- Each file contains plain `ip:port` lines, sorted.
- Updated automatically every 30 minutes via GitHub Actions.
- Stats in `last_run.json`.

## Usage

```bash
curl -O https://raw.githubusercontent.com/asifshaikhtsn/habibi/main/country/US/http.txt
```

Country list: https://api.github.com/repos/asifshaikhtsn/habibi/contents/country

## Sources

| Source | Method |
|---|---|
| Geonode | JSON API |
| ProxyScrape | API (plain text) |
| Free Proxy Lists / SSL Proxies | HTML table |
| Hidemy.name | HTML table |
| ProxyDB | HTML table |
| Spys.one | HTML + JS port deobfuscation |
| ProxyNova | HTML + base64/JS IP deobfuscation |

Paid services (ScraperAPI, Decodo, NetNut) are intentionally excluded.
