# Angular HttpClient XSRF origin bypass

Small browser PoC for Angular `20.3.33`. The [CVE-2025-66035 patch](https://github.com/angular/angular/security/advisories/GHSA-58c5-g7wp-6w37) blocks protocol-relative URLs, but the v20 check still treats some cross-origin URLs as relative. If an attacker controls the start of a URL passed to `HttpClient.post()`, the request can expose `X-XSRF-TOKEN`.

The demo API returns five `href` values. The app posts to each one using `withFetch()`:

| Input | Attacker receives token? |
| --- | --- |
| `/api/echo` | Same-origin control: token stays with app |
| `//localhost:4301/collect` | No |
| `http://localhost:4301/collect` | No |
| `/\localhost:4301/collect` | **Yes** |
| leading space and tab before `//localhost:4301/collect` | **Yes** |

## Run

```powershell
npm ci
npm run poc
```

Requires Chrome or Edge. Set `$env:CHROME_PATH` if the browser is outside its default Windows path. The runner builds the app, starts both local servers, drives a real browser, and checks captured headers. `npm start` serves the manual demo at `http://127.0.0.1:4200`.

## Files

- `src/app/` — Angular request flow.
- `backend/server.mjs` — demo API at `127.0.0.1:4200` and attacker receiver at `localhost:4301`.
- `scripts/poc.mjs` — browser validation.

Both servers bind to loopback. The XSRF cookie is random test data; the attacker receiver gets the header, not the cookie.
