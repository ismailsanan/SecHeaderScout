<p align="center">
 <img width="1942" height="809" alt="SecHeaderScout logo" src="https://github.com/user-attachments/assets/2135b846-ad4f-4c29-aac1-16e249cda606" />
</p>

<p align="center">
   A Burp Suite extension that audits HTTP security headers against the OWASP Secure Headers Project:
   automatically through Burp's passive scanner, and on demand in its own tab.
</p>

---

## Overview

SecHeaderScout has two independent parts:

| | Passive scanner | Manual scanner (SecHeaderScout tab) |
|---|---|---|
| Trigger | Automatic, on traffic Burp passively scans | User clicks Quick Scan / Deep Scan |
| Output | Native **Burp issues** (Target → Issues, Dashboard) | Results table, HTML report, report-ready Markdown, comparison |
| Headers | The 8 headers Burp does **not** already cover (below) | All OWASP-recommended headers + CORS |
| Network | **Never** sends requests | Quick Scan: one GET per target (+1 plain-HTTP GET if HTTPS fails and fallback is on); Rescan: one GET per URL; Deep Scan: none |
| Edition | Burp Suite Professional / Enterprise | All editions |

## Features

- **Burp passive scan check** reporting `AuditIssue`s with name, detail, remediation, background, severity,
  confidence and the request/response as evidence (offending header lines highlighted).
- **Header-specific validation**: each header is parsed according to its specification. Duplicate headers,
  invalid syntax, deprecated directives, case-sensitive tokens, conflicting headers and weak values are all
  detected. Legitimate alternatives are not reported merely for differing from OWASP's preferred value.
- **Quick Scan** (one request per host or URL, plus an optional, clearly marked HTTP fallback) and **Deep Scan** (re-analyses responses already in the site map).
- **Deep Scan grouping**: responses already in the site map are grouped by host and path (`/api/*`), so a large
  site reads as a few rows ("`/api/*`, 40 URLs, missing: ..."), with login/logout/payment/admin groups first.
- **Copy for report**: one click copies the results as Markdown grouped by host (**Missing:** /
  **Misconfigured:** bullets), ready to paste into a pentest report.
- **Transparent HTTP fallback**: if HTTPS fails, the result is clearly marked as obtained over HTTP, with
  the original HTTPS status, in the table, details, Markdown and report. It can be switched off.
- **Overall risk score** (average per URL, so it does not grow with the number of pages scanned), **critical URL** highlighting (login, logout, admin, API, payment), with editable **endpoint types** (saved in the Burp project) for URLs the keywords miss.
- **Honest results**: if a rule fails internally, the result is marked *incomplete* (never "clean") in the table, report and score.
- **HTML report export** (XSS-safe) and **Rescan & Compare** against a previous report.
- **Offline OWASP definitions**: a commit-pinned, validated copy is bundled and used by default. **Sync OWASP Headers** optionally pulls the latest upstream file (TLS-verified, validated, in memory only).
- Responsive UI: all slow work runs in the background, with progress and **Cancel**.

## Supported security headers

### Passive scanner (Burp Issues)

Burp's built-in scanner already reports CSP, HSTS, X-Frame-Options, CORS and caching issues, so the
passive check deliberately covers only:

| Header | What is reported |
|---|---|
| Cross-Origin-Opener-Policy | not set (HTML), invalid/duplicate/mis-cased value, explicit `unsafe-none` |
| Cross-Origin-Embedder-Policy | not set (HTML), invalid value, COEP without `COOP: same-origin` (isolation incomplete) |
| Cross-Origin-Resource-Policy | not set, invalid value (Fetch compares byte-for-byte: parameters, case differences or lists make it invalid), `cross-origin` on a response to an authenticated request |
| Referrer-Policy | not set (HTML), no valid token, effective `unsafe-url` / `no-referrer-when-downgrade`, conflicting headers |
| Permissions-Policy | not set (HTML), invalid RFC 8941 syntax that makes browsers drop the whole header (e.g. Feature-Policy style `'self'`), unrecognised allowlist entries that browsers ignore per feature (e.g. `camera=none`), duplicate features, powerful features granted to `*`, deprecated `Feature-Policy` |
| X-DNS-Prefetch-Control | not set (HTML), explicit `on`, invalid value |
| X-Permitted-Cross-Domain-Policies | not set (non-API), `all`, invalid value |
| Clear-Site-Data | not set on logout URLs, unquoted or unknown directives, sent over HTTP, logout without `"cookies"` / incomplete |

"Header not set" issues are reported **once per origin** to avoid flooding the Issues panel (Clear-Site-Data:
once per logout URL). Other issues are reported per URL, and Burp's consolidation keeps one instance per issue and URL.

### Manual scanner

All headers in the active OWASP definitions (Cache-Control, Clear-Site-Data, Content-Security-Policy, COEP,
COOP, CORP, Permissions-Policy, Referrer-Policy, Strict-Transport-Security, X-Content-Type-Options,
X-DNS-Prefetch-Control, X-Frame-Options, X-Permitted-Cross-Domain-Policies) plus CORS response headers.

## Installation

1. Download `SecHeaderScout.jar` from the releases page (or build it, see below).
2. In Burp: **Extensions → Installed → Add**, extension type **Java**, select the JAR.
3. The output tab shows the active OWASP definitions version. No network request is made at startup.

### Compatibility

- Burp Suite Professional / Enterprise / Community **2026.2 or later** (Montoya API 2026.2).
  Community Edition has no scanner, so only the manual tab is available there.
- Java 17+ (Burp's bundled JRE is fine).

## Building from source

Requirements: JDK 17+, Maven 3.9+.

```bash
git clone https://github.com/ismailsanan/SecHeaderScout
cd SecHeaderScout
mvn clean package        # compiles, runs the test suite, builds the JAR
```

The JAR is written to `target/SecHeaderScout.jar`. It has no runtime dependencies (the Montoya API is
`provided` by Burp).

## Usage

### Passive scanning
Browse the target through Burp's proxy (with live passive scanning enabled, which is the default). Issues
appear under **Target → Site map → Issues** and in the **Dashboard**. They can be reported like any other Burp issue.

### Manual scanning (SecHeaderScout tab)
1. **Refresh from Burp** loads hosts from the site map (in the background; it can be cancelled), or add a
   custom target (`host`, `host:port`, `host/path` or a full `http(s)://` URL).

   Select hosts and press **Delete** (or Backspace) to remove them from the list.

   **Endpoint types** (bottom panel, *Endpoint types* tab): which paths count as logout, login, admin, payment or
   API. Some checks depend on this: Clear-Site-Data is only expected on **logout** responses, and Cache-Control is
   checked strictly on login, logout, admin, API and payment endpoints. The tab lists:
   - **built-in** keyword patterns (`*/logout*`, `*/signout*`, `*/login*`, `*/admin*`, `*/api/*`, `*/checkout*`,
     ...). Untick **On** to disable one (e.g. `*/dashboard*` when the target's dashboard is not an admin area);
     built-ins cannot be deleted, so you can always switch them back on;
   - your **custom** patterns, added with *Pattern* + *Type* + **Add** and removed with **Remove selected** or Delete:

   | Pattern | Matches |
   |---|---|
   | `/auth/session/destroy` | that exact path, on any host (query ignored) |
   | `/auth/*` | every path under `/auth/`, on any host |
   | `*/terminate*` | `/terminate` anywhere in the path |
   | `https://app.example.com/auth?action=logout` | that host and path, when the query contains `action=logout` |

   Choose **NOT SENSITIVE** to correct a false match (e.g. `/blog/*` for a post about logging out). Custom patterns
   win over built-ins; among them the most specific wins (host-specific, then exact, prefix, suffix, contains, then
   longest). Changes apply immediately to new scans **and** to Burp's passive scanner, and are **saved in the Burp
   project**, so they come back when the project is reopened. Rescan to update existing results.

2. Select one or more targets and click
   - **Quick Scan**: sends one GET to each target. Targets without a scheme are tried over HTTPS first;
     with *Fall back to HTTP* enabled, a failed or 4xx/5xx HTTPS attempt is retried over HTTP and the
     result is marked **⚠ HTTP**. Redirects are not followed; the redirect response itself is analysed and a note says so.
   - **Deep Scan**: analyses the responses already in the site map for the selected hosts. No requests are sent,
     so browse (or crawl) the application through Burp first. If nothing was captured, or every response was
     filtered out, a message says so and what to change.
     - **Noise filters** (the "Deep Scan also analyses" row) run before analysis: static files, 4xx/5xx error
       pages and redirects are skipped by default, and query-string variants of the same endpoint
       (`/search?q=a`, `/search?q=b`) are analysed once. The status line says how many responses each filter skipped.
     - **Header profiles** (the **By profile** tab): endpoints are grouped by host and first path segment
       (`/api/*`, `/app/*`, `/login`) when they have exactly the same issues, so thousands of URLs collapse into
       a handful of rows such as "`/api/*`, 40 URLs, missing: Content-Security-Policy, Referrer-Policy". Issue
       *names* are compared, not values, so per-request CSP nonces do not split groups.
     - **Priority**: groups containing logout, login, payment or admin endpoints are listed first (and labelled),
       then by severity and size. The **Type** column shows LOGOUT / LOGIN / PAYMENT / ADMIN for those groups.
3. Click a row to see its details. The **By URL** tab (the default) lists every analysed URL; the **By profile**
   tab shows the Deep Scan groups, each with its missing headers, misconfigurations and URLs (query strings hidden).
4. **Copy for report** copies all current results as Markdown you can paste straight into a pentest report,
   grouped by host:

   ```markdown
   ### www.example.com

   **Missing:**

   - Content-Security-Policy
   - Referrer-Policy (1 of 2 URLs)

   **Misconfigured:**

   - X-Frame-Options header has an invalid value: `ALLOWALL`
   ```

   Each header or issue appears once per host; "(n of m URLs)" is added when only some URLs are affected.
   HTTP-fallback warnings, incomplete evaluations and URLs that could not be analysed are included, and
   server-supplied text is escaped so it cannot inject links, images or HTML.

### Reports and comparison
- **Export Report** writes a self-contained HTML file. All values are HTML-escaped, and the page declares
  a CSP that forbids scripts.
- **Rescan & Compare** loads a previous report (this version or 1.x). Because a report file decides which URLs
  are requested, it first shows the hosts it would contact, flags hosts outside Burp's target scope and
  asks for confirmation (at most 500 URLs; files over 5 MB are rejected). It then rescans the same URLs and lists
  FIXED / STILL MISSING / NEW ISSUE / NO LONGER CHECKED / PRESENT BUT INVALID per URL. URLs that could not be
  analysed in the old report are shown as "no baseline" instead of producing false NEW ISSUE verdicts. A header counts as FIXED only if it is now
  actually present in the response.

### OWASP definitions
The tab header shows the definitions in use, e.g. `bundled 06b5c6f (2026-10-18 07:04:36 UTC, 13 headers)`:
the OWASP Secure Headers Project's `headers_add.json`, pinned to commit `06b5c6f` and bundled in the JAR, so the
extension works offline and results are reproducible. The same label is printed in exported reports.

**Sync OWASP Headers** (next to *Refresh from Burp*) fetches the latest upstream file after a confirmation:
- the download goes through Burp's HTTP stack with TLS certificate verification, a 10 s timeout, no redirects,
  HTTP 200 only and a 256 KB size limit;
- the content is validated (JSON structure, header-name syntax, value length and characters, entry count, no
  duplicates, timestamp) before it is used; on any failure the current definitions stay active and the status line
  says why;
- on success the label changes to `synced latest (...)` and the status line lists added/removed headers. Synced
  definitions apply to Quick Scan, Deep Scan and reports; Burp's passive scanner keeps its fixed rule set;
- nothing is written to disk: reloading the extension returns to the pinned copy.

To change the pinned copy itself, see [Updating the bundled OWASP definitions](#updating-the-bundled-owasp-definitions).

## Architecture

```
io.github.ismailsanan.secheaderscout
├── SecHeaderScout          entry point: wiring, passive-check registration, unload cleanup
├── headers/                parsing only: case-insensitive multi-value headers, list/directive/RFC 8941 parsers
├── engine/                 evaluation: HeaderRule per header → Finding (type, severity, confidence, evidence);
│                           UrlClassifier + EndpointRules (built-in and custom endpoint patterns), EndpointRulesStore
│   └── rules/              COOP, COEP, CORP, Referrer-Policy, Permissions-Policy, DNS prefetch, XPCDP,
│                           Clear-Site-Data, CSP, HSTS, XFO, XCTO, Cache-Control, CORS, generic
├── definitions/            bundled, commit-pinned and validated OWASP definitions; optional validated sync
├── model/                  ResponseSnapshot (input), ScanResult (output, incl. fallback metadata),
│                           HeaderProfile (Deep Scan group)
├── manual/                 ManualScanner (Quick/Deep scan, fallback, cancellation), DeepScanOptions + StaticResources (noise filters),
│                           ProfileGrouper (host + path groups, priority), HttpFetcher, ScanTarget
├── report/                 ReportExporter, ReportParser, Comparison, ScoreCalculator, TextFormatter
├── scanner/                Burp PassiveScanCheck + Finding → AuditIssue mapping
├── burp/                   Montoya adapters: HTTP (TLS-verified), site map, messages, logging, project persistence
├── ui/                     Swing tab, table models, Endpoint types tab, WrapLayout, OperationRunner (one cancellable task at a time)
└── util/                   BackgroundTasks (managed executor), Log facade (with URL redaction), MiniJson, HtmlEscaper,
                            UrlPaths
```

Design rules:
- `headers`, `engine`, `definitions`, `model`, `manual`, `report` and `util` do not depend on the Montoya
  API, so the logic is unit-testable without Burp.
- The passive check has no access to Burp's HTTP API, so it cannot send requests.
- All background work runs on one `BackgroundTasks` executor (named daemon threads). It is shut down by the
  extension's unloading handler, which also cancels running scans and clears passive-check state.
- Swing components are touched only on the EDT. Results are published as immutable snapshots.

See [`docs/REQUIREMENTS.md`](docs/REQUIREMENTS.md) for the full, traceable requirement list.

## Known limitations

- **Heuristic URL classification**: logout/login/admin/API/payment detection is based on URL path keywords,
  plus the patterns in the **Endpoint types** tab. Clear-Site-Data findings are therefore reported with *Tentative* confidence.
- **Headers only**: policies delivered via `<meta>` (CSP, referrer) are not seen.
- **Passive CORS checks cannot prove origin reflection**; credentialed CORS findings in the manual tab are
  *Tentative*, so verify them in Repeater.
- **Once-per-origin reporting** of "header not set" issues is kept in memory. If you delete such an issue, it is
  not re-reported until the extension is reloaded.
- **Redirects are not followed** by Quick Scan; scan the destination URL separately.
- Burp's `sendRequest` is not interruptible, so cancelling a Quick Scan stops after the in-flight request
  completes or times out (10 s).

## Development and testing

```bash
mvn test                  # run the JUnit 5 suite
```

The tests do not need Burp. Montoya interfaces are faked with `java.lang.reflect.Proxy` "strict" fakes that
fail on any unexpected call, and Montoya's static factories are served by a fake installed in
`ObjectFactoryLocator.FACTORY` (see `src/test/.../testsupport`). Coverage includes header evaluation per rule,
passive-check behaviour (detection, de-duplication, consolidation, severity and confidence, escaping, no
network), report escaping with XSS payloads, empty and large reports, definitions validation, fallback and
TLS options, cancellation, executor shutdown and concurrent result access.

### Updating the bundled OWASP definitions

1. Pick a commit of [OWASP/www-project-secure-headers](https://github.com/OWASP/www-project-secure-headers)
   and download `ci/headers_add.json` at that commit:
   `curl -fsSLO https://raw.githubusercontent.com/OWASP/www-project-secure-headers/<commit>/ci/headers_add.json`
2. Replace `src/main/resources/owasp/headers_add.json`.
3. Update `src/main/resources/owasp/definitions.properties` (`source.commit`, `source.last_update_utc`,
   `source.sha256` = `sha256sum headers_add.json`).
4. Run `mvn test`: `DefinitionsTest` checks that the bundled file loads and validates. Adjust its expected
   commit and header count.
5. Review whether new headers need a dedicated rule in `engine/rules` (otherwise a presence-only check is used).

## License

See [LICENSE](LICENSE).
