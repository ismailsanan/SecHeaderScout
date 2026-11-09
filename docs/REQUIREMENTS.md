# SecHeaderScout: Engineering Requirements

Status: baseline for the PortSwigger resubmission (v2.0). Revised after the architecture, security and test reviews (SEC-8..SEC-10 added).
Each requirement has an ID, a priority (**MUST** / **SHOULD**), the PortSwigger
feedback item it answers (PS-n, where applicable) and an acceptance criterion
that a reviewer or test can verify.

PortSwigger feedback items:
PS-1 passive scanner integration · PS-2 refresh on the EDT · PS-3 unmanaged threads / unload ·
PS-4 shared state (`lastResults`, `currentFilter`; the filter has since been removed) · PS-5 exception handling in scans ·
PS-6 TLS verification in `OWASPHeaders.fetchHeaders()` · PS-7 XSS in `ReportExporter` ·
PS-8 silent HTTP fallback · PS-9 unpinned OWASP definitions URL.

---

## 1. Functional requirements

| ID | Pri | Source | Requirement | Acceptance criterion |
|----|-----|--------|-------------|----------------------|
| FR-1 | MUST | PS-1 | Register a `PassiveScanCheck` with `api.scanner().registerPassiveScanCheck(check, ScanCheckType.PER_REQUEST)` during `initialize`. | Code inspection; findings appear in Burp's Issues panel when browsing through the proxy. |
| FR-2 | MUST | PS-1 | The passive check evaluates exactly: COOP, COEP, CORP, Referrer-Policy, Permissions-Policy, X-DNS-Prefetch-Control, X-Permitted-Cross-Domain-Policies, Clear-Site-Data. | `RuleSets.passiveRules()` contains these 8 and no CSP/HSTS/XFO rule (unit test). |
| FR-3 | MUST | PS-1 | Each finding becomes an `AuditIssue` with name, detail, remediation, background, base URL, severity, confidence, and the request/response as evidence (header line highlighted when present). | Unit test on the produced `AuditIssue`. |
| FR-4 | MUST | PS-1 | No duplicate issues: "header not set" is reported once per origin (except URL-specific Clear-Site-Data); other issues are consolidated per URL via `consolidateIssues` → `KEEP_EXISTING`. | Unit test: the same missing header on 2 URLs of one origin gives 1 issue; repeated response gives `KEEP_EXISTING`. |
| FR-5 | MUST | PS-1 | The passive check sends no HTTP requests. | Structural: the check has no reference to `Http`; test passes a response proxy that fails on unexpected calls. |
| FR-6 | MUST | — | Quick Scan, Deep Scan, Export, Rescan & Compare, Copy for report, Sync OWASP Headers and custom targets are available (the result filter buttons were removed in favour of the By URL / By profile views); button rows wrap instead of hiding buttons on narrow windows. | Manual UI checklist (§6). |
| FR-7 | MUST | PS-8 | HTTP fallback is recorded in `ScanResult` (`httpFallback`, `originalHttpsStatus`, `fallbackReason`, actual protocol) and shown in the UI table, details pane, Markdown and HTML report. | Unit tests on `ManualScanner`; report contains a warning block for fallback results. |
| FR-8 | MUST | PS-8 | HSTS is never reported missing/weak on an HTTP response; a note explains it was not evaluated. | Unit test. |
| FR-9 | MUST | PS-9 | Bundled, commit-pinned OWASP `headers_add.json` is the default; the extension works offline. | Startup performs no network request; unit test loads the bundled resource. |
| FR-10 | MUST | PS-9 | Updating definitions is optional and user-triggered ("Sync OWASP Headers", after confirmation, in the background). The download is TLS-verified, bounded (timeout, no redirects, HTTP 200, 256 KB) and validated (schema, header-name syntax, value length/charset, count bounds, no duplicates); on failure the last known good definitions stay active; synced definitions live in memory only. The bundled file is validated at load and its SHA-256 is pinned. | `DefinitionsTest`, `DefinitionsValidationBoundaryTest`, `BurpHttpFetcherOptionsTest`, `DeepScanUiTest#syncOwaspHeadersSitsNextToRefreshFromBurp`. |
| FR-11 | MUST | PS-9 | The active definitions version (source, commit, upstream timestamp, count) is shown in the UI and the report. | UI label + report text. |
| FR-12 | SHOULD | — | Rescan & Compare reports FIXED only when the header is actually present now; otherwise NO LONGER CHECKED. | Unit test on `Comparison`. |
| FR-13 | SHOULD | — | Deep Scan applies noise filters before analysis (static files, 4xx/5xx, redirects off by default; query-string variants merged) and reports what each filter skipped. | `DeepScanProfilesTest#noiseFiltersRunBeforeAnalysisAndAreAccounted`. |
| FR-14 | SHOULD | — | Deep Scan groups results into header profiles: host + first path segment (`/api/*`) + identical issue names (robust to per-request values such as CSP nonces). | `DeepScanProfilesTest`, `DeepScanUiTest`. |
| FR-15 | — | — | *Removed:* flagging profiles that are weaker than the rest of their host (too noisy in practice). | — |
| FR-16 | SHOULD | — | Profiles are ordered: sensitive endpoints (logout, login, payment, admin) first, then severity and size. Profiles appear in the UI ("By URL" is the default tab) and, escaped, in the HTML report. | `DeepScanProfilesTest#sensitiveEndpointsComeFirstThenSeverityAndSize`, `ProfilesPresentationTest`. |
| FR-17 | SHOULD | — | "Copy for report" produces Markdown grouped by host, with deduplicated **Missing:** and **Misconfigured:** bullets and "(n of m URLs)" for partial coverage; fallback warnings, incomplete evaluations and unanalysed URLs are kept. | `TextFormatterAndReportVersionTest`. |
| FR-18 | SHOULD | — | A Deep Scan that analyses nothing explains why (no captured traffic vs. everything filtered) and what to do. | `PanelLayoutAndDeepScanMessagesTest`. |
| FR-19 | SHOULD | — | Endpoint types (logout, login, admin, payment, API, not sensitive) come from one rule set: built-in keyword patterns (can be disabled, not removed) plus custom patterns (exact path, prefix, suffix, contains, or full URL with optional query), edited in the "Endpoint types" tab. Custom patterns win. The set applies to manual and passive scanning, is published as an immutable snapshot (thread-safe for Burp's scan threads), is saved in the Burp project (`extensionData`, treated as untrusted on load: bounded size and count, invalid lines skipped) and restored to the defaults on unload. | `EndpointRulesTest`, `DeepScanUiTest`. |
| FR-20 | SHOULD | — | Selected hosts can be removed from the target list with the Delete or Backspace key. | `DeepScanUiTest#theDeleteKeyRemovesSelectedHosts`. |

## 2. Header evaluation requirements

| ID | Pri | Requirement | Acceptance criterion |
|----|-----|-------------|----------------------|
| HE-1 | MUST | Header parsing (`headers` package) is separate from security evaluation (`engine` package). | Package dependency inspection. |
| HE-2 | MUST | Header names are matched case-insensitively; duplicate field lines are preserved and evaluated. | Unit tests. |
| HE-3 | MUST | Each rule distinguishes MISSING / INVALID (browser ignores it) / WEAK / DEPRECATED / CONFLICT. | Unit tests per rule. |
| HE-4 | MUST | Spec semantics are respected: Referrer-Policy last-recognised-token wins; Permissions-Policy is an RFC 8941 dictionary; COOP/COEP are structured items (lists are invalid, tokens are case-sensitive, params allowed); CORP is compared byte-for-byte as Fetch does (no params, no lists, case-sensitive); Permissions-Policy separates fatal syntax errors (whole header dropped) from per-feature unrecognised entries; Clear-Site-Data directives must be quoted and need a secure context. | Unit tests. |
| HE-5 | MUST | No finding merely for differing from the OWASP preferred value; legitimate alternatives (e.g. COOP `same-origin-allow-popups`, CORP `cross-origin` on public assets, XPCDP `master-only`) are not reported. | Unit tests asserting *no* finding. |
| HE-6 | MUST | Document-only headers are only expected on HTML documents (no "CSP missing" on images/JSON). | Unit test. |
| HE-7 | MUST | Every finding carries header, observed value, recommendation, impact, remediation, severity, confidence. | `Finding` record invariants. |
| HE-8 | SHOULD | An exception in one rule does not suppress the other rules; it is logged with its stack trace. | Unit test with a throwing rule. |
| HE-9 | MUST | A rule that fails internally marks the result *incomplete*; an incomplete result is never reported as clean (UI, report, Markdown, score, comparison). | `ManualScannerHardeningTest`, `ReportFixPassRegressionTest`. |

## 3. Security requirements

| ID | Pri | Source | Requirement | Acceptance criterion |
|----|-----|--------|-------------|----------------------|
| SEC-1 | MUST | PS-7 | Every HTTP-derived or user-supplied value in the HTML report is HTML-escaped (`& < > " '`) and placed only in element content or double-quoted attributes. | Test: `<script>alert(document.cookie)</script>` in URL, header value, finding text and notes is present only escaped; no `<script` in output. |
| SEC-2 | MUST | PS-7 | The report contains no JavaScript and declares `default-src 'none'` CSP (defence in depth). | Test. |
| SEC-3 | MUST | — | Values shown in Burp issue details (which render HTML) are escaped. | Unit test with a malicious header value. |
| SEC-4 | MUST | PS-6 | All extension-originated requests use `RequestOptions.requestOptions().withUpstreamTLSVerification().withResponseTimeout(..).withRedirectionMode(NEVER)`. | Code inspection + unit test on the options passed. |
| SEC-5 | MUST | PS-6 | TLS/connection failures are reported as failures, never silently replaced by insecure results; fallback to HTTP is explicit (FR-7) and can be disabled. | Unit tests. |
| SEC-6 | MUST | — | Report parsing (compare) treats files as data only; no deserialisation of objects and no code execution. | Code inspection. |
| SEC-7 | SHOULD | — | Logs do not contain response bodies, cookies, Authorization values or URL query strings (`Log.redact`). | Code inspection + unit test. |
| SEC-8 | MUST | review S-1 | Parsing an untrusted report file is linear-time and cancellable (no lazy `.*?` regex over file content). | Regression test: ~1 MB of unterminated blocks parses in milliseconds; interrupted parse throws `CancellationException`. |
| SEC-9 | MUST | review S-2 | Rescan & Compare shows the hosts it will contact, flags hosts outside Burp's scope, caps URLs (500) and requires confirmation before sending any request. | Unit tests on `RescanComparer.plan`; code inspection of the dialog. |
| SEC-10 | SHOULD | review S-3 | Server-derived text in copied Markdown cannot inject HTML, links or images. | Regression test with hostile payload. |
| SEC-11 | MUST | type-design review | Types reject contradictory states (e.g. an errored result with findings, an HTTP-fallback result marked HTTPS, a mutable confirmed rescan plan). The URL type of an `EvaluationContext` is taken once in `EvaluationContext.of`, because user endpoint rules can change it at runtime. | `TypeInvariantsTest`, `RescanPlanTest`. |

## 4. Concurrency & lifecycle requirements

| ID | Pri | Source | Requirement | Acceptance criterion |
|----|-----|--------|-------------|----------------------|
| CC-1 | MUST | PS-2 | No site map iteration, HTTP request, file I/O or report rendering on the EDT. | Code inspection; the refresh path uses a background task. |
| CC-2 | MUST | PS-2 | Swing components are mutated only on the EDT (`SwingUtilities.invokeLater`). | Code inspection. |
| CC-3 | MUST | PS-3 | No `new Thread(...)`; background work uses one managed `ExecutorService` with named daemon threads. | `grep "new Thread("` finds only the thread factory. |
| CC-4 | MUST | PS-3 | Running operations can be cancelled; at most one manual operation runs at a time (no duplicate refreshes). | Unit test on the task runner; UI disables buttons. |
| CC-5 | MUST | PS-3 | The unloading handler cancels running work, shuts down the executor (`shutdownNow` + bounded `awaitTermination`) and clears passive-check state. | Unit test on shutdown; code inspection of the handler. |
| CC-6 | MUST | PS-4 | Results are published as immutable snapshots (no `ConcurrentModificationException`); UI-only state (filter) is EDT-confined. | Concurrency unit test. |
| CC-7 | MUST | PS-5 | Background tasks catch and log exceptions (with stack trace for unexpected errors) and report the failure in the UI; interruption is treated as cancellation. | Unit tests. |

## 5. Quality requirements

| ID | Pri | Requirement |
|----|-----|-------------|
| Q-1 | MUST | Java 17, Montoya `2026.2` as `provided` scope, no unused runtime dependencies (jsoup/gson removed). |
| Q-2 | MUST | Code lives in package `io.github.ismailsanan.secheaderscout`; Burp-independent packages (`headers`, `engine`, `definitions`, `model`, `manual`, `report`, `util`) do not import `burp.*`. |
| Q-3 | MUST | JUnit 5 tests cover engine, passive check, report, concurrency and HTTP behaviour; all pass. |
| Q-4 | MUST | README documents features, architecture, build, usage, limitations, testing and how to update definitions. |
| Q-5 | MUST | No build artifacts, IDE files or credentials committed. |

## 6. Manual verification checklist (in Burp)

1. Load the JAR → output log shows the definitions version and no network request at startup.
2. Browse a site via the proxy → SecHeaderScout issues appear in **Target → Issues** / Dashboard, once per origin for missing headers.
3. Refresh from Burp on a large project → UI stays responsive; Cancel works.
4. Quick Scan a host whose HTTPS fails → yellow fallback warning in the table, details and report.
5. Export → open report in a browser; a target containing `<script>` shows as text.
6. Unload extension → no `SecHeaderScout-worker` threads remain (check with a thread dump).
