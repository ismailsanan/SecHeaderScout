# SecHeaderScout: Software Specification

Version 2.0 · Burp Suite extension (Montoya API) · Java 17

This document describes what SecHeaderScout does (functional requirements), the qualities it must
have (non-functional requirements), how it is built (architecture) and how it is used and maintained
(brief documentation). Requirement IDs are stable; the test suite refers to them.

---

## 1. Introduction

### 1.1 Purpose
SecHeaderScout audits HTTP security headers against the
[OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/). It helps penetration
testers find missing or misconfigured headers, report them in Burp's native issue list and export
findings ready for a report.

### 1.2 Scope
| In scope | Out of scope |
|---|---|
| Response security headers (CSP, HSTS, X-Frame-Options, COOP, COEP, CORP, Referrer-Policy, Permissions-Policy, Cache-Control, CORS, Clear-Site-Data, …) | Exploitation, active attacks, fuzzing |
| Passive analysis of proxied traffic and analysis of traffic already in Burp's site map | Policies delivered through `<meta>` tags |
| On-demand requests to targets the user selects (Quick Scan, Rescan & Compare) | Crawling or spidering |
| HTML report, report-ready Markdown, comparison with a previous report | Persistent storage of scan results |

### 1.3 Definitions
| Term | Meaning |
|---|---|
| Finding | One problem with one header: MISSING, INVALID, WEAK, DEPRECATED or CONFLICT, with severity and confidence |
| Passive check | Burp scanner check that analyses responses already flowing through Burp, without sending requests |
| Quick Scan | One GET request per selected target, analysed immediately |
| Deep Scan | Analysis of the responses already captured in Burp's site map for the selected hosts |
| Header profile | A group of Deep Scan endpoints on one host and path group (`/api/*`) with exactly the same issues |
| Endpoint type | Logout, login, payment, admin, API or not sensitive; decides which checks apply (e.g. Clear-Site-Data on logout) |
| OWASP definitions | The OWASP `headers_add.json` file listing recommended headers and values |
| HTTP fallback | Retrying a target over plain HTTP when HTTPS fails |

### 1.4 Users and operating environment
- **Users:** penetration testers and security engineers using Burp Suite.
- **Environment:** Burp Suite Professional, Enterprise or Community (the passive scanner requires a
  scanner, so it is disabled on Community; the manual tab works everywhere), Java 17 or later.
- **Constraints:** Montoya API `2026.2`; no runtime dependencies besides Burp; no network access at
  startup.

---

## 2. Functional requirements

### 2.1 Passive scanning
| ID | Requirement |
|---|---|
| FR-1 | The extension registers a passive scan check (`registerPassiveScanCheck`, `PER_REQUEST`) when it loads. |
| FR-2 | The passive check evaluates exactly the headers Burp does not already cover: COOP, COEP, CORP, Referrer-Policy, Permissions-Policy, X-DNS-Prefetch-Control, X-Permitted-Cross-Domain-Policies and Clear-Site-Data. |
| FR-3 | Each finding becomes a Burp issue with name, detail, remediation, background, URL, severity, confidence and the request/response as evidence, with the offending header highlighted. |
| FR-4 | Issues are not duplicated: "header not set" is reported once per origin (Clear-Site-Data once per logout URL); other issues are consolidated per URL. |
| FR-5 | The passive check never sends HTTP requests. |

### 2.2 Manual scanning (SecHeaderScout tab)
| ID | Requirement |
|---|---|
| FR-6 | The tab offers: target list (hosts from the site map or custom targets, deletable with the Delete key), Quick Scan, Deep Scan, Cancel, Export Report, Rescan & Compare, Copy for report, Clear and Sync OWASP Headers. Button rows wrap on narrow windows instead of hiding buttons. |
| FR-7 | When HTTP fallback is used, the result records it (protocol, original HTTPS status, reason) and every view (table, details, Markdown, HTML report) shows a visible warning. Fallback can be switched off. |
| FR-8 | HSTS is never reported missing or weak on a response received over HTTP; a note explains that it was not evaluated. |
| FR-12 | Rescan & Compare reports a header as FIXED only when it is actually present now; otherwise it reports STILL MISSING, NEW ISSUE, NO LONGER CHECKED or PRESENT BUT INVALID. |

### 2.3 OWASP definitions
| ID | Requirement |
|---|---|
| FR-9 | A commit-pinned copy of the OWASP definitions is bundled in the JAR and used by default; the extension works offline. |
| FR-10 | "Sync OWASP Headers" optionally downloads the latest upstream definitions after confirmation. The download is TLS-verified and bounded; the content is validated before use; on failure the current definitions stay active; synced definitions are kept in memory only. |
| FR-11 | The active definitions version (source, commit, upstream timestamp, header count) is shown in the tab and printed in exported reports. |

### 2.4 Deep Scan
| ID | Requirement |
|---|---|
| FR-13 | Noise filters run before analysis: static files, 4xx/5xx responses and redirects are skipped by default, query-string variants of one endpoint are analysed once; the status line reports what each filter skipped. |
| FR-14 | Results are grouped into header profiles by host, first path segment (`/api/*`) and identical issue names (robust to per-request values such as CSP nonces). The "By profile" table lists the missing header names per group. |
| FR-15 | Groups containing logout, login, payment or admin endpoints are listed first and labelled, then groups by severity and size. "By URL" is the default view. |
| FR-16 | A Deep Scan that analyses nothing explains why (no captured traffic, or everything filtered) and what to change. |

### 2.5 Reporting
| ID | Requirement |
|---|---|
| FR-17 | Export Report writes a self-contained HTML report (results, score, profiles, definitions version). |
| FR-18 | "Copy for report" copies Markdown grouped by host with **Missing:** and **Misconfigured:** bullets, "(n of m URLs)" for partial coverage, and the fallback, incomplete and not-analysed results. |
| FR-19 | An overall risk score (INFO, LOW, MEDIUM, HIGH, CRITICAL) is shown; it is marked as a lower bound when some results were not fully evaluated. |

### 2.6 Endpoint types
| ID | Requirement |
|---|---|
| FR-20 | Endpoint types come from one rule set: built-in keyword patterns (`*/logout*`, `*/login*`, …; can be disabled, not removed) plus custom patterns (exact path, prefix `/auth/*`, contains `*/x*`, suffix `*/x`, or a full URL with optional query). Custom patterns win, then the most specific match. |
| FR-21 | The "Endpoint types" tab lists, adds, removes (button or Delete key) and enables/disables patterns. Changes apply immediately to manual and passive scanning. |
| FR-22 | Endpoint types are saved in the Burp project and restored when it is reopened; saved data is treated as untrusted (bounded size and count, invalid entries skipped). |

---

## 3. Header evaluation requirements

| ID | Requirement |
|---|---|
| HE-1 | Header parsing (`headers` package) is separate from security evaluation (`engine` package). |
| HE-2 | Header names are matched case-insensitively; repeated header lines are preserved and evaluated. |
| HE-3 | Each rule distinguishes MISSING, INVALID (ignored by browsers), WEAK, DEPRECATED and CONFLICT. |
| HE-4 | Specification semantics are respected: last recognised Referrer-Policy token wins; Permissions-Policy is an RFC 8941 dictionary; COOP/COEP are structured items; CORP is compared exactly as browsers do; Clear-Site-Data directives must be quoted and need a secure context. |
| HE-5 | No finding merely for differing from the OWASP preferred value; legitimate alternatives (e.g. COOP `same-origin-allow-popups`) are not reported. |
| HE-6 | Document-only headers are expected only on HTML documents (no "CSP missing" on images or JSON). |
| HE-7 | Every finding carries header, observed value, recommendation, impact, remediation, severity and confidence. |
| HE-8 | An exception in one rule does not stop the other rules; it is logged with its stack trace. |
| HE-9 | A result where a rule failed is marked *incomplete* and is never reported as clean (UI, report, Markdown, score, comparison). |

---

## 4. Non-functional requirements

### 4.1 Security
| ID | Requirement |
|---|---|
| SEC-1 | Every value from HTTP traffic or the user is HTML-escaped in the HTML report. |
| SEC-2 | The HTML report contains no JavaScript and declares a `default-src 'none'` Content Security Policy. |
| SEC-3 | Values shown in Burp issue details (rendered as HTML) are escaped; Swing tables, lists and labels never render server-supplied text as HTML. |
| SEC-4 | Every request the extension sends verifies the upstream TLS certificate, has a timeout (10 s) and does not follow redirects. |
| SEC-5 | TLS and connection failures are reported as failures, never replaced silently by insecure results. |
| SEC-6 | Report files are parsed as data only: no deserialisation, no code execution. |
| SEC-7 | Logs never contain response bodies, cookies, Authorization values or URL query strings. |
| SEC-8 | Parsing an untrusted report file is linear-time and cancellable. |
| SEC-9 | Rescan & Compare shows the hosts it will contact, flags hosts outside Burp's scope, caps the URLs (500) and the file size (5 MB), and requires confirmation before sending any request. |
| SEC-10 | Server-derived text in copied Markdown cannot inject HTML, links or images. |
| SEC-11 | Data types reject contradictory states (e.g. an errored result with findings, an HTTP-fallback result marked HTTPS). |
| SEC-12 | Downloaded definitions and saved endpoint types are treated as untrusted input: size-bounded and validated. |

### 4.2 Concurrency, reliability and lifecycle
| ID | Requirement |
|---|---|
| CC-1 | No site map iteration, HTTP request, file I/O or report rendering runs on the Swing event thread. |
| CC-2 | Swing components are changed only on the event thread. |
| CC-3 | Background work uses one managed executor with named daemon threads; no ad-hoc threads. |
| CC-4 | Running operations can be cancelled; at most one manual operation runs at a time. |
| CC-5 | Unloading the extension cancels running work, shuts the executor down (bounded wait, 3 s), clears passive-check state and restores the default endpoint types. |
| CC-6 | Shared state is published as immutable snapshots (results, endpoint types, OWASP definitions). |
| CC-7 | Background tasks catch and log exceptions and report the failure in the UI; interruption is treated as cancellation. |

### 4.3 Performance and scalability
| ID | Requirement |
|---|---|
| PERF-1 | The passive check classifies and evaluates each response once, without regex compilation or network access on the hot path. |
| PERF-2 | Deep Scan streams site map responses (analyse, then drop) so large projects (100k+ entries) do not need all responses in memory at once. |
| PERF-3 | Progress updates to the UI are throttled; large result sets render without blocking the UI. |
| PERF-4 | Report rendering is linear in the number of results (a 20,000-result report is a regression test). |

### 4.4 Usability
| ID | Requirement |
|---|---|
| US-1 | Every long operation shows progress and can be cancelled. |
| US-2 | Error and empty states explain the cause and the next step (e.g. "browse the site through Burp's proxy first"). |
| US-3 | Output is directly reusable: report-ready Markdown, self-contained HTML report. |

### 4.5 Maintainability and portability
| ID | Requirement |
|---|---|
| Q-1 | Java 17; Montoya `2026.2` as a `provided` dependency; no other runtime dependencies. |
| Q-2 | The `headers`, `engine`, `definitions`, `model`, `manual`, `report` and `util` packages do not depend on Burp, so they are unit-testable without it. |
| Q-3 | JUnit 5 tests cover evaluation rules, passive check, reports, concurrency, HTTP behaviour and the UI wiring; all pass on every build. |
| Q-4 | The README documents features, usage, architecture, build, limitations and how to update the definitions. |

---

## 5. Architecture

```
io.github.ismailsanan.secheaderscout
├── SecHeaderScout   entry point: wiring, passive-check registration, unload cleanup
├── headers/         parsing only: multi-value headers, list/directive/RFC 8941 parsers
├── engine/          evaluation: one HeaderRule per header → Finding; UrlClassifier + EndpointRules
├── definitions/     bundled, pinned OWASP definitions; validated optional sync
├── model/           ResponseSnapshot (input), ScanResult (output), HeaderProfile
├── manual/          ManualScanner (Quick/Deep Scan), noise filters, ProfileGrouper, Rescan & Compare
├── report/          HTML report, report parser, comparison, score, text/Markdown formatting
├── scanner/         Burp passive scan check and Finding → AuditIssue mapping
├── burp/            Montoya adapters: HTTP (TLS-verified), site map, logging, project persistence
├── ui/              Swing tab, tables, Endpoint types tab, OperationRunner, WrapLayout
└── util/            BackgroundTasks (managed executor), Log (redaction), UrlPaths, HtmlEscaper, MiniJson
```

**Data flow.** A response (proxied, captured in the site map, or fetched by Quick Scan) becomes an
immutable `ResponseSnapshot`. The `HeaderEvaluator` runs every applicable `HeaderRule` and produces
`Finding`s, collected in a `ScanResult`. The passive check maps findings to Burp `AuditIssue`s; the
manual tab shows results, groups Deep Scan results into `HeaderProfile`s and renders reports.

**Threading.** User actions start work through `OperationRunner` on the single managed
`BackgroundTasks` executor; results return to the Swing event thread as immutable snapshots.

---

## 6. Brief documentation

### 6.1 Installation
1. Build the JAR (see 6.4) or download a release.
2. In Burp: **Extensions → Installed → Add**, type *Java*, select `SecHeaderScout.jar`.
3. A **SecHeaderScout** tab appears; on Professional/Enterprise the passive check is active.

### 6.2 Usage
- **Passive:** browse the target through Burp's proxy; issues appear in **Target → Issues** and the Dashboard.
- **Targets:** *Refresh from Burp* loads hosts from the site map, or add a custom target (`host`,
  `host:port`, `host/path` or a URL). Select hosts and press Delete to remove them.
- **Quick Scan:** one request per selected target, HTTPS first (optional HTTP fallback, clearly marked).
- **Deep Scan:** analyses traffic already captured for the selected hosts; no requests are sent.
  Results appear per URL (*By URL*) and grouped (*By profile*).
- **Reports:** *Copy for report* (Markdown grouped by host), *Export Report* (HTML),
  *Rescan & Compare* (rescans the URLs of a previous report and lists what changed).
- **Endpoint types:** bottom tab; mark which paths are logout, login, admin, payment or API.
- **Sync OWASP Headers:** optionally use the latest upstream definitions until the extension is reloaded.

### 6.3 Configuration and data
| Item | Where it is kept |
|---|---|
| Endpoint types | Burp project file (restored when the project is reopened) |
| Synced OWASP definitions | Memory only (reload returns to the bundled copy) |
| Scan results | Memory only (export a report to keep them) |

### 6.4 Build and test
```bash
mvn clean verify            # compiles, runs the JUnit 5 suite, builds target/SecHeaderScout.jar
```
Requires a JDK 17+ with Maven. The tests do not need Burp: Montoya interfaces are replaced by strict
test doubles.

### 6.5 Known limitations
- Endpoint types come from URL patterns, so Clear-Site-Data findings have *Tentative* confidence.
- Only headers are analysed; policies in `<meta>` tags are not seen.
- Passive CORS checks cannot prove origin reflection; verify credentialed CORS findings in Repeater.
- Quick Scan does not follow redirects; scan the destination separately.
- A Quick Scan request in flight cannot be interrupted; cancelling stops after it completes or times out.

---

## 7. Verification

| Area | Verified by |
|---|---|
| Header rules and specification semantics (HE-*) | Rule unit tests (`engine/*Test`), including "no finding" cases for legitimate values |
| Passive check (FR-1..FR-5) | `SecurityHeadersPassiveCheck` tests with strict Burp doubles that fail on any request |
| Manual scanning, fallback, comparison (FR-6..FR-12) | `ManualScanner*Test`, `RescanComparerTest`, `ComparisonTest` |
| Deep Scan and profiles (FR-13..FR-16) | `DeepScanProfilesTest`, `DeepScanUiTest` |
| Reports and Markdown (FR-17..FR-19, SEC-1, SEC-2, SEC-10) | `ReportExporterTest`, `TextFormatterAndReportVersionTest`, XSS payload tests |
| Endpoint types (FR-20..FR-22) | `EndpointRulesTest`, `DeepScanUiTest` |
| Definitions and sync (FR-9..FR-11, SEC-12) | `DefinitionsTest`, `DefinitionsValidationBoundaryTest`, `BurpHttpFetcherOptionsTest` |
| Concurrency and lifecycle (CC-*) | `OperationRunner*Test`, `UiConcurrencyTest`, `SecHeaderScoutUnloadTest` |

**Manual check in Burp:** load the JAR (no network request at startup); browse a site (issues appear
once per origin); Deep Scan a large project (UI stays responsive, Cancel works); export a report and
open it in a browser (a `<script>` target shows as text); unload the extension (no
`SecHeaderScout-worker` threads remain).
