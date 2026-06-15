<p align="center">
  <img width="2760" height="1000" alt="SecHeaderScout logo" src="https://github.com/user-attachments/assets/3bf81a1c-d1c8-40f0-9640-af3e29ace0b8" />
</p>

<h1 align="center">SecHeaderScout</h1>

<p align="center">
  A Burp Suite extension for auditing OWASP recommended security headers across your entire application.
</p>

---

Because let's be honest — why manually check security headers when you can automate it and be lazier?

## What It Does

Quick Scan  -> sends a request to each target's root page, checks response headers

Deep Scan   -> reads every response already captured in Burp's site map, analyzes headers per URL with no new requests

Reads targets from Burp's site map or you can insert custom hosts → sends request → checks headers → reports missing or misconfigured

## OWASP Headers Checked


| Header | Description |
|--------|-------------|
| Content-Security-Policy | Prevents XSS and code injection attacks |
| X-Frame-Options | Prevents clickjacking attacks |
| X-Content-Type-Options | Prevents MIME type sniffing |
| Strict-Transport-Security | Enforces HTTPS connections |
| Referrer-Policy | Controls referrer information sent with requests |
| Permissions-Policy | Controls access to browser features and APIs |
| Cross-Origin-Opener-Policy | Controls cross-origin window access |
| Cross-Origin-Resource-Policy | Controls cross-origin resource sharing |
| Cross-Origin-Embedder-Policy | Controls cross-origin resource embedding |
| X-DNS-Prefetch-Control | Controls DNS prefetching behavior |
| Cache-Control | Controls caching behavior of responses |
| Clear-Site-Data | Clears browsing data on logout |
| X-Permitted-Cross-Domain-Policies | Controls cross-domain data loading |

Headers are fetched dynamically from the [OWASP Secure Headers Project](https://github.com/OWASP/www-project-secure-headers) on startup, with the list above used as a fallback if the fetch fails.

---

## Features

- Quick Scan and Deep Scan
- Flags misconfigured headers
- Highlights critical URLs (login, logout, admin, api, payment)
- Overall security score for each scan
- Export results as an HTML report
- Rescan & Compare against a previous report to track activity 

---

## Installation

Currently not available on the Burp BApp Store YET...

If you're from PortSwigger and reading this feel free to make it happen 👀

### Manual Installation
1. Download the latest JAR from releases
2. Open Burp Suite
3. Go to Extensions → Add
4. Select Java as extension type
5. Select the downloaded JAR
6. Click Next



## Building From Source

Requirements:
- Java 17+
- Maven

```bash
git clone https://github.com/ismailsanan/SecHeaderScout
cd SecHeaderScout
mvn clean package
```

JAR will be in `target/SecHeaderScout.jar`


