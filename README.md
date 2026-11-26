<p align="center">
 <img width="1942" height="809" alt="SecHeaderScout logo" src="https://github.com/user-attachments/assets/2135b846-ad4f-4c29-aac1-16e249cda606" />
</p>

<p align="center">
   A Burp Suite extension for auditing OWASP recommended security headers across your entire application.
</p>

---

Because let's be honest why manually check security headers when you can automate it and be lazier?

## What It Does

Quick Scan  -> sends a request to each target, checks the response headers

Deep Scan   -> reads every response already captured in Burp's site map, analyzes headers per URL with no new requests

Passive     -> reports header issues straight to Burp's Issues panel while you browse (Professional / Enterprise)

Reads targets from Burp's site map, custom hosts, or a right-click **Send to SecHeaderScout** on any request → checks headers → reports missing or misconfigured

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

The header list comes from the [OWASP Secure Headers Project](https://github.com/OWASP/www-project-secure-headers) and is bundled in the JAR, so it works offline. **Sync OWASP Headers** pulls the latest list on demand.

---

## Features

- Quick Scan and Deep Scan
- Right-click any request in Burp → **Send to SecHeaderScout**
- Flags misconfigured headers, not just missing ones
- **Request / Response** tabs showing exactly what was sent and received, as evidence
- Deep Scan groups URLs with the same issues (`/api/*`, 40 URLs) in the **By profile** tab
- Highlights critical URLs (login, logout, admin, api, payment)
- Overall security score for each scan
- **Copy for report**: one plain-text list of missing and misconfigured headers, ready for your pentest report
- Export results as an HTML report
- Rescan & Compare against a previous report to track progress

---

## Installation

Currently not available on the Burp BApp Store YET...

### Manual Installation
1. Download the latest JAR from releases
2. Open Burp Suite
3. Go to Extensions → Add
4. Select Java as extension type
5. Select the downloaded JAR
6. Click Next

Works on Burp Suite 2026.2 or later. Community Edition has no scanner, so only the SecHeaderScout tab is available there.

## Building From Source

Requirements:
- JDK 17+
- Maven

```bash
git clone https://github.com/ismailsanan/SecHeaderScout
cd SecHeaderScout
mvn clean package
```

JAR will be in `target/SecHeaderScout.jar`

## License

See [LICENSE](LICENSE).
