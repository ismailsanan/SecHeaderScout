# SecHeaderScout

A Burp Suite extension that automatically detects missing OWASP recommended security headers in HTTP responses

Because let’s be honest why manually check security headers when you can automate it and be lazier?

## What It Does
```
Reads targets from Burp site map or you can insert custom hosts  → sends request → checks headers → reports missing
```

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
---

## Installation

Currently not available on the Burp BApp Store.

If you're from PortSwigger and reading this feel free to make it happen 👀

### Manual Installation
1. Download the latest JAR from releases
2. Open Burp Suite
3. Go to Extensions → Add
4. Select Java as extension type
5. Select the downloaded JAR
6. Click Next

---

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

---
