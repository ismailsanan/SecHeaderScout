# SecHeaderScout

A Burp Suite extension that automatically detects missing OWASP 
recommended security headers in HTTP responses.

---

## Features

- Automatically reads targets from Burp's site map
- Supports adding custom targets manually
- Checks against all OWASP recommended security headers
- Clean results panel showing missing headers per host
- Runs scans in background without freezing Burp

---

## OWASP Headers Checked

| Header | Description |
|--------|-------------|
| Content-Security-Policy | Prevents XSS and injection attacks |
| X-Frame-Options | Prevents clickjacking |
| X-Content-Type-Options | Prevents MIME sniffing |
| Strict-Transport-Security | Enforces HTTPS |
| Referrer-Policy | Controls referrer information |
| Permissions-Policy | Controls browser features |
| Cross-Origin-Opener-Policy | Controls cross-origin window access |
| Cross-Origin-Resource-Policy | Controls cross-origin resource sharing |

---

## Installation

### From BApp Store
1. Open Burp Suite
2. Go to Extensions → BApp Store
3. Search for SecHeaderScout
4. Click Install

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
git clone https://github.com/yourusername/SecHeaderScout.git
cd SecHeaderScout
mvn clean package
```

JAR will be in `target/SecHeaderScout.jar`

---

## Usage

1. Browse your target application through Burp Proxy
2. Open the SecHeaderScout tab in Burp
3. Click Refresh from Burp to load discovered hosts
4. Or add a custom target manually
5. Select one or more hosts
6. Click Scan Selected or Scan All
7. Review missing headers in the results panel

---

## Requirements

- Burp Suite Community or Pro
- Java 17+

---

## License

MIT License — see LICENSE file for details
