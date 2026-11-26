# Release notes

## 2.1.0

### New
- **Send to SecHeaderScout**: right-click one or more requests anywhere in Burp (Proxy history, site map,
  Repeater, ...) to add them as targets. They are selected and ready for Quick Scan or Deep Scan.
- **Request / Response tabs** next to Details: Burp's own read-only message viewer (Pretty / Raw / Hex) shows
  exactly the request sent and the response received for the selected result, as evidence. Each message is
  kept up to 32 KB.

### Changed
- **By URL** now uses the same layout as **By profile**: Host, Path, Type, Protocol, Status, Missing (header
  names), Misconfigured, Worst.
- **Details**: misconfigured headers no longer show a severity; their problems are nested under each header.
  Section counts and the "Notes" section are gone.
- **Copy for report** produces one plain-text list across all results, with no hosts or URLs:
  "There exist some HTTP response headers that can increase the security posture of a web application.
  One or more of the following security headers are missing: • ..." followed by the misconfigured headers
  and their problems. HTTP-fallback warnings, incomplete evaluations and unanalysed URLs are no longer included.
- **Export Report** starts with that same summary, lists each URL in the Details layout (no notes, no severity on
  misconfigurations) and includes the request and response in collapsible sections. Reports still load in
  Rescan & Compare.
- **Rescan & Compare** results are grouped per URL as bullet lists (Fixed, Still missing, New issues, ...).
- Removed the "OWASP security header checker" title from the tab.

### Notes
- Exports of large Deep Scans are bigger now that they carry the request and response (up to about 64 KB per URL).
