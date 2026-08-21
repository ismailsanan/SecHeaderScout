import java.util.Map;

/**
 * everything a check needs to know about the response
 * built once per response and passed to every checker
 *
 */
public record ScanContext(
        UrlClassifier.UrlType urlType,
        String contentType,
        boolean isHttps,
        int statusCode,
        Map<String, String> headers   // lowercased name -> lowercased value
) {

    // CSP, X-Frame-Options and Permissions-Policy only matter for rendered content
    public boolean isHtml() {
        if (contentType == null) return urlType != UrlClassifier.UrlType.API
                && urlType != UrlClassifier.UrlType.STATIC;
        return contentType.contains("text/html") || contentType.contains("application/xhtml");
    }

    public boolean isJson() {
        return contentType != null &&
                (contentType.contains("application/json") || contentType.contains("+json"));
    }

    // login, logout, admin, payment, api
    public boolean isSensitive() {
        return UrlClassifier.isSensitive(urlType);
    }

    // the server handed out a session, so this response is part of an auth flow
    // strongest signal available that the response holds something worth protecting
    public boolean setsCookie() {
        return headers.containsKey("set-cookie");
    }

    public boolean isRedirect() {
        return statusCode >= 300 && statusCode < 400;
    }

    public String header(String name) {
        return headers.get(name);
    }

    public boolean has(String name) {
        return headers.containsKey(name);
    }

    // CSP frame-ancestors supersedes X-Frame-Options (CSP Level 2)
    // browsers supporting frame-ancestors ignore XFO entirely
    // so flagging XFO as missing when CSP covers it is a false positive
    public boolean cspCoversFraming() {
        String csp = headers.get("content-security-policy");
        return csp != null && csp.contains("frame-ancestors");
    }
}