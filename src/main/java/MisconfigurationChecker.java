import java.util.ArrayList;
import java.util.List;

public class MisconfigurationChecker {

    public static List<String> check(String headerName, String headerValue) {
        List<String> issues = new ArrayList<>();
        String name = headerName.toLowerCase();
        String value = headerValue.toLowerCase();

        switch (name) {

            case "content-security-policy":
                checkCSP(value, issues);
                break;

            case "strict-transport-security":
                checkHSTS(value, issues);
                break;

            case "x-frame-options":
                checkXFrameOptions(value, issues);
                break;

            case "referrer-policy":
                checkReferrerPolicy(value, issues);
                break;

            case "cache-control":
                checkCacheControl(value, issues);
                break;
        }

        return issues;
    }

    private static void checkCSP(String value, List<String> issues) {
        if (value.contains("unsafe-inline")) {
            issues.add("CSP contains 'unsafe-inline' — allows inline scripts, XSS possible");
        }
        if (value.contains("unsafe-eval")) {
            issues.add("CSP contains 'unsafe-eval' — allows eval(), XSS possible");
        }
        if (value.contains("*")) {
            issues.add("CSP contains wildcard '*' — allows resources from any origin");
        }
        if (!value.contains("default-src")) {
            issues.add("CSP missing 'default-src' — no fallback policy defined");
        }
        if (value.contains("http://")) {
            issues.add("CSP allows HTTP sources — insecure resources permitted");
        }
    }

    private static void checkHSTS(String value, List<String> issues) {
        if (!value.contains("max-age")) {
            issues.add("HSTS missing 'max-age' directive");
            return;
        }

        // extract max-age value
        try {
            String[] parts = value.split(";");
            for (String part : parts) {
                if (part.trim().startsWith("max-age")) {
                    int maxAge = Integer.parseInt(
                            part.trim().replace("max-age=", "").trim()
                    );
                    if (maxAge < 31536000) {
                        issues.add("HSTS max-age is less than 1 year (recommended: 31536000)");
                    }
                }
            }
        } catch (Exception e) {
            issues.add("HSTS max-age value could not be parsed");
        }

        if (!value.contains("includesubdomains")) {
            issues.add("HSTS missing 'includeSubDomains' directive");
        }
    }

    private static void checkXFrameOptions(String value, List<String> issues) {
        if (value.contains("allow-from")) {
            issues.add("X-Frame-Options uses deprecated 'ALLOW-FROM' directive — use CSP frame-ancestors instead");
        }
        if (!value.contains("deny") && !value.contains("sameorigin")) {
            issues.add("X-Frame-Options has unexpected value — use DENY or SAMEORIGIN");
        }
    }

    private static void checkReferrerPolicy(String value, List<String> issues) {
        if (value.contains("unsafe-url")) {
            issues.add("Referrer-Policy set to 'unsafe-url' — sends full URL as referrer");
        }
        if (value.contains("no-referrer-when-downgrade")) {
            issues.add("Referrer-Policy set to 'no-referrer-when-downgrade' — leaks URLs over HTTP");
        }
    }

    private static void checkCacheControl(String value, List<String> issues) {
        if (!value.contains("no-store")) {
            issues.add("Cache-Control missing 'no-store' — sensitive data may be cached");
        }
        if (value.contains("public")) {
            issues.add("Cache-Control set to 'public' — response may be cached by proxies");
        }
    }
}