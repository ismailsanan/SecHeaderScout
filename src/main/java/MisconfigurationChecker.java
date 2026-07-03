import java.util.ArrayList;
import java.util.List;

public class MisconfigurationChecker {

    public static List<String> check(String headerName, String headerValue, UrlClassifier.UrlType urlType) {
        List<String> issues = new ArrayList<>();
        String name  = headerName.toLowerCase().trim();
        String value = headerValue.toLowerCase().trim();

        switch (name) {

            // always checked regardless of URL type
            case "strict-transport-security":
                checkHSTS(value, issues);
                break;

            case "cache-control":
                checkCacheControl(value, issues);
                break;

            case "referrer-policy":
                checkReferrerPolicy(value, issues);
                break;

            case "cross-origin-resource-policy":
                checkCORP(value, issues);
                break;

            case "cross-origin-opener-policy":
                checkCOOP(value, issues);
                break;

            case "x-content-type-options":
                checkXContentTypeOptions(value, issues);
                break;

            case "x-dns-prefetch-control":
                checkDNSPrefetch(value, issues);
                break;

            case "x-permitted-cross-domain-policies":
                checkCrossDomainPolicies(value, issues);
                break;

            case "clear-site-data":
                checkClearSiteData(value, issues);
                break;

            // HTML only checks —> skipped for API endpoints
            // APIs return JSON so CSP framing and permissions dont need client side checks
            case "content-security-policy":
                if (urlType != UrlClassifier.UrlType.API) checkCSP(value, issues);
                break;

            case "x-frame-options":
                if (urlType != UrlClassifier.UrlType.API) checkXFrameOptions(value, issues);
                break;

            case "permissions-policy":
                if (urlType != UrlClassifier.UrlType.API) checkPermissionsPolicy(value, issues);
                break;
        }

        return issues;
    }


    private static void checkClearSiteData(String value, List<String> issues) {
        if (!value.contains("cookies"))
            issues.add("Clear-Site-Data missing 'cookies' —> session cookies not cleared on logout");

        if (!value.contains("storage"))
            issues.add("Clear-Site-Data missing 'storage' —> localStorage and sessionStorage not cleared on logout");

        if (!value.contains("cache"))
            issues.add("Clear-Site-Data missing 'cache' —> cached responses not cleared on logout");
    }


    private static void checkCSP(String value, List<String> issues) {
        if (value.contains("unsafe-inline")) {
            issues.add("CSP contains 'unsafe-inline' —> allows inline scripts, XSS possible");
        }
        if (value.contains("unsafe-eval")) {
            issues.add("CSP contains 'unsafe-eval' —> allows eval(), XSS possible");
        }
        if (value.contains("*")) {
            issues.add("CSP contains wildcard '*' —> allows resources from any origin");
        }
        if (!value.contains("default-src")) {
            issues.add("CSP missing 'default-src' —> no fallback policy defined");
        }
        if (value.contains("http://")) {
            issues.add("CSP allows HTTP sources —> insecure resources permitted");
        }
    }


    private static void checkPermissionsPolicy(String value, List<String> issues) {
        if (value.equals("*") || value.contains("=*"))
            issues.add("Permissions-Policy uses wildcard —> grants all features to all origins");

        if (value.contains("camera=*") || value.contains("camera=(*)"))
            issues.add("Permissions-Policy allows camera access from all origins");

        if (value.contains("microphone=*") || value.contains("microphone=(*)"))
            issues.add("Permissions-Policy allows microphone access from all origins");

        if (value.contains("geolocation=*") || value.contains("geolocation=(*)"))
            issues.add("Permissions-Policy allows geolocation access from all origins");
    }


    private static void checkCORP(String value, List<String> issues) {
        if (value.equals("cross-origin"))
            issues.add("Cross-Origin-Resource-Policy set to 'cross-origin' —> allows any site to load this resource");

        if (!value.equals("same-origin") && !value.equals("same-site") && !value.equals("cross-origin"))
            issues.add("Cross-Origin-Resource-Policy has unexpected value —> expected same-origin or same-site");
    }

    private static void checkCOOP(String value, List<String> issues) {
        if (value.equals("unsafe-none"))
            issues.add("Cross-Origin-Opener-Policy set to 'unsafe-none' —> origin isolation disabled");

        if (value.equals("same-origin-allow-popups"))
            issues.add("Cross-Origin-Opener-Policy set to 'same-origin-allow-popups' —> popups can bypass isolation");
    }

    private static void checkXContentTypeOptions(String value, List<String> issues) {
        if (!value.equals("nosniff"))
            issues.add("X-Content-Type-Options has unexpected value '" + value + "' —> only 'nosniff' is valid");
    }


    private static void checkDNSPrefetch(String value, List<String> issues) {
        if (value.equals("on"))
            issues.add("X-DNS-Prefetch-Control set to 'on' —> DNS prefetching enabled leaks link information");
    }

    private static void checkCrossDomainPolicies(String value, List<String> issues) {
        if (value.equals("all") || value.equals("master-only"))
            issues.add("X-Permitted-Cross-Domain-Policies set to '" + value + "' —> allows cross-domain data loading should be 'none'");
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
            issues.add("X-Frame-Options uses deprecated 'ALLOW-FROM' directive —> use CSP frame-ancestors instead");
        }
        if (!value.contains("deny") && !value.contains("sameorigin")) {
            issues.add("X-Frame-Options has unexpected value —> use DENY or SAMEORIGIN");
        }
    }

    private static void checkReferrerPolicy(String value, List<String> issues) {
        if (value.contains("unsafe-url")) {
            issues.add("Referrer-Policy set to 'unsafe-url' —> sends full URL as referrer");
        }
        if (value.contains("no-referrer-when-downgrade")) {
            issues.add("Referrer-Policy set to 'no-referrer-when-downgrade' —> leaks URLs over HTTP");
        }
    }

    private static void checkCacheControl(String value, List<String> issues) {
        if (!value.contains("no-store")) {
            issues.add("Cache-Control missing 'no-store' —> sensitive data may be cached");
        }
        if (value.contains("public")) {
            issues.add("Cache-Control set to 'public' —> response may be cached by proxies");
        }
    }
}