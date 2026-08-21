import java.util.ArrayList;
import java.util.List;

/**
 * checks header VALUES, not presence
 *
 * the CSP directive checks come straight from the OWASP Secure Headers Project
 * "Prevent CSP bypasses" section, which documents that form-action, base-uri
 * and frame-ancestors do NOT fall back to default-src
 */
public class MisconfigurationChecker {

    public static List<String> check(String headerName, String headerValue, ScanContext ctx) {
        List<String> issues = new ArrayList<>();

        if (headerName == null || headerValue == null) return issues;

        String name  = headerName.toLowerCase().trim();
        String value = headerValue.toLowerCase().trim();

        if (value.isEmpty()) {
            issues.add("header is present but empty");
            return issues;
        }

        switch (name) {
            case "content-security-policy":       checkCSP(value, ctx, issues); break;
            case "strict-transport-security":     checkHSTS(value, ctx, issues); break;
            case "x-frame-options":               checkXFrameOptions(value, issues); break;
            case "x-content-type-options":        checkXContentTypeOptions(value, issues); break;
            case "referrer-policy":               checkReferrerPolicy(value, issues); break;
            case "cache-control":                 checkCacheControl(value, ctx, issues); break;
            case "permissions-policy":            checkPermissionsPolicy(value, issues); break;
            case "cross-origin-resource-policy":  checkCORP(value, ctx, issues); break;
            case "cross-origin-opener-policy":    checkCOOP(value, ctx, issues); break;
            case "clear-site-data":               checkClearSiteData(value, ctx, issues); break;
            case "x-dns-prefetch-control":        checkDNSPrefetch(value, issues); break;
            case "x-permitted-cross-domain-policies": checkCrossDomainPolicies(value, issues); break;
            case "x-xss-protection":              checkXssProtection(value, issues); break;
            case "set-cookie":                    checkSetCookie(value, ctx, issues); break;
        }

        return issues;
    }

    //  CSP 

    private static void checkCSP(String value, ScanContext ctx, List<String> issues) {

        // the classics
        if (value.contains("'unsafe-inline'") || value.contains("unsafe-inline"))
            issues.add("contains 'unsafe-inline' —> inline scripts execute, XSS protection is effectively void");

        if (value.contains("unsafe-eval"))
            issues.add("contains 'unsafe-eval' —> eval() and Function() allowed, common XSS sink stays open");

        if (value.contains("unsafe-hashes"))
            issues.add("contains 'unsafe-hashes' —> inline event handlers allowed");

        if (hasBareWildcard(value))
            issues.add("uses a bare '*' source —> resources load from any origin, policy provides no restriction");

        if (value.contains("http://"))
            issues.add("allows http:// sources —> policy permits resources over cleartext");

        // OWASP documented bypasses, these directives do NOT inherit from default-src
        // each of these has a demo video on the OWASP Secure Headers Project site
        if (!value.contains("form-action"))
            issues.add("missing 'form-action' —> a form can be injected that posts to an attacker origin, this directive does not fall back to default-src");

        if (!value.contains("base-uri"))
            issues.add("missing 'base-uri' —> an injected <base> tag can rewrite every relative script path, this directive does not fall back to default-src");

        if (!value.contains("frame-ancestors"))
            issues.add("missing 'frame-ancestors' —> framing is controlled only by X-Frame-Options, this directive does not fall back to default-src");
        else if (value.contains("frame-ancestors *"))
            issues.add("'frame-ancestors *' —> any origin may frame the page, clickjacking possible");

        if (!value.contains("default-src") && !value.contains("script-src"))
            issues.add("neither 'default-src' nor 'script-src' set —> no script policy at all");

        if (!value.contains("object-src") && !value.contains("default-src"))
            issues.add("missing 'object-src' —> plugin content unrestricted");

        // a report-only policy enforces nothing, easy to miss in a header dump
        if (ctx.has("content-security-policy-report-only") && !ctx.has("content-security-policy"))
            issues.add("policy is report-only —> violations are logged but nothing is blocked");
    }

    // walks each directive token so *.cdn.example.com is not treated as a bare wildcard
    private static boolean hasBareWildcard(String csp) {
        for (String directive : csp.split(";")) {
            for (String token : directive.trim().split("\\s+")) {
                if (token.equals("*")) return true;
            }
        }
        return false;
    }

    //  HSTS 
    // OWASP now proposes max-age=63072000 (2 years)
    // Mozilla Observatory fails anything under 6 months

    private static void checkHSTS(String value, ScanContext ctx, List<String> issues) {
        if (!ctx.isHttps()) return;  // RFC 6797, ignored over cleartext

        if (!value.contains("max-age")) {
            issues.add("missing 'max-age' —> the header does nothing without it");
            return;
        }

        try {
            for (String part : value.split(";")) {
                part = part.trim();
                if (!part.startsWith("max-age")) continue;

                long maxAge = Long.parseLong(part.replace("max-age=", "").trim());

                if (maxAge == 0)
                    issues.add("max-age=0 —> HSTS is explicitly disabled, browsers drop the pin");
                else if (maxAge < 15768000)  // 6 months, Mozilla Observatory fail threshold
                    issues.add("max-age=" + maxAge + " is under 6 months —> Mozilla Observatory fails this, OWASP proposes 63072000");
                else if (maxAge < 31536000)
                    issues.add("max-age=" + maxAge + " is under 1 year —> OWASP proposes 63072000 (2 years)");
            }
        } catch (NumberFormatException e) {
            issues.add("max-age could not be parsed —> the header may be ignored entirely");
        }

        if (!value.contains("includesubdomains"))
            issues.add("missing 'includeSubDomains' —> a subdomain served over HTTP can still set cookies for the parent domain");

        // duplicate HSTS headers are a real world bug, Observatory treats it as invalid
        if (value.split("max-age").length > 2)
            issues.add("multiple max-age directives in one header —> browsers may reject the whole policy");
    }

    //  X-Frame-Options

    private static void checkXFrameOptions(String value, List<String> issues) {
        if (value.contains("allow-from")) {
            issues.add("uses deprecated 'ALLOW-FROM' —> ignored by every modern browser, framing is unprotected, use CSP frame-ancestors");
            return;
        }
        if (!value.equals("deny") && !value.equals("sameorigin"))
            issues.add("unexpected value '" + value + "' —> browsers ignore unrecognised values, expected DENY or SAMEORIGIN");
    }

    //  X-Content-Type-Options

    private static void checkXContentTypeOptions(String value, List<String> issues) {
        if (!value.equals("nosniff"))
            issues.add("value is '" + value + "' —> only 'nosniff' is recognised, MIME sniffing is still active");
    }

    //  Referrer-Policy

    private static void checkReferrerPolicy(String value, List<String> issues) {
        if (value.contains("unsafe-url"))
            issues.add("'unsafe-url' —> full URL including query string sent to every origin, tokens in URLs leak");

        if (value.contains("no-referrer-when-downgrade"))
            issues.add("'no-referrer-when-downgrade' —> full URL still sent on cross origin HTTPS requests");

        if (value.equals("origin-when-cross-origin") || value.equals("origin"))
            issues.add("'" + value + "' —> origin is still disclosed cross site, OWASP proposes no-referrer");
    }

    //  Cache-Control 
    // OWASP scopes this to responses holding sensitive information
    // demanding no-store on a public page or a stylesheet is not a finding

    private static void checkCacheControl(String value, ScanContext ctx, List<String> issues) {
        if (!ctx.isSensitive() && !ctx.setsCookie()) return;

        if (!value.contains("no-store"))
            issues.add("missing 'no-store' on a sensitive response —> the body is written to the browser disk cache and readable by any local process");

        if (value.contains("public"))
            issues.add("'public' on a sensitive response —> shared proxies and CDNs may cache and serve it to other users");

        // the single most common misunderstanding in this area
        if (value.contains("no-cache") && !value.contains("no-store"))
            issues.add("'no-cache' without 'no-store' —> no-cache only forces revalidation, the response is still written to disk");

        if (!value.contains("max-age=0") && !value.contains("no-store"))
            issues.add("no 'max-age=0' —> existing cached copies are not expired, OWASP proposes 'no-store, max-age=0'");
    }

    //  Permissions-Policy 

    private static void checkPermissionsPolicy(String value, List<String> issues) {
        if (value.equals("*"))
            issues.add("'*' —> every browser feature granted to every origin");

        for (String feature : new String[]{"camera", "microphone", "geolocation", "payment", "usb"}) {
            if (value.contains(feature + "=*") || value.contains(feature + "=(*)"))
                issues.add("'" + feature + "' allowed from all origins —> an embedded frame can request it on your origin");
        }
    }

    //  CORP 

    private static void checkCORP(String value, ScanContext ctx, List<String> issues) {
        boolean known = value.equals("same-origin") || value.equals("same-site") || value.equals("cross-origin");

        if (!known) {
            issues.add("unexpected value '" + value + "' —> expected same-origin, same-site or cross-origin");
            return;
        }

        // cross-origin is legitimate for a public CDN asset, not for an API response
        if (value.equals("cross-origin") && ctx.urlType() != UrlClassifier.UrlType.STATIC)
            issues.add("'cross-origin' —> any site may load this resource, the header provides no protection here");
    }

    //  COOP 

    private static void checkCOOP(String value, ScanContext ctx, List<String> issues) {
        if (value.equals("unsafe-none"))
            issues.add("'unsafe-none' —> isolation explicitly disabled, identical to omitting the header");

        if (value.equals("same-origin-allow-popups") && ctx.isSensitive())
            issues.add("'same-origin-allow-popups' on a sensitive endpoint —> a popup retains a window reference back to this page");
    }

    //  Clear-Site-Data 
    // only meaningful on logout, and only processed over HTTPS
    // "*" is valid shorthand for everything so it is not a finding

    private static void checkClearSiteData(String value, ScanContext ctx, List<String> issues) {
        if (ctx.urlType() != UrlClassifier.UrlType.LOGOUT) return;
        if (value.contains("*")) return;

        if (!value.contains("cookies"))
            issues.add("missing \"cookies\" —> session cookies survive logout");

        if (!value.contains("storage"))
            issues.add("missing \"storage\" —> localStorage and sessionStorage survive logout, tokens often live there");

        if (!value.contains("cache"))
            issues.add("missing \"cache\" —> cached authenticated pages remain reachable via the back button");
    }

    //  low value headers, only checked when actually present 

    private static void checkDNSPrefetch(String value, List<String> issues) {
        if (value.equals("on"))
            issues.add("'on' —> prefetching explicitly enabled, an injected <link rel=dns-prefetch> can exfiltrate over DNS");
    }

    private static void checkCrossDomainPolicies(String value, List<String> issues) {
        if (value.equals("all") || value.equals("master-only"))
            issues.add("'" + value + "' —> permits cross domain policy files, OWASP proposes 'none'");
    }

    // present is worse than absent 
    // Chrome removed the XSS Auditor in v78 because it was itself exploitable
    // for cross origin content detection, the guidance is to send 0 or omit it

    private static void checkXssProtection(String value, List<String> issues) {
        if (value.startsWith("1"))
            issues.add("XSS Auditor enabled —> deprecated and itself exploitable for XS-Leaks, set to '0' or remove the header");
    }

    //  Set-Cookie 
    // cookie flags are the single most common real finding alongside headers
    // securityheaders.com does not check this, Mozilla Observatory does

    private static void checkSetCookie(String value, ScanContext ctx, List<String> issues) {
        // only session-ish cookies are worth flagging, skip obvious tracking junk
        boolean looksLikeSession = value.contains("session") || value.contains("sess")
                || value.contains("token") || value.contains("auth")
                || value.contains("jsessionid") || value.contains("phpsessid")
                || value.contains("asp.net_sessionid");

        if (!looksLikeSession && !ctx.isSensitive()) return;

        if (ctx.isHttps() && !value.contains("secure"))
            issues.add("cookie missing 'Secure' —> transmitted over cleartext if the user hits an http:// URL");

        if (!value.contains("httponly"))
            issues.add("cookie missing 'HttpOnly' —> readable by JavaScript, any XSS becomes session theft");

        if (!value.contains("samesite"))
            issues.add("cookie missing 'SameSite' —> browser default is Lax, set it explicitly, use Strict for session cookies");
        else if (value.contains("samesite=none") && !value.contains("secure"))
            issues.add("cookie has 'SameSite=None' without 'Secure' —> browsers reject the cookie entirely");
    }
}