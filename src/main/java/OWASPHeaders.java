import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.*;

<<<<<<< Updated upstream
public class OWASPHeaders {
=======
/**
 * the OWASP recommended header list plus the logic that decides
 * which of them actually apply to a given response
 */
public class OWASPHeaders {

    private static final String OWASP_JSON_URL =
            "https://raw.githubusercontent.com/OWASP/www-project-secure-headers/master/ci/headers_add.json";

    // STRICT_MODE = true  —> report the full OWASP list on every response
    // STRICT_MODE = false —> report only what pentesters and the major scanners
    //                        (securityheaders.com, Mozilla Observatory) actually
    //                        treat as findings, which is the default
    public static final boolean STRICT_MODE = false;
>>>>>>> Stashed changes

    private final MontoyaApi api;

    // hardcoded descriptions if OWASP github fails for some specific reason
    // LinkedHashMap keeps them in a sensible order in reports
    private static final Map<String, HeaderInfo> HEADER_INFO = buildHeaderInfo();

    private static Map<String, HeaderInfo> buildHeaderInfo() {
        Map<String, HeaderInfo> m = new LinkedHashMap<>();

        m.put("content-security-policy", new HeaderInfo(
                "content-security-policy",
                "Controls which resources the browser may load, the strongest browser side defence against XSS",
                "default-src 'self'; form-action 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; upgrade-insecure-requests",
                "Stored and reflected XSS execute unrestricted, injected scripts can exfiltrate to any origin"));

        m.put("strict-transport-security", new HeaderInfo(
                "strict-transport-security",
                "Forces the browser to use HTTPS for the domain for a fixed period",
                "max-age=63072000; includeSubDomains",
                "Protocol downgrade and SSL stripping on the first or any subsequent request, session cookie theft"));

        m.put("x-frame-options", new HeaderInfo(
                "x-frame-options",
                "Stops the page being loaded inside a frame on another origin",
                "deny",
                "Clickjacking, UI redress attacks against authenticated actions"));

        m.put("x-content-type-options", new HeaderInfo(
                "x-content-type-options",
                "Stops the browser guessing a MIME type different from the declared one",
                "nosniff",
                "MIME confusion, an uploaded file served as text/plain can be executed as script"));

        m.put("referrer-policy", new HeaderInfo(
                "referrer-policy",
                "Controls how much of the current URL is sent in the Referer header",
                "no-referrer",
                "Session tokens, reset tokens and internal paths in query strings leak to third parties"));

        m.put("permissions-policy", new HeaderInfo(
                "permissions-policy",
                "Restricts which browser features the page and its frames may use",
                "geolocation=(), camera=(), microphone=(), payment=(), usb=(), fullscreen=()",
                "Embedded third party frames can request camera, mic or geolocation on your origin"));

        m.put("cache-control", new HeaderInfo(
                "cache-control",
                "Controls whether the response may be written to a cache",
                "no-store, max-age=0",
                "Sensitive responses persist in the browser disk cache and can be read by any local process"));

        m.put("cross-origin-opener-policy", new HeaderInfo(
                "cross-origin-opener-policy",
                "Isolates the browsing context from cross origin windows",
                "same-origin",
                "Cross window scripting via window.opener, tabnabbing, XS-Leaks"));

        m.put("cross-origin-resource-policy", new HeaderInfo(
                "cross-origin-resource-policy",
                "Blocks other origins from loading this resource with a no-cors request",
                "same-origin",
                "Side channel resource inclusion, cross origin data reads via speculative execution"));

        m.put("clear-site-data", new HeaderInfo(
                "clear-site-data",
                "Instructs the browser to clear cookies, storage and cache, intended for logout",
                "\"cache\", \"cookies\", \"storage\"",
                "Session artefacts survive logout on shared machines"));

        m.put("cross-origin-embedder-policy", new HeaderInfo(
                "cross-origin-embedder-policy",
                "Requires cross origin resources to opt in before they can be embedded",
                "require-corp",
                "Cross origin isolation unavailable, only relevant if the app needs SharedArrayBuffer"));

        m.put("x-permitted-cross-domain-policies", new HeaderInfo(
                "x-permitted-cross-domain-policies",
                "Controls Adobe Flash and Acrobat cross domain data loading",
                "none",
                "Legacy Flash cross domain data access, Flash reached end of life in December 2020"));

        m.put("x-dns-prefetch-control", new HeaderInfo(
                "x-dns-prefetch-control",
                "Disables speculative DNS resolution of links on the page",
                "off",
                "DNS based exfiltration via injected link rel=dns-prefetch tags, and link disclosure to the resolver"));

        return m;
    }

    // full OWASP list, used when STRICT_MODE is on
    public static final List<String> ALL_HEADERS = List.copyOf(HEADER_INFO.keySet());

    public OWASPHeaders(MontoyaApi api) {
        this.api = api;
    }

    // ══════════════════════════════════════════════════════════════════════
    // which headers are actually required for THIS response
    // ══════════════════════════════════════════════════════════════════════
    //
    // grounded in what the major scanners score and what appears in real reports
    //
    //   securityheaders.com checks 6  —> CSP, HSTS, XFO, XCTO, Referrer-Policy, Permissions-Policy
    //   Mozilla Observatory penalties —> CSP -25, HSTS -20, XFO -20
    //                                    Referrer-Policy missing scores 0 and PASSES
    //   OWASP itself scopes three of its own headers:
    //     Clear-Site-Data        "set it to the logout function when possible"
    //     Cache-Control          tied to responses holding sensitive information
    //     X-DNS-Prefetch-Control tied to responses returning PII or prone to HTML injection
    //
    // COEP is excluded because require-corp breaks any site loading third party
    // resources, most applications deliberately do not set it
    //
    public static List<String> requiredFor(ScanContext ctx) {
        if (STRICT_MODE) return ALL_HEADERS;

<<<<<<< Updated upstream
// check if the url classifer is API then use API headers
    public static List<String> headersForUrlType(UrlClassifier.UrlType type) {
        if (type == UrlClassifier.UrlType.API) {
            return API_HEADERS;
        }
        return FALLBACK_HEADERS;
=======
        List<String> required = new ArrayList<>();

        // applies to literally every response, trivial to set, real MIME risk
        required.add("x-content-type-options");

        // browsers ignore HSTS over plain HTTP (RFC 6797) so only require it on HTTPS
        if (ctx.isHttps()) required.add("strict-transport-security");

        // static assets need nothing else
        if (ctx.urlType() == UrlClassifier.UrlType.STATIC) return required;

        // CSP applies wherever a browser executes content
        required.add("content-security-policy");

        if (ctx.isHtml()) {
            // CSP frame-ancestors supersedes XFO, dont report both
            if (!ctx.cspCoversFraming()) required.add("x-frame-options");
            required.add("referrer-policy");
            required.add("permissions-policy");
            required.add("cross-origin-opener-policy");
        }

        if (ctx.urlType() == UrlClassifier.UrlType.API) {
            required.add("cross-origin-resource-policy");
        }

        // OWASP ties this to sensitive content, not to every response
        // Set-Cookie is the strongest available signal that a response is authenticated
        if (ctx.isSensitive() || ctx.setsCookie()) {
            required.add("cache-control");
        }

        // OWASP: "set it to the logout function when possible"
        if (ctx.urlType() == UrlClassifier.UrlType.LOGOUT && ctx.isHttps()) {
            required.add("clear-site-data");
        }

        // OWASP scopes this to responses returning PII or prone to HTML injection
        if (ctx.isSensitive() && ctx.isHtml()) {
            required.add("x-dns-prefetch-control");
        }

        return required;
>>>>>>> Stashed changes
    }

    public static HeaderInfo getInfo(String headerName) {
        return HEADER_INFO.getOrDefault(
                headerName.toLowerCase(),
                new HeaderInfo(headerName,
                        "See the OWASP Secure Headers Project",
                        "See OWASP documentation",
                        "Unknown"));
    }

    // ══════════════════════════════════════════════════════════════════════
    // dynamic fetch
    // ══════════════════════════════════════════════════════════════════════

    // pulls the current OWASP list so the extension stays current if OWASP adds a header
    // the local HEADER_INFO map still supplies descriptions and risk text
    public List<String> fetchHeaders() {
        try {
            HttpRequest request = HttpRequest.httpRequestFromUrl(OWASP_JSON_URL);
            HttpRequestResponse interaction = sendWithTimeout(request, 5);

            if (interaction == null || !interaction.hasResponse()
                    || interaction.response().statusCode() != 200) {
                api.logging().logToOutput("[OWASP] fetch failed —> using built in list");
                return ALL_HEADERS;
            }

            String body = interaction.response().bodyToString();

            if (!api.utilities().jsonUtils().isValidJson(body)) {
                api.logging().logToOutput("[OWASP] response was not valid JSON —> using built in list");
                return ALL_HEADERS;
            }

            List<String> headers = new ArrayList<>();

            // jsonUtils is JSONPath based with no array length helper
            // so we walk indexes until the path stops resolving
            for (int i = 0; i < 100; i++) {
                String name;
                try {
                    name = api.utilities().jsonUtils()
                            .readString(body, "$.headers[" + i + "].name");
                } catch (Exception e) {
                    break;
                }
                if (name == null || name.isBlank()) break;
                headers.add(name.trim().toLowerCase());
            }

            if (headers.isEmpty()) {
                api.logging().logToOutput("[OWASP] nothing parsed —> using built in list");
                return ALL_HEADERS;
            }

            api.logging().logToOutput("[OWASP] fetched " + headers.size() + " headers from OWASP");
            return headers;

        } catch (Exception e) {
            api.logging().logToOutput("[OWASP] error: " + e.getMessage() + " —> using built in list");
            return ALL_HEADERS;
        }
    }

    // fetchHeaders runs inside initialize() so a slow GitHub would stall extension loading
    private HttpRequestResponse sendWithTimeout(HttpRequest request, int seconds) {
        ExecutorService executor = Executors.newSingleThreadExecutor();
        try {
            Future<HttpRequestResponse> future =
                    executor.submit(() -> api.http().sendRequest(request));
            return future.get(seconds, TimeUnit.SECONDS);
        } catch (Exception e) {
            return null;
        } finally {
            executor.shutdownNow();
        }
    }
}