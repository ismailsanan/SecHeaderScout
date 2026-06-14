import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;


import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class OWASPHeaders {

    private final MontoyaApi api;

    // hardcoded descriptions if OWASP github fails for some specific reason
    private static final Map<String, HeaderInfo> HEADER_INFO = Map.ofEntries(
            Map.entry("content-security-policy", new HeaderInfo(
                    "content-security-policy",
                    "Prevents XSS and code injection attacks by controlling which resources the browser is allowed to load",
                    "default-src 'self'; script-src 'self'; object-src 'none'"
            )),
            Map.entry("x-frame-options", new HeaderInfo(
                    "x-frame-options",
                    "Prevents clickjacking attacks by controlling whether the page can be embedded in an iframe",
                    "DENY or SAMEORIGIN"
            )),
            Map.entry("x-content-type-options", new HeaderInfo(
                    "x-content-type-options",
                    "Prevents MIME type sniffing attacks by forcing the browser to use the declared content type",
                    "nosniff"
            )),
            Map.entry("strict-transport-security", new HeaderInfo(
                    "strict-transport-security",
                    "Enforces HTTPS connections and prevents downgrade attacks",
                    "max-age=31536000; includeSubDomains; preload"
            )),
            Map.entry("referrer-policy", new HeaderInfo(
                    "referrer-policy",
                    "Controls how much referrer information is included with requests",
                    "strict-origin-when-cross-origin"
            )),
            Map.entry("permissions-policy", new HeaderInfo(
                    "permissions-policy",
                    "Controls access to browser features and APIs such as camera, microphone and geolocation",
                    "geolocation=(), microphone=(), camera=()"
            )),
            Map.entry("cross-origin-opener-policy", new HeaderInfo(
                    "cross-origin-opener-policy",
                    "Controls cross-origin window access and prevents cross-origin attacks",
                    "same-origin"
            )),
            Map.entry("cross-origin-resource-policy", new HeaderInfo(
                    "cross-origin-resource-policy",
                    "Controls which origins can load your resources",
                    "same-origin"
            )),
            Map.entry("cross-origin-embedder-policy", new HeaderInfo(
                    "cross-origin-embedder-policy",
                    "Prevents loading cross-origin resources that do not explicitly grant permission",
                    "require-corp"
            )),
            Map.entry("x-dns-prefetch-control", new HeaderInfo(
                    "x-dns-prefetch-control",
                    "Controls DNS prefetching behavior which can leak information about links on the page",
                    "off"
            )),
            Map.entry("cache-control", new HeaderInfo(
                    "cache-control",
                    "Controls caching behavior to prevent sensitive data from being stored in browser cache",
                    "no-store, no-cache"
            )),
            Map.entry("clear-site-data", new HeaderInfo(
                    "clear-site-data",
                    "Clears browsing data such as cookies, storage and cache on logout",
                    "\"cache\", \"cookies\", \"storage\""
            )),
            Map.entry("x-permitted-cross-domain-policies", new HeaderInfo(
                    "x-permitted-cross-domain-policies",
                    "Controls cross-domain data loading for Adobe Flash and Acrobat",
                    "none"
            ))
    );

    // fallback list if fetch fails
    public static final List<String> FALLBACK_HEADERS = new ArrayList<>(HEADER_INFO.keySet());

    public OWASPHeaders(MontoyaApi api) {
        this.api = api;
    }

    // fetch headers dynamically from OWASP GitHub
    public List<String> fetchHeaders() {
        try {
            HttpRequest request = HttpRequest.httpRequestFromUrl(
                    "https://raw.githubusercontent.com/OWASP/www-project-secure-headers/master/ci/headers_add.json"
            );

            HttpRequestResponse interaction = api.http().sendRequest(request);

            if (!interaction.hasResponse() ||
                    interaction.response().statusCode() != 200) {
                api.logging().logToOutput("[OWASP] Fetch failed — using fallback list");
                return FALLBACK_HEADERS;
            }

            String body = interaction.response().bodyToString();

            if (!api.utilities().jsonUtils().isValidJson(body)) {
                api.logging().logToOutput("[OWASP] Invalid JSON — using fallback list");
                return FALLBACK_HEADERS;
            }

            List<String> headers = new ArrayList<>();
            int index = 0;

            while (true) {
                String path = "$.headers[" + index + "].name";

                String name;
                try {
                    name = api.utilities().jsonUtils().readString(body, path);
                } catch (Exception e) {
                    break; // index out of range — no more elements
                }

                if (name == null || name.isEmpty()) break;

                headers.add(name.toLowerCase());
                index++;
            }

            if (headers.isEmpty()) {
                api.logging().logToError("[OWASP] No headers parsed — using fallback list");
                return FALLBACK_HEADERS;
            }

            api.logging().logToOutput("[OWASP] Fetched " + headers.size() + " headers");
            return headers;

        } catch (Exception e) {
            api.logging().logToOutput("[OWASP] Error: " + e.getMessage() + " — using fallback");
            return FALLBACK_HEADERS;
        }
    }

    // get HeaderInfo for a specific header name
    public static HeaderInfo getInfo(String headerName) {
        return HEADER_INFO.getOrDefault(
                headerName.toLowerCase(),
                new HeaderInfo(headerName, "No description available", "See OWASP documentation")
        );
    }
}