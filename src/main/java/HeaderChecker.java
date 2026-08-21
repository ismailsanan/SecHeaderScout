import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.*;

/**
 * Quick Scan sends a request per target
 * analyzeResponse is shared with DeepScanner so both produce identical findings
 *
 * two categories only —> the header is absent, or it is present and wrong
 */
public class HeaderChecker {

    private static final int TIMEOUT_SECONDS = 5;

    private final MontoyaApi api;

    // fetched from OWASP at startup, kept so a newly added OWASP header
    // still gets its value checked even before it lands in requiredFor()
    private final List<String> owaspList;

    public HeaderChecker(MontoyaApi api, List<String> owaspList) {
        this.api = api;
        this.owaspList = owaspList;
    }

    // Quick Scan —> root page of a host
    public ScanResult checkHeaders(String host) {
        String cleanHost = host
                .replace("https://", "")
                .replace("http://", "")
                .replaceAll("/+$", "")
                .trim();

        return scanUrl("https://" + cleanHost + "/");
    }

    // scans one exact URL with the path intact
    // ReportComparator needs this, otherwise a rescan of /logout silently becomes /
    public ScanResult scanUrl(String url) {
        api.logging().logToOutput("[SCAN] " + url);

        HttpRequestResponse interaction = sendWithTimeout(url);

        if (!usable(interaction) && url.startsWith("https://")) {
            String httpUrl = url.replaceFirst("^https://", "http://");
            api.logging().logToOutput("[SCAN] https failed —> trying " + httpUrl);
            HttpRequestResponse fallback = sendWithTimeout(httpUrl);
            if (usable(fallback)) {
                interaction = fallback;
                url = httpUrl;
            }
        }

        if (interaction == null || !interaction.hasResponse())
            return new ScanResult(url, List.of("[ERROR] host unreachable"), List.of(), "GET");

        return analyzeResponse(url, interaction);
    }

    public ScanResult analyzeResponse(String url, HttpRequestResponse interaction) {

<<<<<<< Updated upstream
        // extract response header names lowercase
        UrlClassifier.UrlType urlType = UrlClassifier.classify(url);
        List<String> headersToCheck = OWASPHeaders.headersForUrlType(urlType);
        String method = interaction.request().method();
=======
        // one pass over the headers builds everything downstream needs
        // a map instead of a set because checks need values
        // (CSP frame-ancestors supersedes XFO, Set-Cookie signals an auth flow)
        Map<String, String> present = new HashMap<>();
        interaction.response().headers().forEach(h ->
                present.put(h.name().trim().toLowerCase(), h.value().trim().toLowerCase())
        );

        ScanContext ctx = new ScanContext(
                UrlClassifier.classify(url),
                present.get("content-type"),
                url.toLowerCase().startsWith("https://"),
                interaction.response().statusCode(),
                present
        );
>>>>>>> Stashed changes

        // @@@@@@@@@ missing @@@@@@@
        // requiredFor() already decides what actually applies to this response
        // so anything it returns and the server didnt send is a real finding
        List<String> missing = new ArrayList<>();
        for (String header : OWASPHeaders.requiredFor(ctx)) {
            if (!present.containsKey(header)) missing.add(header);
        }

<<<<<<< Updated upstream
        // find missing headers
        List<String> missing = requiredHeaders
                .stream()
                .filter(h -> !responseHeaders.contains(h))
                .toList();

        // find misconfigured headers
=======
        // @@@@@@@@@@ misconfigured @@@@@@@@@
>>>>>>> Stashed changes
        List<String> misconfigured = new ArrayList<>();

        interaction.response().headers().forEach(header ->
                MisconfigurationChecker.check(header.name(), header.value(), ctx)
                        .forEach(issue -> misconfigured.add(header.name() + ": " + issue))
        );

        // CORS needs the whole header set at once to spot dangerous combinations
        // that individual header checks cannot see
        misconfigured.addAll(CORSChecker.check(interaction.response().headers(), ctx));

        String method = interaction.request() != null ? interaction.request().method() : null;

        return new ScanResult(url, missing, misconfigured, method);
    }

    private boolean usable(HttpRequestResponse i) {
        return i != null && i.hasResponse() && i.response().statusCode() < 400;
    }

    // sendRequest has no timeout of its own and blocks for up to 2 minutes
    // wrapping it in a Future caps that at 5 seconds
    private HttpRequestResponse sendWithTimeout(String url) {
        ExecutorService executor = Executors.newSingleThreadExecutor();
        try {
            Future<HttpRequestResponse> future = executor.submit(() ->
                    api.http().sendRequest(HttpRequest.httpRequestFromUrl(url))
            );
            return future.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        } catch (TimeoutException e) {
            api.logging().logToOutput("[TIMEOUT] " + url);
            return null;
        } catch (Exception e) {
            api.logging().logToError("[ERROR] " + url + " —> " + e.getMessage());
            return null;
        } finally {
            executor.shutdownNow();
        }
    }
}