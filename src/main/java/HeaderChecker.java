import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;

/**
 * Handles Quick Scan  sends GET / per host
 */
public class HeaderChecker {

    private final MontoyaApi api;
    private final List<String> requiredHeaders;

    public HeaderChecker(MontoyaApi api, List<String> requiredHeaders) {
        this.api = api;
        this.requiredHeaders = requiredHeaders;
    }

    public ScanResult checkHeaders(String host) {

        String cleanHost = host
                .replace("https://", "")
                .replace("http://", "")
                .trim();

        api.logging().logToOutput("[CHECK] " + cleanHost);

        HttpRequestResponse interaction = sendWithTimeout("https://" + cleanHost + "/", 5);

        // fallback to HTTP if HTTPS fails
        if (interaction == null ||
                !interaction.hasResponse() ||
                interaction.response().statusCode() >= 400) {

            api.logging().logToOutput("[CHECK] HTTPS failed — trying HTTP");
            interaction = sendWithTimeout("http://" + cleanHost + "/", 5);
        }

        if (interaction == null || !interaction.hasResponse()) {
            return new ScanResult(
                    "https://" + cleanHost + "/",
                    List.of("[ERROR] Host Unreachable"),
                    List.of()
            );
        }

        return analyzeResponse(
                "https://" + cleanHost + "/",
                interaction
        );
    }

    public ScanResult analyzeResponse(String url, HttpRequestResponse interaction) {

        // extract response header names lowercase
        List<String> responseHeaders = interaction.response().headers()
                .stream()
                .map(h -> h.name().toLowerCase())
                .toList();

        // find missing headers
        List<String> missing = requiredHeaders
                .stream()
                .filter(h -> !responseHeaders.contains(h))
                .toList();

        // find misconfigured headers
        List<String> misconfigured = new ArrayList<>();

        interaction.response().headers().forEach(header -> {
            List<String> issues = MisconfigurationChecker.check(
                    header.name(),
                    header.value()
            );
            issues.forEach(issue ->
                    misconfigured.add(header.name() + ": " + issue)
            );
        });

        return new ScanResult(url, missing, misconfigured);
    }

    private HttpRequestResponse sendWithTimeout(String url, int seconds) {
        ExecutorService executor = Executors.newSingleThreadExecutor();
        try {
            Future<HttpRequestResponse> future = executor.submit(() ->
                    api.http().sendRequest(HttpRequest.httpRequestFromUrl(url))
            );
            return future.get(seconds, TimeUnit.SECONDS);
        } catch (TimeoutException e) {
            api.logging().logToOutput("[TIMEOUT] " + url);
            return null;
        } catch (Exception e) {
            api.logging().logToError("[ERROR] " + url + " — " + e.getMessage());
            return null;
        } finally {
            executor.shutdownNow();
        }
    }
}