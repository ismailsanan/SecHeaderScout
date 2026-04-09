
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.List;
import java.util.concurrent.*;


public class HeaderChecker {

    private final MontoyaApi api;


    public HeaderChecker(MontoyaApi api) {
        this.api = api;
    }


    public List<String> checkHeaders (String host) {

        String cleanHost = host
                .replace("https://", "")
                .replace("http://", "")
                .replace("/", "")
                .trim();


        api.logging().logToOutput("[DEBUG] Checking host: " + cleanHost);
        api.logging().logToOutput("[DEBUG] Sending HTTPS to: https://" + cleanHost + "/");

        // try HTTPS with 5 second timeout
        HttpRequestResponse response = null;
        ExecutorService executor = Executors.newSingleThreadExecutor();

        try {
            Future<HttpRequestResponse> future = executor.submit(() ->
                    api.http().sendRequest(HttpRequest.httpRequestFromUrl("https://" + cleanHost + "/"))
            );

            response = future.get(5, TimeUnit.SECONDS);
            api.logging().logToOutput("[DEBUG] HTTPS responded — status: " + response.response().statusCode());

        } catch (TimeoutException e) {
            api.logging().logToOutput("[DEBUG] HTTPS timed out after 5 seconds");
            api.logging().logToOutput("[DEBUG] Falling back to HTTP: http://" + cleanHost + "/");

        } catch (Exception e) {
            api.logging().logToOutput("[DEBUG] HTTPS error: " + e.getMessage());

        } finally {
            executor.shutdownNow();
        }

        // if HTTPS timed out or failed — try HTTP
        if (response == null || !response.hasResponse() || (response.response().statusCode() >= 400 && response.response().statusCode() < 600)) {

            api.logging().logToOutput("[DEBUG] Trying HTTP: http://" + cleanHost + "/");

            ExecutorService httpExecutor = Executors.newSingleThreadExecutor();

            try {
                Future<HttpRequestResponse> httpFuture = httpExecutor.submit(() ->
                        api.http().sendRequest(HttpRequest.httpRequestFromUrl("http://" + cleanHost + "/"))
                );

                HttpRequestResponse fallback = httpFuture.get(5, TimeUnit.SECONDS);

                api.logging().logToOutput("[DEBUG] HTTP responded — status: " +
                        fallback.response().statusCode());

                if (!fallback.hasResponse() || fallback.response().statusCode() >= 400) {
                    return List.of("[ERROR] Host Unreachable");
                }

                return findMissing(extractHeader(fallback));

            } catch (TimeoutException e) {
                api.logging().logToOutput("[DEBUG] HTTP also timed out");
                return List.of("[ERROR] Host Unreachable — both HTTPS and HTTP timed out");

            } catch (Exception e) {
                api.logging().logToOutput("[DEBUG] HTTP error: " + e.getMessage());
                return List.of("[ERROR] " + e.getMessage());

            } finally {
                httpExecutor.shutdownNow();
            }
        }

        // HTTPS worked — check headers
        return findMissing(extractHeader(response));
    }

    //extract headers
    private  List<String> extractHeader (HttpRequestResponse res ) {

        return res.response().headers()
                .stream()
                .map(header -> header.name())
                .toList();

    }
    // find missing headers
    private List<String> findMissing (List<String> missingheaders) {

        return OWASPHeaders.REQUIRED_HEADERS
                .stream()
                .filter(s -> !missingheaders.contains(s))
                .toList();
    }


}

