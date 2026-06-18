import burp.api.montoya.MontoyaApi;

import java.util.*;

/**
 * reads all responses from Burp site map
 * no new requests sent
 * per URL analysis
 */
public class DeepScanner {

    private final MontoyaApi api;
    private final HeaderChecker headerChecker;

    public DeepScanner(MontoyaApi api, HeaderChecker headerChecker) {
        this.api = api;
        this.headerChecker = headerChecker;
    }

    public List<ScanResult> scan(String host) {
        List<ScanResult> results = new ArrayList<>();
        Set<String> seenUrls = new HashSet<>();

        api.logging().logToOutput("[DEEP] Scanning host: " + host);

        api.siteMap().requestResponses().forEach(interaction -> {
            try {
                if (!interaction.hasResponse()) return;

                String requestHost = interaction.request().httpService().host();

                // only process selected host
                if (!requestHost.equalsIgnoreCase(host)) return;

                String url = interaction.request().url();

                if (seenUrls.contains(url)) return;
                seenUrls.add(url);

                int status = interaction.response().statusCode();
                if (status < 200 || status >= 600) return; // should i consider only 200 okay ?

                api.logging().logToOutput("[DEEP] Analyzing: " + url);

                ScanResult result = headerChecker.analyzeResponse(url, interaction);
                results.add(result);

            } catch (Exception e) {
                api.logging().logToOutput("[DEEP] Error: " + e.getMessage());
            }
        });

        api.logging().logToOutput("[DEEP] Scanned " + results.size() + " URLs for " + host);
        return results;
    }
}