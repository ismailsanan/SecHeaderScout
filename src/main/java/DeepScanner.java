import burp.api.montoya.MontoyaApi;

import java.util.ArrayList;
import java.util.List;

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

                //take request from sitemap
        api.siteMap().requestResponses().forEach(interaction -> {
            try {

                if(!interaction.request().hasHeader("Host", host)) return;

                if (!interaction.hasResponse()) return;

                String url = interaction.request().url();

                // skip non HTTP responses
                int status = interaction.response().statusCode();
                if (status < 200 || status >= 600) return;

                api.logging().logToOutput("[DEEP] Analyzing: " + url);

                ScanResult result = headerChecker.analyzeResponse(url, interaction);
                results.add(result);

            } catch (Exception e) {
                api.logging().logToOutput("[DEEP] Error: " + e.getMessage());
            }
        });
        return results;
    }
}