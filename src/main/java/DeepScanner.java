import burp.api.montoya.MontoyaApi;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * reads responses already captured in Burp's site map
 * no new requests are sent
 */
public class DeepScanner {

    private final MontoyaApi api;
    private final HeaderChecker headerChecker;

    // static assets carry the same global headers as everything else
    // 300 favicons and js files bury the findings that matter
    private boolean skipStatic = true;

    // most servers apply headers globally, so once a host produces an identical
    // finding set 20 times over there is nothing new to learn from URL 300
    private boolean collapseDuplicates = true;

    public DeepScanner(MontoyaApi api, HeaderChecker headerChecker) {
        this.api = api;
        this.headerChecker = headerChecker;
    }

    public void setSkipStatic(boolean v)         { this.skipStatic = v; }
    public void setCollapseDuplicates(boolean v) { this.collapseDuplicates = v; }

    public List<ScanResult> scan(String host) {
        List<ScanResult> results = new ArrayList<>();
        Set<String> seenUrls = new HashSet<>();
        Set<String> seenFingerprints = new HashSet<>();

        int[] skippedStatic = {0};
        int[] collapsed     = {0};

        api.siteMap().requestResponses().forEach(interaction -> {
            try {
                if (!interaction.hasResponse()) return;

                // match on the service host, not the Host header
                // hasHeader("Host", v) breaks on HTTP/2 which uses :authority
                // and on any request carrying a port in the header
                String requestHost = interaction.request().httpService().host();
                if (!requestHost.equalsIgnoreCase(host)) return;

                String url = interaction.request().url();

                // the site map keeps every visit, the same URL repeats constantly
                if (!seenUrls.add(normalize(url))) return;

                int status = interaction.response().statusCode();
                if (status < 200 || status >= 600) return;

                if (skipStatic && UrlClassifier.classify(url) == UrlClassifier.UrlType.STATIC) {
                    skippedStatic[0]++;
                    return;
                }

                ScanResult result = headerChecker.analyzeResponse(url, interaction);

                // fingerprint = url type + the exact finding set
                // keeps one representative URL per distinct configuration
                if (collapseDuplicates) {
                    String fingerprint = result.getUrlType() + "|"
                            + result.getMissingHeaders() + "|"
                            + result.getMisconfiguredHeaders();
                    if (!seenFingerprints.add(fingerprint)) {
                        collapsed[0]++;
                        return;
                    }
                }

                results.add(result);

            } catch (Exception e) {
                api.logging().logToError("[DEEP] " + e.getMessage());
            }
        });

        api.logging().logToOutput("[DEEP] " + host + " —> " + results.size()
                + " reported, " + collapsed[0] + " duplicate configurations collapsed, "
                + skippedStatic[0] + " static assets skipped");

        return results;
    }

    // /page, /page/ and /page?x=1 should not each get their own entry
    private String normalize(String url) {
        String u = url.toLowerCase();
        int q = u.indexOf('?');
        if (q != -1) u = u.substring(0, q);
        if (u.endsWith("/") && u.length() > 1) u = u.substring(0, u.length() - 1);
        return u;
    }
}