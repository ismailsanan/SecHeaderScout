import java.util.List;

/**
 * Represents the result of scanning a single URL
 */
public class ScanResult {

    private final String url;
    private final List<String> missingHeaders;
    private final List<String> misconfiguredHeaders;
    private final UrlClassifier.UrlType urlType;

    public ScanResult(
            String url,
            List<String> missingHeaders,
            List<String> misconfiguredHeaders
    ) {
        this.url = url;
        this.missingHeaders = missingHeaders;
        this.misconfiguredHeaders = misconfiguredHeaders;
        this.urlType = UrlClassifier.classify(url);
    }

    public String getUrl() { return url; }
    public List<String> getMissingHeaders() { return missingHeaders; }
    public List<String> getMisconfiguredHeaders() { return misconfiguredHeaders; }
    public UrlClassifier.UrlType getUrlType() { return urlType; }

    public boolean isClean() {
        return missingHeaders.isEmpty() && misconfiguredHeaders.isEmpty();
    }
}