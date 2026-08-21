import java.util.List;

/**
<<<<<<< Updated upstream
 * Represents the result of scanning a single URL
=======
 * result of scanning one URL
 * two categories only —> the header is absent, or it is present and wrong
>>>>>>> Stashed changes
 */
public class ScanResult {

    private final String url;
    private final List<String> missingHeaders;
    private final List<String> misconfiguredHeaders;
    private final UrlClassifier.UrlType urlType;
    private final String method;

    public ScanResult(String url,
                      List<String> missingHeaders,
                      List<String> misconfiguredHeaders,
                      String method) {
        this.url = url;
        this.missingHeaders       = List.copyOf(missingHeaders);
        this.misconfiguredHeaders = List.copyOf(misconfiguredHeaders);
        this.urlType = UrlClassifier.classify(url);
        // method is null when the request object isnt available
        // defaulting here stops "null https://..." appearing in the panel
        this.method = (method == null || method.isBlank()) ? "GET" : method;
    }

    public String getUrl() { return url; }
    public List<String> getMissingHeaders()       { return missingHeaders; }
    public List<String> getMisconfiguredHeaders() { return misconfiguredHeaders; }
    public UrlClassifier.UrlType getUrlType()     { return urlType; }
    public String getMethod() { return method; }

    public boolean isClean() {
        return missingHeaders.isEmpty() && misconfiguredHeaders.isEmpty();
    }

    public int findingCount() {
        return missingHeaders.size() + misconfiguredHeaders.size();
    }
}