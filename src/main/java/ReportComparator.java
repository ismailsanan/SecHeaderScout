import burp.api.montoya.MontoyaApi;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Loads a previous SecHeaderScout HTML report re-scans the same URLs,
 * and compares old findings against new findings.
 */
public class ReportComparator {

    private static final Pattern URL_BLOCK_PATTERN =
            Pattern.compile("<div class='url-block[^']*'>(.*?)</div>\\s*(?=<div class='url-block|</body>)", Pattern.DOTALL);

    // matches the URL itself inside a block
    // <div class='url'>https://example.com/ <span class='label'>...</span></div>
    private static final Pattern URL_PATTERN =
            Pattern.compile("<div class='url'>(.*?)(?:\\s*<span|</div>)", Pattern.DOTALL);

    // matches each missing header line
    // <div class='missing'>MISSING &#8594; content-security-policy | Recommended: ...</div>
    private static final Pattern MISSING_PATTERN =
            Pattern.compile("MISSING\\s*(?:&#8594;|&rarr;|->|→)\\s*([^<|]+)");

    private final MontoyaApi api;
    private final HeaderChecker headerChecker;

    public ReportComparator(MontoyaApi api, HeaderChecker headerChecker) {
        this.api = api;
        this.headerChecker = headerChecker;
    }

    public List<ComparisonResult> compare(String oldReportPath) throws IOException {

        String html = Files.readString(Path.of(oldReportPath));

        List<ComparisonResult> comparisons = new ArrayList<>();

        Matcher urlBlockMatcher = URL_BLOCK_PATTERN.matcher(html);

        while (urlBlockMatcher.find()) {

            String blockBody = urlBlockMatcher.group(1);

            Matcher urlMatcher = URL_PATTERN.matcher(blockBody);
            if (!urlMatcher.find()) continue;

            String url = urlMatcher.group(1).trim();
            if (url.isEmpty()) continue;

            // extract old missing headers from this block
            List<String> oldMissing = new ArrayList<>();
            Matcher missingMatcher = MISSING_PATTERN.matcher(blockBody);
            while (missingMatcher.find()) {
                oldMissing.add(missingMatcher.group(1).trim().toLowerCase());
            }

            api.logging().logToOutput("[COMPARE] Rescanning: " + url +
                    " (previously " + oldMissing.size() + " missing)");

            ScanResult newResult = headerChecker.checkHeaders(url);

            comparisons.add(new ComparisonResult(url, oldMissing, newResult));
        }

        api.logging().logToOutput("[COMPARE] Parsed " + comparisons.size() + " URLs from report");

        return comparisons;
    }

    public static class ComparisonResult {

        private final String url;
        private final List<String> oldMissing;
        private final ScanResult newResult;

        public ComparisonResult(String url, List<String> oldMissing, ScanResult newResult) {
            this.url = url;
            this.oldMissing = oldMissing;
            this.newResult = newResult;
        }

        public String getUrl() {
            return url;
        }

       // was missing before, present now
        public List<String> getFixed() {
            return oldMissing.stream()
                    .filter(h -> !newResult.getMissingHeaders().contains(h))
                    .toList();
        }

      // was missing before, still missing now
        public List<String> getStillMissing() {
            return oldMissing.stream()
                    .filter(h -> newResult.getMissingHeaders().contains(h))
                    .toList();
        }

     // was present before, missing now
        public List<String> getNewIssues() {
            return newResult.getMissingHeaders().stream()
                    .filter(h -> !oldMissing.contains(h))
                    .toList();
        }
    }
}