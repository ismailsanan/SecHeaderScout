import burp.api.montoya.MontoyaApi;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * loads a previous SecHeaderScout HTML report, rescans the same URLs
 * and reports what changed
 *
 */
public class ReportComparator {

    // one chunk per URL, lookahead stops at the next block so nested divs dont break it
    private static final Pattern URL_BLOCK = Pattern.compile(
            "<div class='url-block[^']*'>(.*?)</div>\\s*(?=<div class='url-block|</body>)",
            Pattern.DOTALL);

    // the URL sits inside a span for the method and may be followed by a label span
    private static final Pattern URL = Pattern.compile(
            "<div class='url'>(?:<span class='method'>[^<]*</span>)?([^<]+)",
            Pattern.DOTALL);

    private static final Pattern MISSING = Pattern.compile(
            "MISSING\\s*(?:&#8594;|&rarr;|->|—>)\\s*([^<|]+)");

    private final MontoyaApi api;
    private final HeaderChecker headerChecker;

    public ReportComparator(MontoyaApi api, HeaderChecker headerChecker) {
        this.api = api;
        this.headerChecker = headerChecker;
    }

    public List<ComparisonResult> compare(String oldReportPath) throws IOException {

        String html = Files.readString(Path.of(oldReportPath));
        List<ComparisonResult> comparisons = new ArrayList<>();

        Matcher blocks = URL_BLOCK.matcher(html);

        while (blocks.find()) {
            String body = blocks.group(1);

            Matcher urlMatcher = URL.matcher(body);
            if (!urlMatcher.find()) continue;

            String url = urlMatcher.group(1).trim();
            if (url.isEmpty()) continue;

            List<String> oldMissing = new ArrayList<>();
            Matcher m = MISSING.matcher(body);
            while (m.find()) oldMissing.add(m.group(1).trim().toLowerCase());

            api.logging().logToOutput("[COMPARE] rescanning " + url
                    + " (was missing " + oldMissing.size() + ")");

            // scanUrl not checkHeaders, otherwise /logout gets rescanned as /
            ScanResult fresh = headerChecker.scanUrl(url);

            comparisons.add(new ComparisonResult(url, oldMissing, fresh));
        }

        api.logging().logToOutput("[COMPARE] parsed " + comparisons.size() + " URLs from the report");
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

        public String getUrl() { return url; }

        // was missing, present now
        public List<String> getFixed() {
            return oldMissing.stream()
                    .filter(h -> !newResult.getMissingHeaders().contains(h))
                    .toList();
        }

        // was missing, still missing
        public List<String> getStillMissing() {
            return oldMissing.stream()
                    .filter(h -> newResult.getMissingHeaders().contains(h))
                    .toList();
        }

        // was fine, missing now
        public List<String> getNewIssues() {
            return newResult.getMissingHeaders().stream()
                    .filter(h -> !oldMissing.contains(h))
                    .toList();
        }
    }
}