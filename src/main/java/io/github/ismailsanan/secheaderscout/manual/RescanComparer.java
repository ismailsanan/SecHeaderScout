package io.github.ismailsanan.secheaderscout.manual;

import io.github.ismailsanan.secheaderscout.model.ScanResult;
import io.github.ismailsanan.secheaderscout.report.Comparison;
import io.github.ismailsanan.secheaderscout.report.ReportParser;

import java.io.IOException;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Predicate;

/**
 * Rescan &amp; Compare. Burp- and Swing-independent.
 *
 * <p>A report file is untrusted input: whoever wrote it chooses the URLs that will
 * be requested. The workflow is therefore split in two: {@link #load} and
 * {@link #plan} describe what would be requested (hosts, URL count, out-of-scope
 * hosts, truncation), so the UI can ask for confirmation before
 * {@link #compare} sends anything.</p>
 */
public final class RescanComparer {

    /** Maximum URLs rescanned from one report. */
    public static final int MAX_URLS = 500;
    /** Real reports are about 1 KB per URL; anything far larger is not a SecHeaderScout report. */
    public static final long MAX_REPORT_BYTES = 5L * 1024 * 1024;

    /** Expected, user-facing problem with the selected file. */
    public static final class InvalidReportException extends Exception {
        private static final long serialVersionUID = 1L;

        public InvalidReportException(String message) {
            super(message);
        }
    }

    /**
     * What a rescan would do. This is the object the user confirms (SEC-9), so it is
     * immutable and internally consistent: whatever {@link #compare} scans is exactly
     * what the confirmation dialog showed.
     *
     * @param toScan          entries that will be rescanned (at most {@link #MAX_URLS})
     * @param totalUrls       distinct, valid http(s) URLs found in the report (before the cap)
     * @param hosts           distinct hosts that will be contacted, in report order
     * @param outOfScopeHosts hosts with at least one URL outside Burp's target scope
     * @param skippedInvalid  URLs from the report that are not valid http(s) targets and will not be requested
     */
    public record Plan(List<ReportParser.PreviousResult> toScan, int totalUrls, Set<String> hosts,
                       Set<String> outOfScopeHosts, List<String> skippedInvalid) {
        public Plan {
            toScan = List.copyOf(toScan);
            hosts = Collections.unmodifiableSet(new LinkedHashSet<>(hosts));
            outOfScopeHosts = Collections.unmodifiableSet(new LinkedHashSet<>(outOfScopeHosts));
            skippedInvalid = List.copyOf(skippedInvalid);
            if (toScan.size() > MAX_URLS || totalUrls < toScan.size() || !hosts.containsAll(outOfScopeHosts)) {
                throw new IllegalArgumentException("inconsistent rescan plan");
            }
        }

        public boolean truncated() {
            return totalUrls > toScan.size();
        }
    }

    /** Outcome of a compare run. */
    public record Outcome(List<Comparison> comparisons, boolean cancelled) {
        public Outcome {
            comparisons = List.copyOf(comparisons);
        }
    }

    private RescanComparer() {
    }

    public static List<ReportParser.PreviousResult> load(Path file) throws IOException, InvalidReportException {
        if (Files.size(file) > MAX_REPORT_BYTES) {
            throw new InvalidReportException("file is larger than " + (MAX_REPORT_BYTES / (1024 * 1024))
                    + " MB; not a SecHeaderScout report");
        }
        String html;
        try {
            html = Files.readString(file, StandardCharsets.UTF_8);
        } catch (CharacterCodingException e) {
            throw new InvalidReportException(file.getFileName() + " is not UTF-8 text; it is not a report "
                    + "exported by this version of SecHeaderScout (re-export it, or convert it to UTF-8)");
        }
        List<ReportParser.PreviousResult> previous = ReportParser.parse(html);
        if (previous.isEmpty()) {
            throw new InvalidReportException("no SecHeaderScout results found in " + file.getFileName());
        }
        return previous;
    }

    /**
     * @param inScope URL predicate (Burp's target scope); out-of-scope URLs are reported, not removed.
     *                If the predicate throws for a URL taken from the file, the URL counts as out of scope.
     */
    public static Plan plan(List<ReportParser.PreviousResult> previous, Predicate<String> inScope) {
        Map<String, ReportParser.PreviousResult> distinct = new LinkedHashMap<>();
        Map<String, String> hostByUrl = new LinkedHashMap<>();
        Set<String> skipped = new LinkedHashSet<>();
        for (ReportParser.PreviousResult p : previous) {
            Optional<ScanTarget> target = ScanTarget.parse(p.url());
            if (target.isPresent()) {
                hostByUrl.putIfAbsent(p.url(), target.get().host());
                // for duplicate URLs prefer an entry that was actually analysed (it has a baseline)
                distinct.merge(p.url(), p, (kept, next) -> !kept.analysed() && next.analysed() ? next : kept);
            } else {
                skipped.add(p.url());
            }
        }
        List<ReportParser.PreviousResult> toScan = new ArrayList<>(distinct.values());
        if (toScan.size() > MAX_URLS) {
            toScan = new ArrayList<>(toScan.subList(0, MAX_URLS));
        }
        Set<String> hosts = new LinkedHashSet<>();
        Set<String> outOfScope = new LinkedHashSet<>();
        for (ReportParser.PreviousResult p : toScan) {
            String host = hostByUrl.get(p.url()); // every planned URL parsed successfully above
            hosts.add(host);
            if (!isInScope(inScope, p.url())) {
                outOfScope.add(host);
            }
        }
        return new Plan(toScan, distinct.size(), hosts, outOfScope, new ArrayList<>(skipped));
    }

    private static boolean isInScope(Predicate<String> inScope, String url) {
        try {
            return inScope.test(url);
        } catch (RuntimeException e) {
            return false; // a URL Burp cannot judge is flagged, never silently trusted
        }
    }

    /** Rescans the planned URLs (exact URLs, no HTTP fallback) and compares them with the report. */
    public static Outcome compare(ManualScanner scanner, Plan plan, ProgressListener progress) {
        List<String> urls = plan.toScan().stream().map(ReportParser.PreviousResult::url).toList();
        ScanBatch batch = scanner.rescanUrls(urls, progress);
        Map<String, ScanResult> byUrl = new LinkedHashMap<>();
        for (ScanResult r : batch.results()) {
            byUrl.putIfAbsent(r.target(), r);
        }
        List<Comparison> comparisons = new ArrayList<>();
        for (ReportParser.PreviousResult p : plan.toScan()) {
            ScanResult now = byUrl.get(p.url());
            if (now != null) {
                comparisons.add(Comparison.of(p, now)); // carries "previously not analysed" through
            }
        }
        return new Outcome(comparisons, batch.cancelled());
    }
}
