package io.github.ismailsanan.secheaderscout.report;

import io.github.ismailsanan.secheaderscout.engine.Finding;
import io.github.ismailsanan.secheaderscout.model.HeaderProfile;
import io.github.ismailsanan.secheaderscout.model.ScanResult;
import io.github.ismailsanan.secheaderscout.util.UrlPaths;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/** Plain-text renderings for the UI and report-ready Markdown for the clipboard. */
public final class TextFormatter {

    private TextFormatter() {
    }

    /** Detailed plain-text description of one result (also used by the details pane). */
    public static String details(ScanResult r) {
        StringBuilder sb = new StringBuilder();
        sb.append(r.method() == null ? "" : r.method() + " ").append(r.url());
        if (!r.urlType().label().isEmpty()) {
            sb.append("  [").append(r.urlType().label()).append(']');
        }
        sb.append("  (").append(r.protocol()).append(r.statusCode() > 0 ? " " + r.statusCode() : "").append(")\n");
        if (r.httpFallback()) {
            sb.append("  ⚠ ").append(r.fallbackWarning()).append('\n');
        }
        switch (r.status()) {
            case ERROR -> sb.append("  ERROR         -> ").append(r.error()).append('\n');
            case INCOMPLETE -> sb.append("  EVALUATION INCOMPLETE -> at least one rule failed; the absence of "
                    + "findings does not mean clean (see notes)\n");
            case CLEAN -> sb.append("  No issues found for the evaluated headers\n");
            case FINDINGS -> { }
        }
        for (Finding f : r.missing()) {
            sb.append("  MISSING       -> ").append(f.header()).append("  [").append(f.severity()).append(", ")
                    .append(f.confidence()).append("]  recommended: ").append(f.recommended()).append('\n');
        }
        for (Finding f : r.misconfigured()) {
            sb.append("  ").append(String.format("%-13s", f.type())).append(" -> ").append(f.issueName())
                    .append("  [").append(f.severity()).append(", ").append(f.confidence()).append("]\n")
                    .append("                   ").append(f.detail()).append('\n');
            if (f.observedValue() != null) {
                sb.append("                   observed: ").append(f.observedValue()).append('\n');
            }
        }
        for (String note : r.notes()) {
            sb.append("  NOTE          -> ").append(note).append('\n');
        }
        return sb.toString();
    }

    /**
     * Markdown ready to paste into a pentest report, grouped by host:
     * <pre>
     * ### www.example.com
     *
     * **Missing:**
     *
     * - Content-Security-Policy
     *
     * **Misconfigured:**
     *
     * - Referrer-Policy header has an invalid value: `foo`
     * </pre>
     * Each header or issue is listed once per host, with "(n of m URLs)" when only
     * some of the host's URLs are affected. Hosts without anything to report are left
     * out, but never one with an HTTP-fallback result (its warning must reach the
     * reader, FR-7), an incomplete evaluation (that is not clean, HE-9) or an
     * unanalysed URL. Server-derived text is escaped (SEC-10).
     */
    public static String reportMarkdown(List<ScanResult> results) {
        Map<String, List<ScanResult>> byHost = new LinkedHashMap<>();
        for (ScanResult r : results) {
            byHost.computeIfAbsent(hostOf(r), k -> new ArrayList<>()).add(r);
        }
        StringBuilder md = new StringBuilder();
        byHost.forEach((host, hostResults) -> appendHost(md, host, hostResults));
        return md.length() == 0 ? "No findings to copy." : md.toString().stripTrailing() + "\n";
    }

    private static void appendHost(StringBuilder md, String host, List<ScanResult> results) {
        List<ScanResult> analysed = results.stream().filter(r -> !r.hasError()).toList();
        List<ScanResult> errors = results.stream().filter(ScanResult::hasError).toList();
        List<ScanResult> incomplete = analysed.stream().filter(ScanResult::evaluationIncomplete).toList();
        Set<String> warnings = new LinkedHashSet<>();
        results.stream().filter(ScanResult::httpFallback).forEach(r -> warnings.add(r.fallbackWarning()));

        Map<String, Integer> missing = new LinkedHashMap<>();
        Map<String, Misconfiguration> misconfigured = new LinkedHashMap<>();
        for (ScanResult r : analysed) {
            r.missing().stream().map(Finding::header).distinct().forEach(h -> missing.merge(h, 1, Integer::sum));
            Set<String> seenHere = new HashSet<>();
            for (Finding f : r.misconfigured()) {
                String key = f.header().toLowerCase(Locale.ROOT) + '\n' + f.issueName();
                Misconfiguration m = misconfigured.computeIfAbsent(key, k -> new Misconfiguration(f));
                m.observed.add(f.observedValue());
                if (seenHere.add(key)) {
                    m.urls++;
                }
            }
        }
        if (missing.isEmpty() && misconfigured.isEmpty() && errors.isEmpty() && incomplete.isEmpty()
                && warnings.isEmpty()) {
            return;
        }

        int total = analysed.size();
        md.append("### ").append(text(host)).append("\n\n");
        for (String warning : warnings) {
            md.append("> **Warning:** ").append(text(warning)).append("\n\n");
        }
        if (!missing.isEmpty()) {
            md.append("**Missing:**\n\n");
            missing.forEach((header, urls) -> md.append("- ").append(text(header)).append(coverage(urls, total))
                    .append('\n'));
            md.append('\n');
        }
        if (!misconfigured.isEmpty()) {
            md.append("**Misconfigured:**\n\n");
            for (Misconfiguration m : misconfigured.values()) {
                md.append("- ").append(m.render()).append(coverage(m.urls, total)).append('\n');
            }
            md.append('\n');
        }
        if (!incomplete.isEmpty()) {
            md.append("**Evaluation incomplete** (").append(incomplete.size()).append(" of ").append(total)
                    .append(" URLs): a rule failed, so headers not listed above are not confirmed as correct.\n\n");
            incomplete.stream().flatMap(r -> r.notes().stream()).distinct()
                    .forEach(note -> md.append("- ").append(text(note)).append('\n'));
            md.append('\n');
        }
        if (!errors.isEmpty()) {
            md.append("**Not analysed:**\n\n");
            for (ScanResult r : errors) {
                md.append("- ").append(code(r.url())).append(": ")
                        .append(text(r.error())).append('\n');
            }
            md.append('\n');
        }
    }

    /** One misconfiguration of a host, merged across the URLs where it occurs. */
    private static final class Misconfiguration {
        private final Finding first;
        private final Set<String> observed = new LinkedHashSet<>();
        private int urls;

        Misconfiguration(Finding first) {
            this.first = first;
        }

        String render() {
            String name = first.issueName();
            StringBuilder sb = new StringBuilder();
            if (!name.toLowerCase(Locale.ROOT).contains(first.header().toLowerCase(Locale.ROOT))) {
                sb.append(text(first.header())).append(": ");
            }
            sb.append(text(name));
            observed.remove(null);
            if (!observed.isEmpty()) {
                sb.append(": ").append(code(observed.iterator().next()));
                if (observed.size() > 1) {
                    sb.append(" (value varies across URLs)");
                }
            }
            return sb.toString();
        }
    }

    private static String coverage(int affected, int total) {
        return total > 1 && affected < total ? " (" + affected + " of " + total + " URLs)" : "";
    }

    private static String hostOf(ScanResult r) {
        String host = UrlPaths.host(r.url());
        return (host.isBlank() ? r.url() : host).strip().toLowerCase(Locale.ROOT);
    }

    /**
     * Escapes text for Markdown prose: the backslash itself ({@code \}), characters
     * that can open raw HTML or entities ({@code < > &}), links and images
     * ({@code [ ] !}), emphasis or strikethrough ({@code * _ ~}), code spans and tables ({@code ` |}) are
     * backslash-escaped (CommonMark section 2.4), and line breaks are flattened, so a
     * value can never start a block construct. Other punctuation is left alone for
     * readability (e.g. header names such as {@code X-Frame-Options}). Header values come from
     * untrusted servers and are pasted into wikis and tickets that may render HTML.
     */
    static String text(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(value.length() + 8);
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '\n' || c == '\r') {
                sb.append(' ');
            } else if ("\\`*_[]<>|!~&".indexOf(c) >= 0) {
                sb.append('\\').append(c);
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    /**
     * Details-pane description of a profile: what every endpoint of the group is missing or
     * has misconfigured, then the endpoints as paths (query strings hidden, long values shortened).
     */
    public static String profile(HeaderProfile p) {
        StringBuilder sb = new StringBuilder();
        sb.append(p.host()).append(abbreviate(p.path())).append("  (").append(p.size())
                .append(p.size() == 1 ? " URL)\n" : " URLs)\n");
        if (p.sensitive()) {
            sb.append("Contains a ").append(p.sensitivity().label()).append(" endpoint\n");
        }
        ScanResult r = p.representative();
        if (r.hasError()) {
            sb.append("\nNot analysed: ").append(r.error()).append('\n');
        } else if (p.issues().isEmpty()) {
            sb.append("\nNo issues found for the evaluated headers\n");
        }
        if (!p.missingHeaders().isEmpty()) {
            sb.append("\nMissing:\n");
            p.missingHeaders().forEach(h -> sb.append("  - ").append(h).append('\n'));
        }
        if (!p.misconfigured().isEmpty()) {
            sb.append("\nMisconfigured:\n");
            for (Finding f : p.misconfigured()) {
                sb.append("  - ").append(f.issueName());
                if (f.observedValue() != null) {
                    sb.append("  (observed: ").append(abbreviate(f.observedValue())).append(')');
                }
                sb.append('\n');
            }
        }
        if (r.evaluationIncomplete()) {
            sb.append("\nEvaluation incomplete: a rule failed, so headers not listed are not confirmed as correct.\n");
            r.notes().forEach(n -> sb.append("  - ").append(n).append('\n'));
        }
        sb.append("\nURLs:\n");
        int shown = Math.min(p.size(), 500);
        for (int k = 0; k < shown; k++) {
            String url = p.urls().get(k);
            sb.append("  ").append(abbreviate(UrlPaths.path(url)))
                    .append(UrlPaths.query(url).isEmpty() ? "" : "?...").append('\n');
        }
        if (p.size() > shown) {
            sb.append("  ... and ").append(p.size() - shown).append(" more\n");
        }
        return sb.toString();
    }

    /** Cuts {@code value} to 120 characters for display. */
    public static String abbreviate(String value) {
        return value.length() <= 120 ? value : value.substring(0, 117) + "...";
    }

    /** Plain-text comparison report for the activity log. */
    public static String comparison(List<Comparison> comparisons, boolean cancelled) {
        StringBuilder sb = new StringBuilder("\n[COMPARISON RESULTS]").append(cancelled ? " (cancelled, partial)" : "")
                .append('\n');
        for (Comparison c : comparisons) {
            sb.append('\n').append(c.url());
            if (c.rescanFailed()) {
                sb.append("\n  RESCAN FAILED     -> could not rescan: ").append(c.current().error())
                        .append(" (no comparison possible)\n");
                continue;
            }
            sb.append("  (").append(c.current().protocol()).append(")\n");
            if (c.noBaseline()) {
                sb.append("  NO BASELINE       -> previously not analysed — no baseline to compare against\n");
                continue;
            }
            if (c.currentIncomplete()) {
                sb.append("  EVALUATION INCOMPLETE -> a rule failed during the rescan; FIXED/NEW verdicts "
                        + "cannot be given\n");
            }
            c.fixed().forEach(h -> sb.append("  FIXED             -> ").append(h).append('\n'));
            c.presentButInvalid().forEach(h -> sb.append("  PRESENT, INVALID  -> ").append(h)
                    .append(" (now sent but unparseable, so browsers ignore it: not fixed)\n"));
            c.stillMissing().forEach(h -> sb.append("  STILL MISSING     -> ").append(h).append('\n'));
            c.newlyMissing().forEach(h -> sb.append("  NEW ISSUE         -> ").append(h).append('\n'));
            c.noLongerChecked().forEach(h -> sb.append("  NO LONGER CHECKED -> ").append(h)
                    .append(" (still absent, but not required for this response under the current rules)\n"));
            if (c.unchanged() && c.stillMissing().isEmpty()) {
                sb.append("  No changes\n");
            }
        }
        return sb.toString();
    }

    /** Inline code span that cannot be broken out of by backticks in the value. */
    private static String code(String value) {
        return "`" + value.replace("`", "'").replace("\n", " ").replace("\r", " ") + "`";
    }
}
