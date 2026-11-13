package io.github.ismailsanan.secheaderscout.report;

import io.github.ismailsanan.secheaderscout.engine.Finding;
import io.github.ismailsanan.secheaderscout.engine.FindingType;
import io.github.ismailsanan.secheaderscout.engine.Severity;
import io.github.ismailsanan.secheaderscout.model.HeaderProfile;
import io.github.ismailsanan.secheaderscout.model.ScanResult;
import io.github.ismailsanan.secheaderscout.util.UrlPaths;

import java.util.ArrayList;
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

    /** Longest observed value still shown inline; longer ones (e.g. full CSP policies) are left out. */
    private static final int MAX_INLINE_VALUE = 40;

    /**
     * Plain-text description of one result for the details pane: the missing headers, then each
     * misconfigured header once with its problems listed under it and a one-sentence explanation.
     * Long raw header values (such as a CSP listing every allowed origin) are not repeated.
     */
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
            case ERROR -> sb.append("\nERROR: ").append(r.error()).append('\n');
            case INCOMPLETE -> sb.append("\nEVALUATION INCOMPLETE: at least one rule failed, so the absence of "
                    + "findings does not mean clean (see notes)\n");
            case CLEAN -> sb.append("\nNo issues found for the evaluated headers\n");
            case FINDINGS -> { }
        }
        Map<String, List<Finding>> misconfigured = byHeader(r.misconfigured());
        int width = 0;
        for (Finding f : r.missing()) {
            width = Math.max(width, f.header().length());
        }
        for (String header : misconfigured.keySet()) {
            width = Math.max(width, header.length());
        }
        int columns = Math.min(width, 40);

        if (!r.missing().isEmpty()) {
            sb.append("\nMissing (").append(r.missing().size()).append(")\n");
            for (Finding f : r.missing()) {
                sb.append("  - ").append(pad(f.header(), columns)).append("  [Severity: ")
                        .append(severity(f.severity()))
                        .append("]\n");
            }
        }
        if (!misconfigured.isEmpty()) {
            sb.append("\nMisconfigured (").append(misconfigured.size()).append(misconfigured.size() == 1
                    ? " header)\n" : " headers)\n");
            misconfigured.forEach((header, findings) -> {
                sb.append("  - ").append(pad(header, columns)).append("  [Severity: ")
                        .append(severity(worst(findings)))
                        .append("]\n");
                for (Finding f : findings) {
                    sb.append("      * ").append(problem(f));
                    String brief = brief(f);
                    if (brief != null) {
                        sb.append(": ").append(brief);
                    }
                    if (f.type() != FindingType.WEAK) {
                        sb.append("  (").append(f.type().label()).append(')');
                    }
                    sb.append('\n');
                    // the short summary already says what is lacking and why; only explain findings without one
                    String why = f.summary().isEmpty() ? firstSentence(f.detail()) : "";
                    if (!why.isEmpty()) {
                        sb.append("        ").append(why).append('\n');
                    }
                }
            });
        }
        if (!r.notes().isEmpty()) {
            sb.append("\nNotes\n");
            r.notes().forEach(note -> sb.append("  - ").append(note).append('\n'));
        }
        return sb.toString();
    }

    /**
     * Markdown ready to paste into a pentest report, grouped by host, then by header:
     * <pre>
     * ### www.example.com
     *
     * **Missing:**
     *
     * - Referrer-Policy
     *
     * **Misconfigured:**
     *
     * - Strict-Transport-Security
     *   - Max-age is short: max-age is 300 (5 minutes), should be at least 31536000 (one year); ...
     * </pre>
     * Each header appears once per host with its problems as sub-bullets, each followed by
     * the finding's short summary (what is lacking and, briefly, why), or the first sentence
     * of its explanation when it has no summary. No URLs, URL
     * counts or raw header values are listed, so the text stays short. Hosts without anything to report
     * are left out, but never one with an HTTP-fallback result (its warning must reach the
     * reader, FR-7), an incomplete evaluation (that is not clean, HE-9) or an unanalysed
     * URL. Server-derived text is escaped (SEC-10).
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

        Set<String> missing = new LinkedHashSet<>();
        // header (lower case) -> issue name -> first finding with that issue (its reason is the one shown)
        Map<String, Map<String, Finding>> misconfigured = new LinkedHashMap<>();
        for (ScanResult r : analysed) {
            r.missing().forEach(f -> missing.add(f.header()));
            for (Finding f : r.misconfigured()) {
                misconfigured.computeIfAbsent(f.header().toLowerCase(Locale.ROOT), k -> new LinkedHashMap<>())
                        .putIfAbsent(f.issueName(), f);
            }
        }
        if (missing.isEmpty() && misconfigured.isEmpty() && errors.isEmpty() && incomplete.isEmpty()
                && warnings.isEmpty()) {
            return;
        }

        md.append("### ").append(text(host)).append("\n\n");
        for (String warning : warnings) {
            md.append("> **Warning:** ").append(text(warning)).append("\n\n");
        }
        if (!missing.isEmpty()) {
            md.append("**Missing:**\n\n");
            missing.forEach(header -> md.append("- ").append(text(header)).append('\n'));
            md.append('\n');
        }
        if (!misconfigured.isEmpty()) {
            md.append("**Misconfigured:**\n\n");
            for (Map<String, Finding> problems : misconfigured.values()) {
                md.append("- ").append(text(problems.values().iterator().next().header())).append('\n');
                for (Finding f : problems.values()) {
                    md.append("  - ").append(text(problem(f)));
                    String why = f.summary().isEmpty() ? firstSentence(f.detail()) : f.summary();
                    if (!why.isEmpty()) {
                        md.append(": ").append(text(why));
                    }
                    md.append('\n');
                }
            }
            md.append('\n');
        }
        if (!incomplete.isEmpty()) {
            md.append("**Evaluation incomplete:** a rule failed, so headers not listed above are not confirmed "
                    + "as correct.\n\n");
            incomplete.stream().flatMap(r -> r.notes().stream()).distinct()
                    .forEach(note -> md.append("- ").append(text(note)).append('\n'));
            md.append('\n');
        }
        if (!errors.isEmpty()) {
            md.append("**Not analysed:**\n\n");
            errors.stream().map(r -> r.error() == null ? "unknown error" : r.error()).distinct()
                    .forEach(reason -> md.append("- ").append(text(reason)).append('\n'));
            md.append('\n');
        }
    }

    /** Groups findings by header (case-insensitively), keeping first-seen order and spelling. */
    private static Map<String, List<Finding>> byHeader(List<Finding> findings) {
        Map<String, List<Finding>> byKey = new LinkedHashMap<>();
        Map<String, String> spelling = new LinkedHashMap<>();
        for (Finding f : findings) {
            String key = f.header().toLowerCase(Locale.ROOT);
            spelling.putIfAbsent(key, f.header());
            byKey.computeIfAbsent(key, k -> new ArrayList<>()).add(f);
        }
        Map<String, List<Finding>> out = new LinkedHashMap<>();
        byKey.forEach((key, list) -> out.put(spelling.get(key), list));
        return out;
    }

    /**
     * The issue name without the header it is listed under: "Content-Security-Policy allows eval"
     * becomes "Allows eval", "X-Frame-Options header has an invalid value" becomes "Has an invalid value".
     */
    static String problem(Finding f) {
        String name = f.issueName();
        String header = f.header();
        if (name.regionMatches(true, 0, header, 0, header.length())) {
            String rest = name.substring(header.length()).strip();
            if (rest.regionMatches(true, 0, "header ", 0, 7)) {
                rest = rest.substring(7).strip();
            }
            if (!rest.isEmpty()) {
                name = rest;
            }
        }
        return name.isEmpty() ? name : Character.toUpperCase(name.charAt(0)) + name.substring(1);
    }

    /**
     * What goes after the problem name in the details pane: the finding's short summary
     * (what is lacking and why), else the observed value when it is short, else {@code null}.
     */
    private static String brief(Finding f) {
        return f.summary().isEmpty() ? inlineValue(f.observedValue()) : f.summary();
    }

    /** {@code value} if it is short enough to show inline, else {@code null}. */
    private static String inlineValue(String value) {
        if (value == null) {
            return null;
        }
        String v = value.strip();
        return v.isEmpty() || v.length() > MAX_INLINE_VALUE ? null : v;
    }

    private static Severity worst(List<Finding> findings) {
        Severity worst = Severity.INFORMATION;
        for (Finding f : findings) {
            if (f.severity().compareTo(worst) > 0) {
                worst = f.severity();
            }
        }
        return worst;
    }

    private static String severity(Severity s) {
        return switch (s) {
            case INFORMATION -> "Info";
            case LOW -> "Low";
            case MEDIUM -> "Medium";
            case HIGH -> "High";
        };
    }

    /** The first sentence of {@code text}, cut to 160 characters. */
    private static String firstSentence(String text) {
        if (text == null) {
            return "";
        }
        String t = text.strip().replace('\n', ' ').replace('\r', ' ');
        int end = t.indexOf(". ");
        if (end >= 0) {
            t = t.substring(0, end + 1);
        }
        return t.length() <= 160 ? t : t.substring(0, 157) + "...";
    }

    private static String pad(String value, int width) {
        return value.length() >= width ? value : value + " ".repeat(width - value.length());
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
            byHeader(p.misconfigured()).forEach((header, findings) -> {
                sb.append("  - ").append(header).append('\n');
                for (Finding f : findings) {
                    sb.append("      * ").append(problem(f));
                    String brief = brief(f);
                    if (brief != null) {
                        sb.append(": ").append(brief);
                    }
                    sb.append('\n');
                }
            });
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
}
