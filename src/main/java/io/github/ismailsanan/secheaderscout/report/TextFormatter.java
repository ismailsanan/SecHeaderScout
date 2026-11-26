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
                    + "findings does not mean clean\n");
            case CLEAN -> sb.append("\nNo issues found for the evaluated headers\n");
            case FINDINGS -> { }
        }
        Map<String, List<Finding>> misconfigured = byHeader(r.misconfigured());
        int width = 0;
        for (Finding f : r.missing()) {
            width = Math.max(width, f.header().length());
        }
        int columns = Math.min(width, 40);

        if (!r.missing().isEmpty()) {
            sb.append("\nMissing\n");
            for (Finding f : r.missing()) {
                sb.append("  - ").append(pad(f.header(), columns)).append("  [Severity: ")
                        .append(severity(f.severity()))
                        .append("]\n");
            }
        }
        if (!misconfigured.isEmpty()) {
            sb.append("\nMisconfigured\n");
            appendMisconfigured(sb, misconfigured, true);
        }
        return sb.toString();
    }

    /**
     * Each header once, its problems nested under it ("  - Header", then "    - Problem: why"). With
     * {@code explain}, findings without a short summary get the first sentence of their explanation.
     */
    private static void appendMisconfigured(StringBuilder sb, Map<String, List<Finding>> byHeader, boolean explain) {
        byHeader.forEach((header, findings) -> {
            sb.append("  - ").append(header).append('\n');
            for (Finding f : findings) {
                sb.append("    - ").append(problem(f));
                String brief = brief(f);
                if (brief != null) {
                    sb.append(": ").append(brief);
                }
                if (explain && f.type() != FindingType.WEAK) {
                    sb.append("  (").append(f.type().label()).append(')');
                }
                sb.append('\n');
                String why = explain && f.summary().isEmpty() ? firstSentence(f.detail()) : "";
                if (!why.isEmpty()) {
                    sb.append("      ").append(why).append('\n');
                }
            }
        });
    }

    /**
     * What goes after the problem name: the finding's short summary (what is lacking and why),
     * else the observed value when it is short, else {@code null}.
     */
    private static String brief(Finding f) {
        if (!f.summary().isEmpty()) {
            return f.summary();
        }
        String v = f.observedValue() == null ? "" : f.observedValue().strip();
        // long raw values (e.g. a CSP listing every allowed origin) are not repeated
        return v.isEmpty() || v.length() > 40 ? null : v;
    }

    static final String REPORT_INTRO = "There exist some HTTP response headers that can increase the security "
            + "posture of a web application.\n";

    /**
     * Plain text ready to paste into a pentest report: every missing header once, then every
     * misconfigured header once with its problems under it, across all results. No hosts, URLs,
     * counts or raw values. Server-derived text is flattened to one line and stripped of
     * {@code < >}, so it cannot add lines or HTML wherever it is pasted (SEC-10).
     */
    public static String reportText(List<ScanResult> results) {
        Map<String, String> missing = new LinkedHashMap<>(); // lower case -> first spelling
        // header (lower case) -> issue name -> first finding with that issue (its reason is the one shown)
        Map<String, Map<String, Finding>> misconfigured = new LinkedHashMap<>();
        for (ScanResult r : results) {
            r.missing().forEach(f -> missing.putIfAbsent(f.header().toLowerCase(Locale.ROOT), f.header()));
            for (Finding f : r.misconfigured()) {
                misconfigured.computeIfAbsent(f.header().toLowerCase(Locale.ROOT), k -> new LinkedHashMap<>())
                        .putIfAbsent(f.issueName(), f);
            }
        }
        if (missing.isEmpty() && misconfigured.isEmpty()) {
            return "No findings to copy.";
        }
        StringBuilder sb = new StringBuilder(REPORT_INTRO);
        if (!missing.isEmpty()) {
            sb.append("One or more of the following security headers are missing:\n");
            missing.values().forEach(h -> sb.append("\u2022 ").append(plain(h)).append('\n'));
        }
        if (!misconfigured.isEmpty()) {
            sb.append(missing.isEmpty() ? "" : "\n")
                    .append("One or more of the following security headers are misconfigured:\n");
            for (Map<String, Finding> problems : misconfigured.values()) {
                sb.append("\u2022 ").append(plain(problems.values().iterator().next().header())).append('\n');
                for (Finding f : problems.values()) {
                    sb.append("    \u25e6 ").append(plain(problem(f)));
                    String why = f.summary().isEmpty() ? firstSentence(f.detail()) : f.summary();
                    if (!why.isEmpty()) {
                        sb.append(": ").append(plain(why));
                    }
                    sb.append('\n');
                }
            }
        }
        return sb.toString();
    }

    /** One line, no {@code < >}: server text pasted into a report cannot add lines or markup. */
    static String plain(String value) {
        return value == null ? "" : value.replaceAll("[\\r\\n]+", " ").replace("<", "").replace(">", "");
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
            appendMisconfigured(sb, byHeader(p.misconfigured()), false);
        }
        if (r.evaluationIncomplete()) {
            sb.append("\nEvaluation incomplete: a rule failed, so headers not listed are not confirmed as correct.\n");
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
        StringBuilder sb = new StringBuilder("\nRescan & Compare results").append(cancelled ? " (cancelled, partial)" : "")
                .append('\n');
        for (Comparison c : comparisons) {
            sb.append('\n').append(c.url());
            if (c.rescanFailed()) {
                sb.append("\n  Could not rescan: ").append(c.current().error()).append(" (no comparison possible)\n");
                continue;
            }
            sb.append("  (").append(c.current().protocol()).append(")\n");
            if (c.noBaseline()) {
                sb.append("  No baseline: previously not analysed\n");
                continue;
            }
            if (c.currentIncomplete()) {
                sb.append("  Evaluation incomplete: a rule failed during the rescan, so fixed/new cannot be told\n");
            }
            comparisonGroup(sb, "Fixed", c.fixed());
            comparisonGroup(sb, "Present but invalid (browsers ignore it, so not fixed)", c.presentButInvalid());
            comparisonGroup(sb, "Still missing", c.stillMissing());
            comparisonGroup(sb, "New issues", c.newlyMissing());
            comparisonGroup(sb, "No longer checked (still absent, but not required here under the current rules)",
                    c.noLongerChecked());
            if (c.unchanged() && c.stillMissing().isEmpty()) {
                sb.append("  No changes\n");
            }
        }
        return sb.toString();
    }

    private static void comparisonGroup(StringBuilder sb, String title, List<String> headers) {
        if (!headers.isEmpty()) {
            sb.append("  ").append(title).append(":\n");
            headers.forEach(h -> sb.append("    • ").append(h).append('\n'));
        }
    }
}
