package io.github.ismailsanan.secheaderscout.report;

import io.github.ismailsanan.secheaderscout.util.HtmlEscaper;
import io.github.ismailsanan.secheaderscout.engine.Finding;
import io.github.ismailsanan.secheaderscout.model.HeaderProfile;
import io.github.ismailsanan.secheaderscout.model.ScanResult;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.function.Function;

/**
 * Renders manual-scan results as a self-contained HTML report.
 *
 * <p>Security: every value that comes from HTTP traffic or user input (URLs,
 * header names and values, finding text, notes, errors) goes through
 * {@link HtmlEscaper#escape} and appears only as element content or inside
 * double-quoted attributes. The page has no JavaScript and declares a
 * Content-Security-Policy that blocks script, so a missed escape still could
 * not execute code.</p>
 *
 * <p>Format: each result is a {@code <section class="url-block" data-url="...">}
 * and each missing header a {@code <li class="missing" data-header="...">}.
 * A result that could not be analysed carries {@code data-error="true"} and one whose
 * evaluation is incomplete (a rule crashed) {@code data-incomplete="true"}: their
 * missing lists are no baseline for a later comparison.
 * {@link ReportParser} relies on these attributes.</p>
 */
public final class ReportExporter {

    static final String FORMAT_VERSION = "2";

    private static final String STYLE = """
            body { font-family: monospace; background: #1a1a1a; color: #e0e0e0; padding: 20px; }
            h1 { color: #00ff88; }
            h2 { color: #888; border-bottom: 1px solid #333; padding-bottom: 5px; }
            .score { font-size: 20px; font-weight: bold; padding: 6px 10px; border-radius: 4px; display: inline-block; }
            .INFO { background: #002244; color: #66aaff; }
            .LOW { background: #443300; color: #ffcc00; }
            .MEDIUM { background: #442200; color: #ff8800; }
            .HIGH { background: #440000; color: #ff4444; }
            .CRITICAL { background: #330000; color: #ff0000; }
            .url-block { background: #222; margin: 10px 0; padding: 10px; border-radius: 4px; border-left: 3px solid #444; }
            .url-block.critical { border-left-color: #ff0000; }
            .url-block.clean { border-left-color: #00ff88; }
            .url-block.fallback { border-left-color: #ffcc00; }
            .profile { background: #222; margin: 10px 0; padding: 10px; border-radius: 4px; border-left: 3px solid #4477aa; }
            .profile.critical { border-left-color: #ff0000; }
            .url-block.incomplete { border-left-color: #ff8800; }
            .url { color: #00aaff; font-weight: bold; word-break: break-all; }
            .label { color: #ff8800; font-size: 11px; margin-left: 10px; }
            .proto { color: #aaa; font-size: 11px; margin-left: 10px; }
            .warning { color: #111; background: #ffcc00; padding: 4px 6px; margin-top: 6px; border-radius: 3px; }
            .error { color: #ff4444; margin-top: 6px; }
            ul { margin: 6px 0; padding-left: 18px; }
            .missing { color: #ff4444; }
            .misconfigured { color: #ff8800; }
            .notes { color: #999; }
            .clean-msg { color: #00ff88; }
            .observed { color: #bbb; }
            """;

    private ReportExporter() {
    }

    /**
     * Writes the report to a temp file in the target directory, then moves it onto
     * {@code output}. The move is atomic ({@link StandardCopyOption#ATOMIC_MOVE}) where the
     * file system supports it, so readers see either the old or the new report; otherwise
     * it falls back to a plain replacing move, which is not atomic.
     *
     * @return the path written
     */
    public static Path export(List<ScanResult> results, String definitionsVersion, Path output) throws IOException {
        return export(results, List.of(), definitionsVersion, output);
    }

    /** As {@link #export(List, String, Path)}, with a "Header profiles" section (from a Deep Scan). */
    public static Path export(List<ScanResult> results, List<HeaderProfile> profiles, String definitionsVersion,
                              Path output) throws IOException {
        Path absolute = output.toAbsolutePath();
        Path dir = absolute.getParent();
        Path tmp = Files.createTempFile(dir, ".secheaderscout-", ".tmp");
        try {
            try (Writer writer = Files.newBufferedWriter(tmp, StandardCharsets.UTF_8)) {
                render(results, profiles, definitionsVersion, ZonedDateTime.now(), writer);
            } catch (UncheckedIOException ex) {
                throw ex.getCause();
            }
            try {
                Files.move(tmp, absolute, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(tmp, absolute, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(tmp);
        }
        return absolute;
    }

    /** Pure rendering function (convenience for tests and small reports). */
    public static String render(List<ScanResult> results, String definitionsVersion, ZonedDateTime generatedAt) {
        StringBuilder sb = new StringBuilder(4096 + results.size() * 1024);
        render(results, List.of(), definitionsVersion, generatedAt, sb);
        return sb.toString();
    }

    /** Renders with a "Header profiles" section (empty list: no section). */
    public static String render(List<ScanResult> results, List<HeaderProfile> profiles, String definitionsVersion,
                                ZonedDateTime generatedAt) {
        StringBuilder sb = new StringBuilder(4096 + results.size() * 1024);
        render(results, profiles, definitionsVersion, generatedAt, sb);
        return sb.toString();
    }

    /**
     * Renders straight into {@code out}. Exporting streams to the file this way instead of
     * building the whole report in memory and copying it twice (toString + encoding), which
     * for tens of thousands of results means hundreds of MB of heap inside Burp.
     *
     * @throws UncheckedIOException if {@code out} fails
     */
    public static void render(List<ScanResult> results, List<HeaderProfile> profiles, String definitionsVersion,
                              ZonedDateTime generatedAt,
                              Appendable out) {
        Function<String, String> e = HtmlEscaper::escape;
        ScoreCalculator.Score score = ScoreCalculator.calculate(results);
        Out html = new Out(out);

        html.append("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"UTF-8\">\n")
                .append("<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; ")
                .append("style-src 'unsafe-inline'\">\n")
                .append("<meta name=\"generator\" content=\"SecHeaderScout\" data-format=\"")
                .append(FORMAT_VERSION).append("\">\n")
                .append("<title>SecHeaderScout Report</title>\n<style>\n").append(STYLE).append("</style>\n")
                .append("</head>\n<body>\n<h1>SecHeaderScout Report</h1>\n");

        html.append("<p>Generated: ")
                .append(e.apply(generatedAt.format(DateTimeFormatter.ISO_OFFSET_DATE_TIME))).append("</p>\n")
                .append("<p>OWASP definitions: ").append(e.apply(definitionsVersion)).append("</p>\n")
                .append("<p>Overall score: <span class=\"score ").append(score.name()).append("\">")
                .append(e.apply(score.label())).append("</span>");
        long incomplete = results.stream().filter(ScanResult::evaluationIncomplete).count();
        if (incomplete > 0) {
            html.append(" (lower bound: ").append(incomplete).append(" result(s) not fully evaluated)");
        }
        html.append("</p>\n")
                .append("<p>URLs scanned: ").append(results.size()).append("</p>\n");
        long fallbacks = results.stream().filter(ScanResult::httpFallback).count();
        if (fallbacks > 0) {
            html.append("<p class=\"warning\">").append(fallbacks)
                    .append(" result(s) were obtained over plain HTTP after HTTPS failed; they are marked below "
                            + "and do not describe the HTTPS site.</p>\n");
        }
        if (!profiles.isEmpty()) {
            renderProfiles(profiles, html, e);
        }
        html.append("<h2>Results</h2>\n");
        if (results.isEmpty()) {
            html.append("<p>No results.</p>\n");
        }

        for (ScanResult r : results) {
            String label = r.urlType().label();
            html.append("<section class=\"url-block")
                    .append(r.urlType().isSensitive() ? " critical" : "")
                    .append(r.isClean() ? " clean" : "")
                    .append(r.httpFallback() ? " fallback" : "")
                    .append(r.evaluationIncomplete() ? " incomplete" : "")
                    .append("\" data-url=\"").append(e.apply(r.url()))
                    .append("\" data-protocol=\"").append(r.protocol())
                    .append("\" data-fallback=\"").append(r.httpFallback());
            if (r.hasError()) {
                html.append("\" data-error=\"true");
            }
            if (r.evaluationIncomplete()) {
                html.append("\" data-incomplete=\"true");
            }
            html.append("\">\n");

            html.append("<div class=\"url\">")
                    .append(r.method() == null ? "" : e.apply(r.method()) + " ")
                    .append(e.apply(r.url()));
            if (!label.isEmpty()) {
                html.append(" <span class=\"label\">").append(e.apply(label)).append("</span>");
            }
            html.append(" <span class=\"proto\">").append(r.protocol())
                    .append(r.statusCode() > 0 ? " " + r.statusCode() : "").append("</span></div>\n");

            if (r.httpFallback()) {
                html.append("<div class=\"warning\">⚠ ").append(e.apply(r.fallbackWarning())).append("</div>\n");
            }
            switch (r.status()) {
                case ERROR -> html.append("<div class=\"error\">Not analysed: ").append(e.apply(r.error()))
                        .append("</div>\n");
                case INCOMPLETE -> html.append("<div class=\"warning\">⚠ Evaluation incomplete: at least one rule "
                        + "failed, so headers may be unassessed and the absence of findings does not mean this URL "
                        + "is clean (see the notes below)</div>\n");
                case CLEAN -> html.append("<div class=\"clean-msg\">✓ No issues found for the evaluated headers</div>\n");
                case FINDINGS -> { }
            }

            List<Finding> missing = r.missing();
            List<Finding> misconfigured = r.misconfigured();
            if (!missing.isEmpty() || !misconfigured.isEmpty()) {
                html.append("<ul>\n");
                for (Finding f : missing) {
                    html.append("<li class=\"missing\" data-header=\"").append(e.apply(f.header())).append("\">")
                            .append("MISSING → ").append(e.apply(f.header()))
                            .append(" | Recommended: ").append(e.apply(f.recommended()))
                            .append(" <span class=\"observed\">[").append(f.severity()).append(", ")
                            .append(f.confidence()).append("]</span></li>\n");
                }
                for (Finding f : misconfigured) {
                    html.append("<li class=\"misconfigured\" data-header=\"").append(e.apply(f.header())).append("\">")
                            .append(f.type()).append(" → ").append(e.apply(f.issueName()))
                            .append(" [").append(f.severity()).append(", ").append(f.confidence()).append("]: ")
                            .append(e.apply(f.detail()));
                    if (f.observedValue() != null) {
                        html.append(" <span class=\"observed\">Observed: ").append(e.apply(f.observedValue()))
                                .append("</span>");
                    }
                    html.append("</li>\n");
                }
                html.append("</ul>\n");
            }
            if (!r.notes().isEmpty()) {
                html.append("<ul class=\"notes\">\n");
                for (String note : r.notes()) {
                    html.append("<li>").append(e.apply(note)).append("</li>\n");
                }
                html.append("</ul>\n");
            }
            html.append("</section>\n");
        }
        html.append("</body>\n</html>\n");
    }

    /** Every dynamic value is escaped, exactly like the per-URL results. */
    private static void renderProfiles(List<HeaderProfile> profiles, Out html, Function<String, String> e) {
        html.append("<h2>Header profiles</h2>\n<p>").append(profiles.size())
                .append(" group(s) of endpoints with the same host, path group and issues; groups with logout, ")
                .append("login, payment or admin endpoints first.</p>\n");
        for (HeaderProfile p : profiles) {
            html.append("<section class=\"profile").append(p.sensitive() ? " critical" : "")
                    .append("\">\n<div class=\"url\">").append(e.apply(p.host())).append(e.apply(p.path()))
                    .append(" <span class=\"proto\">").append(p.size()).append(" URL(s)</span>");
            if (p.sensitive()) {
                html.append(" <span class=\"label\">").append(e.apply(p.sensitivity().label())).append("</span>");
            }
            html.append("</div>\n<ul>\n");
            if (p.issues().isEmpty()) {
                html.append("<li class=\"clean-msg\">No issues found for the evaluated headers</li>\n");
            }
            for (String header : p.missingHeaders()) {
                html.append("<li class=\"missing\">Missing: ").append(e.apply(header)).append("</li>\n");
            }
            for (Finding f : p.misconfigured()) {
                html.append("<li class=\"misconfigured\">").append(e.apply(f.issueName())).append("</li>\n");
            }
            html.append("</ul>\n<details><summary>URLs</summary><ul class=\"notes\">\n");
            for (String url : p.urls()) {
                html.append("<li>").append(e.apply(url)).append("</li>\n");
            }
            html.append("</ul></details>\n</section>\n");
        }
    }

    /** Fluent, unchecked wrapper so the template reads like StringBuilder code. */
    private static final class Out {
        private final Appendable target;

        Out(Appendable target) {
            this.target = target;
        }

        Out append(CharSequence s) {
            try {
                target.append(s);
            } catch (IOException ex) {
                throw new UncheckedIOException(ex);
            }
            return this;
        }

        Out append(char c) {
            try {
                target.append(c);
            } catch (IOException ex) {
                throw new UncheckedIOException(ex);
            }
            return this;
        }

        Out append(Object o) {
            return append(String.valueOf(o));
        }
    }
}
