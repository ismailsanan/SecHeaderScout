import java.io.FileWriter;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

/**
 * standalone HTML report
 *
 * the class names and the "MISSING ->" text below are the contract that
 * ReportComparator parses, changing them means updating its regex too
 */
public class ReportExporter {

    public static String export(List<ScanResult> results, String outputPath) throws IOException {

        ScoreCalculator.Score score = ScoreCalculator.calculate(results);
        String timestamp = LocalDateTime.now()
                .format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));

        long withFindings = results.stream().filter(r -> !r.isClean()).count();

        StringBuilder html = new StringBuilder();

        html.append("""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>SecHeaderScout Report</title>
                <style>
                    body { font-family: monospace; background: #0d1117; color: #e6edf3; padding: 24px; line-height: 1.5; }
                    h1 { color: #2bd9a3; margin-bottom: 4px; }
                    h2 { color: #7d8590; border-bottom: 1px solid #21262d; padding-bottom: 6px; margin-top: 28px; }
                    .meta { color: #7d8590; font-size: 13px; }
                    .score { font-size: 20px; font-weight: bold; padding: 6px 14px; border-radius: 4px; display: inline-block; }
                    .PASS     { background: #04360f; color: #2bd9a3; }
                    .LOW      { background: #2a3300; color: #c9d600; }
                    .MEDIUM   { background: #3a2a00; color: #ffb700; }
                    .HIGH     { background: #3d1a00; color: #ff8800; }
                    .CRITICAL { background: #3d0000; color: #ff5555; }
                    .url-block { background: #161b22; margin: 12px 0; padding: 12px 14px; border-radius: 6px; border-left: 3px solid #30363d; }
                    .url-block.critical { border-left-color: #ff8800; }
                    .url-block.clean    { border-left-color: #2bd9a3; }
                    .url { color: #58a6ff; font-weight: bold; word-break: break-all; }
                    .method { color: #7d8590; margin-right: 6px; }
                    .section { color: #7d8590; font-size: 12px; margin-top: 10px; text-transform: uppercase; letter-spacing: 1px; }
                    .missing { color: #ff7b72; margin-left: 12px; }
                    .misconfigured { color: #ffb700; margin-left: 12px; }
                    .clean-msg { color: #2bd9a3; }
                    .label { color: #ff8800; font-size: 11px; margin-left: 8px; }
                    .rec { color: #7d8590; }
                </style>
            </head>
            <body>
            """);

        html.append("<h1>SecHeaderScout Report</h1>");
        html.append("<div class='meta'>Generated ").append(timestamp).append("</div>");
        html.append("<p>Overall: <span class='score ").append(score.name()).append("'>")
            .append(ScoreCalculator.getLabel(score)).append("</span></p>");
        html.append("<div class='meta'>")
            .append(results.size()).append(" URLs scanned, ")
            .append(withFindings).append(" with findings")
            .append("</div>");

        html.append("<h2>Findings</h2>");

        for (ScanResult result : results) {

            String label = UrlClassifier.getLabel(result.getUrlType());
            boolean flagged = !label.isEmpty();

            html.append("<div class='url-block")
                .append(flagged ? " critical" : "")
                .append(result.isClean() ? " clean" : "")
                .append("'>");

            html.append("<div class='url'><span class='method'>")
                .append(esc(result.getMethod())).append("</span>")
                .append(esc(result.getUrl()))
                .append(flagged ? " <span class='label'>" + esc(label) + "</span>" : "")
                .append("</div>");

            if (result.isClean()) {
                html.append("<div class='clean-msg'>no findings</div></div>");
                continue;
            }

            if (!result.getMissingHeaders().isEmpty()) {
                html.append("<div class='section'>Missing</div>");
                for (String header : result.getMissingHeaders()) {
                    HeaderInfo info = OWASPHeaders.getInfo(header);
                    html.append("<div class='missing'>MISSING &#8594; ").append(esc(header))
                        .append(" <span class='rec'>| recommended: ")
                        .append(esc(info.getRecommended())).append("</span></div>");
                }
            }

            if (!result.getMisconfiguredHeaders().isEmpty()) {
                html.append("<div class='section'>Misconfigured</div>");
                for (String issue : result.getMisconfiguredHeaders()) {
                    html.append("<div class='misconfigured'>MISCONFIGURED &#8594; ")
                        .append(esc(issue)).append("</div>");
                }
            }

            html.append("</div>");
        }

        html.append("</body></html>");

        try (FileWriter writer = new FileWriter(outputPath)) {
            writer.write(html.toString());
        }

        return outputPath;
    }

    // header values can contain < and > which would break the report layout
    private static String esc(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }
}