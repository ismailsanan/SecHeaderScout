import java.io.FileWriter;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

/**
 * Generates HTML report from scan results
 */
public class ReportExporter {

    public static String export(List<ScanResult> results, String outputPath) throws IOException {

        ScoreCalculator.Score score = ScoreCalculator.calculate(results);
        String timestamp = LocalDateTime.now()
                .format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));

        StringBuilder html = new StringBuilder();

        html.append("""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>SecHeaderScout Report</title>
                <style>
                    body { font-family: monospace; background: #1a1a1a; color: #e0e0e0; padding: 20px; }
                    h1 { color: #00ff88; }
                    h2 { color: #888; border-bottom: 1px solid #333; padding-bottom: 5px; }
                    .score { font-size: 24px; font-weight: bold; padding: 10px; border-radius: 4px; display: inline-block; }
                    .SECURE   { background: #004400; color: #00ff88; }
                    .LOW      { background: #443300; color: #ffcc00; }
                    .MEDIUM   { background: #442200; color: #ff8800; }
                    .HIGH     { background: #440000; color: #ff4444; }
                    .CRITICAL { background: #330000; color: #ff0000; }
                    .url-block { background: #222; margin: 10px 0; padding: 10px; border-radius: 4px; border-left: 3px solid #444; }
                    .url-block.critical { border-left-color: #ff0000; }
                    .url-block.clean { border-left-color: #00ff88; }
                    .url { color: #00aaff; font-weight: bold; }
                    .missing { color: #ff4444; }
                    .misconfigured { color: #ff8800; }
                    .clean-msg { color: #00ff88; }
                    .label { color: #ff8800; font-size: 11px; margin-left: 10px; }
                    table { width: 100%; border-collapse: collapse; margin-top: 20px; }
                    th { background: #333; padding: 8px; text-align: left; }
                    td { padding: 8px; border-bottom: 1px solid #333; }
                </style>
            </head>
            <body>
            """);

        html.append("<h1>SecHeaderScout Report</h1>");
        html.append("<p>Generated: ").append(timestamp).append("</p>");
        html.append("<p>Overall Score: <span class='score ")
                .append(score.name()).append("'>")
                .append(ScoreCalculator.getLabel(score))
                .append("</span></p>");
        html.append("<p>URLs Scanned: ").append(results.size()).append("</p>");

        html.append("<h2>Results</h2>");

        for (ScanResult result : results) {

            String urlType = UrlClassifier.getLabel(result.getUrlType());
            boolean isCritical = !urlType.isEmpty();
            boolean isClean = result.isClean();

            html.append("<div class='url-block")
                    .append(isCritical ? " critical" : "")
                    .append(isClean ? " clean" : "")
                    .append("'>");

            html.append("<div class='url'>")
                    .append(result.getUrl())
                    .append(urlType.isEmpty() ? "" : " <span class='label'>" + urlType + "</span>")
                    .append("</div>");

            if (isClean) {
                html.append("<div class='clean-msg'>✓ All headers present and configured correctly</div>");
            } else {

                if (!result.getMissingHeaders().isEmpty()) {
                    html.append("<div style='margin-top:5px'>");
                    for (String header : result.getMissingHeaders()) {
                        HeaderInfo info = OWASPHeaders.getInfo(header);
                        html.append("<div class='missing'>")
                                .append("MISSING → ").append(header)
                                .append(" | Recommended: ").append(info.getRecommended())
                                .append("</div>");
                    }
                    html.append("</div>");
                }

                if (!result.getMisconfiguredHeaders().isEmpty()) {
                    html.append("<div style='margin-top:5px'>");
                    for (String issue : result.getMisconfiguredHeaders()) {
                        html.append("<div class='misconfigured'>")
                                .append("MISCONFIGURED → ").append(issue)
                                .append("</div>");
                    }
                    html.append("</div>");
                }
            }

            html.append("</div>");
        }

        html.append("</body></html>");

        // write to file
        try (FileWriter writer = new FileWriter(outputPath)) {
            writer.write(html.toString());
        }

        return outputPath;
    }
}