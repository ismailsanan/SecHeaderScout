package io.github.ismailsanan.secheaderscout.ui;

import io.github.ismailsanan.secheaderscout.engine.UrlClassifier;
import io.github.ismailsanan.secheaderscout.model.ScanResult;
import io.github.ismailsanan.secheaderscout.report.TextFormatter;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ResultsTableModelTest {

    private static final String URL = "https://a.example/api/users?id=1";

    @Test
    void byUrlUsesTheByProfileLayoutAndDetailsShowEvidence() {
        ScanResult r = new ScanResult(URL, URL, "GET", 200, true, false, null, null, null,
                UrlClassifier.classify(URL), List.of(), List.of(), Set.of(), false,
                "GET /api/users?id=1 HTTP/1.1\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\n");
        ResultsTableModel model = new ResultsTableModel();
        model.setRows(List.of(r));

        assertEquals("a.example", model.getValueAt(0, 2));
        assertEquals("/api/users?id=1", model.getValueAt(0, ResultsTableModel.COL_PATH));
        assertEquals("", model.getValueAt(0, ResultsTableModel.COL_MISSING));
        assertEquals("", model.getValueAt(0, 9), "no findings, no worst severity");
        assertFalse(TextFormatter.details(r).contains("GET /api/users?id=1 HTTP"), "raw request has its own tab");

        ScanResult noted = new ScanResult(URL, URL, "GET", 200, true, false, null, null, null,
                UrlClassifier.classify(URL), List.of(), List.of("a redirect note"), Set.of(), false,
                "GET /<x> HTTP/1.1\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\n");
        String html = io.github.ismailsanan.secheaderscout.report.ReportExporter.render(List.of(noted), "v",
                java.time.ZonedDateTime.now());
        assertTrue(html.contains("<summary>Request</summary><pre>GET /&lt;x&gt; HTTP/1.1"), html);
        assertTrue(html.contains("<summary>Response</summary>"), html);
        assertFalse(html.contains("a redirect note"), html);
    }
}
