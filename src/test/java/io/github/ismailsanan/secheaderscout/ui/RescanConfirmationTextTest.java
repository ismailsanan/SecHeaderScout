package io.github.ismailsanan.secheaderscout.ui;

import io.github.ismailsanan.secheaderscout.manual.RescanComparer;
import io.github.ismailsanan.secheaderscout.report.ReportParser;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** SEC-9: the confirmation dialog names every out-of-scope host, whatever its position. */
class RescanConfirmationTextTest {

    @Test
    void outOfScopeHostsAreAlwaysListedEvenBeyondTheDisplayLimit() {
        List<ReportParser.PreviousResult> previous = new ArrayList<>();
        for (int i = 0; i < 20; i++) {
            previous.add(new ReportParser.PreviousResult("https://h" + i + ".example/", Set.of()));
        }
        previous.add(new ReportParser.PreviousResult("http://169.254.169.254/latest/meta-data/", Set.of()));
        previous.add(new ReportParser.PreviousResult("not a url", Set.of()));
        RescanComparer.Plan plan = RescanComparer.plan(previous, u -> u.contains(".example"));

        String text = ScanPanel.rescanConfirmationText(plan);

        assertTrue(text.contains("169.254.169.254   [NOT IN SCOPE]"), text);
        assertTrue(text.indexOf("169.254.169.254") < text.indexOf("h0.example"), "out-of-scope hosts come first");
        assertTrue(text.contains("WARNING: 1 host(s) are outside Burp's target scope"), text);
        assertTrue(text.contains("... and 5 more in-scope host(s)"), text);
        assertTrue(text.contains("1 entry(ies) in the report are not valid http(s) URLs"), text);
        assertFalse(text.contains("h19.example"), "in-scope hosts beyond the limit are abbreviated");
    }

    @Test
    void truncationIsStated() {
        List<ReportParser.PreviousResult> previous = new ArrayList<>();
        for (int i = 0; i < RescanComparer.MAX_URLS + 3; i++) {
            previous.add(new ReportParser.PreviousResult("https://e.example/" + i, Set.of()));
        }
        String text = ScanPanel.rescanConfirmationText(RescanComparer.plan(previous, u -> true));
        assertTrue(text.contains("Only the first " + RescanComparer.MAX_URLS + " of " + (RescanComparer.MAX_URLS + 3)),
                text);
    }
}
