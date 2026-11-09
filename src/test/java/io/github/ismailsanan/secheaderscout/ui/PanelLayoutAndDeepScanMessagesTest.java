package io.github.ismailsanan.secheaderscout.ui;

import io.github.ismailsanan.secheaderscout.manual.DeepScanResult;
import org.junit.jupiter.api.Test;

import javax.swing.JButton;
import javax.swing.JPanel;
import java.awt.Dimension;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Button rows wrap instead of hiding buttons; an empty Deep Scan explains itself. */
class PanelLayoutAndDeepScanMessagesTest {

    private static JPanel row() {
        JPanel row = new JPanel(new WrapLayout());
        for (int i = 0; i < 6; i++) {
            row.add(new JButton("Button number " + i));
        }
        return row;
    }

    @Test
    void aNarrowContainerWrapsTheRowOntoSeveralLines() {
        JPanel wide = row();
        JPanel narrow = row();
        int oneLine = wide.getPreferredSize().height; // unsized: no width limit, one line

        JPanel parent = new JPanel(null);
        parent.setSize(new Dimension(250, 400));
        parent.add(narrow);
        int wrapped = narrow.getPreferredSize().height;

        assertTrue(wrapped >= 3 * new JButton("Button number 0").getPreferredSize().height,
                "6 buttons in 250px need several lines: " + wrapped + " vs one line " + oneLine);
        assertTrue(narrow.getPreferredSize().width <= 250, "wrapped row fits its parent");
    }

    /** Regression: after shrinking a wide window, a wrapped row must get the height of its second line. */
    @Test
    void aRowThatWrapsAfterAResizeGetsItsExtraLine() {
        JPanel parent = new JPanel(new java.awt.GridBagLayout());
        java.awt.GridBagConstraints c = new java.awt.GridBagConstraints();
        c.gridx = 0;
        c.weightx = 1;
        c.fill = java.awt.GridBagConstraints.HORIZONTAL;
        JPanel row = row();
        parent.add(row, c);
        parent.add(new JButton("next row"), c);

        layOut(parent, 2000);
        int oneLine = row.getHeight();
        layOut(parent, 300);
        assertTrue(row.getHeight() > 2 * oneLine, "wrapped row height " + row.getHeight() + " vs " + oneLine);
        for (java.awt.Component b : row.getComponents()) {
            assertTrue(b.getY() + b.getHeight() <= row.getHeight(), "button below the row's visible area: " + b);
        }
    }

    private static void layOut(JPanel parent, int width) {
        parent.setSize(width, 600);
        for (int pass = 0; pass < 2; pass++) {
            parent.doLayout();
            for (java.awt.Component child : parent.getComponents()) {
                ((java.awt.Container) child).doLayout();
            }
        }
    }

    @Test
    void noCapturedTrafficExplainsThatDeepScanOnlyReadsTheSiteMap() {
        String text = ScanPanel.deepScanEmptyExplanation(new DeepScanResult.Stats(0, 0, 0, 0, 0, 0, 0));
        assertTrue(text.contains("sends no requests"), text);
        assertTrue(text.contains("Browse the application through Burp's proxy"), text);
        assertTrue(text.contains("Quick Scan"), text);
    }

    @Test
    void everythingFilteredExplainsWhichFiltersToUntick() {
        String text = ScanPanel.deepScanEmptyExplanation(new DeepScanResult.Stats(5, 0, 3, 2, 0, 0, 0));
        assertTrue(text.startsWith("All 5 captured responses were filtered out (3 static files, 2 error responses)"),
                text);
        assertTrue(text.contains("static files"), text);
        assertFalse(text.contains("skipped"), text);
    }

    @Test
    void aScanThatAnalysedSomethingNeedsNoExplanation() {
        assertNull(ScanPanel.deepScanEmptyExplanation(new DeepScanResult.Stats(5, 1, 4, 0, 0, 0, 0)));
    }
}
