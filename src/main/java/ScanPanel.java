import burp.api.montoya.MontoyaApi;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * main UI tab
 *
 * NORTH  -> title + score, target list, controls
 * CENTER -> results, expands to fill the rest
 */
public class ScanPanel {

    private final MontoyaApi api;
    private final HeaderChecker headerChecker;
    private final DeepScanner deepScanner;

    private final JPanel mainPanel;
    private final DefaultListModel<String> hostListModel;
    private final JList<String> hostList;
    private final JTextArea resultsArea;
    private final JLabel scoreLabel;

    private List<ScanResult> lastResults = new ArrayList<>();
    private String currentFilter = "ALL";

    public ScanPanel(MontoyaApi api, HeaderChecker headerChecker) {
        this.api = api;
        this.headerChecker = headerChecker;
        this.deepScanner = new DeepScanner(api, headerChecker);
        this.hostListModel = new DefaultListModel<>();
        this.hostList = new JList<>(hostListModel);
        this.resultsArea = new JTextArea();
        this.scoreLabel = new JLabel("Score: N/A");
        this.mainPanel = buildUI();
    }

    public JPanel getPanel() { return mainPanel; }

    //  UI 

    private JPanel buildUI() {
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // BoxLayout stacks by preferred height
        // GridLayout forces equal rows and squashes everything
        JPanel top = new JPanel();
        top.setLayout(new BoxLayout(top, BoxLayout.Y_AXIS));

        top.add(buildTitlePanel());
        top.add(Box.createVerticalStrut(8));
        top.add(buildTargetPanel());
        top.add(Box.createVerticalStrut(8));
        top.add(buildInputRow());
        top.add(Box.createVerticalStrut(4));
        top.add(buildScanRow());
        top.add(Box.createVerticalStrut(4));
        top.add(buildFilterRow());

        panel.add(top, BorderLayout.NORTH);
        panel.add(buildResultsPanel(), BorderLayout.CENTER);

        return panel;
    }

    private JPanel buildTitlePanel() {
        JPanel p = new JPanel(new BorderLayout());
        JLabel title = new JLabel("SecHeaderScout { OWASP Header Checker }");
        title.setFont(new Font("Arial", Font.BOLD, 14));
        scoreLabel.setFont(new Font("Arial", Font.BOLD, 13));
        p.add(title, BorderLayout.WEST);
        p.add(scoreLabel, BorderLayout.EAST);
        return p;
    }

    private JPanel buildTargetPanel() {
        JPanel p = new JPanel(new BorderLayout());
        hostList.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        JScrollPane sp = new JScrollPane(hostList);
        sp.setPreferredSize(new Dimension(800, 100));
        p.add(new JLabel("Targets:"), BorderLayout.NORTH);
        p.add(sp, BorderLayout.CENTER);
        return p;
    }

    private JPanel buildInputRow() {
        JPanel row = new JPanel(new FlowLayout(FlowLayout.LEFT));

        JTextField customInput = new JTextField(20);
        JButton addButton     = new JButton("Add Target");
        JButton deleteButton  = new JButton("Delete Selected");
        JButton clearTargets  = new JButton("Clear Targets");
        JButton refreshButton = new JButton("Refresh from Burp");

        row.add(new JLabel("Custom Target:"));
        row.add(customInput);
        row.add(addButton);
        row.add(deleteButton);
        row.add(clearTargets);
        row.add(refreshButton);

        addButton.addActionListener(e -> {
            String host = customInput.getText().trim();
            if (!host.isEmpty() && !hostListModel.contains(host)) {
                hostListModel.addElement(host);
                customInput.setText("");
            }
        });

        // remove every selected entry, not just the first
        deleteButton.addActionListener(e -> {
            for (String selected : hostList.getSelectedValuesList()) {
                hostListModel.removeElement(selected);
            }
        });

        clearTargets.addActionListener(e -> hostListModel.clear());
        refreshButton.addActionListener(e -> refreshHostsFromBurp());

        return row;
    }

    private JPanel buildScanRow() {
        JPanel row = new JPanel(new FlowLayout(FlowLayout.LEFT));

        JButton quickScan  = new JButton("Quick Scan");
        JButton deepScan   = new JButton("Deep Scan");
        JButton export     = new JButton("Export Report");
        JButton compare    = new JButton("Rescan & Compare");
        JButton clear      = new JButton("Clear");
        JButton copy       = new JButton("Copy");
        JButton copyMd     = new JButton("Copy as MD");

        row.add(quickScan);
        row.add(deepScan);
        row.add(export);
        row.add(compare);
        row.add(clear);
        row.add(copy);
        row.add(copyMd);

        // read the selection inside the listener, not when the UI is built
        // otherwise the lambda captures an empty list forever
        quickScan.addActionListener(e -> {
            List<String> selected = hostList.getSelectedValuesList();
            if (selected.isEmpty()) { appendResult("No targets selected.\n"); return; }
            runQuickScan(selected);
        });

        deepScan.addActionListener(e -> {
            List<String> selected = hostList.getSelectedValuesList();
            if (selected.isEmpty()) { appendResult("No targets selected.\n"); return; }
            runDeepScan(selected);
        });

        export.addActionListener(e -> exportReport());
        compare.addActionListener(e -> runCompare());

        clear.addActionListener(e -> {
            resultsArea.setText("");
            scoreLabel.setText("Score: N/A");
            scoreLabel.setForeground(Color.GRAY);
            lastResults = new ArrayList<>();
        });

        copy.addActionListener(e -> toClipboard(resultsArea.getText()));

        copyMd.addActionListener(e -> {
            toClipboard(buildMarkdownReport(lastResults));
            appendResult("[COPIED] results copied as Markdown\n");
        });

        return row;
    }

    private JPanel buildFilterRow() {
        JPanel row = new JPanel(new FlowLayout(FlowLayout.LEFT));

        JButton all       = new JButton("All");
        JButton missing   = new JButton("Missing");
        JButton misconfig = new JButton("Misconfigured");
        JButton critical  = new JButton("Critical URLs");

        row.add(new JLabel("Filter:"));
        row.add(all);
        row.add(missing);
        row.add(misconfig);
        row.add(critical);

        all.addActionListener(e       -> applyFilter("ALL"));
        missing.addActionListener(e   -> applyFilter("MISSING"));
        misconfig.addActionListener(e -> applyFilter("MISCONFIG"));
        critical.addActionListener(e  -> applyFilter("CRITICAL"));

        return row;
    }

    private JPanel buildResultsPanel() {
        resultsArea.setEditable(false);
        resultsArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        JPanel p = new JPanel(new BorderLayout());
        p.add(new JLabel("Results:"), BorderLayout.NORTH);
        p.add(new JScrollPane(resultsArea), BorderLayout.CENTER);
        return p;
    }

    //  targets

    private void refreshHostsFromBurp() {
        hostListModel.clear();
        api.siteMap().requestResponses().forEach(rr -> {
            String host = rr.request().httpService().host();
            if (!hostListModel.contains(host)) hostListModel.addElement(host);
        });
    }

    //  scanning

    private void runQuickScan(List<String> hosts) {
        new Thread(() -> {
            List<ScanResult> results = new ArrayList<>();
            for (String host : hosts) {
                appendResult("\n[SCANNING] " + host + "\n");
                results.add(headerChecker.checkHeaders(host));
            }
            finish(results);
        }).start();
    }

    private void runDeepScan(List<String> hosts) {
        new Thread(() -> {
            List<ScanResult> results = new ArrayList<>();
            appendResult("\n[DEEP SCAN] reading Burp site map...\n");
            for (String host : hosts) {
                results.addAll(deepScanner.scan(host));
            }
            finish(results);
        }).start();
    }

    private void finish(List<ScanResult> results) {
        lastResults = results;
        displayResults(results);
        updateScore(results);
        appendResult("\n[DONE] " + results.size() + " URLs reported\n");
    }

    //  results

    private void applyFilter(String filter) {
        currentFilter = filter;
        displayResults(lastResults);
    }

    private void displayResults(List<ScanResult> results) {
        SwingUtilities.invokeLater(() -> resultsArea.setText(""));

        if (results == null || results.isEmpty()) {
            appendResult("No results.\n");
            return;
        }

        for (ScanResult result : results) {

            if (currentFilter.equals("MISSING")   && result.getMissingHeaders().isEmpty()) continue;
            if (currentFilter.equals("MISCONFIG") && result.getMisconfiguredHeaders().isEmpty()) continue;
            if (currentFilter.equals("CRITICAL")  && result.getUrlType() == UrlClassifier.UrlType.NORMAL) continue;

            String label = UrlClassifier.getLabel(result.getUrlType());

            appendResult("\n" + result.getMethod() + " " + result.getUrl()
                    + (label.isEmpty() ? "" : " " + label) + "\n");

            if (result.isClean()) {
<<<<<<< Updated upstream
                appendResult("  All headers present\n");
            } else {
                result.getMissingHeaders().forEach(h ->
                        appendResult("  MISSING       -> " + h + "\n")
                );
                result.getMisconfiguredHeaders().forEach(h ->
                        appendResult("  MISCONFIGURED -> " + h + "\n")
                );
=======
                appendResult("  no findings\n");
                continue;
>>>>>>> Stashed changes
            }

            result.getMissingHeaders().forEach(h ->
                    appendResult("  MISSING       -> " + h + "\n"));

            result.getMisconfiguredHeaders().forEach(h ->
                    appendResult("  MISCONFIGURED -> " + h + "\n"));
        }
    }

    private void updateScore(List<ScanResult> results) {
        ScoreCalculator.Score score = ScoreCalculator.calculate(results);
        SwingUtilities.invokeLater(() -> {
            scoreLabel.setText("Score: " + ScoreCalculator.getLabel(score));
            scoreLabel.setForeground(ScoreCalculator.getColor(score));
        });
    }

    // export / compare

    private void exportReport() {
        if (lastResults.isEmpty()) {
            appendResult("[EXPORT] nothing to export, run a scan first\n");
            return;
        }

        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File("SecHeaderScout_Report.html"));

        if (chooser.showSaveDialog(mainPanel) != JFileChooser.APPROVE_OPTION) return;

        String path = chooser.getSelectedFile().getAbsolutePath();
        new Thread(() -> {
            try {
                appendResult("[EXPORT] saved to " + ReportExporter.export(lastResults, path) + "\n");
            } catch (Exception e) {
                appendResult("[EXPORT] error: " + e.getMessage() + "\n");
            }
        }).start();
    }

    private void runCompare() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Select a previous SecHeaderScout report");

        if (chooser.showOpenDialog(mainPanel) != JFileChooser.APPROVE_OPTION) return;

        String path = chooser.getSelectedFile().getAbsolutePath();
        new Thread(() -> {
            try {
                appendResult("\n[COMPARE] loading " + path + "\n");
                List<ReportComparator.ComparisonResult> comparisons =
                        new ReportComparator(api, headerChecker).compare(path);

                appendResult("\n[COMPARISON]\n");

                for (ReportComparator.ComparisonResult c : comparisons) {
                    appendResult("\n" + c.getUrl() + "\n");
                    c.getFixed().forEach(h        -> appendResult("  FIXED         -> " + h + "\n"));
                    c.getStillMissing().forEach(h -> appendResult("  STILL MISSING -> " + h + "\n"));
                    c.getNewIssues().forEach(h    -> appendResult("  NEW ISSUE     -> " + h + "\n"));

                    if (c.getFixed().isEmpty() && c.getStillMissing().isEmpty() && c.getNewIssues().isEmpty())
                        appendResult("  no changes\n");
                }

                appendResult("\n[COMPARE DONE]\n");

            } catch (Exception e) {
                appendResult("[COMPARE] error: " + e.getMessage() + "\n");
            }
        }).start();
    }

    //  markdown 

    private String buildMarkdownReport(List<ScanResult> results) {
        if (results == null || results.isEmpty()) return "No results to copy.";

        StringBuilder md = new StringBuilder();

        for (ScanResult result : results) {
            if (result.isClean()) continue;

            String label = UrlClassifier.getLabel(result.getUrlType());

            md.append("#### ").append(result.getUrl());
            if (!label.isEmpty())
                md.append(" `").append(label.replace("[", "").replace("]", "")).append("`");
            md.append("\n\n");

            if (!result.getMissingHeaders().isEmpty()) {
                md.append("**Missing**\n\n");
                for (String header : result.getMissingHeaders())
                    md.append("* ").append(header).append("\n");
                md.append("\n");
            }

            if (!result.getMisconfiguredHeaders().isEmpty()) {
                md.append("**Misconfigured**\n\n");
                for (String issue : result.getMisconfiguredHeaders())
                    md.append("* ").append(cleanIssue(issue)).append("\n");
                md.append("\n");
            }

            md.append("---\n\n");
        }

        return md.toString().isBlank() ? "No findings to copy." : md.toString();
    }

    // cuts everything after the arrow so the report reads as a statement
    // "Cache-Control: missing 'no-store' —> the body is written to disk"
    //   becomes "Cache-Control: missing 'no-store'"
    private String cleanIssue(String issue) {
        int arrow = issue.indexOf("—>");
        if (arrow == -1) arrow = issue.indexOf("->");
        String cleaned = (arrow == -1) ? issue : issue.substring(0, arrow);
        return cleaned.trim().replaceAll("\\s+", " ");
    }

    // helpers

    private void toClipboard(String text) {
        Toolkit.getDefaultToolkit().getSystemClipboard()
                .setContents(new StringSelection(text), null);
    }

    private void appendResult(String text) {
        SwingUtilities.invokeLater(() -> resultsArea.append(text));
    }
}