import burp.api.montoya.MontoyaApi;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * Main UI tabs.
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

    public JPanel getPanel() {
        return mainPanel;
    }

    private JPanel buildUI() {

        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JPanel topPanel = new JPanel();
        topPanel.setLayout(new BoxLayout(topPanel, BoxLayout.Y_AXIS));

        topPanel.add(buildTitlePanel());
        topPanel.add(Box.createVerticalStrut(8));
        topPanel.add(buildTargetPanel());
        topPanel.add(Box.createVerticalStrut(8));
        topPanel.add(buildInputRow());
        topPanel.add(Box.createVerticalStrut(4));
        topPanel.add(buildScanRow());
        topPanel.add(Box.createVerticalStrut(4));
        topPanel.add(buildFilterRow());

        panel.add(topPanel, BorderLayout.NORTH);
        panel.add(buildResultsPanel(), BorderLayout.CENTER);

        return panel;
    }

    private JPanel buildTitlePanel() {
        JPanel titlePanel = new JPanel(new BorderLayout());

        JLabel title = new JLabel("SecHeaderScout — OWASP Header Checker");
        title.setFont(new Font("Arial", Font.BOLD, 14));

        scoreLabel.setFont(new Font("Arial", Font.BOLD, 13));

        titlePanel.add(title, BorderLayout.WEST);
        titlePanel.add(scoreLabel, BorderLayout.EAST);

        return titlePanel;
    }

    private JPanel buildTargetPanel() {
        JPanel targetPanel = new JPanel(new BorderLayout());

        hostList.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);

        JScrollPane listScrollPane = new JScrollPane(hostList);
        listScrollPane.setPreferredSize(new Dimension(800, 100));

        targetPanel.add(new JLabel("Targets:"), BorderLayout.NORTH);
        targetPanel.add(listScrollPane, BorderLayout.CENTER);

        return targetPanel;
    }

    private JPanel buildInputRow() {
        JPanel inputRow = new JPanel(new FlowLayout(FlowLayout.LEFT));

        JTextField customInput = new JTextField(20);
        JButton addButton = new JButton("Add Custom Target");
        JButton deleteButton = new JButton("Delete Selected");
        JButton refreshButton = new JButton("Refresh from Burp ");

        inputRow.add(new JLabel("Custom Target:"));
        inputRow.add(customInput);
        inputRow.add(addButton);
        inputRow.add(deleteButton);
        inputRow.add(refreshButton);

        addButton.addActionListener(e -> {
            String host = customInput.getText().trim();
            if (!host.isEmpty() && !hostListModel.contains(host)) {
                hostListModel.addElement(host);
                customInput.setText("");
            }
        });

        deleteButton.addActionListener(e -> {
            String selected = hostList.getSelectedValue();
            if (selected != null) {
                hostListModel.removeElement(selected);
            }
        });

        refreshButton.addActionListener(e -> refreshHostsFromBurp());

        return inputRow;
    }

    private JPanel buildScanRow() {
        JPanel scanRow = new JPanel(new FlowLayout(FlowLayout.LEFT));

        JButton quickScanButton = new JButton("Quick Scan");
        JButton deepScanButton = new JButton("Deep Scan");
        JButton exportButton = new JButton("Export Report");
        JButton compareButton = new JButton("Rescan & Compare");
        JButton clearButton = new JButton("Clear");
        JButton copyButton = new JButton("Copy");

        scanRow.add(quickScanButton);
        scanRow.add(deepScanButton);
        scanRow.add(exportButton);
        scanRow.add(compareButton);
        scanRow.add(clearButton);
        scanRow.add(copyButton);

        quickScanButton.addActionListener(e -> {
            List<String> selected = hostList.getSelectedValuesList();
            if (selected.isEmpty()) {
                appendResult("No targets selected.\n");
                return;
            }
            runQuickScan(selected);
        });

        deepScanButton.addActionListener(e -> runDeepScan());
        exportButton.addActionListener(e -> exportReport());
        compareButton.addActionListener(e -> runCompare());

        clearButton.addActionListener(e -> {
            resultsArea.setText("");
            scoreLabel.setText("Score: N/A");
            scoreLabel.setForeground(Color.GRAY);
            lastResults.clear();
        });

        copyButton.addActionListener(e -> {
            StringSelection selection = new StringSelection(resultsArea.getText());
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, null);
        });

        return scanRow;
    }

    private JPanel buildFilterRow() {
        JPanel filterRow = new JPanel(new FlowLayout(FlowLayout.LEFT));

        JButton filterAll = new JButton("All");
        JButton filterMissing = new JButton("Missing");
        JButton filterMisconfig = new JButton("Misconfigured");
        JButton filterCritical = new JButton("Critical URLs");

        filterRow.add(new JLabel("Filter:"));
        filterRow.add(filterAll);
        filterRow.add(filterMissing);
        filterRow.add(filterMisconfig);
        filterRow.add(filterCritical);

        filterAll.addActionListener(e -> {
            currentFilter = "ALL";
            displayResults(lastResults);
        });
        filterMissing.addActionListener(e -> {
            currentFilter = "MISSING";
            displayResults(lastResults);
        });
        filterMisconfig.addActionListener(e -> {
            currentFilter = "MISCONFIG";
            displayResults(lastResults);
        });
        filterCritical.addActionListener(e -> {
            currentFilter = "CRITICAL";
            displayResults(lastResults);
        });

        return filterRow;
    }
//functions 
    private JPanel buildResultsPanel() {
        resultsArea.setEditable(false);
        resultsArea.setFont(new Font("Monospaced", Font.PLAIN, 12));

        JPanel resultsPanel = new JPanel(new BorderLayout());
        resultsPanel.add(new JLabel("Results:"), BorderLayout.NORTH);
        resultsPanel.add(new JScrollPane(resultsArea), BorderLayout.CENTER);

        return resultsPanel;
    }


    private void refreshHostsFromBurp() {
        hostListModel.clear();
        api.siteMap().requestResponses().forEach(rr -> {
            String host = rr.request().httpService().host();
            if (!hostListModel.contains(host)) {
                hostListModel.addElement(host);
            }
        });
    }


    private void runQuickScan(List<String> hosts) {
        new Thread(() -> {
            List<ScanResult> results = new ArrayList<>();

            for (String host : hosts) {
                appendResult("\n[SCANNING] " + host + "\n");
                ScanResult result = headerChecker.checkHeaders(host);
                results.add(result);
            }

            lastResults = results;
            displayResults(results);
            updateScore(results);

        }).start();
    }

    private void runDeepScan() {
        new Thread(() -> {
            appendResult("\n[DEEP SCAN] Reading from Burp site map...\n");
            List<ScanResult> results = deepScanner.scan();
            lastResults = results;
            displayResults(results);
            updateScore(results);
            appendResult("\n[DONE] Scanned " + results.size() + " URLs\n");
        }).start();
    }


    // Results display
    private void displayResults(List<ScanResult> results) {
        resultsArea.setText("");

        for (ScanResult result : results) {

            if (currentFilter.equals("MISSING") && result.getMissingHeaders().isEmpty()) continue;
            if (currentFilter.equals("MISCONFIG") && result.getMisconfiguredHeaders().isEmpty()) continue;
            if (currentFilter.equals("CRITICAL") &&
                    result.getUrlType() == UrlClassifier.UrlType.NORMAL) continue;

            String urlLabel = UrlClassifier.getLabel(result.getUrlType());

            appendResult("\n" + result.getUrl() +
                    (urlLabel.isEmpty() ? "" : " " + urlLabel) + "\n");

            if (result.isClean()) {
                appendResult("  All headers present\n");
            } else {
                result.getMissingHeaders().forEach(h ->
                        appendResult("  MISSING       -> " + h + "\n")
                );
                result.getMisconfiguredHeaders().forEach(h ->
                        appendResult("  MISCONFIGURED -> " + h + "\n")
                );
            }
        }
    }

    private void updateScore(List<ScanResult> results) {
        ScoreCalculator.Score score = ScoreCalculator.calculate(results);
        SwingUtilities.invokeLater(() -> {
            scoreLabel.setText("Score: " + ScoreCalculator.getLabel(score));
            scoreLabel.setForeground(ScoreCalculator.getColor(score));
        });
    }

    // Export / Compare

    private void exportReport() {
        if (lastResults.isEmpty()) {
            appendResult("[EXPORT] No results to export. Run a scan first.\n");
            return;
        }

        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setSelectedFile(new File("SecHeaderScout_Report.html"));

        int result = fileChooser.showSaveDialog(mainPanel);
        if (result == JFileChooser.APPROVE_OPTION) {
            String path = fileChooser.getSelectedFile().getAbsolutePath();
            new Thread(() -> {
                try {
                    String exported = ReportExporter.export(lastResults, path);
                    appendResult("[EXPORT] Report saved to: " + exported + "\n");
                } catch (Exception e) {
                    appendResult("[EXPORT] Error: " + e.getMessage() + "\n");
                }
            }).start();
        }
    }

    private void runCompare() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Select previous SecHeaderScout report");

        int result = fileChooser.showOpenDialog(mainPanel);
        if (result == JFileChooser.APPROVE_OPTION) {
            String path = fileChooser.getSelectedFile().getAbsolutePath();
            new Thread(() -> {
                try {
                    appendResult("\n[COMPARE] Loading report: " + path + "\n");
                    ReportComparator comparator = new ReportComparator(api, headerChecker);
                    List<ReportComparator.ComparisonResult> comparisons = comparator.compare(path);

                    appendResult("\n[COMPARISON RESULTS]\n");

                    for (ReportComparator.ComparisonResult comp : comparisons) {
                        appendResult("\n" + comp.getUrl() + "\n");

                        comp.getFixed().forEach(h ->
                                appendResult("  FIXED         -> " + h + "\n")
                        );
                        comp.getStillMissing().forEach(h ->
                                appendResult("  STILL MISSING -> " + h + "\n")
                        );
                        comp.getNewIssues().forEach(h ->
                                appendResult("  NEW ISSUE     -> " + h + "\n")
                        );

                        if (comp.getFixed().isEmpty() &&
                                comp.getStillMissing().isEmpty() &&
                                comp.getNewIssues().isEmpty()) {
                            appendResult("  No changes\n");
                        }
                    }

                    appendResult("\n[COMPARE DONE]\n");

                } catch (Exception e) {
                    appendResult("[COMPARE] Error: " + e.getMessage() + "\n");
                }
            }).start();
        }
    }

    private void appendResult(String text) {
        SwingUtilities.invokeLater(() -> resultsArea.append(text));
    }
}
