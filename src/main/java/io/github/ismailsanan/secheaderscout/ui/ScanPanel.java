package io.github.ismailsanan.secheaderscout.ui;

import io.github.ismailsanan.secheaderscout.definitions.DefinitionsRepository;
import io.github.ismailsanan.secheaderscout.engine.EndpointRulesStore;
import io.github.ismailsanan.secheaderscout.manual.DeepScanOptions;
import io.github.ismailsanan.secheaderscout.manual.DeepScanResult;
import io.github.ismailsanan.secheaderscout.manual.ManualScanner;
import io.github.ismailsanan.secheaderscout.model.HeaderProfile;
import io.github.ismailsanan.secheaderscout.manual.ProgressListener;
import io.github.ismailsanan.secheaderscout.manual.RescanComparer;
import io.github.ismailsanan.secheaderscout.manual.ScanBatch;
import io.github.ismailsanan.secheaderscout.manual.ScanTarget;
import io.github.ismailsanan.secheaderscout.manual.SiteMapSource;
import io.github.ismailsanan.secheaderscout.model.ScanResult;
import io.github.ismailsanan.secheaderscout.report.ReportExporter;
import io.github.ismailsanan.secheaderscout.report.ScoreCalculator;
import io.github.ismailsanan.secheaderscout.report.TextFormatter;
import io.github.ismailsanan.secheaderscout.util.BackgroundTasks;
import io.github.ismailsanan.secheaderscout.util.Log;

import javax.swing.AbstractAction;
import javax.swing.AbstractButton;
import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.DefaultListCellRenderer;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.JViewport;
import javax.swing.KeyStroke;
import javax.swing.Scrollable;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableRowSorter;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.function.Predicate;

/**
 * The SecHeaderScout suite tab (manual scanning). Results of the passive
 * scanner appear in Burp's own Issues panel, not here.
 *
 * <p>Threading: every method in this class runs on the EDT, except the
 * {@link ProgressListener} returned by {@code progressReporter}, which is called on worker
 * threads and only posts to the EDT. Site map access,
 * HTTP requests, file I/O and report rendering run through
 * {@link OperationRunner} on background threads, and only their results come
 * back to the EDT. The custom-target set is UI state, confined to the EDT, so it needs
 * no synchronisation.</p>
 */
public final class ScanPanel {

    private static final int MAX_LOG_CHARS = 200_000;
    private static final long PROGRESS_INTERVAL_MS = 150;
    /** Most of the tab height (percent) the controls may take before they scroll; the rest is for results. */
    private static final int MAX_CONTROLS_SHARE = 45;

    private final ManualScanner scanner;
    private final SiteMapSource siteMap;
    private final DefinitionsRepository definitions;
    private final DefinitionsRepository.Downloader downloader;
    private final Predicate<String> inScope;
    private final Log log;
    private final OperationRunner runner;
    private final ResultsStore store = new ResultsStore();

    private final JPanel root = new JPanel(new BorderLayout(8, 8));
    private final DefaultListModel<String> hostModel = new DefaultListModel<>();
    private final JList<String> hostList = new JList<>(hostModel) {
        private static final long serialVersionUID = 1L;

        /** Off: typing in the list goes to the filter field instead of jumping by first letter. */
        @Override
        public int getNextMatch(String prefix, int startIndex, javax.swing.text.Position.Bias bias) {
            return -1;
        }
    };
    /** Every target, in order; {@link #hostModel} shows the ones matching {@link #targetFilter}. EDT-only. */
    private final List<String> allTargets = new ArrayList<>();
    private final JTextField targetFilter = new JTextField(24);
    private final JLabel targetsLabel = new JLabel();
    private final Set<String> customTargets = new LinkedHashSet<>();
    private final ResultsTableModel tableModel = new ResultsTableModel();
    private final JTable table = new JTable(tableModel);
    private final TableRowSorter<ResultsTableModel> sorter = new TableRowSorter<>(tableModel);
    private final JTextArea detailsArea = new JTextArea();
    private final JTextArea logArea = new JTextArea();
    private final JTabbedPane bottomTabs = new JTabbedPane();
    private final EndpointTypesPanel endpointTypes;
    private final JLabel scoreLabel = new JLabel("Score: N/A");
    private final JLabel definitionsLabel = new JLabel();
    private final JLabel statusLabel = new JLabel("Ready.");
    private final JProgressBar progressBar = new JProgressBar();
    private final JCheckBox fallbackBox = new JCheckBox("Fall back to HTTP if HTTPS fails", true);
    private final ProfilesTableModel profilesModel = new ProfilesTableModel();
    private final JTable profilesTable = new JTable(profilesModel);
    private final JTabbedPane resultsTabs = new JTabbedPane();
    // Deep Scan noise filters (defaults = DeepScanOptions.DEFAULT)
    private final JCheckBox includeStaticBox = new JCheckBox("static files", DeepScanOptions.DEFAULT.includeStatic());
    private final JCheckBox includeErrorsBox =
            new JCheckBox("error responses (4xx/5xx)", DeepScanOptions.DEFAULT.includeErrors());
    private final JCheckBox includeRedirectsBox =
            new JCheckBox("redirects (3xx)", DeepScanOptions.DEFAULT.includeRedirects());
    private final JCheckBox mergeVariantsBox =
            new JCheckBox("merge query-string variants", DeepScanOptions.DEFAULT.mergeQueryVariants());
    private final List<AbstractButton> busySensitive = new ArrayList<>();
    private final JButton cancelButton = new JButton("Cancel");

    /**
     * @param downloader    TLS-verified download used by "Sync OWASP Headers"
     * @param endpointTypes where the "Endpoint types" tab saves its patterns
     * @param inScope       Burp target-scope check, used to warn before rescanning URLs taken from a report file
     */
    public ScanPanel(ManualScanner scanner, SiteMapSource siteMap, DefinitionsRepository definitions,
                     DefinitionsRepository.Downloader downloader, EndpointRulesStore endpointTypes,
                     Predicate<String> inScope,
                     BackgroundTasks tasks, Log log) {
        this.scanner = scanner;
        this.inScope = inScope;
        this.siteMap = siteMap;
        this.definitions = definitions;
        this.downloader = downloader;
        this.log = log;
        this.endpointTypes = new EndpointTypesPanel(endpointTypes, this::setStatus, this::appendLog);
        this.runner = new OperationRunner(tasks, log, new OperationRunner.Listener() {
            @Override
            public void busyChanged(boolean busy, String operation) {
                setBusy(busy, operation);
            }

            @Override
            public void status(String message) {
                setStatus(message);
            }
        });
        buildUi();
    }

    public JComponent component() {
        return root;
    }

    /** Cancels any running operation; called on the EDT when the extension unloads. */
    public void dispose() {
        runner.cancel();
    }

    // ------------------------------------------------------------------ layout

    private void buildUi() {
        // statuses can quote targets, URLs and file names: never let "<html>" render
        List.of(scoreLabel, definitionsLabel, statusLabel).forEach(UiSupport::plain);
        root.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
        // one full-width row per line; GridBagLayout recomputes row heights on every layout (BoxLayout
        // caches them), so a WrapLayout row that wraps onto a second line after a resize gets the room
        JPanel top = new WidthTrackingPanel(new GridBagLayout());
        GridBagConstraints row = new GridBagConstraints();
        row.gridx = 0;
        row.weightx = 1;
        row.fill = GridBagConstraints.HORIZONTAL;
        row.anchor = GridBagConstraints.WEST;
        top.add(titleRow(), row);
        row.insets = new Insets(6, 0, 0, 0);
        top.add(targetPanel(), row);
        row.insets = new Insets(0, 0, 0, 0);
        for (JPanel line : List.of(inputRow(), scanRow(), deepOptionsRow(), resultsActionsRow())) {
            top.add(line, row);
        }
        root.add(controlsPane(top), BorderLayout.NORTH);
        root.add(resultsPane(), BorderLayout.CENTER);
        root.add(statusBar(), BorderLayout.SOUTH);
        setBusy(false, null);
        updateDefinitionsLabel();
    }

    private JPanel titleRow() {
        JPanel row = new JPanel(new BorderLayout());
        JLabel title = new JLabel("SecHeaderScout - OWASP security header checker");
        title.setFont(title.getFont().deriveFont(Font.BOLD, title.getFont().getSize2D() + 2f));
        scoreLabel.setFont(scoreLabel.getFont().deriveFont(Font.BOLD));
        JPanel left = new JPanel();
        left.setLayout(new BoxLayout(left, BoxLayout.Y_AXIS));
        left.add(title);
        left.add(definitionsLabel);
        row.add(left, BorderLayout.WEST);
        row.add(scoreLabel, BorderLayout.EAST);
        return row;
    }

    /**
     * The controls above the results, in a scroll pane that never takes more than
     * {@link #MAX_CONTROLS_SHARE}% of the tab's height: on a short Burp window the controls
     * scroll instead of squeezing the "By URL" / "By profile" results out of view.
     */
    private JScrollPane controlsPane(JPanel controls) {
        JScrollPane pane = new JScrollPane(controls, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                JScrollPane.HORIZONTAL_SCROLLBAR_NEVER) {
            private static final long serialVersionUID = 1L;

            @Override
            public Dimension getPreferredSize() {
                Dimension d = super.getPreferredSize();
                int available = root.getHeight();
                if (available > 0) {
                    d.height = Math.min(d.height, available * MAX_CONTROLS_SHARE / 100);
                }
                return d;
            }
        };
        pane.setBorder(BorderFactory.createEmptyBorder());
        pane.getVerticalScrollBar().setUnitIncrement(16);
        return pane;
    }

    private JPanel targetPanel() {
        hostList.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        hostList.setCellRenderer(UiSupport.plain(new DefaultListCellRenderer()));
        UiSupport.onDeleteKey(hostList, this::deleteSelectedHosts);
        hostList.addKeyListener(new KeyAdapter() {
            @Override
            public void keyTyped(KeyEvent e) {
                char c = e.getKeyChar();
                if (c != KeyEvent.CHAR_UNDEFINED && !Character.isISOControl(c)
                        && !e.isControlDown() && !e.isMetaDown() && !e.isAltDown()) {
                    targetFilter.setText(targetFilter.getText() + c);
                    targetFilter.requestFocusInWindow();
                    e.consume();
                }
            }
        });
        targetFilter.setToolTipText("Show only targets containing this text (typing in the list also searches; "
                + "Esc clears)");
        targetFilter.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                applyTargetFilter();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                applyTargetFilter();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                applyTargetFilter();
            }
        });
        targetFilter.getInputMap(JComponent.WHEN_FOCUSED).put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), "clear");
        targetFilter.getActionMap().put("clear", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                targetFilter.setText("");
            }
        });
        // Enter or Down in the filter moves to the list, so a match can be selected from the keyboard
        targetFilter.addActionListener(e -> focusTargetList());
        targetFilter.getInputMap(JComponent.WHEN_FOCUSED).put(KeyStroke.getKeyStroke(KeyEvent.VK_DOWN, 0), "toList");
        targetFilter.getActionMap().put("toList", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                focusTargetList();
            }
        });

        JScrollPane scroll = new JScrollPane(hostList);
        scroll.setPreferredSize(new Dimension(800, 100));
        JPanel search = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 0));
        search.add(new JLabel("Search:"));
        search.add(targetFilter);
        JPanel header = new JPanel(new BorderLayout());
        header.add(targetsLabel, BorderLayout.WEST);
        header.add(search, BorderLayout.EAST);
        JPanel panel = new JPanel(new BorderLayout(0, 2));
        panel.add(header, BorderLayout.NORTH);
        panel.add(scroll, BorderLayout.CENTER);
        updateTargetsLabel();
        return panel;
    }

    private void focusTargetList() {
        if (hostModel.isEmpty()) {
            return;
        }
        if (hostList.isSelectionEmpty()) {
            hostList.setSelectedIndex(0);
        }
        hostList.requestFocusInWindow();
    }

    /** Shows the targets matching the filter (case-insensitive substring), keeping visible selections. */
    private void applyTargetFilter() {
        String query = targetFilter.getText().strip().toLowerCase(Locale.ROOT);
        List<String> selected = hostList.getSelectedValuesList();
        List<String> shown = query.isEmpty() ? allTargets
                : allTargets.stream().filter(t -> t.toLowerCase(Locale.ROOT).contains(query)).toList();
        hostModel.clear();
        hostModel.addAll(shown);
        int[] keep = selected.stream().mapToInt(hostModel::indexOf).filter(i -> i >= 0).toArray();
        hostList.setSelectedIndices(keep);
        updateTargetsLabel();
    }

    private void updateTargetsLabel() {
        targetsLabel.setText(hostModel.size() == allTargets.size()
                ? "Targets (select one or more):"
                : "Targets (" + hostModel.size() + " of " + allTargets.size() + " shown, select one or more):");
    }

    /** Downloads, validates and activates the latest OWASP definitions, after confirmation. */
    private void syncOwaspHeaders() {
        int answer = JOptionPane.showConfirmDialog(root,
                "Download the latest OWASP Secure Headers definitions from\n" + DefinitionsRepository.UPSTREAM_URL
                        + "\n\nCurrent: " + definitions.current().versionLabel()
                        + "\n\nThe download is TLS-verified and validated before use; if it fails or is invalid, "
                        + "the current definitions stay active.\nSynced definitions apply to Quick Scan, Deep Scan "
                        + "and reports until the extension is reloaded.\nBurp's passive scanner keeps its fixed rules.",
                "Sync OWASP Headers", JOptionPane.OK_CANCEL_OPTION);
        if (answer == JOptionPane.OK_OPTION) {
            startOwaspSync();
        }
    }

    /** The sync itself, without the confirmation dialog (runs the download in the background). */
    private void startOwaspSync() {
        runner.start("Sync OWASP Headers", () -> definitions.sync(downloader), result -> {
            updateDefinitionsLabel();
            if (result.updated()) {
                log.info("[OWASP] " + result.message());
            } else {
                log.warn("[OWASP] " + result.message());
            }
            appendLog("[OWASP] " + result.message());
            setStatus(result.message());
        });
    }

    /** Removes the selected hosts from the target list (button, Delete or Backspace key). */
    private void deleteSelectedHosts() {
        for (String selected : hostList.getSelectedValuesList()) {
            hostModel.removeElement(selected);
            allTargets.remove(selected);
            customTargets.remove(selected);
        }
        updateTargetsLabel();
    }

    private JPanel inputRow() {
        JPanel row = new JPanel(new WrapLayout());
        JTextField input = new JTextField(28);
        JButton add = new JButton("Add Custom Target");
        JButton delete = new JButton("Delete Selected");
        JButton refresh = busyButton("Refresh from Burp");
        JButton sync = busyButton("Sync OWASP Headers");
        sync.setToolTipText("Download the latest OWASP Secure Headers definitions (validated; kept until the "
                + "extension is reloaded)");

        add.addActionListener(e -> addCustomTarget(input));
        input.addActionListener(e -> addCustomTarget(input));
        delete.addActionListener(e -> deleteSelectedHosts());
        refresh.addActionListener(e -> refreshHosts());
        sync.addActionListener(e -> syncOwaspHeaders());

        row.add(new JLabel("Custom target:"));
        row.add(input);
        row.add(add);
        row.add(delete);
        row.add(refresh);
        row.add(sync);
        return row;
    }

    /** Scanning: what to scan and how. */
    private JPanel scanRow() {
        JPanel row = new JPanel(new WrapLayout());
        JButton quick = busyButton("Quick Scan");
        JButton deep = busyButton("Deep Scan");

        quick.setToolTipText("Sends one GET request per selected target and analyses the response headers");
        deep.setToolTipText("Analyses the responses Burp already captured for the selected hosts (browse the site "
                + "through Burp's proxy first); sends no requests");
        fallbackBox.setToolTipText("If HTTPS fails or returns 4xx/5xx for a target without an explicit scheme, retry over "
                + "HTTP. Fallback results are clearly marked.");

        quick.addActionListener(e -> quickScan());
        deep.addActionListener(e -> deepScan());
        cancelButton.addActionListener(e -> runner.cancel());

        row.add(new JLabel("Scan:"));
        for (Component c : List.of(quick, deep, cancelButton, fallbackBox)) {
            row.add(c);
        }
        return row;
    }

    /** What to do with the results. */
    private JPanel resultsActionsRow() {
        JPanel row = new JPanel(new WrapLayout());
        JButton copyReport = busyButton("Copy for report");
        JButton export = busyButton("Export Report");
        JButton compare = busyButton("Rescan & Compare");
        JButton clear = new JButton("Clear");

        copyReport.setToolTipText("Copies the filtered results as Markdown grouped by host (missing and misconfigured "
                + "headers as bullet lists), ready to paste into a pentest report");
        // rendering tens of thousands of results can take a while: never on the EDT
        copyReport.addActionListener(e -> copyInBackground("Report findings", TextFormatter::reportMarkdown));
        export.addActionListener(e -> exportReport());
        compare.addActionListener(e -> rescanAndCompare());
        clear.addActionListener(e -> clearResults());

        row.add(new JLabel("Results:"));
        for (Component c : List.of(copyReport, export, compare, clear)) {
            row.add(c);
        }
        return row;
    }

    private JPanel deepOptionsRow() {
        JPanel row = new JPanel(new WrapLayout());
        row.add(new JLabel("Deep Scan also analyses:"));
        row.add(includeStaticBox);
        row.add(includeErrorsBox);
        row.add(includeRedirectsBox);
        row.add(mergeVariantsBox);
        includeStaticBox.setToolTipText("Images, scripts, stylesheets, fonts and media (skipped by default: noisy)");
        mergeVariantsBox.setToolTipText("Analyse /search?q=a and /search?q=b once, as one endpoint");
        return row;
    }

    private DeepScanOptions deepScanOptions() {
        return new DeepScanOptions(includeStaticBox.isSelected(), includeErrorsBox.isSelected(),
                includeRedirectsBox.isSelected(), mergeVariantsBox.isSelected());
    }

    private JSplitPane resultsPane() {
        profilesTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        profilesTable.setDefaultRenderer(String.class, new HighlightingRenderer(ProfilesTableModel.COL_FLAG));
        profilesTable.setDefaultRenderer(Integer.class, new HighlightingRenderer(ProfilesTableModel.COL_FLAG));
        profilesTable.getColumnModel().getColumn(ProfilesTableModel.COL_FLAG).setPreferredWidth(80);
        profilesTable.getColumnModel().getColumn(ProfilesTableModel.COL_PATH).setPreferredWidth(220);
        profilesTable.getColumnModel().getColumn(ProfilesTableModel.COL_MISSING).setPreferredWidth(420);
        profilesTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                showSelectedProfile();
            }
        });
        table.setRowSorter(sorter);
        table.setAutoCreateRowSorter(false);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setDefaultRenderer(String.class, new HighlightingRenderer(ResultsTableModel.COL_WARNING));
        table.setDefaultRenderer(Integer.class, new HighlightingRenderer(ResultsTableModel.COL_WARNING));
        table.getColumnModel().getColumn(ResultsTableModel.COL_WARNING).setMaxWidth(70);
        table.getColumnModel().getColumn(2).setPreferredWidth(500);
        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                showSelectedDetails();
            }
        });

        resultsTabs.addTab("By URL", new JScrollPane(table)); // first tab: the default view
        resultsTabs.addTab("By profile", new JScrollPane(profilesTable));
        resultsTabs.setToolTipTextAt(1, "Deep Scan results grouped by host and path (e.g. /api/*) with the same "
                + "issues; groups with logout, login, payment or admin endpoints first");

        for (JTextArea area : List.of(detailsArea, logArea)) {
            area.setEditable(false);
            area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, area.getFont().getSize()));
        }
        detailsArea.setLineWrap(true);
        detailsArea.setWrapStyleWord(true);
        bottomTabs.addTab("Details", new JScrollPane(detailsArea));
        bottomTabs.addTab("Activity log", new JScrollPane(logArea));
        bottomTabs.addTab("Endpoint types", endpointTypes.component());

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, resultsTabs, bottomTabs);
        split.setResizeWeight(0.6);
        // the bottom tabs prefer ~500px (Endpoint types); left to preferred sizes, a short window would give
        // the results only a strip. Let both sides shrink and start at 60% results / 40% details.
        resultsTabs.setMinimumSize(new Dimension(0, 80));
        bottomTabs.setMinimumSize(new Dimension(0, 60));
        split.addComponentListener(new ComponentAdapter() {
            private boolean placed;

            @Override
            public void componentResized(ComponentEvent e) {
                if (!placed && split.getHeight() > 0) {
                    placed = true;
                    split.setDividerLocation(0.6);
                }
            }
        });
        return split;
    }

    private JPanel statusBar() {
        JPanel bar = new JPanel(new BorderLayout(8, 0));
        progressBar.setStringPainted(false);
        progressBar.setPreferredSize(new Dimension(200, progressBar.getPreferredSize().height));
        bar.add(statusLabel, BorderLayout.CENTER);
        bar.add(progressBar, BorderLayout.EAST);
        return bar;
    }

    private JButton busyButton(String label) {
        JButton b = new JButton(label);
        busySensitive.add(b);
        return b;
    }

    // ------------------------------------------------------------------ state

    private void setBusy(boolean busy, String operation) {
        for (AbstractButton b : busySensitive) {
            b.setEnabled(!busy);
        }
        cancelButton.setEnabled(busy);
        progressBar.setVisible(busy);
        progressBar.setIndeterminate(busy);
        if (busy) {
            setStatus(operation + "...");
        }
    }

    private void setStatus(String message) {
        statusLabel.setText(message);
        appendLog(message);
    }

    private void appendLog(String message) {
        logArea.append(message + "\n");
        int excess = logArea.getDocument().getLength() - MAX_LOG_CHARS;
        if (excess > 0) {
            logArea.replaceRange("", 0, excess);
        }
    }

    private void updateDefinitionsLabel() {
        definitionsLabel.setText("OWASP definitions: " + definitions.current().versionLabel());
    }

    /** Throttled progress reporting from worker threads to the status bar. */
    private ProgressListener progressReporter(String operation) {
        long[] last = {0};
        return (done, total, current) -> {
            long now = System.currentTimeMillis();
            if (now - last[0] < PROGRESS_INTERVAL_MS && done < total) {
                return;
            }
            last[0] = now;
            SwingUtilities.invokeLater(() -> {
                if (!runner.isBusy()) {
                    return;
                }
                progressBar.setIndeterminate(false);
                progressBar.setMaximum(Math.max(total, 1));
                progressBar.setValue(done);
                statusLabel.setText(operation + ": " + done + "/" + total
                        + (current.isEmpty() ? "" : "  " + TextFormatter.abbreviate(current)));
            });
        };
    }

    // ------------------------------------------------------------------ actions

    private void addCustomTarget(JTextField input) {
        String target = input.getText().trim();
        if (target.isEmpty()) {
            return;
        }
        if (ScanTarget.parse(target).isEmpty()) {
            setStatus("Invalid target '" + TextFormatter.abbreviate(target) + "'. Use host, host:port or an http(s) URL.");
            return;
        }
        if (!allTargets.contains(target)) {
            allTargets.add(target);
        }
        customTargets.add(target);
        input.setText("");
        targetFilter.setText(""); // the new target must be visible, whatever the filter was
        applyTargetFilter();
    }

    private void refreshHosts() {
        runner.start("Refresh targets from site map", () -> {
            List<String> hosts = siteMap.hosts();
            if (Thread.currentThread().isInterrupted()) {
                throw new InterruptedException();
            }
            return hosts;
        }, hosts -> {
            Set<String> all = new LinkedHashSet<>(hosts);
            all.addAll(customTargets);
            allTargets.clear();
            allTargets.addAll(all);
            applyTargetFilter();
            setStatus("Loaded " + hosts.size() + " host(s) from the site map"
                    + (customTargets.isEmpty() ? "." : " plus " + customTargets.size() + " custom target(s)."));
        });
    }

    private List<String> selectedTargets() {
        List<String> selected = hostList.getSelectedValuesList();
        if (selected.isEmpty()) {
            setStatus(allTargets.isEmpty()
                    ? "No targets yet: click \"Refresh from Burp\" (or \"Add Custom Target\"), select one or more "
                    + "hosts, then scan."
                    : hostModel.isEmpty() ? "No targets match the search \"" + targetFilter.getText().strip()
                    + "\": change or clear it (Esc), select one or more hosts, then scan."
                    : "No targets selected: select one or more hosts in the list, then scan.");
        }
        return selected;
    }

    private void quickScan() {
        List<String> targets = selectedTargets();
        if (targets.isEmpty()) {
            return;
        }
        boolean fallback = fallbackBox.isSelected();
        runner.start("Quick Scan", () -> scanner.quickScan(targets, fallback, progressReporter("Quick Scan")),
                batch -> showBatch("Quick Scan", batch));
    }

    private void deepScan() {
        List<String> targets = selectedTargets();
        if (targets.isEmpty()) {
            return;
        }
        List<String> hosts = targets.stream()
                .map(ScanTarget::hostOrRaw)
                .distinct().toList();
        DeepScanOptions options = deepScanOptions(); // read on the EDT
        runner.start("Deep Scan", () -> scanner.deepScan(hosts, siteMap, options, progressReporter("Deep Scan")),
                this::showDeepScan);
    }

    /** Why a Deep Scan analysed nothing, in terms the user can act on; {@code null} if it analysed something. */
    static String deepScanEmptyExplanation(DeepScanResult.Stats stats) {
        if (stats.analysed() > 0) {
            return null;
        }
        if (stats.captured() == 0) {
            return "Burp's site map has no captured responses for the selected host(s).\n\n"
                    + "Deep Scan sends no requests: it analyses traffic that is already in Target > Site map.\n"
                    + "Browse the application through Burp's proxy (or crawl it) first, then run Deep Scan again.\n"
                    + "To check a host without captured traffic, use Quick Scan.";
        }
        return "All " + stats.captured() + " captured responses were filtered out ("
                + stats.skippedSummary() + ").\n\n"
                + "Tick \"static files\", \"error responses (4xx/5xx)\" or \"redirects (3xx)\" under the Deep Scan "
                + "options to include them.";
    }

    private void showDeepScan(DeepScanResult result) {
        showBatch("Deep Scan", result.batch());
        profilesModel.setRows(result.profiles());
        String empty = deepScanEmptyExplanation(result.stats());
        if (empty != null && !result.cancelled()) {
            setStatus("Deep Scan finished: " + result.stats().summary() + ".");
            JOptionPane.showMessageDialog(root, empty, "Deep Scan", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        setStatus("Deep Scan " + (result.cancelled() ? "cancelled (partial): " : "finished: ")
                + result.stats().summary() + "; " + result.profiles().size()
                + " group(s) in the \"By profile\" tab.");
    }

    private void showSelectedProfile() {
        int row = profilesTable.getSelectedRow();
        if (row < 0) {
            return;
        }
        HeaderProfile p = profilesModel.rowAt(profilesTable.convertRowIndexToModel(row));
        detailsArea.setText(TextFormatter.profile(p));
        detailsArea.setCaretPosition(0);
        bottomTabs.setSelectedIndex(0);
    }

    private void showBatch(String operation, ScanBatch batch) {
        profilesModel.setRows(List.of()); // profiles only describe a Deep Scan; showDeepScan sets them after this
        resultsTabs.setSelectedIndex(0);
        store.replace(batch.results());
        tableModel.setRows(store.snapshot());
        detailsArea.setText("");
        updateScore();
        long fallbacks = batch.results().stream().filter(ScanResult::httpFallback).count();
        long errors = batch.results().stream().filter(ScanResult::hasError).count();
        setStatus(operation + (batch.cancelled() ? " cancelled; showing partial results: " : " finished: ")
                + batch.results().size() + " URL(s) analysed"
                + (errors > 0 ? ", " + errors + " could not be analysed" : "")
                + (fallbacks > 0 ? ", " + fallbacks + " via HTTP fallback (marked with ⚠)" : "") + ".");
    }

    private void showSelectedDetails() {
        int viewRow = table.getSelectedRow();
        if (viewRow < 0) {
            detailsArea.setText("");
            return;
        }
        ScanResult r = tableModel.rowAt(table.convertRowIndexToModel(viewRow));
        detailsArea.setText(TextFormatter.details(r));
        detailsArea.setCaretPosition(0);
        bottomTabs.setSelectedIndex(0);
    }

    private void updateScore() {
        List<ScanResult> results = store.snapshot();
        ScoreCalculator.Score score = ScoreCalculator.calculate(results);
        boolean lowerBound = ScoreCalculator.hasIncompleteEvaluations(results);
        scoreLabel.setText(results.isEmpty() ? "Score: N/A"
                : "Score: " + score.label() + (lowerBound ? " (lower bound: some results not fully evaluated)" : ""));
        scoreLabel.setForeground(scoreColor(score));
    }

    static Color scoreColor(ScoreCalculator.Score score) {
        return switch (score) {
            case INFO -> new Color(70, 120, 220);
            case LOW -> new Color(0, 140, 0);
            case MEDIUM -> new Color(200, 150, 0);
            case HIGH -> new Color(210, 100, 0);
            case CRITICAL -> new Color(200, 0, 0);
        };
    }

    private void clearResults() {
        store.clear();
        tableModel.setRows(List.of());
        profilesModel.setRows(List.of());
        detailsArea.setText("");
        scoreLabel.setText("Score: N/A");
        scoreLabel.setForeground(Color.GRAY);
        setStatus("Results cleared.");
    }

    private void copyInBackground(String what, java.util.function.Function<List<ScanResult>, String> render) {
        List<ScanResult> snapshot = store.snapshot(); // immutable snapshot taken on the EDT
        runner.start("Copy " + what, () -> render.apply(snapshot), text -> copyToClipboard(text, what));
    }

    private void copyToClipboard(String text, String what) {
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(text), null);
        setStatus(what + " copied to clipboard.");
    }

    private void exportReport() {
        List<ScanResult> snapshot = store.snapshot();
        if (snapshot.isEmpty()) {
            setStatus("No results to export. Run a scan first.");
            return;
        }
        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File("SecHeaderScout_Report.html"));
        if (chooser.showSaveDialog(root) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        Path target = chooser.getSelectedFile().toPath();
        if (Files.exists(target) && JOptionPane.showConfirmDialog(root, "Overwrite " + target.getFileName() + "?",
                "SecHeaderScout", JOptionPane.YES_NO_OPTION) != JOptionPane.YES_OPTION) {
            return;
        }
        String version = definitions.current().versionLabel();
        List<HeaderProfile> profiles = profilesModel.rows(); // immutable, taken on the EDT
        runner.start("Export report", () -> {
            try {
                return ReportExporter.export(snapshot, profiles, version, target);
            } catch (IOException e) {
                throw new OperationRunner.OperationException("cannot write " + target + ": " + e.getMessage(), e);
            }
        }, path -> setStatus("Report saved to " + path));
    }

    /**
     * Rescan &amp; Compare in two steps: (1) load and parse the report in the
     * background; (2) show which hosts would be contacted, flag out-of-scope hosts
     * and truncation, and only rescan after explicit confirmation, because the
     * URLs come from a file, i.e. untrusted input.
     */
    private void rescanAndCompare() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Select a previous SecHeaderScout report");
        if (chooser.showOpenDialog(root) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        Path source = chooser.getSelectedFile().toPath();
        runner.start("Load report", () -> {
            try {
                return RescanComparer.plan(RescanComparer.load(source), inScope);
            } catch (IOException e) {
                throw new OperationRunner.OperationException("cannot read " + source + ": " + e.getMessage(), e);
            } catch (RescanComparer.InvalidReportException e) {
                throw new OperationRunner.OperationException(e.getMessage(), e);
            }
        // deferred one EDT turn: the "Load report" operation is only marked finished after this callback,
        // and the rescan it may start would otherwise be rejected as a concurrent operation
        }, plan -> SwingUtilities.invokeLater(() -> confirmAndRescan(plan)));
    }

    static final int MAX_LISTED_IN_SCOPE_HOSTS = 15;

    /**
     * Text of the Rescan &amp; Compare confirmation (SEC-9). Hosts outside Burp's scope are
     * ALWAYS listed, first and in full; only in-scope hosts are abbreviated.
     */
    static String rescanConfirmationText(RescanComparer.Plan plan) {
        StringBuilder message = new StringBuilder("Rescanning sends one GET request per URL ")
                .append("(").append(plan.toScan().size()).append(" URL(s)) to these hosts:\n\n");
        for (String h : plan.outOfScopeHosts()) {
            message.append("  ").append(h).append("   [NOT IN SCOPE]\n");
        }
        List<String> inScope = plan.hosts().stream().filter(h -> !plan.outOfScopeHosts().contains(h)).toList();
        inScope.stream().limit(MAX_LISTED_IN_SCOPE_HOSTS).forEach(h -> message.append("  ").append(h).append('\n'));
        if (inScope.size() > MAX_LISTED_IN_SCOPE_HOSTS) {
            message.append("  ... and ").append(inScope.size() - MAX_LISTED_IN_SCOPE_HOSTS)
                    .append(" more in-scope host(s)\n");
        }
        if (!plan.outOfScopeHosts().isEmpty()) {
            message.append("\nWARNING: ").append(plan.outOfScopeHosts().size())
                    .append(" host(s) are outside Burp's target scope. The URLs come from the selected file; ")
                    .append("only continue if you trust it.\n");
        }
        if (plan.truncated()) {
            message.append("\nOnly the first ").append(RescanComparer.MAX_URLS).append(" of ")
                    .append(plan.totalUrls()).append(" URLs will be rescanned.\n");
        }
        if (!plan.skippedInvalid().isEmpty()) {
            message.append("\n").append(plan.skippedInvalid().size())
                    .append(" entry(ies) in the report are not valid http(s) URLs and will NOT be requested.\n");
        }
        return message.append("\nContinue?").toString();
    }

    private void confirmAndRescan(RescanComparer.Plan plan) {
        if (plan.toScan().isEmpty()) {
            setStatus("The report contains no valid URLs to rescan.");
            return;
        }
        // a JTextArea, never a String: JOptionPane renders String messages through a JLabel,
        // which would interpret "<html>" in host names taken from the file
        JTextArea text = new JTextArea(rescanConfirmationText(plan));
        text.setEditable(false);
        text.setOpaque(false);
        int answer = JOptionPane.showConfirmDialog(root, text, "Rescan & Compare", JOptionPane.OK_CANCEL_OPTION,
                plan.outOfScopeHosts().isEmpty() ? JOptionPane.QUESTION_MESSAGE : JOptionPane.WARNING_MESSAGE);
        if (answer != JOptionPane.OK_OPTION) {
            setStatus("Rescan & Compare cancelled; no requests were sent.");
            return;
        }
        runner.start("Rescan & Compare",
                () -> RescanComparer.compare(scanner, plan, progressReporter("Rescan & Compare")),
                this::showComparison);
    }

    private void showComparison(RescanComparer.Outcome outcome) {
        appendLog(TextFormatter.comparison(outcome.comparisons(), outcome.cancelled()));
        bottomTabs.setSelectedIndex(1);
        setStatus("Rescan & Compare " + (outcome.cancelled() ? "cancelled; partial comparison of " : "finished: ")
                + outcome.comparisons().size() + " URL(s). See the Activity log.");
    }

    // ------------------------------------------------------------------ renderers

    /**
     * Plain-text cells (values come from HTTP traffic, so HTML rendering is disabled) with the
     * row highlighted when its {@code flagColumn} is non-empty (fallback, error, sensitive group).
     */
    private static final class HighlightingRenderer extends DefaultTableCellRenderer {
        private static final long serialVersionUID = 1L;
        private final int flagColumn;

        HighlightingRenderer(int flagColumn) {
            this.flagColumn = flagColumn;
            UiSupport.plain(this);
        }

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
                                                       boolean hasFocus, int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            if (!isSelected) {
                Object warning = table.getModel().getValueAt(table.convertRowIndexToModel(row), flagColumn);
                boolean flagged = warning != null && !warning.toString().isEmpty();
                c.setBackground(flagged ? new Color(255, 236, 160) : table.getBackground());
                c.setForeground(flagged ? Color.BLACK : table.getForeground());
            }
            return c;
        }
    }

    /** A panel that always takes the scroll pane's width, so its button rows wrap instead of scrolling sideways. */
    private static final class WidthTrackingPanel extends JPanel implements Scrollable {
        private static final long serialVersionUID = 1L;

        WidthTrackingPanel(java.awt.LayoutManager layout) {
            super(layout);
        }

        @Override
        public Dimension getPreferredScrollableViewportSize() {
            return getPreferredSize();
        }

        @Override
        public int getScrollableUnitIncrement(java.awt.Rectangle visible, int orientation, int direction) {
            return 16;
        }

        @Override
        public int getScrollableBlockIncrement(java.awt.Rectangle visible, int orientation, int direction) {
            return Math.max(16, visible.height - 16);
        }

        @Override
        public boolean getScrollableTracksViewportWidth() {
            return true;
        }

        @Override
        public boolean getScrollableTracksViewportHeight() {
            return getParent() instanceof JViewport v && v.getHeight() > getPreferredSize().height;
        }
    }
}
