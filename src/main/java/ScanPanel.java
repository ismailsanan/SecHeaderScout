import burp.api.montoya.MontoyaApi;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

//
//1. Read hosts from Burp's site map
//2. Display them in a list
//3. User selects one or more hosts
//4. Clicks "Scan"
//5. Results show missing headers per host
//
public class ScanPanel {

    private final MontoyaApi api;
    private final HeaderChecker headerChecker;
    private final JPanel mainPanel;
    private final DefaultListModel<String> hostListModel;
    private final JTextArea resultsArea;

    public ScanPanel(MontoyaApi api) {
        this.api = api;
        this.headerChecker = new HeaderChecker(api);
        this.hostListModel = new DefaultListModel<>();
        this.resultsArea = new JTextArea();
        this.mainPanel = buildUI();
    }


    public JPanel getPanel() {
        return mainPanel;
    }


    private JPanel buildUI() {

        JPanel panel = new JPanel(new BorderLayout(10, 10));
//        panel.setPreferredSize(new Dimension(400, 200));
        JLabel title = new JLabel("SecHeaderScout — OWASP Header Checker");
        title.setFont(new Font("Arial", Font.BOLD, 14));
        panel.add(title, BorderLayout.NORTH);

        // CENTER — host list
        JPanel centerPanel = new JPanel(new BorderLayout());
        JLabel listLabel = new JLabel("Targets:");
        JList<String> hostList = new JList<>(hostListModel);
        hostList.setSelectionMode(
                ListSelectionModel.MULTIPLE_INTERVAL_SELECTION
        );
        centerPanel.add(listLabel, BorderLayout.NORTH);
        JScrollPane listScrollPane = new JScrollPane(hostList);
        listScrollPane.setPreferredSize(new Dimension(200, 50));
        centerPanel.add(listScrollPane, BorderLayout.CENTER);

//toDo inmpleement a delete button

        panel.add(centerPanel, BorderLayout.CENTER);

        // SOUTH — controls
        JPanel controlPanel = new JPanel(new GridLayout(3, 1, 5, 5));

        // row 1 — refresh and custom input
        JPanel inputRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JTextField customInput = new JTextField(20);
        JButton addButton = new JButton("Add Custom Target");
        JButton refreshButton = new JButton("Refresh from Burp");
        inputRow.add(new JLabel("Custom Target:"));
        inputRow.add(customInput);
        inputRow.add(addButton);
        inputRow.add(refreshButton);

        // row 2 — scan buttons
        JPanel scanRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton scanSelectedButton = new JButton("Scan Selected");
        JButton scanAllButton = new JButton("Scan All");
        JButton clearButton = new JButton("Clear Results");
        scanRow.add(scanSelectedButton);
        scanRow.add(scanAllButton);
        scanRow.add(clearButton);

        // row 3 — results
        resultsArea.setEditable(false);
        resultsArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        JPanel resultsPanel = new JPanel(new BorderLayout());
        resultsPanel.add(new JLabel("Results:"), BorderLayout.NORTH);
        JScrollPane resultsScrollPane = new JScrollPane(resultsArea);
        resultsScrollPane.setPreferredSize(new Dimension(600, 300));
        resultsPanel.add(resultsScrollPane, BorderLayout.CENTER);

        controlPanel.add(inputRow);
        controlPanel.add(scanRow);
        panel.add(controlPanel, BorderLayout.SOUTH);
        panel.add(resultsPanel, BorderLayout.EAST);

        // button actions
        addButton.addActionListener(e -> {
            String host = customInput.getText().trim();
            if (!host.isEmpty() && !hostListModel.contains(host)) {
                hostListModel.addElement(host);
                customInput.setText("");
            }
        });

        refreshButton.addActionListener(e -> {
            refreshHostsFromBurp();
        });

        scanSelectedButton.addActionListener(e -> {
            List<String> selected = hostList.getSelectedValuesList();
            scanHosts(selected);
        });

        scanAllButton.addActionListener(e -> {
            List<String> all = new ArrayList<>();
            for (int i = 0; i < hostListModel.size(); i++) {
                all.add(hostListModel.getElementAt(i));
            }
            scanHosts(all);
        });

        clearButton.addActionListener(e -> {
            resultsArea.setText("");
        });

        return panel;
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

    private void scanHosts(List<String> hosts) {
        if (hosts.isEmpty()) {
            resultsArea.append("No targets selected.\n");
            return;
        }

        // run in background thread so UI does not freeze
        new Thread(() -> {
            for (String host : hosts) {
                resultsArea.append("\n[SCANNING] " + host + "\n");
                List<String> missing = headerChecker.checkHeaders(host);

                if (missing.isEmpty()) {
                    resultsArea.append("[✓] All headers present\n");
                } else {
                    resultsArea.append("[!] Missing headers:\n");
                    missing.forEach(h ->
                            resultsArea.append(" - " + h + "\n")
                    );
                }
            }
            resultsArea.append("\n[DONE]\n");
        }).start();
    }
}
