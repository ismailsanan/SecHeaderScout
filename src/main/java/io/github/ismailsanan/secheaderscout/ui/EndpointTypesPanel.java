package io.github.ismailsanan.secheaderscout.ui;

import io.github.ismailsanan.secheaderscout.engine.EndpointRules;
import io.github.ismailsanan.secheaderscout.engine.EndpointRulesStore;
import io.github.ismailsanan.secheaderscout.engine.UrlClassifier;
import io.github.ismailsanan.secheaderscout.engine.UrlClassifier.UrlType;

import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.table.AbstractTableModel;
import java.awt.BorderLayout;
import java.util.Comparator;
import java.util.List;
import java.util.function.Consumer;

/**
 * The "Endpoint types" tab: which paths count as logout, login, admin, payment or API, for all
 * scans and Burp's passive scanner. Built-in keyword patterns can be switched off; custom
 * patterns can be added and removed. Every change is published to {@link UrlClassifier} and saved
 * through the {@link EndpointRulesStore}. EDT-only.
 */
final class EndpointTypesPanel {

    private final EndpointRulesStore store;
    private final Consumer<String> status;
    private final Consumer<String> activity;
    private final RulesTableModel model = new RulesTableModel();
    private final JTable table = new JTable(model);
    private final JPanel root = new JPanel(new BorderLayout(0, 4));

    EndpointTypesPanel(EndpointRulesStore store, Consumer<String> status, Consumer<String> activity) {
        this.store = store;
        this.status = status;
        this.activity = activity;
        model.setRules(UrlClassifier.rules());
        buildUi();
    }

    JComponent component() {
        return root;
    }

    private void buildUi() {
        root.add(new JLabel("Which paths count as logout, login, admin, payment or API (any host unless a full URL "
                + "is given). Used by all scans and Burp's passive scanner; the most specific match wins."),
                BorderLayout.NORTH);

        table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        table.setDefaultRenderer(String.class, UiSupport.plainRenderer());
        table.getColumnModel().getColumn(0).setMaxWidth(40);
        table.getColumnModel().getColumn(1).setPreferredWidth(110);
        table.getColumnModel().getColumn(2).setPreferredWidth(420);
        table.getColumnModel().getColumn(3).setMaxWidth(90);
        UiSupport.onDeleteKey(table, this::removeSelected);
        root.add(new JScrollPane(table), BorderLayout.CENTER);

        JTextField pattern = new JTextField(26);
        JComboBox<String> type = new JComboBox<>(java.util.Arrays.stream(UrlType.values())
                .map(UrlType::displayName).toArray(String[]::new));
        JButton add = new JButton("Add");
        JButton remove = new JButton("Remove selected");
        add.addActionListener(e -> add(pattern, UrlType.values()[type.getSelectedIndex()]));
        pattern.addActionListener(e -> add.doClick());
        remove.addActionListener(e -> removeSelected());

        JPanel controls = new JPanel(new WrapLayout());
        controls.add(new JLabel("Pattern:"));
        controls.add(pattern);
        controls.add(new JLabel("Type:"));
        controls.add(type);
        controls.add(add);
        controls.add(remove);
        controls.add(new JLabel("Examples: /auth/end · /auth/* · */logout* · https://host/path?action=logout"));
        root.add(controls, BorderLayout.SOUTH);
    }

    private void add(JTextField field, UrlType type) {
        String pattern = field.getText().strip();
        try {
            apply(UrlClassifier.rules().with(pattern, type));
        } catch (IllegalArgumentException e) {
            status.accept(e.getMessage());
            return;
        }
        field.setText("");
        activity.accept("[TYPES] " + pattern + " -> " + type.displayName());
        status.accept("Endpoint type added: " + pattern + " is " + type.displayName()
                + ". Applies to new scans and to passive scanning; rescan to update existing results.");
    }

    private void removeSelected() {
        List<EndpointRules.Rule> selected = selectedRules();
        if (selected.isEmpty()) {
            status.accept("Select one or more custom patterns to remove.");
            return;
        }
        EndpointRules next = UrlClassifier.rules();
        int builtIns = 0;
        for (EndpointRules.Rule r : selected) {
            if (r.builtIn()) {
                builtIns++;
            } else {
                next = next.withoutCustom(r.pattern());
                activity.accept("[TYPES] removed " + r.pattern());
            }
        }
        apply(next);
        status.accept(builtIns > 0
                ? "Built-in patterns cannot be removed; untick \"On\" to disable them."
                : "Removed " + selected.size() + " pattern(s).");
    }

    private void toggle(EndpointRules.Rule rule, boolean enabled) {
        apply(UrlClassifier.rules().withEnabled(rule.pattern(), rule.builtIn(), enabled));
        activity.accept("[TYPES] " + rule.pattern() + (enabled ? " enabled" : " disabled"));
    }

    private List<EndpointRules.Rule> selectedRules() {
        return java.util.Arrays.stream(table.getSelectedRows())
                .mapToObj(row -> model.ruleAt(table.convertRowIndexToModel(row))).toList();
    }

    /** Publishes, saves and shows {@code next}. */
    private void apply(EndpointRules next) {
        UrlClassifier.setRules(next);
        store.save(next);
        model.setRules(next);
    }

    /** Rules grouped by type (in {@link UrlType} priority order), custom before built-in. */
    private final class RulesTableModel extends AbstractTableModel {

        private static final long serialVersionUID = 1L;
        private static final String[] COLUMNS = {"On", "Type", "Pattern", "Source"};

        private transient List<EndpointRules.Rule> rows = List.of();

        void setRules(EndpointRules rules) {
            rows = rules.rules().stream()
                    .sorted(Comparator.comparing(EndpointRules.Rule::type)
                            .thenComparing(EndpointRules.Rule::builtIn))
                    .toList();
            fireTableDataChanged();
        }

        EndpointRules.Rule ruleAt(int row) {
            return rows.get(row);
        }

        @Override
        public int getRowCount() {
            return rows.size();
        }

        @Override
        public int getColumnCount() {
            return COLUMNS.length;
        }

        @Override
        public String getColumnName(int column) {
            return COLUMNS[column];
        }

        @Override
        public Class<?> getColumnClass(int column) {
            return column == 0 ? Boolean.class : String.class;
        }

        @Override
        public boolean isCellEditable(int row, int column) {
            return column == 0;
        }

        @Override
        public Object getValueAt(int row, int column) {
            EndpointRules.Rule r = rows.get(row);
            return switch (column) {
                case 0 -> r.enabled();
                case 1 -> r.type().displayName();
                case 2 -> r.pattern();
                default -> r.builtIn() ? "built-in" : "custom";
            };
        }

        @Override
        public void setValueAt(Object value, int row, int column) {
            if (column == 0 && value instanceof Boolean enabled) {
                toggle(rows.get(row), enabled);
            }
        }
    }
}
