package io.github.ismailsanan.secheaderscout.ui;

import io.github.ismailsanan.secheaderscout.model.ScanResult;

import javax.swing.table.AbstractTableModel;
import java.util.List;

/** Table model over an immutable results snapshot. EDT-only. */
final class ResultsTableModel extends AbstractTableModel {

    private static final long serialVersionUID = 1L;

    static final int COL_WARNING = 0;
    private static final String[] COLUMNS = {"!", "Method", "URL", "Type", "Protocol", "Status", "Missing", "Issues"};

    private transient List<ScanResult> rows = List.of();
    // the Missing/Issues columns are Integers: the row sorter does not cache them and calls
    // getValueAt on every comparison, so count once here instead of re-streaming findings
    private int[] missingCounts = new int[0];
    private int[] issueCounts = new int[0];

    void setRows(List<ScanResult> results) {
        this.rows = results;
        missingCounts = new int[results.size()];
        issueCounts = new int[results.size()];
        for (int i = 0; i < results.size(); i++) {
            int missing = results.get(i).missing().size();
            missingCounts[i] = missing;
            issueCounts[i] = results.get(i).findings().size() - missing;
        }
        fireTableDataChanged();
    }

    ScanResult rowAt(int modelIndex) {
        return rows.get(modelIndex);
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
        return column == 5 || column == 6 || column == 7 ? Integer.class : String.class;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        ScanResult r = rows.get(rowIndex);
        return switch (columnIndex) {
            case COL_WARNING -> switch (r.status()) {
                case ERROR -> "ERROR";
                case INCOMPLETE -> "INCOMPLETE";
                default -> r.httpFallback() ? "⚠ HTTP" : "";
            };
            case 1 -> r.method() == null ? "" : r.method();
            case 2 -> r.url();
            case 3 -> r.urlType().label();
            case 4 -> r.protocol();
            case 5 -> r.statusCode();
            case 6 -> missingCounts[rowIndex];
            case 7 -> issueCounts[rowIndex];
            default -> "";
        };
    }
}
