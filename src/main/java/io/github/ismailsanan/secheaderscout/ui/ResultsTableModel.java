package io.github.ismailsanan.secheaderscout.ui;

import io.github.ismailsanan.secheaderscout.model.ScanResult;
import io.github.ismailsanan.secheaderscout.util.UrlPaths;

import java.util.Comparator;

import javax.swing.table.AbstractTableModel;
import java.util.List;

/** Table model over an immutable results snapshot. EDT-only. */
final class ResultsTableModel extends AbstractTableModel {

    private static final long serialVersionUID = 1L;

    static final int COL_WARNING = 0;
    static final int COL_PATH = 3;
    static final int COL_MISSING = 7;
    // same layout as the "By profile" tab: host, path, missing header names, worst severity
    private static final String[] COLUMNS =
            {"!", "Method", "Host", "Path", "Type", "Protocol", "Status", "Missing", "Misconfigured", "Worst"};

    private transient List<ScanResult> rows = List.of();
    // the row sorter does not cache cells and calls getValueAt on every comparison and paint,
    // so derived cells are built once here instead of re-streaming findings
    private transient List<String> missingText = List.of();
    private transient List<String> worst = List.of();
    private int[] issueCounts = new int[0];

    void setRows(List<ScanResult> results) {
        this.rows = results;
        missingText = results.stream().map(r -> r.hasError() ? "(not analysed)"
                : String.join(", ", r.missingHeaderNames())).toList();
        worst = results.stream().map(r -> r.findings().stream().map(f -> f.severity())
                .max(Comparator.naturalOrder()).map(Enum::name).orElse("")).toList();
        issueCounts = results.stream().mapToInt(r -> r.misconfigured().size()).toArray();
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
        return column == 6 || column == 8 ? Integer.class : String.class;
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
            case 2 -> UrlPaths.host(r.url());
            case COL_PATH -> UrlPaths.path(r.url()) + (UrlPaths.query(r.url()).isEmpty() ? "" : "?" + UrlPaths.query(r.url()));
            case 4 -> r.urlType().label();
            case 5 -> r.protocol();
            case 6 -> r.statusCode();
            case COL_MISSING -> missingText.get(rowIndex);
            case 8 -> issueCounts[rowIndex];
            case 9 -> worst.get(rowIndex);
            default -> "";
        };
    }
}
