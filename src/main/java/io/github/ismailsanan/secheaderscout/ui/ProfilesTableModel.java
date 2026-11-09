package io.github.ismailsanan.secheaderscout.ui;

import io.github.ismailsanan.secheaderscout.model.HeaderProfile;

import javax.swing.table.AbstractTableModel;
import java.util.List;

/**
 * Deep Scan header profiles, already in priority order (groups with logout, login, payment
 * or admin endpoints first, then severity and size). EDT-only.
 */
final class ProfilesTableModel extends AbstractTableModel {

    private static final long serialVersionUID = 1L;

    /** Non-empty for groups with logout, login, payment or admin endpoints; the renderer highlights them. */
    static final int COL_FLAG = 0;
    private static final String[] COLUMNS = {"Type", "Host", "Path", "URLs", "Missing", "Misconfigured", "Worst"};
    static final int COL_PATH = 2;
    static final int COL_MISSING = 4;

    private transient List<HeaderProfile> rows = List.of();
    /** The "Missing" cell per row, built once: getValueAt runs on every paint and sort comparison. */
    private transient List<String> missingText = List.of();

    void setRows(List<HeaderProfile> profiles) {
        this.rows = List.copyOf(profiles);
        this.missingText = rows.stream().map(p -> p.representative().hasError() ? "(not analysed)"
                : String.join(", ", p.missingHeaders())).toList();
        fireTableDataChanged();
    }

    List<HeaderProfile> rows() {
        return rows;
    }

    HeaderProfile rowAt(int modelIndex) {
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
        return column == 3 || column == 5 ? Integer.class : String.class;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        HeaderProfile p = rows.get(rowIndex);
        return switch (columnIndex) {
            case COL_FLAG -> p.sensitive() ? p.sensitivity().label() : "";
            case 1 -> p.host();
            case COL_PATH -> p.path();
            case 3 -> p.size();
            case COL_MISSING -> missingText.get(rowIndex);
            case 5 -> p.misconfigured().size();
            case 6 -> p.worstSeverity().map(Enum::name).orElse("");
            default -> "";
        };
    }
}
