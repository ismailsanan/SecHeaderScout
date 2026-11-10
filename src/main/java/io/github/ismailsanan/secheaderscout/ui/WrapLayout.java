package io.github.ismailsanan.secheaderscout.ui;

import javax.swing.JComponent;
import javax.swing.JScrollPane;
import javax.swing.SwingUtilities;
import java.awt.Component;
import java.awt.Container;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Insets;

/**
 * A {@link FlowLayout} that wraps onto further lines when the container is too narrow,
 * and reports the wrapped height as its preferred size.
 *
 * <p>Plain FlowLayout always reports a single-line preferred size, so inside a vertical
 * BoxLayout the components that do not fit are laid out past the right edge and are
 * simply invisible, which is how buttons "disappeared" on narrower Burp windows.</p>
 */
final class WrapLayout extends FlowLayout {

    private static final long serialVersionUID = 1L;

    /** The size last reported for the current width; a change means the parents must re-layout. */
    private Dimension lastLayoutSize;

    WrapLayout() {
        super(FlowLayout.LEFT);
    }

    /**
     * Ancestors cache their preferred size, so when a resize makes the row wrap onto more (or fewer)
     * lines nobody would ask again and the extra line stays hidden. When the wrapped size changes,
     * invalidate the ancestors and schedule one more validation; it stops once the size is stable.
     */
    @Override
    public void layoutContainer(Container target) {
        Dimension size = preferredLayoutSize(target);
        if (!size.equals(lastLayoutSize)) {
            boolean firstLayout = lastLayoutSize == null;
            lastLayoutSize = size;
            if (!firstLayout) {
                target.invalidate();
                if (target instanceof JComponent c) {
                    SwingUtilities.invokeLater(c::revalidate);
                }
            }
        }
        super.layoutContainer(target);
    }

    @Override
    public Dimension preferredLayoutSize(Container target) {
        return layoutSize(target, true);
    }

    @Override
    public Dimension minimumLayoutSize(Container target) {
        Dimension minimum = layoutSize(target, false);
        minimum.width -= getHgap() + 1;
        return minimum;
    }

    private Dimension layoutSize(Container target, boolean preferred) {
        synchronized (target.getTreeLock()) {
            int targetWidth = availableWidth(target);
            Insets insets = target.getInsets();
            int horizontalInsets = insets.left + insets.right + getHgap() * 2;
            int maxWidth = targetWidth - horizontalInsets;

            Dimension total = new Dimension(0, 0);
            int rowWidth = 0;
            int rowHeight = 0;
            for (Component c : target.getComponents()) {
                if (!c.isVisible()) {
                    continue;
                }
                Dimension d = preferred ? c.getPreferredSize() : c.getMinimumSize();
                if (rowWidth + d.width > maxWidth && rowWidth > 0) {
                    addRow(total, rowWidth, rowHeight);
                    rowWidth = 0;
                    rowHeight = 0;
                }
                if (rowWidth != 0) {
                    rowWidth += getHgap();
                }
                rowWidth += d.width;
                rowHeight = Math.max(rowHeight, d.height);
            }
            addRow(total, rowWidth, rowHeight);
            total.width += horizontalInsets;
            total.height += insets.top + insets.bottom + getVgap() * 2;

            // when inside a scroll pane, do not let the preferred width force a horizontal scrollbar
            Container scrollPane = SwingUtilities.getAncestorOfClass(JScrollPane.class, target);
            if (scrollPane != null && target.isValid()) {
                total.width -= getHgap() + 1;
            }
            return total;
        }
    }

    /** Width to wrap at: the container's own width once laid out, else its nearest sized ancestor's. */
    private static int availableWidth(Container target) {
        Container c = target;
        while (c.getSize().width == 0 && c.getParent() != null) {
            c = c.getParent();
        }
        int width = c.getSize().width;
        return width == 0 ? Integer.MAX_VALUE : width;
    }

    private void addRow(Dimension total, int rowWidth, int rowHeight) {
        total.width = Math.max(total.width, rowWidth);
        if (total.height > 0) {
            total.height += getVgap();
        }
        total.height += rowHeight;
    }
}
