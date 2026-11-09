package io.github.ismailsanan.secheaderscout.ui;

import javax.swing.AbstractAction;
import javax.swing.JComponent;
import javax.swing.KeyStroke;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;

/** Small Swing helpers shared by the panels. EDT-only. */
final class UiSupport {

    private UiSupport() {
    }

    /**
     * Turns off Swing's HTML rendering for {@code c}. Values shown in tables and lists come from
     * captured traffic; a server-supplied value starting with {@code <html>} must stay plain text.
     */
    static <T extends JComponent> T plain(T c) {
        c.putClientProperty("html.disable", Boolean.TRUE);
        return c;
    }

    /** A table cell renderer that never interprets HTML. */
    static DefaultTableCellRenderer plainRenderer() {
        return plain(new DefaultTableCellRenderer());
    }

    /** Runs {@code action} when Delete or Backspace is pressed while {@code c} has the focus. */
    static void onDeleteKey(JComponent c, Runnable action) {
        for (int key : new int[]{KeyEvent.VK_DELETE, KeyEvent.VK_BACK_SPACE}) {
            c.getInputMap(JComponent.WHEN_FOCUSED).put(KeyStroke.getKeyStroke(key, 0), "delete");
        }
        c.getActionMap().put("delete", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                action.run();
            }
        });
    }
}
