package io.github.ismailsanan.secheaderscout.ui;

import javax.swing.JComponent;

/** A read-only view of one raw HTTP message (the Request and Response tabs). EDT-only. */
public interface MessageView {

    JComponent component();

    /** Shows {@code raw} exactly as sent or received, or a placeholder when it is empty. */
    void show(String raw);
}
