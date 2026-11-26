package io.github.ismailsanan.secheaderscout.burp;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import io.github.ismailsanan.secheaderscout.ui.MessageView;

import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.SwingConstants;
import java.awt.CardLayout;
import java.util.function.Consumer;

/** Burp's own read-only request/response editor (Pretty / Raw / Hex, as in Proxy history). */
public final class BurpMessageView implements MessageView {

    private final CardLayout cards = new CardLayout();
    private final JPanel panel = new JPanel(cards);
    private final Consumer<String> setter;

    private BurpMessageView(java.awt.Component editor, Consumer<String> setter) {
        this.setter = setter;
        panel.add(new JLabel("No request/response captured for this result.", SwingConstants.CENTER), "none");
        panel.add(editor, "editor");
    }

    public static MessageView request(UserInterface ui) {
        HttpRequestEditor editor = ui.createHttpRequestEditor(EditorOptions.READ_ONLY);
        return new BurpMessageView(editor.uiComponent(), raw -> editor.setRequest(HttpRequest.httpRequest(raw)));
    }

    public static MessageView response(UserInterface ui) {
        HttpResponseEditor editor = ui.createHttpResponseEditor(EditorOptions.READ_ONLY);
        return new BurpMessageView(editor.uiComponent(), raw -> editor.setResponse(HttpResponse.httpResponse(raw)));
    }

    @Override
    public JComponent component() {
        return panel;
    }

    @Override
    public void show(String raw) {
        if (raw == null || raw.isEmpty()) {
            cards.show(panel, "none");
            return;
        }
        setter.accept(raw);
        cards.show(panel, "editor");
    }
}
