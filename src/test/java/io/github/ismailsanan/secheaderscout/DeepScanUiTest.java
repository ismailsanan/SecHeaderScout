package io.github.ismailsanan.secheaderscout;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.burpsuite.BurpSuite;
import burp.api.montoya.core.BurpSuiteEdition;
import burp.api.montoya.core.Version;
import burp.api.montoya.extension.Extension;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.scanner.Scanner;
import burp.api.montoya.sitemap.SiteMap;
import burp.api.montoya.sitemap.SiteMapFilter;
import burp.api.montoya.sitemap.SiteMapNode;
import burp.api.montoya.ui.UserInterface;
import io.github.ismailsanan.secheaderscout.testsupport.FakeMontoya;
import io.github.ismailsanan.secheaderscout.testsupport.Http;
import io.github.ismailsanan.secheaderscout.testsupport.Strict;
import org.junit.jupiter.api.BeforeAll;
import io.github.ismailsanan.secheaderscout.engine.UrlClassifier;
import org.junit.jupiter.api.Test;

import javax.swing.AbstractButton;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.SwingUtilities;
import java.awt.Component;
import java.awt.Container;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** End-to-end wiring of Deep Scan profiles in the real Swing panel (fake Burp, headless). */
class DeepScanUiTest {

    @BeforeAll
    static void install() {
        FakeMontoya.install();
    }

    private final AtomicReference<Component> tab = new AtomicReference<>();
    private final java.util.Map<String, String> projectData = new java.util.concurrent.ConcurrentHashMap<>();
    private final AtomicReference<ExtensionUnloadingHandler> unload = new AtomicReference<>();

    private static Http.Exchange page(String url) {
        return Http.exchange().url(url).html()
                .header("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
                .header("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
                .header("X-Content-Type-Options", "nosniff")
                .header("Cache-Control", "no-store")
                .header("Referrer-Policy", "no-referrer");
    }

    private MontoyaApi api() {
        Map<String, HttpRequestResponse> siteMapEntries = new LinkedHashMap<>();
        for (int i = 0; i < 12; i++) {
            siteMapEntries.put("https://e.example/app/p" + i, page("https://e.example/app/p" + i).build());
        }
        // a route that bypasses the middleware (no HSTS) and some noise the default filters drop
        siteMapEntries.put("https://e.example/export/x", Http.exchange().url("https://e.example/export/x").html()
                .header("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
                .header("X-Content-Type-Options", "nosniff").header("Cache-Control", "no-store")
                .header("Referrer-Policy", "no-referrer").build());
        siteMapEntries.put("https://e.example/logo.png",
                Http.exchange().url("https://e.example/logo.png").header("Content-Type", "image/png").build());
        siteMapEntries.put("https://e.example/app/p0?page=2", page("https://e.example/app/p0?page=2").build());

        SiteMap siteMap = Strict.of(SiteMap.class).answers("requestResponses", a -> {
            SiteMapFilter filter = (SiteMapFilter) a[0];
            List<HttpRequestResponse> matched = new ArrayList<>();
            siteMapEntries.forEach((url, rr) -> {
                if (filter.matches(Strict.of(SiteMapNode.class).returns("url", url).build())) {
                    matched.add(rr);
                }
            });
            return matched;
        }).build();
        return Strict.of(MontoyaApi.class)
                .returns("extension", Strict.of(Extension.class).returns("setName", null)
                        .answers("registerUnloadingHandler", a -> {
                            unload.set((ExtensionUnloadingHandler) a[0]);
                            return null;
                        }).build())
                .returns("logging", Strict.of(Logging.class).returns("logToOutput", null).returns("logToError", null).build())
                .returns("scanner", Strict.of(Scanner.class).returns("registerPassiveScanCheck", null).build())
                .returns("burpSuite", Strict.of(BurpSuite.class).returns("version",
                        Strict.of(Version.class).returns("edition", BurpSuiteEdition.PROFESSIONAL).build()).build())
                .returns("http", Strict.of(burp.api.montoya.http.Http.class).build()) // Deep Scan sends nothing
                .returns("siteMap", siteMap)
                .returns("scope", Strict.of(burp.api.montoya.scope.Scope.class).build())
                .returns("persistence", io.github.ismailsanan.secheaderscout.testsupport.FakeMontoya.persistence(projectData))
                .returns("userInterface", Strict.of(UserInterface.class).returns("applyThemeToComponent", null)
                        .answers("registerSuiteTab", a -> {
                            tab.set((Component) a[1]);
                            return null;
                        }).build())
                .build();
    }

    @SuppressWarnings("unchecked")
    private static <T extends Component> List<T> find(Component root, Class<T> type) {
        List<T> out = new ArrayList<>();
        if (type.isInstance(root)) {
            out.add((T) root);
        }
        if (root instanceof Container c) {
            for (Component child : c.getComponents()) {
                out.addAll(find(child, type));
            }
        }
        return out;
    }

    private static AbstractButton button(Component root, String text) {
        return find(root, AbstractButton.class).stream().filter(b -> text.equals(b.getText())).findFirst()
                .orElseThrow(() -> new AssertionError("no button " + text));
    }

    private static void await(BooleanSupplier condition) throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (System.nanoTime() < deadline) {
            AtomicReference<Boolean> ok = new AtomicReference<>(false);
            SwingUtilities.invokeAndWait(() -> ok.set(condition.getAsBoolean()));
            if (ok.get()) {
                return;
            }
            Thread.onSpinWait();
        }
        throw new AssertionError("condition not reached");
    }

    @Test
    void deepScanFillsTheByProfileTabAndKeepsByUrlAsTheDefault() throws Exception {
        new SecHeaderScout().initialize(api());
        Component root = tab.get();
        JList<?> hosts = find(root, JList.class).get(0);
        JTabbedPane resultsTabs = find(root, JTabbedPane.class).stream()
                .filter(t -> t.getTabCount() == 2 && "By URL".equals(t.getTitleAt(0)) && "By profile".equals(t.getTitleAt(1))).findFirst().orElseThrow();
        JTable profilesTable = find(root, JTable.class).stream()
                .filter(t -> "Path".equals(t.getColumnName(2))).findFirst().orElseThrow();
        JLabel status = find(root, JLabel.class).stream().filter(l -> "Ready.".equals(l.getText())).findFirst()
                .orElseThrow();

        SwingUtilities.invokeAndWait(button(root, "Refresh from Burp")::doClick);
        await(() -> hosts.getModel().getSize() == 1);
        SwingUtilities.invokeAndWait(() -> hosts.setSelectedIndex(0));
        SwingUtilities.invokeAndWait(button(root, "Deep Scan")::doClick);
        await(() -> profilesTable.getRowCount() > 0 && button(root, "Deep Scan").isEnabled());

        assertEquals(0, resultsTabs.getSelectedIndex(), "By URL stays the default tab");
        assertEquals(2, profilesTable.getRowCount());
        int app = "/app/*".equals(profilesTable.getValueAt(0, 2)) ? 0 : 1;
        assertEquals("/app/*", profilesTable.getValueAt(app, 2));
        assertEquals(12, profilesTable.getValueAt(app, 3), "the query variant was merged, the PNG skipped");
        assertEquals("/export/x", profilesTable.getValueAt(1 - app, 2));
        assertTrue(String.valueOf(profilesTable.getValueAt(1 - app, 4)).contains("Strict-Transport-Security"));
        String text = status.getText();
        assertNotNull(text);
        assertTrue(text.contains("analysed 13 of 15 captured responses"), text);
        assertTrue(text.contains("2 group(s) in the \"By profile\" tab"), text);
        assertFalse(find(root, AbstractButton.class).stream().anyMatch(b -> "Missing".equals(b.getText())),
                "the result filter buttons are gone");

        SwingUtilities.invokeAndWait(() -> profilesTable.setRowSelectionInterval(0, 0));
        unload.get().extensionUnloaded();
    }

    /** The control next to {@code button} (same row) of the given type. */
    private static <T extends Component> T sibling(Component root, String button, Class<T> type) {
        return find(button(root, button).getParent(), type).get(0);
    }

    private static int rowOf(JTable table, String pattern) {
        for (int r = 0; r < table.getRowCount(); r++) {
            if (pattern.equals(table.getValueAt(r, 2))) {
                return r;
            }
        }
        throw new AssertionError("no row " + pattern);
    }

    @Test
    void endpointTypesTabAddsTogglesRemovesAndSavesToTheProject() throws Exception {
        new SecHeaderScout().initialize(api());
        Component root = tab.get();
        javax.swing.JTextField pattern = sibling(root, "Remove selected", javax.swing.JTextField.class);
        javax.swing.JComboBox<?> type = sibling(root, "Remove selected", javax.swing.JComboBox.class);
        JTable rules = find(root, JTable.class).stream().filter(t -> "Pattern".equals(t.getColumnName(2)))
                .findFirst().orElseThrow();
        try {
            assertEquals(io.github.ismailsanan.secheaderscout.engine.EndpointRules.DEFAULT.rules().size(),
                    rules.getRowCount(), "built-in patterns are listed");

            SwingUtilities.invokeAndWait(() -> {
                pattern.setText("/session/*");
                type.setSelectedIndex(0); // LOGOUT
                button(root, "Add").doClick();
            });
            assertEquals(UrlClassifier.UrlType.LOGOUT, UrlClassifier.classify("https://e.example/session/destroy"));
            assertEquals("C\t1\tLOGOUT\t/session/*\n", projectData.get("endpointTypes.v1"));

            SwingUtilities.invokeAndWait(() -> rules.setValueAt(false, rowOf(rules, "*/login*"), 0));
            assertEquals(UrlClassifier.UrlType.NORMAL, UrlClassifier.classify("https://e.example/login"));
            assertTrue(projectData.get("endpointTypes.v1").contains("B\t0\t\t*/login*\n"));

            SwingUtilities.invokeAndWait(() -> {
                int row = rowOf(rules, "/session/*");
                rules.setRowSelectionInterval(row, row);
                button(root, "Remove selected").doClick();
            });
            assertEquals(UrlClassifier.UrlType.NORMAL, UrlClassifier.classify("https://e.example/session/destroy"));

            unload.get().extensionUnloaded();
            assertEquals(UrlClassifier.UrlType.LOGIN, UrlClassifier.classify("https://e.example/login"),
                    "unload restores the built-in patterns");
        } finally {
            UrlClassifier.setRules(io.github.ismailsanan.secheaderscout.engine.EndpointRules.DEFAULT);
        }
    }

    @Test
    void savedEndpointTypesApplyAsSoonAsTheExtensionLoads() throws Exception {
        projectData.put("endpointTypes.v1", "C\t1\tLOGOUT\t/session/*\nB\t0\t\t*/login*\ngarbage\n");
        try {
            new SecHeaderScout().initialize(api());
            assertEquals(UrlClassifier.UrlType.LOGOUT, UrlClassifier.classify("https://e.example/session/x"));
            assertEquals(UrlClassifier.UrlType.NORMAL, UrlClassifier.classify("https://e.example/login"));
            unload.get().extensionUnloaded();
        } finally {
            UrlClassifier.setRules(io.github.ismailsanan.secheaderscout.engine.EndpointRules.DEFAULT);
        }
    }

    @Test
    void theDeleteKeyRemovesSelectedHosts() throws Exception {
        new SecHeaderScout().initialize(api());
        Component root = tab.get();
        JList<?> hosts = find(root, JList.class).get(0);
        javax.swing.JTextField target = sibling(root, "Add Custom Target", javax.swing.JTextField.class);
        SwingUtilities.invokeAndWait(() -> {
            target.setText("a.example");
            button(root, "Add Custom Target").doClick();
            target.setText("b.example");
            button(root, "Add Custom Target").doClick();
            hosts.setSelectedIndex(0);
            Object key = hosts.getInputMap(javax.swing.JComponent.WHEN_FOCUSED)
                    .get(javax.swing.KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_DELETE, 0));
            hosts.getActionMap().get(key).actionPerformed(null);
        });
        assertEquals(1, hosts.getModel().getSize());
        assertEquals("b.example", hosts.getModel().getElementAt(0));
        unload.get().extensionUnloaded();
    }

    @Test
    void syncOwaspHeadersSitsNextToRefreshFromBurp() throws Exception {
        new SecHeaderScout().initialize(api());
        Component root = tab.get();
        AbstractButton sync = button(root, "Sync OWASP Headers");
        assertTrue(sync.getParent() == button(root, "Refresh from Burp").getParent(), "same row as Refresh");
        assertTrue(sync.isEnabled());
        assertTrue(sync.getToolTipText().contains("validated"));
        unload.get().extensionUnloaded();
    }
}
