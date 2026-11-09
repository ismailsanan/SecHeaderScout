package io.github.ismailsanan.secheaderscout;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.burpsuite.BurpSuite;
import burp.api.montoya.core.BurpSuiteEdition;
import burp.api.montoya.core.Version;
import burp.api.montoya.extension.Extension;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.http.Http;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.scanner.Scanner;
import burp.api.montoya.sitemap.SiteMap;
import burp.api.montoya.ui.UserInterface;
import io.github.ismailsanan.secheaderscout.testsupport.FakeMontoya;
import io.github.ismailsanan.secheaderscout.testsupport.Strict;
import io.github.ismailsanan.secheaderscout.testsupport.Threads;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.swing.AbstractButton;
import javax.swing.JComponent;
import javax.swing.SwingUtilities;
import java.awt.Component;
import java.awt.Container;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CC-5: unloading cancels REAL running work and leaves no worker thread, and the
 * unloading handler is safe on any thread, including the Swing EDT.
 */
class SecHeaderScoutUnloadTest {

    @BeforeAll
    static void installFactory() {
        FakeMontoya.install();
    }

    private final List<String> output = new CopyOnWriteArrayList<>();
    private final AtomicReference<ExtensionUnloadingHandler> unload = new AtomicReference<>();
    private final AtomicReference<Component> tab = new AtomicReference<>();
    private final java.util.Map<String, String> projectData = new java.util.concurrent.ConcurrentHashMap<>();
    private final CountDownLatch siteMapEntered = new CountDownLatch(1);
    private final CountDownLatch neverReleased = new CountDownLatch(1);
    private final AtomicBoolean siteMapInterrupted = new AtomicBoolean();

    private MontoyaApi api() {
        Extension extension = Strict.of(Extension.class)
                .returns("setName", null)
                .answers("registerUnloadingHandler", a -> {
                    unload.set((ExtensionUnloadingHandler) a[0]);
                    return null;
                })
                .build();
        Logging logging = Strict.of(Logging.class)
                .answers("logToOutput", a -> output.add(String.valueOf(a[0])))
                .answers("logToError", a -> output.add("ERROR " + a[0]))
                .build();
        // a site map that blocks like a huge project would, until interrupted
        SiteMap siteMap = Strict.of(SiteMap.class).answers("requestResponses", a -> {
            siteMapEntered.countDown();
            try {
                neverReleased.await();
            } catch (InterruptedException e) {
                siteMapInterrupted.set(true);
                Thread.currentThread().interrupt();
            }
            return List.of();
        }).build();
        UserInterface ui = Strict.of(UserInterface.class)
                .returns("applyThemeToComponent", null)
                .answers("registerSuiteTab", a -> {
                    tab.set((Component) a[1]);
                    return null;
                })
                .build();
        return Strict.of(MontoyaApi.class)
                .returns("extension", extension)
                .returns("logging", logging)
                .returns("scanner", Strict.of(Scanner.class).returns("registerPassiveScanCheck", null).build())
                .returns("burpSuite", Strict.of(BurpSuite.class).returns("version",
                        Strict.of(Version.class).returns("edition", BurpSuiteEdition.PROFESSIONAL).build()).build())
                .returns("http", Strict.of(Http.class).build())
                .returns("siteMap", siteMap)
                .returns("scope", Strict.of(burp.api.montoya.scope.Scope.class).build())
                .returns("persistence", io.github.ismailsanan.secheaderscout.testsupport.FakeMontoya.persistence(projectData))
                .returns("userInterface", ui)
                .build();
    }

    private static AbstractButton button(Component root, String text) {
        if (root instanceof AbstractButton b && text.equals(b.getText())) {
            return b;
        }
        if (root instanceof Container c) {
            for (Component child : c.getComponents()) {
                AbstractButton found = button(child, text);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }

    @Test
    void unloadDuringABlockedOperationInterruptsItAndStopsTheWorker() throws Exception {
        new SecHeaderScout().initialize(api());
        AbstractButton refresh = button(tab.get(), "Refresh from Burp");
        AbstractButton cancel = button(tab.get(), "Cancel");
        assertNotNull(refresh);
        assertNotNull(cancel);

        SwingUtilities.invokeAndWait(refresh::doClick);
        assertTrue(siteMapEntered.await(5, TimeUnit.SECONDS), "the refresh never reached the site map");
        assertTrue(Thread.getAllStackTraces().keySet().stream()
                        .anyMatch(t -> t.getName().startsWith("SecHeaderScout-worker")),
                "a worker must exist, otherwise the liveness check below proves nothing");

        unload.get().extensionUnloaded();

        assertTrue(siteMapInterrupted.get(), "unload must interrupt the running operation");
        Threads.assertNoLiveThreads("SecHeaderScout-worker");
        assertTrue(output.stream().anyMatch(m -> m.contains("all background tasks stopped")), output.toString());
        SwingUtilities.invokeAndWait(() -> { }); // flush dispose() and the cancelled operation's callbacks
        SwingUtilities.invokeAndWait(() -> { });
        assertFalse(cancel.isEnabled(), "the UI must be idle after unload");
    }

    @Test
    void unloadingOnTheEventDispatchThreadDoesNotDeadlock() throws Exception {
        new SecHeaderScout().initialize(api());
        assertTimeoutPreemptively(Duration.ofSeconds(8),
                () -> SwingUtilities.invokeAndWait(() -> unload.get().extensionUnloaded()));
        assertTrue(output.stream().anyMatch(m -> m.contains("unloaded")), output.toString());
    }

    @Test
    void labelsNeverRenderHtml() throws Exception {
        new SecHeaderScout().initialize(api());
        List<JComponent> labels = new CopyOnWriteArrayList<>();
        collectLabels(tab.get(), labels);
        List<String> mustBePlain = List.of("Ready.", "Score: N/A");
        for (String text : mustBePlain) {
            JComponent label = labels.stream()
                    .filter(l -> text.equals(((javax.swing.JLabel) l).getText()))
                    .findFirst().orElseThrow(() -> new AssertionError("label '" + text + "' not found"));
            assertTrue(Boolean.TRUE.equals(label.getClientProperty("html.disable")),
                    "label '" + text + "' must not render HTML (it can show server- or file-derived text)");
        }
        unload.get().extensionUnloaded();
    }

    private static void collectLabels(Component c, List<JComponent> out) {
        if (c instanceof javax.swing.JLabel l) {
            out.add(l);
        }
        if (c instanceof Container k) {
            for (Component child : k.getComponents()) {
                collectLabels(child, out);
            }
        }
    }
}
