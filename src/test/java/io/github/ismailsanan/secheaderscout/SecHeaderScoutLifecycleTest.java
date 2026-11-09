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
import burp.api.montoya.scanner.scancheck.PassiveScanCheck;
import burp.api.montoya.scanner.scancheck.ScanCheckType;
import burp.api.montoya.sitemap.SiteMap;
import burp.api.montoya.ui.UserInterface;
import io.github.ismailsanan.secheaderscout.testsupport.FakeMontoya;
import io.github.ismailsanan.secheaderscout.testsupport.Strict;
import org.junit.jupiter.api.BeforeAll;
import io.github.ismailsanan.secheaderscout.testsupport.Threads;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * FR-1, FR-9, CC-5: extension wiring with strict Montoya fakes. Any call to Burp's
 * HTTP API or site map during startup throws, so startup is proven network-free.
 */
class SecHeaderScoutLifecycleTest {

    @BeforeAll
    static void installFactory() {
        FakeMontoya.install();
    }

    private static final class Wiring {
        final List<String> output = new CopyOnWriteArrayList<>();
        final List<String> errors = new CopyOnWriteArrayList<>();
        final AtomicReference<PassiveScanCheck> check = new AtomicReference<>();
        final AtomicReference<ScanCheckType> checkType = new AtomicReference<>();
        final AtomicReference<ExtensionUnloadingHandler> unload = new AtomicReference<>();
        final AtomicReference<String> name = new AtomicReference<>();
        final AtomicReference<String> tabTitle = new AtomicReference<>();
        final java.util.Map<String, String> projectData = new java.util.concurrent.ConcurrentHashMap<>();

        MontoyaApi api(BurpSuiteEdition edition) {
            Extension extension = Strict.of(Extension.class)
                    .answers("setName", a -> {
                        name.set((String) a[0]);
                        return null;
                    })
                    .answers("registerUnloadingHandler", a -> {
                        unload.set((ExtensionUnloadingHandler) a[0]);
                        return null;
                    })
                    .build();
            Logging logging = Strict.of(Logging.class)
                    .answers("logToOutput", a -> {
                        output.add(String.valueOf(a[0]));
                        return null;
                    })
                    .answers("logToError", a -> {
                        errors.add(String.valueOf(a[0]));
                        return null;
                    })
                    .build();
            Scanner scanner = Strict.of(Scanner.class)
                    .answers("registerPassiveScanCheck", a -> {
                        check.set((PassiveScanCheck) a[0]);
                        checkType.set((ScanCheckType) a[1]);
                        return null;
                    })
                    .build();
            Version version = Strict.of(Version.class).returns("edition", edition).build();
            BurpSuite burpSuite = Strict.of(BurpSuite.class).returns("version", version).build();
            UserInterface ui = Strict.of(UserInterface.class)
                    .returns("applyThemeToComponent", null)
                    .answers("registerSuiteTab", a -> {
                        tabTitle.set((String) a[0]);
                        return null;
                    })
                    .build();
            return Strict.of(MontoyaApi.class)
                    .returns("extension", extension)
                    .returns("logging", logging)
                    .returns("scanner", scanner)
                    .returns("burpSuite", burpSuite)
                    .returns("http", Strict.of(Http.class).build())        // any call throws
                    .returns("siteMap", Strict.of(SiteMap.class).build())  // any call throws
                    .returns("scope", Strict.of(burp.api.montoya.scope.Scope.class).build()) // only used on Rescan
                    .returns("persistence", io.github.ismailsanan.secheaderscout.testsupport.FakeMontoya.persistence(projectData))
                    .returns("userInterface", ui)
                    .build();
        }
    }

    @Test
    void professionalRegistersPerRequestPassiveCheckWithoutNetworkAndUnloadsCleanly() throws Exception {
        Wiring w = new Wiring();
        new SecHeaderScout().initialize(w.api(BurpSuiteEdition.PROFESSIONAL));

        assertEquals("SecHeaderScout", w.name.get());
        assertEquals("SecHeaderScout", w.tabTitle.get());
        assertNotNull(w.check.get(), "passive check registered");
        assertEquals(ScanCheckType.PER_REQUEST, w.checkType.get());
        assertTrue(w.output.stream().anyMatch(m -> m.startsWith("[OWASP] Using bundled")), w.output.toString());
        assertTrue(w.errors.isEmpty(), w.errors.toString());
        assertNotNull(w.unload.get(), "unloading handler registered");

        // populate per-origin state, then unload: state must be cleared and no workers left
        var page = io.github.ismailsanan.secheaderscout.testsupport.Http.exchange().url("https://u.example/").html().build();
        assertEquals(7, w.check.get().doCheck(page).auditIssues().size());
        assertTrue(w.check.get().doCheck(page).auditIssues().isEmpty());

        w.unload.get().extensionUnloaded();

        assertEquals(7, w.check.get().doCheck(page).auditIssues().size(), "unload must reset de-duplication state");
        assertTrue(w.output.stream().anyMatch(m -> m.contains("unloaded; all background tasks stopped.")),
                w.output.toString());
        Threads.assertNoLiveThreads("SecHeaderScout-worker");
        assertTrue(w.errors.isEmpty(), w.errors.toString());
    }

    @Test
    void communityEditionDoesNotRegisterAPassiveCheck() {
        Wiring w = new Wiring();
        new SecHeaderScout().initialize(w.api(BurpSuiteEdition.COMMUNITY_EDITION));
        assertNull(w.check.get());
        assertEquals("SecHeaderScout", w.tabTitle.get());
        assertTrue(w.output.stream().anyMatch(m -> m.contains("Community Edition has no scanner")), w.output.toString());
        w.unload.get().extensionUnloaded();
        assertTrue(w.errors.isEmpty(), w.errors.toString());
    }
}
