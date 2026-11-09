package io.github.ismailsanan.secheaderscout;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.BurpSuiteEdition;
import burp.api.montoya.scanner.scancheck.ScanCheckType;
import io.github.ismailsanan.secheaderscout.burp.BurpEndpointRulesStore;
import io.github.ismailsanan.secheaderscout.burp.BurpHttpFetcher;
import io.github.ismailsanan.secheaderscout.burp.BurpLog;
import io.github.ismailsanan.secheaderscout.burp.BurpSiteMapSource;
import io.github.ismailsanan.secheaderscout.definitions.DefinitionsRepository;
import io.github.ismailsanan.secheaderscout.engine.EndpointRules;
import io.github.ismailsanan.secheaderscout.engine.EndpointRulesStore;
import io.github.ismailsanan.secheaderscout.engine.HeaderEvaluator;
import io.github.ismailsanan.secheaderscout.engine.RuleSets;
import io.github.ismailsanan.secheaderscout.engine.UrlClassifier;
import io.github.ismailsanan.secheaderscout.manual.ManualScanner;
import io.github.ismailsanan.secheaderscout.scanner.SecurityHeadersPassiveCheck;
import io.github.ismailsanan.secheaderscout.ui.ScanPanel;
import io.github.ismailsanan.secheaderscout.util.BackgroundTasks;
import io.github.ismailsanan.secheaderscout.util.Log;

import javax.swing.SwingUtilities;
import java.lang.reflect.InvocationTargetException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Extension entry point: wires the components together and owns their lifecycle.
 *
 * <ul>
 *     <li><b>Passive scanner</b> ({@link SecurityHeadersPassiveCheck}): automatic, reports to Burp's Issues panel.</li>
 *     <li><b>Manual scanner</b> ({@link ManualScanner} + {@link ScanPanel}): user-triggered Quick/Deep Scan,
 *         reports and comparisons in the SecHeaderScout tab.</li>
 * </ul>
 * Startup makes no network requests; the OWASP definitions come from the JAR.
 */
public final class SecHeaderScout implements BurpExtension {

    static final String NAME = "SecHeaderScout";
    private static final long SHUTDOWN_TIMEOUT_MS = 3_000;

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName(NAME);
        Log log = new BurpLog(api.logging());

        DefinitionsRepository definitions = DefinitionsRepository.fromBundledResource();
        log.info("[OWASP] Using " + definitions.current().versionLabel());

        // a buggy rule would otherwise log a stack trace for every proxied response: report each
        // failing rule once (the result is still marked incomplete every time, see ScanResult)
        java.util.Set<String> reportedRuleErrors = java.util.concurrent.ConcurrentHashMap.newKeySet();
        HeaderEvaluator.RuleErrorHandler ruleErrors = (rule, error) -> {
            if (reportedRuleErrors.add(rule.header() + "|" + error.getClass().getName())) {
                log.error("Rule for " + rule.header() + " threw an exception (reported once; affected "
                        + "results are marked as incomplete)", error);
            }
        };

        // endpoint types saved in the project; loaded before the passive check sees any traffic
        EndpointRulesStore endpointTypes = new BurpEndpointRulesStore(api.persistence().extensionData(), log);
        EndpointRules savedTypes = endpointTypes.load();
        UrlClassifier.setRules(savedTypes);
        if (!savedTypes.isDefault()) {
            log.info("[TYPES] Loaded endpoint types from the project: " + savedTypes);
        }

        SecurityHeadersPassiveCheck passiveCheck =
                new SecurityHeadersPassiveCheck(new HeaderEvaluator(RuleSets.passiveRules(), ruleErrors), log);
        registerPassiveCheck(api, passiveCheck, log);

        // one worker: the UI runs at most one manual operation at a time
        BackgroundTasks tasks = new BackgroundTasks(NAME + "-worker", 1, log);
        BurpHttpFetcher fetcher = new BurpHttpFetcher(api.http());
        ManualScanner manualScanner = new ManualScanner(fetcher,
                () -> new HeaderEvaluator(RuleSets.manualRules(definitions.current().headers()), ruleErrors), log);

        ScanPanel panel = createOnEdt(() -> new ScanPanel(manualScanner, new BurpSiteMapSource(api.siteMap(), log),
                definitions, fetcher, endpointTypes, api.scope()::isInScope, tasks, log));
        api.userInterface().applyThemeToComponent(panel.component());
        api.userInterface().registerSuiteTab(NAME, panel.component());

        api.extension().registerUnloadingHandler(() -> {
            // Burp does not specify the unload thread: UI state is reset on the EDT, while the
            // executor shutdown (which interrupts running work) happens right here.
            SwingUtilities.invokeLater(panel::dispose);
            boolean stopped = tasks.shutdown(SHUTDOWN_TIMEOUT_MS, TimeUnit.MILLISECONDS);
            passiveCheck.reset();
            UrlClassifier.setRules(EndpointRules.DEFAULT);
            log.info(NAME + " unloaded" + (stopped ? "; all background tasks stopped." : "."));
        });

        log.info(NAME + " loaded.");
    }

    private static void registerPassiveCheck(MontoyaApi api, SecurityHeadersPassiveCheck check, Log log) {
        BurpSuiteEdition edition = api.burpSuite().version().edition();
        if (edition == BurpSuiteEdition.COMMUNITY_EDITION) {
            log.info("Burp Suite Community Edition has no scanner: passive security-header issues are disabled. "
                    + "The SecHeaderScout tab (manual scanning) is still available.");
            return;
        }
        api.scanner().registerPassiveScanCheck(check, ScanCheckType.PER_REQUEST);
        log.info("Passive scan check registered: COOP, COEP, CORP, Referrer-Policy, Permissions-Policy, "
                + "X-DNS-Prefetch-Control, X-Permitted-Cross-Domain-Policies, Clear-Site-Data.");
    }

    /** Swing components must be created on the EDT; Burp calls initialize() on another thread. */
    private static <T> T createOnEdt(java.util.function.Supplier<T> factory) {
        if (SwingUtilities.isEventDispatchThread()) {
            return factory.get();
        }
        AtomicReference<T> ref = new AtomicReference<>();
        try {
            SwingUtilities.invokeAndWait(() -> ref.set(factory.get()));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while building the UI", e);
        } catch (InvocationTargetException e) {
            throw new IllegalStateException("Failed to build the UI", e.getCause());
        }
        return ref.get();
    }
}
