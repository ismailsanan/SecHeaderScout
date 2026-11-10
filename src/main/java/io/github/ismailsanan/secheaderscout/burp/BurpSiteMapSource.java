package io.github.ismailsanan.secheaderscout.burp;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.sitemap.SiteMap;
import io.github.ismailsanan.secheaderscout.manual.SiteMapSource;
import io.github.ismailsanan.secheaderscout.model.ResponseSnapshot;
import io.github.ismailsanan.secheaderscout.util.Log;
import io.github.ismailsanan.secheaderscout.util.UrlPaths;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Read-only site map access. Methods may be slow on large projects and must
 * never be called on the Swing event dispatch thread. They stop early (with
 * partial results) when the calling thread is interrupted.
 */
public final class BurpSiteMapSource implements SiteMapSource {

    private final SiteMap siteMap;
    private final Log log;

    public BurpSiteMapSource(SiteMap siteMap, Log log) {
        this.siteMap = siteMap;
        this.log = log;
    }

    @Override
    public List<String> hosts() {
        // collect host names inside the filter and match nothing: Burp then never builds the
        // request/response objects, which matters on projects with 100k site map entries
        Set<String> hosts = Collections.synchronizedSet(new LinkedHashSet<>());
        siteMap.requestResponses(node -> {
            if (!Thread.currentThread().isInterrupted()) {
                try {
                    String host = UrlPaths.host(node.url());
                    if (!host.isEmpty()) {
                        hosts.add(host);
                    }
                } catch (RuntimeException e) {
                    log.warn("[SITEMAP] Skipping an unreadable site map entry: " + e.getClass().getSimpleName());
                }
            }
            return false;
        });
        synchronized (hosts) {
            return new ArrayList<>(hosts);
        }
    }

    @Override
    public List<ResponseSnapshot> responsesFor(String host) {
        List<ResponseSnapshot> snapshots = new ArrayList<>();
        forEachResponse(host, (i, total, snapshot) -> snapshots.add(snapshot));
        return snapshots;
    }

    /** Builds each snapshot only when the visitor asks for it, so Deep Scan never holds them all. */
    @Override
    public void forEachResponse(String host, ResponseVisitor visitor) {
        // filter inside Burp by exact host, rather than copying the whole site map
        List<HttpRequestResponse> entries =
                siteMap.requestResponses(node -> host.equalsIgnoreCase(UrlPaths.host(node.url())));
        int skipped = 0;
        for (int i = 0; i < entries.size(); i++) {
            Optional<ResponseSnapshot> snapshot;
            try {
                snapshot = BurpMessages.analysableSnapshot(entries.get(i));
            } catch (RuntimeException e) {
                // one malformed entry must not abort the whole Deep Scan
                if (skipped++ == 0) {
                    log.error("[DEEP] Skipping unreadable site map entry for " + host, e);
                }
                continue;
            }
            if (snapshot.isPresent() && !visitor.visit(i, entries.size(), snapshot.get())) {
                break;
            }
        }
        if (skipped > 0) {
            log.warn("[DEEP] " + host + ": skipped " + skipped + " unreadable site map entr"
                    + (skipped == 1 ? "y" : "ies"));
        }
    }
}
