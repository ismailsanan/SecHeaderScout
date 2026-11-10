package io.github.ismailsanan.secheaderscout.model;

import io.github.ismailsanan.secheaderscout.engine.Finding;
import io.github.ismailsanan.secheaderscout.engine.Severity;
import io.github.ismailsanan.secheaderscout.engine.UrlClassifier;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * A group of Deep Scan endpoints on one host, under the same path group (e.g. {@code /api/*}),
 * that have exactly the same header issues. A site typically has only a handful.
 *
 * @param host           host the endpoints belong to
 * @param path           the group's path: the exact path when all members share it
 *                       (e.g. {@code /login}), otherwise a pattern such as {@code /api/*}
 * @param issues         sorted issue names shared by every member (the grouping key)
 * @param representative one member result, for the finding details
 * @param urls           member URLs, in discovery order
 * @param sensitivity    most sensitive URL type among the members ({@code NORMAL} if none)
 * @param worstSeverity  highest finding severity, if any finding
 */
public record HeaderProfile(String host, String path, List<String> issues, ScanResult representative,
                            List<String> urls, UrlClassifier.UrlType sensitivity,
                            Optional<Severity> worstSeverity) {

    public HeaderProfile {
        Objects.requireNonNull(host);
        Objects.requireNonNull(path);
        Objects.requireNonNull(representative);
        Objects.requireNonNull(sensitivity);
        Objects.requireNonNull(worstSeverity);
        issues = List.copyOf(issues);
        urls = List.copyOf(urls);
        if (urls.isEmpty()) {
            throw new IllegalArgumentException("a profile has at least one URL");
        }
    }

    public int size() {
        return urls.size();
    }

    /** Contains a logout, login, payment or admin endpoint. */
    public boolean sensitive() {
        return sensitivity.isHighValue();
    }

    /** Names of the headers every member is missing. */
    public List<String> missingHeaders() {
        return representative.missingHeaderNames();
    }

    /** Misconfiguration findings (values taken from the representative member). */
    public List<Finding> misconfigured() {
        return representative.misconfigured();
    }
}
