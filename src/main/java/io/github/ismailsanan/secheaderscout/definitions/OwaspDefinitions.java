package io.github.ismailsanan.secheaderscout.definitions;

import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;

/**
 * An immutable, identifiable snapshot of the OWASP header definitions.
 *
 * @param source        where the snapshot came from
 * @param revision      upstream commit the bundled file was taken from, or "latest" after a sync
 * @param lastUpdateUtc the {@code last_update_utc} field of the upstream file
 * @param headers       recommended headers, in upstream order
 */
public record OwaspDefinitions(Source source, String revision, String lastUpdateUtc, List<HeaderDefinition> headers) {

    /** Where definitions come from: the commit-pinned copy in the JAR, or a user-triggered sync. */
    public enum Source {
        BUNDLED,
        SYNCED
    }

    public OwaspDefinitions {
        Objects.requireNonNull(source, "source");
        revision = revision == null ? "unknown" : revision;
        lastUpdateUtc = lastUpdateUtc == null ? "unknown" : lastUpdateUtc;
        headers = List.copyOf(headers);
        java.util.Set<String> seen = new java.util.HashSet<>();
        for (HeaderDefinition h : headers) {
            if (!seen.add(h.name().toLowerCase(Locale.ROOT))) {
                throw new IllegalArgumentException("duplicate header definition: " + h.name());
            }
        }
    }

    /** Human-readable version label, e.g. {@code bundled 06b5c6f (2026-10-18 07:04:36 UTC, 13 headers)}. */
    public String versionLabel() {
        String rev = revision.length() > 7 && revision.matches("[0-9a-f]+") ? revision.substring(0, 7) : revision;
        return source.name().toLowerCase(Locale.ROOT) + " " + rev + " (" + lastUpdateUtc + " UTC, "
                + headers.size() + " headers)";
    }

    public Optional<HeaderDefinition> find(String headerName) {
        return headers.stream().filter(h -> h.name().equalsIgnoreCase(headerName)).findFirst();
    }

    public String recommendedFor(String headerName) {
        return find(headerName).map(HeaderDefinition::recommendedValue).orElse("");
    }
}
