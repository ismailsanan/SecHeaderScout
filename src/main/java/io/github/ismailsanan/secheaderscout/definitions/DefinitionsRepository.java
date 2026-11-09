package io.github.ismailsanan.secheaderscout.definitions;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

/**
 * Holds the OWASP definitions the extension uses.
 *
 * <p>The bundled, commit-pinned resource is always the starting point, so the
 * extension behaves the same offline and does not change silently when the
 * upstream file changes. {@link #sync} is an explicit, user-triggered update
 * ("Sync OWASP Headers"): the download is validated before it replaces the
 * current snapshot, and on any failure the last known good snapshot stays
 * active. Synced definitions are kept in memory only, so a reload returns to the
 * pinned copy and results stay reproducible.</p>
 */
public final class DefinitionsRepository {

    static final String BUNDLED_JSON = "/owasp/headers_add.json";
    static final String BUNDLED_PROPERTIES = "/owasp/definitions.properties";

    /** The upstream file the sync downloads (OWASP Secure Headers Project, default branch). */
    public static final String UPSTREAM_URL =
            "https://raw.githubusercontent.com/OWASP/www-project-secure-headers/master/ci/headers_add.json";

    /** Downloads a URL's body as text. Implementations must verify TLS and bound the size. */
    @FunctionalInterface
    public interface Downloader {
        String download(String url) throws IOException;
    }

    /** Outcome of a sync: whether new definitions became active, and what changed. */
    public record SyncResult(boolean updated, String message, Set<String> added, Set<String> removed) {
        public SyncResult {
            added = Set.copyOf(added);
            removed = Set.copyOf(removed);
        }
    }

    /** Read by scans on worker threads, replaced by a sync: an immutable snapshot behind an atomic reference. */
    private final AtomicReference<OwaspDefinitions> current;

    public DefinitionsRepository(OwaspDefinitions initial) {
        this.current = new AtomicReference<>(Objects.requireNonNull(initial, "initial"));
    }

    /** Loads the definitions bundled in the extension JAR. */
    public static DefinitionsRepository fromBundledResource() {
        return new DefinitionsRepository(loadBundled());
    }

    static OwaspDefinitions loadBundled() {
        Properties props = new Properties();
        try (InputStream in = DefinitionsRepository.class.getResourceAsStream(BUNDLED_PROPERTIES)) {
            if (in == null) {
                // packaging bug: without it the pinned commit (FR-11) silently becomes "unknown"
                throw new IllegalStateException("Bundled resource " + BUNDLED_PROPERTIES + " is missing from the JAR");
            }
            props.load(in);
        } catch (IOException e) {
            throw new UncheckedIOException("Cannot read " + BUNDLED_PROPERTIES, e);
        }
        try (InputStream in = DefinitionsRepository.class.getResourceAsStream(BUNDLED_JSON)) {
            if (in == null) {
                throw new IllegalStateException("Bundled resource " + BUNDLED_JSON + " is missing from the JAR");
            }
            String json = new String(in.readAllBytes(), StandardCharsets.UTF_8);
            return DefinitionsParser.parse(json, OwaspDefinitions.Source.BUNDLED,
                    props.getProperty("source.commit", "unknown"));
        } catch (IOException e) {
            throw new UncheckedIOException("Cannot read " + BUNDLED_JSON, e);
        } catch (DefinitionsParser.InvalidDefinitionsException e) {
            // the bundled file is part of the build; failing validation is a packaging bug
            throw new IllegalStateException("Bundled OWASP definitions are invalid: " + e.getMessage(), e);
        }
    }

    public OwaspDefinitions current() {
        return current.get();
    }

    /**
     * Downloads, validates and, if valid, activates the latest upstream definitions. Never throws
     * for network or validation problems: the previous snapshot stays active and the result says why.
     */
    public SyncResult sync(Downloader downloader) {
        OwaspDefinitions previous = current.get();
        OwaspDefinitions fetched;
        try {
            String body = downloader.download(UPSTREAM_URL);
            if (body == null) {
                throw new IOException("empty response");
            }
            fetched = DefinitionsParser.parse(body, OwaspDefinitions.Source.SYNCED, "latest");
        } catch (IOException e) {
            return new SyncResult(false, "Download failed: " + e.getMessage() + ". Keeping "
                    + previous.versionLabel() + ".", Set.of(), Set.of());
        } catch (DefinitionsParser.InvalidDefinitionsException e) {
            return new SyncResult(false, "Downloaded definitions rejected (" + e.getMessage() + "). Keeping "
                    + previous.versionLabel() + ".", Set.of(), Set.of());
        }
        Set<String> before = names(previous);
        Set<String> after = names(fetched);
        Set<String> added = new LinkedHashSet<>(after);
        added.removeAll(before);
        Set<String> removed = new LinkedHashSet<>(before);
        removed.removeAll(after);
        current.set(fetched);
        String changes = added.isEmpty() && removed.isEmpty() ? "no header added or removed"
                : (added.isEmpty() ? "" : "added " + added) + (added.isEmpty() || removed.isEmpty() ? "" : "; ")
                + (removed.isEmpty() ? "" : "removed " + removed);
        return new SyncResult(true, "Now using " + fetched.versionLabel() + ": " + changes + ".", added, removed);
    }

    private static Set<String> names(OwaspDefinitions defs) {
        return defs.headers().stream().map(HeaderDefinition::name)
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }
}
