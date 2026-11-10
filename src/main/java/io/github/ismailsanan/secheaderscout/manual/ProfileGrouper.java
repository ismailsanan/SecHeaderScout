package io.github.ismailsanan.secheaderscout.manual;

import io.github.ismailsanan.secheaderscout.engine.Finding;
import io.github.ismailsanan.secheaderscout.engine.Severity;
import io.github.ismailsanan.secheaderscout.engine.UrlClassifier;
import io.github.ismailsanan.secheaderscout.model.HeaderProfile;
import io.github.ismailsanan.secheaderscout.model.ScanResult;
import io.github.ismailsanan.secheaderscout.util.UrlPaths;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.TreeSet;

/**
 * Groups Deep Scan results into {@link HeaderProfile}s: endpoints of one host, under the
 * same path group ({@code /api/*}), with exactly the same issues. Groups containing
 * sensitive endpoints (logout, login, payment, admin) come first.
 * Pure function of its input; no Burp or Swing dependency.
 */
public final class ProfileGrouper {

    /** One analysed endpoint and the host it was captured for. */
    public record Analysed(String host, ScanResult result) {
    }

    private ProfileGrouper() {
    }

    public static List<HeaderProfile> group(List<Analysed> analysed) {
        Map<List<Object>, List<Analysed>> groups = new LinkedHashMap<>();
        for (Analysed a : analysed) {
            List<Object> key = List.of(a.host().toLowerCase(Locale.ROOT), pathGroup(a.result().url()),
                    signature(a.result()));
            groups.computeIfAbsent(key, k -> new ArrayList<>()).add(a);
        }
        List<HeaderProfile> profiles = new ArrayList<>();
        for (List<Analysed> members : groups.values()) {
            profiles.add(build(members));
        }
        profiles.sort(Comparator
                .comparing((HeaderProfile p) -> p.sensitive() ? p.sensitivity() : UrlClassifier.UrlType.NORMAL)
                .thenComparing(p -> -p.worstSeverity().map(Enum::ordinal).orElse(-1))
                .thenComparing(p -> -p.size())
                .thenComparing(HeaderProfile::host)
                .thenComparing(HeaderProfile::path));
        return List.copyOf(profiles);
    }

    /**
     * Issue names, not values: values such as CSP nonces differ per response and would split
     * otherwise identical endpoints into thousands of groups.
     */
    static List<String> signature(ScanResult r) {
        if (r.hasError()) {
            return List.of("(not analysed: error)");
        }
        TreeSet<String> names = new TreeSet<>();
        for (Finding f : r.findings()) {
            names.add(f.issueName());
        }
        if (r.evaluationIncomplete()) {
            names.add("(evaluation incomplete)");
        }
        return List.copyOf(names);
    }

    /**
     * The first path segment: {@code /api/v1/users} → {@code /api/*}, {@code /login} → {@code /login},
     * {@code /} → {@code /}. Query strings are ignored.
     */
    static String pathGroup(String url) {
        String path = UrlPaths.path(url);
        int next = path.indexOf('/', 1);
        if (next < 0) {
            return path; // "/" or a single segment such as "/login"
        }
        return path.substring(0, next) + "/*";
    }

    private static HeaderProfile build(List<Analysed> members) {
        Analysed first = members.get(0);
        List<String> urls = members.stream().map(a -> a.result().url()).toList();
        // enum order is priority order: the smallest type is the most sensitive
        UrlClassifier.UrlType sensitivity = members.stream().map(a -> a.result().urlType())
                .min(Comparator.naturalOrder()).orElse(UrlClassifier.UrlType.NORMAL);
        Optional<Severity> worst = members.stream().flatMap(a -> a.result().findings().stream())
                .map(Finding::severity).max(Comparator.naturalOrder());
        // all members on one path (e.g. /search with different queries): show the path itself
        List<String> paths = urls.stream().map(UrlPaths::path).distinct().toList();
        String path = paths.size() == 1 ? paths.get(0) : pathGroup(urls.get(0));
        return new HeaderProfile(first.host(), path, signature(first.result()), first.result(), urls,
                sensitivity, worst);
    }
}
