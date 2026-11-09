package io.github.ismailsanan.secheaderscout.engine;

import io.github.ismailsanan.secheaderscout.engine.UrlClassifier.UrlType;
import io.github.ismailsanan.secheaderscout.util.UrlPaths;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.function.Consumer;

/**
 * The patterns that decide an endpoint's type (logout, login, admin, payment, API or not
 * sensitive): built-in keyword patterns plus the user's own. Immutable; every change returns a
 * new instance, so it can be shared with Burp's scan threads without locking.
 *
 * <p>Pattern syntax (case-insensitive, query strings of the analysed URL are ignored unless the
 * pattern has one):</p>
 * <ul>
 *     <li>{@code /auth/end}: exactly that path, on any host</li>
 *     <li>{@code /auth/*}: every path starting with {@code /auth/}</li>
 *     <li>{@code *}{@code /logout*}: {@code /logout} anywhere in the path (the built-in keywords)</li>
 *     <li>{@code *}{@code /api}: paths ending with {@code /api}</li>
 *     <li>{@code https://app.example.com/auth?action=logout}: that host only; a query in the pattern
 *         must be part of the URL's query</li>
 * </ul>
 * Matching order: enabled custom rules, most specific first (host-specific, then exact, prefix,
 * suffix, contains, then longer); then enabled built-in rules in their fixed order.
 */
public final class EndpointRules {

    static final int MAX_PATTERN_LENGTH = 2048;
    static final int MAX_CUSTOM_RULES = 500;
    private static final int MAX_SERIALIZED_LENGTH = 512 * 1024;

    /** How a rule's path is compared with the analysed path. Declared from most to least specific. */
    public enum Match { EXACT, PREFIX, SUFFIX, CONTAINS }

    /**
     * One rule. {@code host} and {@code query} are {@code null} when not constrained.
     *
     * @param pattern the normalised pattern as the user typed it (the rule's identity)
     * @param builtIn {@code true} for the shipped keyword patterns (can be disabled, not removed)
     */
    public record Rule(String pattern, UrlType type, String host, String path, Match match, String query,
                       boolean builtIn, boolean enabled) {

        boolean matches(String urlHost, String urlPath, String urlQuery) {
            if (!enabled || (host != null && !host.equals(urlHost))) {
                return false;
            }
            boolean pathMatches = switch (match) {
                case EXACT -> urlPath.equals(path);
                case PREFIX -> urlPath.startsWith(path);
                case SUFFIX -> urlPath.endsWith(path);
                case CONTAINS -> urlPath.contains(path);
            };
            return pathMatches && (query == null || urlQuery.contains(query));
        }

        Rule withEnabled(boolean value) {
            return new Rule(pattern, type, host, path, match, query, builtIn, value);
        }
    }

    private static final List<Rule> BUILT_INS = builtIns();

    /** Built-in patterns only, all enabled: the behaviour before the user changes anything. */
    public static final EndpointRules DEFAULT = new EndpointRules(BUILT_INS);

    /** All rules in matching order. */
    private final List<Rule> rules;
    /** Whether any enabled rule looks at the host / the query: if not, typeOf skips extracting them. */
    private final boolean needsHost;
    private final boolean needsQuery;

    private EndpointRules(List<Rule> all) {
        List<Rule> custom = new ArrayList<>(all.stream().filter(r -> !r.builtIn()).toList());
        custom.sort(Comparator.comparing((Rule r) -> r.host() == null)
                .thenComparing(Rule::match)
                .thenComparing(r -> -(r.path().length() + (r.query() == null ? 0 : r.query().length()))));
        List<Rule> ordered = new ArrayList<>(custom);
        ordered.addAll(all.stream().filter(Rule::builtIn).toList()); // built-ins keep their fixed order
        this.rules = List.copyOf(ordered);
        this.needsHost = rules.stream().anyMatch(r -> r.enabled() && r.host() != null);
        this.needsQuery = rules.stream().anyMatch(r -> r.enabled() && r.query() != null);
    }

    private static List<Rule> builtIns() {
        List<Rule> out = new ArrayList<>();
        // order matters: the first matching keyword wins (e.g. /api/logout is a logout)
        addBuiltIns(out, UrlType.LOGOUT, "*/logout*", "*/signout*", "*/sign-out*", "*/log-out*", "*/logoff*");
        addBuiltIns(out, UrlType.LOGIN, "*/login*", "*/signin*", "*/sign-in*", "*/logon*");
        addBuiltIns(out, UrlType.ADMIN, "*/admin*", "*/dashboard*", "*/management*");
        addBuiltIns(out, UrlType.API, "*/api/*", "*/api", "*/v1/*", "*/v2/*", "*/v3/*", "*/graphql*");
        addBuiltIns(out, UrlType.PAYMENT, "*/payment*", "*/checkout*", "*/billing*");
        return List.copyOf(out);
    }

    private static void addBuiltIns(List<Rule> out, UrlType type, String... patterns) {
        for (String p : patterns) {
            Rule r = parse(p, type);
            out.add(new Rule(r.pattern(), type, r.host(), r.path(), r.match(), r.query(), true, true));
        }
    }

    /** All rules in matching order (custom first). */
    public List<Rule> rules() {
        return rules;
    }

    /** {@code true} when only the built-in patterns are active, all enabled: nothing to save. */
    public boolean isDefault() {
        return rules.stream().allMatch(r -> r.builtIn() && r.enabled());
    }

    public long customCount() {
        return rules.stream().filter(r -> !r.builtIn()).count();
    }

    /** The type of {@code url} according to the first matching enabled rule. */
    public Optional<UrlType> typeOf(String url) {
        if (url == null) {
            return Optional.empty();
        }
        String host = needsHost ? UrlPaths.host(url).toLowerCase(Locale.ROOT) : "";
        String path = UrlPaths.path(url).toLowerCase(Locale.ROOT);
        String query = needsQuery ? UrlPaths.query(url).toLowerCase(Locale.ROOT) : "";
        for (Rule r : rules) {
            if (r.matches(host, path, query)) {
                return Optional.of(r.type());
            }
        }
        return Optional.empty();
    }

    /** Adds (or replaces) the custom rule for {@code pattern}, enabled. */
    public EndpointRules with(String pattern, UrlType type) {
        Rule rule = parse(pattern, type);
        if (customCount() >= MAX_CUSTOM_RULES && find(rule.pattern(), false).isEmpty()) {
            throw new IllegalArgumentException("At most " + MAX_CUSTOM_RULES + " custom patterns are supported.");
        }
        List<Rule> next = new ArrayList<>(withoutCustom(rule.pattern()).rules);
        next.add(rule);
        return new EndpointRules(next);
    }

    /** Removes the custom rule for {@code pattern}, if any. Built-in rules can only be disabled. */
    public EndpointRules withoutCustom(String pattern) {
        String key = normalise(pattern);
        return new EndpointRules(rules.stream().filter(r -> r.builtIn() || !r.pattern().equals(key)).toList());
    }

    /** Enables or disables the rule identified by {@code pattern} and {@code builtIn}. */
    public EndpointRules withEnabled(String pattern, boolean builtIn, boolean enabled) {
        String key = normalise(pattern);
        return new EndpointRules(rules.stream()
                .map(r -> r.builtIn() == builtIn && r.pattern().equals(key) ? r.withEnabled(enabled) : r)
                .toList());
    }

    private Optional<Rule> find(String normalisedPattern, boolean builtIn) {
        return rules.stream().filter(r -> r.builtIn() == builtIn && r.pattern().equals(normalisedPattern))
                .findFirst();
    }

    /**
     * Parses a custom pattern.
     *
     * @throws IllegalArgumentException with a user-readable message if the pattern is not usable
     */
    public static Rule parse(String pattern, UrlType type) {
        if (type == null) {
            throw new IllegalArgumentException("Choose an endpoint type.");
        }
        String p = normalise(pattern);
        if (p.isEmpty()) {
            throw new IllegalArgumentException("Enter a path (e.g. /auth/end or /auth/*) or a full URL.");
        }
        if (p.length() > MAX_PATTERN_LENGTH) {
            throw new IllegalArgumentException("The pattern is too long.");
        }
        if (p.chars().anyMatch(c -> c <= ' ' || c == 0x7f)) {
            throw new IllegalArgumentException("The pattern must not contain spaces or control characters.");
        }
        String host = null;
        String rest = p;
        if (p.startsWith("http://") || p.startsWith("https://")) {
            host = UrlPaths.host(p);
            if (host.isEmpty()) {
                throw new IllegalArgumentException("The URL has no host.");
            }
            rest = p.substring(UrlPaths.origin(p).length());
            if (rest.isEmpty() || rest.startsWith("?")) {
                rest = "/" + rest;
            }
        }
        String query = null;
        int q = rest.indexOf('?');
        if (q >= 0) {
            query = rest.substring(q + 1).isEmpty() ? null : rest.substring(q + 1);
            rest = rest.substring(0, q);
        }
        boolean leading = rest.startsWith("*");
        boolean trailing = rest.length() > 1 && rest.endsWith("*");
        String path = rest.substring(leading ? 1 : 0, rest.length() - (trailing ? 1 : 0));
        if (!path.startsWith("/")) {
            throw new IllegalArgumentException("Start with / (e.g. /auth/end), */ for \"anywhere in the path\" "
                    + "(e.g. */logout*), or give a full http(s):// URL.");
        }
        if (path.contains("*")) {
            throw new IllegalArgumentException("* is only allowed at the start or end (e.g. /auth/* or */logout*).");
        }
        Match match = leading && trailing ? Match.CONTAINS : leading ? Match.SUFFIX
                : trailing ? Match.PREFIX : Match.EXACT;
        return new Rule(p, type, host, path, match, query, false, true);
    }

    // ---- persistence ----------------------------------------------------------------------------

    /**
     * One line per custom rule ({@code C<TAB>enabled<TAB>TYPE<TAB>pattern}) and per disabled
     * built-in ({@code B<TAB>0<TAB><TAB>pattern}). Patterns never contain tabs or line breaks.
     */
    public String serialize() {
        StringBuilder sb = new StringBuilder();
        for (Rule r : rules) {
            if (!r.builtIn()) {
                sb.append("C\t").append(r.enabled() ? '1' : '0').append('\t').append(r.type().name()).append('\t')
                        .append(r.pattern()).append('\n');
            } else if (!r.enabled()) {
                sb.append("B\t0\t\t").append(r.pattern()).append('\n');
            }
        }
        return sb.toString();
    }

    /**
     * Rebuilds rules from {@link #serialize()} output, starting from {@link #DEFAULT}. Saved data
     * comes from the project file, so it is treated as untrusted: invalid lines are skipped and
     * reported through {@code warn}, and the size is bounded.
     */
    public static EndpointRules deserialize(String data, Consumer<String> warn) {
        EndpointRules result = DEFAULT;
        if (data == null || data.isEmpty()) {
            return result;
        }
        if (data.length() > MAX_SERIALIZED_LENGTH) {
            warn.accept("Saved endpoint types are too large; using the built-in patterns only.");
            return result;
        }
        int skipped = 0;
        for (String line : data.split("\n")) {
            if (line.isBlank()) {
                continue;
            }
            String[] f = line.split("\t", -1);
            try {
                if (f.length == 4 && f[0].equals("C") && (f[1].equals("0") || f[1].equals("1"))) {
                    result = result.with(f[3], UrlType.valueOf(f[2]));
                    if (f[1].equals("0")) {
                        result = result.withEnabled(f[3], false, false);
                    }
                } else if (f.length == 4 && f[0].equals("B") && result.find(normalise(f[3]), true).isPresent()) {
                    result = result.withEnabled(f[3], true, false);
                } else {
                    skipped++;
                }
            } catch (IllegalArgumentException e) {
                skipped++;
            }
        }
        if (skipped > 0) {
            warn.accept("Skipped " + skipped + " unreadable saved endpoint type(s).");
        }
        return result;
    }

    private static String normalise(String pattern) {
        String p = pattern == null ? "" : pattern.strip().toLowerCase(Locale.ROOT);
        int fragment = p.indexOf('#');
        return fragment >= 0 ? p.substring(0, fragment) : p;
    }

    @Override
    public String toString() {
        return rules.stream().filter(r -> !r.builtIn() || !r.enabled())
                .map(r -> r.pattern() + "=" + r.type() + (r.enabled() ? "" : " (off)")).toList().toString();
    }
}
