package io.github.ismailsanan.secheaderscout.headers;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/**
 * Immutable, case-insensitive view of the header fields of one HTTP message.
 *
 * <p>Unlike a simple {@code Map<String,String>}, this keeps every field line in
 * arrival order, so rules can detect duplicate headers and evaluate
 * comma-separated list headers the way browsers do (RFC 9110 section 5.3:
 * repeated list-based fields are equivalent to one comma-joined field).</p>
 *
 * <p>This class has no Burp dependency so the evaluation engine can be unit
 * tested in isolation.</p>
 */
public final class ResponseHeaders {

    private static final ResponseHeaders EMPTY = new ResponseHeaders(Map.of());

    /** lower-cased header name -> raw values in arrival order */
    private final Map<String, List<String>> fields;

    private ResponseHeaders(Map<String, List<String>> fields) {
        this.fields = fields;
    }

    public static ResponseHeaders empty() {
        return EMPTY;
    }

    /** Builds headers from name/value pairs; names are matched case-insensitively. */
    public static ResponseHeaders of(List<? extends Map.Entry<String, String>> nameValuePairs) {
        Map<String, List<String>> map = new LinkedHashMap<>();
        for (Map.Entry<String, String> entry : nameValuePairs) {
            if (entry.getKey() == null) {
                continue;
            }
            String name = normalize(entry.getKey());
            if (name.isEmpty()) {
                continue;
            }
            String value = entry.getValue() == null ? "" : entry.getValue().trim();
            map.computeIfAbsent(name, k -> new ArrayList<>()).add(value);
        }
        Map<String, List<String>> frozen = new LinkedHashMap<>();
        map.forEach((k, v) -> frozen.put(k, List.copyOf(v)));
        return new ResponseHeaders(Collections.unmodifiableMap(frozen));
    }

    /** Convenience factory: {@code of("Name", "value", "Other", "value")}. */
    public static ResponseHeaders of(String... alternatingNamesAndValues) {
        if (alternatingNamesAndValues.length % 2 != 0) {
            throw new IllegalArgumentException("Expected name/value pairs");
        }
        List<Map.Entry<String, String>> pairs = new ArrayList<>();
        for (int i = 0; i < alternatingNamesAndValues.length; i += 2) {
            pairs.add(Map.entry(alternatingNamesAndValues[i], alternatingNamesAndValues[i + 1]));
        }
        return of(pairs);
    }

    public static String normalize(String headerName) {
        return headerName.trim().toLowerCase(Locale.ROOT);
    }

    public boolean has(String name) {
        return fields.containsKey(normalize(name));
    }

    /** Every field line for {@code name}, in arrival order (empty if absent). */
    public List<String> values(String name) {
        return fields.getOrDefault(normalize(name), List.of());
    }

    public Optional<String> first(String name) {
        List<String> values = values(name);
        return values.isEmpty() ? Optional.empty() : Optional.of(values.get(0));
    }

    /** Number of separate field lines with this name. */
    public int count(String name) {
        return values(name).size();
    }

    /**
     * All field lines joined with {@code ", "} as defined by RFC 9110 for
     * list-based fields. Returns {@code null} when the header is absent.
     */
    public String combined(String name) {
        List<String> values = values(name);
        return values.isEmpty() ? null : String.join(", ", values);
    }

    /**
     * Comma-separated members across all field lines, trimmed, empties removed.
     * Commas inside double quotes or parentheses are not treated as separators.
     */
    public List<String> listMembers(String name) {
        List<String> members = new ArrayList<>();
        for (String value : values(name)) {
            members.addAll(HeaderSyntax.splitTopLevel(value, ','));
        }
        return members;
    }

    /** Lower-cased names of all headers present. */
    public java.util.Set<String> names() {
        return fields.keySet();
    }
}
