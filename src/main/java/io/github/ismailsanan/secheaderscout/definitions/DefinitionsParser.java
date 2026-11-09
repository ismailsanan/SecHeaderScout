package io.github.ismailsanan.secheaderscout.definitions;

import io.github.ismailsanan.secheaderscout.util.MiniJson;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Parses and validates the OWASP {@code headers_add.json} format. Validation is
 * strict, because remotely downloaded content must not be able to inject
 * arbitrary data into the extension's checks or reports.
 */
public final class DefinitionsParser {

    static final int MAX_CHARS = 256 * 1024;
    static final int MIN_HEADERS = 5;
    static final int MAX_HEADERS = 64;
    private static final int MAX_VALUE_LENGTH = 4096;
    private static final Pattern HEADER_NAME = Pattern.compile("[A-Za-z][A-Za-z0-9-]{1,63}");
    private static final Pattern TIMESTAMP = Pattern.compile("[0-9: T-]{10,32}");

    private DefinitionsParser() {
    }

    /** Thrown when content is not a valid OWASP definitions document. */
    public static final class InvalidDefinitionsException extends Exception {
        private static final long serialVersionUID = 1L;

        public InvalidDefinitionsException(String message) {
            super(message);
        }
    }

    public static OwaspDefinitions parse(String json, OwaspDefinitions.Source source, String revision)
            throws InvalidDefinitionsException {
        if (json == null || json.isBlank()) {
            throw new InvalidDefinitionsException("empty document");
        }
        if (json.length() > MAX_CHARS) {
            throw new InvalidDefinitionsException("document larger than " + MAX_CHARS + " characters");
        }
        Object root;
        try {
            root = MiniJson.parse(json);
        } catch (IllegalArgumentException e) {
            throw new InvalidDefinitionsException(e.getMessage());
        }
        if (!(root instanceof Map<?, ?> obj)) {
            throw new InvalidDefinitionsException("top-level value is not an object");
        }
        Object lastUpdate = obj.get("last_update_utc");
        if (!(lastUpdate instanceof String ts) || !TIMESTAMP.matcher(ts).matches()) {
            throw new InvalidDefinitionsException("missing or malformed last_update_utc");
        }
        if (!(obj.get("headers") instanceof List<?> list)) {
            throw new InvalidDefinitionsException("missing 'headers' array");
        }
        if (list.size() < MIN_HEADERS || list.size() > MAX_HEADERS) {
            throw new InvalidDefinitionsException("unexpected number of headers: " + list.size());
        }
        List<HeaderDefinition> headers = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        for (Object item : list) {
            if (!(item instanceof Map<?, ?> entry)) {
                throw new InvalidDefinitionsException("header entry is not an object");
            }
            if (!(entry.get("name") instanceof String name) || !HEADER_NAME.matcher(name).matches()) {
                throw new InvalidDefinitionsException("invalid header name: " + entry.get("name"));
            }
            if (!(entry.get("value") instanceof String value) || value.length() > MAX_VALUE_LENGTH
                    || value.chars().anyMatch(c -> c < 0x20 || c == 0x7f)) {
                throw new InvalidDefinitionsException("invalid value for header " + name);
            }
            if (!seen.add(name.toLowerCase(Locale.ROOT))) {
                throw new InvalidDefinitionsException("duplicate header " + name);
            }
            headers.add(new HeaderDefinition(name, value));
        }
        return new OwaspDefinitions(source, revision, ts, headers);
    }
}
