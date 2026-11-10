package io.github.ismailsanan.secheaderscout.headers;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Small, dependency-free helpers for tokenising header values. Parsing lives
 * here; deciding whether a parsed value is secure lives in the rules.
 */
public final class HeaderSyntax {

    /** RFC 9110 token characters. */
    private static final Pattern TOKEN = Pattern.compile("[!#$%&'*+.^_`|~0-9A-Za-z-]+");

    private HeaderSyntax() {
    }

    public static boolean isToken(String s) {
        return s != null && TOKEN.matcher(s).matches();
    }

    /**
     * Splits {@code value} on {@code separator}, ignoring separators inside
     * double-quoted strings or parentheses. Members are trimmed and empty members
     * dropped.
     */
    public static List<String> splitTopLevel(String value, char separator) {
        List<String> parts = new ArrayList<>();
        for (String part : splitTopLevelKeepEmpty(value, separator)) {
            if (!part.isEmpty()) {
                parts.add(part);
            }
        }
        return parts;
    }

    /**
     * Like {@link #splitTopLevel} but keeps empty members, which structured-field
     * parsing must reject: {@code "a,"} gives {@code ["a", ""]}.
     */
    public static List<String> splitTopLevelKeepEmpty(String value, char separator) {
        List<String> parts = new ArrayList<>();
        if (value == null) {
            return parts;
        }
        StringBuilder current = new StringBuilder();
        boolean inQuotes = false;
        int depth = 0;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (inQuotes) {
                current.append(c);
                if (c == '\\' && i + 1 < value.length()) {
                    current.append(value.charAt(++i));
                } else if (c == '"') {
                    inQuotes = false;
                }
                continue;
            }
            if (c == '"') {
                inQuotes = true;
            } else if (c == '(') {
                depth++;
            } else if (c == ')' && depth > 0) {
                depth--;
            } else if (c == separator && depth == 0) {
                parts.add(current.toString().trim());
                current.setLength(0);
                continue;
            }
            current.append(c);
        }
        parts.add(current.toString().trim());
        return parts;
    }

    /**
     * Returns the bare item of a structured-field item, i.e. the part before any
     * {@code ;param}, trimmed and lower-cased. {@code "same-origin; report-to=x"}
     * becomes {@code "same-origin"}.
     */
    public static String itemToken(String value) {
        if (value == null) {
            return "";
        }
        int semi = value.indexOf(';');
        String bare = semi >= 0 ? value.substring(0, semi) : value;
        return bare.trim().toLowerCase(Locale.ROOT);
    }

    /**
     * Parses {@code name value; name value} style directive lists (CSP, HSTS).
     * Directive names are lower-cased; the value is everything after the first
     * whitespace (or after {@code =} for HSTS-style {@code name=value}).
     * Duplicate names are reported via {@link Directives#duplicates()} and only
     * the first occurrence is kept in {@link Directives#values()}. That matches
     * CSP, where later duplicates are ignored, but not HSTS: RFC 6797 section 6.1
     * makes a header with a duplicated directive invalid as a whole, so HSTS
     * callers must check {@code duplicates()} before using the values.
     */
    public static Directives parseDirectives(String value, boolean equalsSeparated) {
        Map<String, String> directives = new LinkedHashMap<>();
        List<String> duplicates = new ArrayList<>();
        for (String part : splitTopLevel(value, ';')) {
            String name;
            String arg;
            int sep = equalsSeparated ? part.indexOf('=') : indexOfWhitespace(part);
            if (sep < 0) {
                name = part;
                arg = "";
            } else {
                name = part.substring(0, sep);
                arg = part.substring(sep + 1).trim();
            }
            name = name.trim().toLowerCase(Locale.ROOT);
            if (name.isEmpty()) {
                continue;
            }
            if (directives.containsKey(name)) {
                duplicates.add(name);
            } else {
                directives.put(name, arg);
            }
        }
        return new Directives(directives, duplicates);
    }

    private static int indexOfWhitespace(String s) {
        for (int i = 0; i < s.length(); i++) {
            if (Character.isWhitespace(s.charAt(i))) {
                return i;
            }
        }
        return -1;
    }

    /** Removes surrounding double quotes, or returns {@code null} if not quoted. */
    public static String unquote(String s) {
        String t = s.trim();
        if (t.length() >= 2 && t.charAt(0) == '"' && t.charAt(t.length() - 1) == '"') {
            return t.substring(1, t.length() - 1);
        }
        return null;
    }

    /** Parsed directive list. */
    public record Directives(Map<String, String> values, List<String> duplicates) {
        public boolean has(String name) {
            return values.containsKey(name);
        }

        public String get(String name) {
            return values.get(name);
        }
    }
}
