package io.github.ismailsanan.secheaderscout.headers;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Parses a Permissions-Policy value as an RFC 8941 structured-field dictionary
 * and then interprets each member as an allowlist, as the Permissions Policy
 * specification does.
 *
 * <p>Two kinds of problem are kept apart:</p>
 * <ul>
 *   <li><b>Fatal syntax errors</b> ({@link Result#error()}): the value is not a
 *   valid RFC 8941 dictionary, e.g. legacy Feature-Policy syntax
 *   ({@code camera 'none'}), single-quoted {@code 'self'}, whitespace around
 *   {@code =}, empty members or an unterminated inner list. Browsers then treat
 *   the header as absent, so the whole policy is ignored.</li>
 *   <li><b>Unrecognised allowlist entries</b> ({@link Result#unrecognisedEntries()}):
 *   the dictionary is valid but a feature's value contains something that is
 *   not {@code *}, {@code self}, {@code src} or an origin string, e.g. a bare
 *   key ({@code camera}, i.e. boolean true), a token such as {@code none}, or
 *   parameters on an inner-list item. Browsers ignore such entries for that
 *   feature only; the rest of the policy still applies.</li>
 * </ul>
 */
public final class PermissionsPolicyParser {

    private static final String FEATURE_POLICY_HINT = "single-quoted values such as 'self' or 'none' are "
            + "Feature-Policy syntax and are not valid in Permissions-Policy";

    /** A string allowlist entry must be a URL with a scheme and an authority to yield an origin. */
    private static final Pattern ORIGIN_LIKE = Pattern.compile("[A-Za-z][A-Za-z0-9+.-]*://[^\\s/?#]+.*");

    private PermissionsPolicyParser() {
    }

    /** Allowlist of one feature; contains only recognised entries. */
    public record Allowlist(List<String> members) {
        /** {@code feature=*} or {@code feature=(*)}. */
        public boolean allowsAllOrigins() {
            return members.contains("*");
        }

        public boolean isEmpty() {
            return members.isEmpty();
        }
    }

    /**
     * Result of parsing.
     *
     * @param features            feature name to allowlist; when a feature repeats, the last one wins (RFC 8941)
     * @param duplicates          features that appeared more than once
     * @param error               non-null when the value is not a valid structured-field dictionary, so
     *                            browsers ignore the whole header
     * @param unrecognisedEntries per feature, descriptions of the allowlist entries browsers ignore for that
     *                            feature only (raw entry text, or a note such as a bare key)
     *                            (empty when {@code error} is set)
     */
    public record Result(Map<String, Allowlist> features, List<String> duplicates, String error,
                         Map<String, List<String>> unrecognisedEntries) {
        /** False only for a fatal syntax error that makes browsers drop the whole header. */
        public boolean valid() {
            return error == null;
        }

        public boolean hasUnrecognisedEntries() {
            return !unrecognisedEntries.isEmpty();
        }
    }

    public static Result parse(String value) {
        if (value == null || trimOws(value).isEmpty()) {
            return fatal("empty value");
        }
        try {
            return new Parser(trimOws(value)).parseDictionary();
        } catch (SyntaxError e) {
            String message = e.getMessage();
            if (value.indexOf('\'') >= 0 && !message.contains(FEATURE_POLICY_HINT)) {
                message += "; " + FEATURE_POLICY_HINT;
            }
            return fatal(message);
        }
    }

    private static Result fatal(String error) {
        return new Result(Map.of(), List.of(), error, Map.of());
    }

    private static String trimOws(String s) {
        int start = 0;
        int end = s.length();
        while (start < end && isOws(s.charAt(start))) {
            start++;
        }
        while (end > start && isOws(s.charAt(end - 1))) {
            end--;
        }
        return s.substring(start, end);
    }

    private static boolean isOws(char c) {
        return c == ' ' || c == '\t';
    }

    private static final class SyntaxError extends Exception {
        private static final long serialVersionUID = 1L;

        SyntaxError(String message) {
            super(message, null, false, false);
        }
    }

    private enum Kind { TOKEN, STRING, NUMBER, BYTES, BOOLEAN }

    private record BareItem(Kind kind, String value, String raw) {
    }

    /** Recursive-descent parser following RFC 8941 section 4.2. */
    private static final class Parser {
        private final String s;
        private int pos;

        Parser(String s) {
            this.s = s;
        }

        Result parseDictionary() throws SyntaxError {
            Map<String, Allowlist> features = new LinkedHashMap<>();
            List<String> duplicates = new ArrayList<>();
            Map<String, List<String>> unrecognised = new LinkedHashMap<>();
            while (true) {
                if (atEnd() || peek() == ',') {
                    throw new SyntaxError("empty dictionary member (e.g. a leading, trailing or doubled comma)");
                }
                String key = parseKey("feature name");
                List<String> issues = new ArrayList<>();
                Allowlist allowlist;
                if (!atEnd() && peek() == '=') {
                    pos++;
                    if (atEnd()) {
                        throw new SyntaxError("feature '" + key + "' has '=' but no value");
                    }
                    if (isOws(peek())) {
                        throw new SyntaxError("whitespace around '=' after feature '" + key + "'");
                    }
                    allowlist = peek() == '(' ? parseInnerList(key, issues) : parseSingleItem(key, issues);
                } else {
                    int look = pos;
                    while (look < s.length() && isOws(s.charAt(look))) {
                        look++;
                    }
                    if (look > pos && look < s.length() && s.charAt(look) == '=') {
                        throw new SyntaxError("whitespace around '=' after feature '" + key + "'");
                    }
                    // a bare key is boolean true in RFC 8941: syntactically valid, but not an allowlist
                    issues.add("(bare key without an allowlist)");
                    allowlist = new Allowlist(List.of());
                }
                parseParameters(key); // member parameters such as report-to are allowed and ignored here
                if (features.containsKey(key)) {
                    duplicates.add(key);
                }
                features.put(key, allowlist);
                if (issues.isEmpty()) {
                    unrecognised.remove(key); // a later declaration replaces the earlier one
                } else {
                    unrecognised.put(key, List.copyOf(issues));
                }
                skipOws();
                if (atEnd()) {
                    break;
                }
                if (peek() != ',') {
                    throw new SyntaxError("unexpected character '" + peek() + "' after feature '" + key + "'");
                }
                pos++;
                skipOws();
            }
            return new Result(features, duplicates, null, unrecognised);
        }

        private Allowlist parseInnerList(String key, List<String> issues) throws SyntaxError {
            pos++; // '('
            List<String> members = new ArrayList<>();
            while (!atEnd()) {
                while (!atEnd() && peek() == ' ') {
                    pos++;
                }
                if (atEnd()) {
                    break;
                }
                if (peek() == ')') {
                    pos++;
                    return new Allowlist(List.copyOf(members));
                }
                int start = pos;
                BareItem item = parseBareItem(key);
                int params = parseParameters(key);
                classify(item, members, issues);
                if (params > 0) {
                    // browsers ignore parameters on allowlist items; Permissions Policy defines none
                    issues.add(s.substring(start, pos) + " (parameters on an allowlist item)");
                }
                if (!atEnd() && peek() != ' ' && peek() != ')') {
                    throw new SyntaxError("feature '" + key + "': inner-list items must be separated by spaces, "
                            + "found '" + peek() + "'");
                }
            }
            throw new SyntaxError("feature '" + key + "': unterminated inner list");
        }

        private Allowlist parseSingleItem(String key, List<String> issues) throws SyntaxError {
            List<String> members = new ArrayList<>();
            classify(parseBareItem(key), members, issues);
            return new Allowlist(List.copyOf(members));
        }

        private static void classify(BareItem item, List<String> members, List<String> issues) {
            if (item.kind() == Kind.TOKEN
                    && (item.value().equals("*") || item.value().equals("self") || item.value().equals("src"))) {
                members.add(item.value());
            } else if (item.kind() == Kind.STRING && ORIGIN_LIKE.matcher(item.value()).matches()) {
                members.add(item.value());
            } else {
                issues.add(item.raw());
            }
        }

        /** Parses {@code ;key[=bare-item]} parameters and returns how many there were. */
        private int parseParameters(String context) throws SyntaxError {
            int count = 0;
            while (!atEnd() && peek() == ';') {
                pos++;
                while (!atEnd() && peek() == ' ') {
                    pos++;
                }
                parseKey("parameter name in '" + context + "'");
                if (!atEnd() && peek() == '=') {
                    pos++;
                    parseBareItem(context);
                }
                count++;
            }
            return count;
        }

        private String parseKey(String what) throws SyntaxError {
            int start = pos;
            if (atEnd() || !(isLcAlpha(peek()) || peek() == '*')) {
                throw new SyntaxError("invalid " + what + " '" + runFrom(start) + "'");
            }
            while (!atEnd() && isKeyChar(peek())) {
                pos++;
            }
            if (!atEnd() && !isOws(peek()) && "=;,()".indexOf(peek()) < 0) {
                throw new SyntaxError("invalid " + what + " '" + runFrom(start) + "'");
            }
            return s.substring(start, pos);
        }

        private BareItem parseBareItem(String key) throws SyntaxError {
            if (atEnd()) {
                throw new SyntaxError("feature '" + key + "': missing value");
            }
            int start = pos;
            char c = peek();
            if (c == '"') {
                String v = parseString(key);
                return new BareItem(Kind.STRING, v, s.substring(start, pos));
            }
            if (c == '*' || isAlpha(c)) {
                pos++;
                while (!atEnd() && isTokenChar(peek())) {
                    pos++;
                }
                String t = s.substring(start, pos);
                return new BareItem(Kind.TOKEN, t, t);
            }
            if (c == '-' || isDigit(c)) {
                pos++;
                while (!atEnd() && (isDigit(peek()) || peek() == '.')) {
                    pos++;
                }
                String n = s.substring(start, pos);
                if (!n.matches("-?[0-9]{1,15}") && !n.matches("-?[0-9]{1,12}\\.[0-9]{1,3}")) {
                    throw new SyntaxError("feature '" + key + "': invalid number '" + n + "'");
                }
                return new BareItem(Kind.NUMBER, n, n);
            }
            if (c == ':') {
                pos++;
                while (!atEnd() && peek() != ':') {
                    char b = peek();
                    if (!(isAlpha(b) || isDigit(b) || b == '+' || b == '/' || b == '=')) {
                        throw new SyntaxError("feature '" + key + "': invalid byte sequence");
                    }
                    pos++;
                }
                if (atEnd()) {
                    throw new SyntaxError("feature '" + key + "': unterminated byte sequence");
                }
                pos++;
                return new BareItem(Kind.BYTES, s.substring(start, pos), s.substring(start, pos));
            }
            if (c == '?') {
                if (pos + 1 < s.length() && (s.charAt(pos + 1) == '0' || s.charAt(pos + 1) == '1')) {
                    pos += 2;
                    return new BareItem(Kind.BOOLEAN, s.substring(start, pos), s.substring(start, pos));
                }
                throw new SyntaxError("feature '" + key + "': invalid boolean");
            }
            if (c == '\'') {
                throw new SyntaxError("feature '" + key + "': " + FEATURE_POLICY_HINT);
            }
            throw new SyntaxError("feature '" + key + "': unexpected character '" + c + "'");
        }

        private String parseString(String key) throws SyntaxError {
            pos++; // opening quote
            StringBuilder out = new StringBuilder();
            while (!atEnd()) {
                char c = s.charAt(pos++);
                if (c == '\\') {
                    if (atEnd() || (peek() != '"' && peek() != '\\')) {
                        throw new SyntaxError("feature '" + key + "': invalid escape in string");
                    }
                    out.append(s.charAt(pos++));
                } else if (c == '"') {
                    return out.toString();
                } else if (c < 0x20 || c > 0x7e) {
                    throw new SyntaxError("feature '" + key + "': invalid character in string");
                } else {
                    out.append(c);
                }
            }
            throw new SyntaxError("feature '" + key + "': unterminated string");
        }

        private String runFrom(int start) {
            int end = start;
            while (end < s.length() && !isOws(s.charAt(end)) && "=;,".indexOf(s.charAt(end)) < 0) {
                end++;
            }
            return s.substring(start, end);
        }

        private void skipOws() {
            while (!atEnd() && isOws(peek())) {
                pos++;
            }
        }

        private boolean atEnd() {
            return pos >= s.length();
        }

        private char peek() {
            return s.charAt(pos);
        }

        private static boolean isLcAlpha(char c) {
            return c >= 'a' && c <= 'z';
        }

        private static boolean isAlpha(char c) {
            return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
        }

        private static boolean isDigit(char c) {
            return c >= '0' && c <= '9';
        }

        private static boolean isKeyChar(char c) {
            return isLcAlpha(c) || isDigit(c) || c == '_' || c == '-' || c == '.' || c == '*';
        }

        /** RFC 9110 tchar plus ':' and '/', as allowed in RFC 8941 tokens. */
        private static boolean isTokenChar(char c) {
            return isAlpha(c) || isDigit(c) || "!#$%&'*+-.^_`|~:/".indexOf(c) >= 0;
        }
    }
}
