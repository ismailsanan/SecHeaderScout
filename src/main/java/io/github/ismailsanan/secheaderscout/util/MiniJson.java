package io.github.ismailsanan.secheaderscout.util;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal strict JSON reader for the small OWASP definitions file. It accepts
 * only the RFC 8259 grammar (numbers {@code -?(0|[1-9]\d*)(\.\d+)?([eE][+-]?\d+)?},
 * exactly four hex digits in a {@code u} escape, no trailing commas or comments) and
 * additionally rejects duplicate object keys, which RFC 8259 leaves undefined.
 * Produces {@code Map<String,Object>}, {@code List<Object>}, {@code String},
 * {@code Double}, {@code Boolean} or {@code null}. Nesting depth is bounded so
 * hostile input cannot overflow the stack.
 */
public final class MiniJson {

    private static final int MAX_DEPTH = 32;

    private final String s;
    private int pos;

    private MiniJson(String s) {
        this.s = s;
    }

    /** Parses {@code json}; throws {@link IllegalArgumentException} on any syntax error. */
    public static Object parse(String json) {
        if (json == null) {
            throw new IllegalArgumentException("null input");
        }
        MiniJson p = new MiniJson(json);
        p.skipWs();
        Object value = p.value(0);
        p.skipWs();
        if (p.pos != json.length()) {
            throw p.error("trailing characters");
        }
        return value;
    }

    private Object value(int depth) {
        if (depth > MAX_DEPTH) {
            throw error("nesting too deep");
        }
        if (pos >= s.length()) {
            throw error("unexpected end of input");
        }
        char c = s.charAt(pos);
        switch (c) {
            case '{':
                return object(depth);
            case '[':
                return array(depth);
            case '"':
                return string();
            case 't':
                return literal("true", Boolean.TRUE);
            case 'f':
                return literal("false", Boolean.FALSE);
            case 'n':
                return literal("null", null);
            default:
                if (c == '-' || (c >= '0' && c <= '9')) {
                    return number();
                }
                throw error("unexpected character '" + c + "'");
        }
    }

    private Map<String, Object> object(int depth) {
        Map<String, Object> map = new LinkedHashMap<>();
        pos++; // {
        skipWs();
        if (peek('}')) {
            pos++;
            return map;
        }
        while (true) {
            skipWs();
            if (!peek('"')) {
                throw error("expected string key");
            }
            String key = string();
            skipWs();
            expect(':');
            skipWs();
            if (map.containsKey(key)) {
                throw error("duplicate key \"" + key + "\"");
            }
            map.put(key, value(depth + 1));
            skipWs();
            if (peek(',')) {
                pos++;
            } else if (peek('}')) {
                pos++;
                return map;
            } else {
                throw error("expected ',' or '}'");
            }
        }
    }

    private List<Object> array(int depth) {
        List<Object> list = new ArrayList<>();
        pos++; // [
        skipWs();
        if (peek(']')) {
            pos++;
            return list;
        }
        while (true) {
            skipWs();
            list.add(value(depth + 1));
            skipWs();
            if (peek(',')) {
                pos++;
            } else if (peek(']')) {
                pos++;
                return list;
            } else {
                throw error("expected ',' or ']'");
            }
        }
    }

    private String string() {
        pos++; // opening quote
        StringBuilder sb = new StringBuilder();
        while (pos < s.length()) {
            char c = s.charAt(pos++);
            if (c == '"') {
                return sb.toString();
            }
            if (c < 0x20) {
                throw error("control character in string");
            }
            if (c != '\\') {
                sb.append(c);
                continue;
            }
            if (pos >= s.length()) {
                break;
            }
            char e = s.charAt(pos++);
            switch (e) {
                case '"': sb.append('"'); break;
                case '\\': sb.append('\\'); break;
                case '/': sb.append('/'); break;
                case 'b': sb.append('\b'); break;
                case 'f': sb.append('\f'); break;
                case 'n': sb.append('\n'); break;
                case 'r': sb.append('\r'); break;
                case 't': sb.append('\t'); break;
                case 'u':
                    if (pos + 4 > s.length()) {
                        throw error("truncated unicode escape");
                    }
                    int code = 0;
                    for (int i = 0; i < 4; i++) {
                        int digit = hexDigit(s.charAt(pos + i));
                        if (digit < 0) {
                            throw error("invalid unicode escape");
                        }
                        code = code * 16 + digit;
                    }
                    sb.append((char) code);
                    pos += 4;
                    break;
                default:
                    throw error("invalid escape '\\" + e + "'");
            }
        }
        throw error("unterminated string");
    }

    /** {@code -?(0|[1-9]\d*)(\.\d+)?([eE][+-]?\d+)?} (RFC 8259 section 6). */
    private Double number() {
        int start = pos;
        if (peek('-')) {
            pos++;
        }
        if (peek('0')) {
            pos++;
        } else if (digits() == 0) {
            throw error("invalid number");
        }
        if (peek('.')) {
            pos++;
            if (digits() == 0) {
                throw error("invalid number: digit expected after '.'");
            }
        }
        if (peek('e') || peek('E')) {
            pos++;
            if (peek('+') || peek('-')) {
                pos++;
            }
            if (digits() == 0) {
                throw error("invalid number: digit expected in exponent");
            }
        }
        return Double.valueOf(s.substring(start, pos));
    }

    /** Value of an ASCII hex digit, or -1 (unlike {@link Character#digit}, no non-ASCII digits). */
    private static int hexDigit(char c) {
        if (c >= '0' && c <= '9') {
            return c - '0';
        }
        if (c >= 'a' && c <= 'f') {
            return c - 'a' + 10;
        }
        if (c >= 'A' && c <= 'F') {
            return c - 'A' + 10;
        }
        return -1;
    }

    /** Consumes ASCII digits and returns how many there were. */
    private int digits() {
        int start = pos;
        while (pos < s.length() && s.charAt(pos) >= '0' && s.charAt(pos) <= '9') {
            pos++;
        }
        return pos - start;
    }

    private Object literal(String word, Object result) {
        if (!s.startsWith(word, pos)) {
            throw error("invalid literal");
        }
        pos += word.length();
        return result;
    }

    private boolean peek(char c) {
        return pos < s.length() && s.charAt(pos) == c;
    }

    private void expect(char c) {
        if (!peek(c)) {
            throw error("expected '" + c + "'");
        }
        pos++;
    }

    private void skipWs() {
        while (pos < s.length()) {
            char c = s.charAt(pos);
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                pos++;
            } else {
                return;
            }
        }
    }

    private IllegalArgumentException error(String message) {
        return new IllegalArgumentException("Invalid JSON at offset " + pos + ": " + message);
    }
}
