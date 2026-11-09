package io.github.ismailsanan.secheaderscout.util;

/**
 * HTML escaping for untrusted text inserted into HTML element content or
 * <em>quoted</em> attribute values. It escapes the five characters that are
 * significant in those contexts ({@code & < > " '}), following the OWASP XSS
 * Prevention Cheat Sheet, and replaces control characters that are invalid in
 * HTML.
 *
 * <p>Stricter than Apache Commons Text {@code escapeHtml4} for these contexts: it
 * also escapes {@code '} (as {@code &#39;}) and replaces control characters with
 * U+FFFD. Unlike {@code escapeHtml4} it leaves non-ASCII characters as they are,
 * because reports are written as UTF-8. Implemented locally so the extension
 * needs no runtime dependencies.</p>
 *
 * <p>Never use the output in unquoted attributes, URLs, JavaScript or CSS.</p>
 */
public final class HtmlEscaper {

    private HtmlEscaper() {
    }

    public static String escape(String text) {
        if (text == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(text.length() + 16);
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            switch (c) {
                case '&' -> sb.append("&amp;");
                case '<' -> sb.append("&lt;");
                case '>' -> sb.append("&gt;");
                case '"' -> sb.append("&quot;");
                case '\'' -> sb.append("&#39;");
                default -> {
                    if ((c < 0x20 && c != '\t' && c != '\n' && c != '\r') || c == 0x7f) {
                        sb.append('�');
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        return sb.toString();
    }

    /**
     * Decodes the entities {@link #escape} produces, plus {@code &apos;}, {@code &rarr;}
     * and numeric entities (for reading reports back). Control characters replaced by
     * {@code escape} are not restored.
     */
    public static String unescape(String html) {
        if (html == null || html.indexOf('&') < 0) {
            return html;
        }
        StringBuilder sb = new StringBuilder(html.length());
        int i = 0;
        while (i < html.length()) {
            char c = html.charAt(i);
            // bounded search: an entity is at most 10 chars, and an unbounded indexOf per '&'
            // would make crafted input ("&&&&...") quadratic
            int semi = c == '&' ? indexOf(html, ';', i + 1, Math.min(html.length(), i + 11)) : -1;
            if (semi > i && semi - i <= 10) {
                String entity = html.substring(i + 1, semi);
                String decoded = decode(entity);
                if (decoded != null) {
                    sb.append(decoded);
                    i = semi + 1;
                    continue;
                }
            }
            sb.append(c);
            i++;
        }
        return sb.toString();
    }

    private static String decode(String entity) {
        switch (entity) {
            case "amp": return "&";
            case "lt": return "<";
            case "gt": return ">";
            case "quot": return "\"";
            case "apos": return "'";
            case "rarr": return "→";
            default:
                break;
        }
        try {
            if (entity.startsWith("#x") || entity.startsWith("#X")) {
                return new String(Character.toChars(Integer.parseInt(entity.substring(2), 16)));
            }
            if (entity.startsWith("#")) {
                return new String(Character.toChars(Integer.parseInt(entity.substring(1))));
            }
        } catch (IllegalArgumentException e) {
            return null; // not a valid numeric entity: keep the text as-is
        }
        return null;
    }

    private static int indexOf(String s, char c, int from, int to) {
        for (int k = from; k < to; k++) {
            if (s.charAt(k) == c) {
                return k;
            }
        }
        return -1;
    }
}
