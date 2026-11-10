package io.github.ismailsanan.secheaderscout.report;

import io.github.ismailsanan.secheaderscout.headers.ResponseHeaders;
import io.github.ismailsanan.secheaderscout.util.HtmlEscaper;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CancellationException;

/**
 * Reads the URLs and missing headers back out of a previously exported report.
 * Supports the current format (data attributes) and the legacy format written
 * by SecHeaderScout 1.x.
 *
 * <p>The input is an untrusted file, so the parser is a forward-only
 * {@code indexOf} scan: every search starts after the previous match, which
 * keeps the total work linear in the input size even for crafted files with
 * unterminated tags. (Lazy {@code (.*?)</tag>} regexes are quadratic on such
 * input.) The scan checks the thread's interrupt flag between blocks and throws
 * {@link CancellationException} when cancelled. Nothing is ever executed or
 * deserialised.</p>
 */
public final class ReportParser {

    /**
     * One URL from a previous report.
     *
     * @param url            the URL
     * @param missingHeaders lower-cased headers the report listed as missing
     * @param analysed       {@code false} if the report marks the URL as not (fully) analysed
     *                       ({@code data-error} / {@code data-incomplete}, or a legacy
     *                       {@code [ERROR]} marker): its missing list is then no baseline
     */
    public record PreviousResult(String url, Set<String> missingHeaders, boolean analysed) {
        public PreviousResult {
            missingHeaders = Set.copyOf(missingHeaders);
        }

        /** A fully analysed previous result. */
        public PreviousResult(String url, Set<String> missingHeaders) {
            this(url, missingHeaders, true);
        }
    }

    private static final String SECTION_OPEN = "<section class=\"url-block";
    private static final String SECTION_CLOSE = "</section>";
    private static final String DATA_URL = "data-url=\"";
    private static final String DATA_ERROR = "data-error=\"";
    private static final String DATA_INCOMPLETE = "data-incomplete=\"";
    private static final String MISSING_ITEM = "<li class=\"missing\" data-header=\"";

    private static final String LEGACY_BLOCK = "<div class='url-block";
    private static final String LEGACY_URL = "<div class='url'>";
    private static final String LEGACY_MISSING = "MISSING";
    private static final String LEGACY_ERROR = "[ERROR]";
    private static final String[] LEGACY_ARROWS = {"&#8594;", "&rarr;", "->", "→"};

    private ReportParser() {
    }

    public static List<PreviousResult> parse(String html) {
        List<PreviousResult> results = parseCurrent(html);
        return results.isEmpty() ? parseLegacy(html) : results;
    }

    /**
     * Caches the next occurrence of a needle. Queries must use non-decreasing
     * positions, so each needle is scanned at most once over the whole input
     * (O(n)), even when it never occurs again.
     */
    private static final class Cursor {
        private final String html;
        private final String needle;
        private int cached = -2; // -2: not searched yet; -1: no further occurrence

        Cursor(String html, String needle) {
            this.html = html;
            this.needle = needle;
        }

        int next(int from) {
            if (cached == -1 || cached >= from) {
                return cached;
            }
            cached = html.indexOf(needle, from);
            return cached;
        }
    }

    private static void checkCancelled() {
        if (Thread.currentThread().isInterrupted()) {
            throw new CancellationException("report parsing cancelled");
        }
    }

    private static List<PreviousResult> parseCurrent(String html) {
        List<PreviousResult> results = new ArrayList<>();
        Cursor sections = new Cursor(html, SECTION_OPEN);
        Cursor closes = new Cursor(html, SECTION_CLOSE);
        Cursor tagEnds = new Cursor(html, ">");
        Cursor items = new Cursor(html, MISSING_ITEM);
        Cursor quotes = new Cursor(html, "\"");
        int pos = sections.next(0);
        while (pos >= 0) {
            checkCancelled();
            int tagEnd = tagEnds.next(pos);
            if (tagEnd < 0) {
                break; // unterminated start tag: nothing more can be parsed
            }
            int next = sections.next(tagEnd);
            int close = closes.next(tagEnd);
            int bodyEnd = minPositive(next, close, html.length());

            String tag = html.substring(pos, tagEnd);
            String url = attribute(tag, DATA_URL);
            if (url != null && !url.isBlank()) {
                Set<String> missing = new LinkedHashSet<>();
                int item = items.next(tagEnd);
                while (item >= 0 && item < bodyEnd) {
                    int valueStart = item + MISSING_ITEM.length();
                    int valueEnd = quotes.next(valueStart);
                    if (valueEnd < 0 || valueEnd > bodyEnd) {
                        break;
                    }
                    String raw = html.substring(valueStart, valueEnd);
                    // the exporter escapes values, so a raw '<' or '>' means a broken item: skip it
                    if (raw.indexOf('<') < 0 && raw.indexOf('>') < 0) {
                        String header = ResponseHeaders.normalize(HtmlEscaper.unescape(raw));
                        if (!header.isEmpty()) {
                            missing.add(header);
                        }
                    }
                    item = items.next(valueEnd);
                }
                boolean analysed = !"true".equals(attribute(tag, DATA_ERROR))
                        && !"true".equals(attribute(tag, DATA_INCOMPLETE));
                results.add(new PreviousResult(HtmlEscaper.unescape(url).trim(), missing, analysed));
            }
            pos = next;
        }
        return results;
    }

    /**
     * Value of {@code name="..."} within one start tag, or {@code null}. Start tags
     * are disjoint, so searching each one costs O(n) overall.
     */
    private static String attribute(String tag, String nameEqualsQuote) {
        int start = tag.indexOf(nameEqualsQuote);
        if (start < 0) {
            return null;
        }
        start += nameEqualsQuote.length();
        int end = tag.indexOf('"', start);
        return end < 0 ? null : tag.substring(start, end);
    }

    private static List<PreviousResult> parseLegacy(String html) {
        List<PreviousResult> results = new ArrayList<>();
        int bodyClose = html.lastIndexOf("</body>");
        int limit = bodyClose >= 0 ? bodyClose : html.length();
        Cursor blocks = new Cursor(html, LEGACY_BLOCK);
        Cursor urls = new Cursor(html, LEGACY_URL);
        Cursor spans = new Cursor(html, "<span");
        Cursor divCloses = new Cursor(html, "</div>");
        Cursor missingWords = new Cursor(html, LEGACY_MISSING);
        Cursor errors = new Cursor(html, LEGACY_ERROR);
        int pos = blocks.next(0);
        while (pos >= 0 && pos < limit) {
            checkCancelled();
            int next = blocks.next(pos + LEGACY_BLOCK.length());
            int blockEnd = next >= 0 && next < limit ? next : limit;

            int urlStart = urls.next(pos);
            if (urlStart >= 0 && urlStart < blockEnd) {
                urlStart += LEGACY_URL.length();
                int divClose = divCloses.next(urlStart);
                int urlEnd = Math.min(minPositive(spans.next(urlStart), divClose, blockEnd), blockEnd);
                String url = HtmlEscaper.unescape(html.substring(urlStart, urlEnd)).trim();
                // v1 did not escape URLs, so text such as "MISSING->csp" in a query string must
                // not be read as a finding: findings are only searched after the URL element
                int afterUrl = divClose >= 0 && divClose < blockEnd ? divClose : blockEnd;
                if (!url.isEmpty()) {
                    int error = errors.next(afterUrl);
                    boolean analysed = error < 0 || error >= blockEnd;
                    results.add(new PreviousResult(url, legacyMissing(html, missingWords, afterUrl, blockEnd),
                            analysed));
                }
            }
            pos = next;
        }
        return results;
    }

    private static Set<String> legacyMissing(String html, Cursor missingWords, int from, int to) {
        Set<String> missing = new LinkedHashSet<>();
        int m = missingWords.next(from);
        while (m >= 0 && m < to) {
            int p = skipWhitespace(html, m + LEGACY_MISSING.length(), to);
            int afterArrow = -1;
            for (String arrow : LEGACY_ARROWS) {
                if (html.startsWith(arrow, p)) {
                    afterArrow = p + arrow.length();
                    break;
                }
            }
            if (afterArrow >= 0) {
                int start = skipWhitespace(html, afterArrow, to);
                int end = start;
                while (end < to && html.charAt(end) != '<' && html.charAt(end) != '|') {
                    end++;
                }
                String header = ResponseHeaders.normalize(HtmlEscaper.unescape(html.substring(start, end)));
                if (!header.isEmpty() && !header.startsWith("[error]")) {
                    missing.add(header);
                }
                m = missingWords.next(end);
            } else {
                m = missingWords.next(m + LEGACY_MISSING.length());
            }
        }
        return missing;
    }

    private static int skipWhitespace(String s, int i, int to) {
        while (i < to && Character.isWhitespace(s.charAt(i))) {
            i++;
        }
        return i;
    }

    /** Smallest non-negative of {@code a} and {@code b}, or {@code fallback} if both are negative. */
    private static int minPositive(int a, int b, int fallback) {
        if (a < 0) {
            return b < 0 ? fallback : b;
        }
        return b < 0 ? a : Math.min(a, b);
    }
}
