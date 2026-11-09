package io.github.ismailsanan.secheaderscout.testsupport;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Marker;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.MimeType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

/** Builders for strict fake HTTP messages. */
public final class Http {

    private Http() {
    }

    public static HttpHeader header(String name, String value) {
        return Strict.of(HttpHeader.class).returns("name", name).returns("value", value).build();
    }

    /** Fluent builder for a request/response pair. */
    public static final class Exchange {
        private String url = "https://example.com/";
        private String method = "GET";
        private int status = 200;
        private final List<String[]> responseHeaders = new ArrayList<>();
        private final List<String> requestHeaderNames = new ArrayList<>();
        private String body = "<html></html>";
        private MimeType mime = MimeType.HTML;

        public Exchange url(String url) {
            this.url = url;
            return this;
        }

        public Exchange method(String method) {
            this.method = method;
            return this;
        }

        public Exchange status(int status) {
            this.status = status;
            return this;
        }

        public Exchange header(String name, String value) {
            responseHeaders.add(new String[]{name, value});
            return this;
        }

        public Exchange html() {
            return header("Content-Type", "text/html; charset=utf-8");
        }

        public Exchange json() {
            mime = MimeType.JSON;
            body = "{}";
            return header("Content-Type", "application/json");
        }

        public Exchange requestHeader(String name) {
            requestHeaderNames.add(name.toLowerCase(Locale.ROOT));
            return this;
        }

        public Exchange mime(MimeType mime) {
            this.mime = mime;
            return this;
        }

        /** Sets the response body (default: a tiny HTML document). */
        public Exchange body(String body) {
            this.body = body;
            return this;
        }

        /** The raw response text exactly as the fake exposes it through {@code toByteArray()}. */
        public String raw() {
            StringBuilder raw = new StringBuilder("HTTP/1.1 " + status + " X\r\n");
            for (String[] h : responseHeaders) {
                raw.append(h[0]).append(": ").append(h[1]).append("\r\n");
            }
            return raw.append("\r\n").append(body).toString();
        }

        public HttpRequestResponse build() {
            boolean secure = url.startsWith("https://");
            String rest = url.substring(url.indexOf("://") + 3);
            String authority = rest.contains("/") ? rest.substring(0, rest.indexOf('/')) : rest;
            String host = authority.contains(":") ? authority.substring(0, authority.indexOf(':')) : authority;
            int port = authority.contains(":") ? Integer.parseInt(authority.substring(authority.indexOf(':') + 1))
                    : secure ? 443 : 80;
            HttpService service = Strict.of(HttpService.class)
                    .returns("host", host).returns("port", port).returns("secure", secure).build();
            Set<String> reqHeaders = Set.copyOf(requestHeaderNames);
            HttpRequest request = Strict.of(HttpRequest.class)
                    .returns("url", url)
                    .returns("method", method)
                    .returns("httpService", service)
                    .answers("hasHeader", a -> reqHeaders.contains(((String) a[0]).toLowerCase(Locale.ROOT)))
                    .build();

            StringBuilder raw = new StringBuilder("HTTP/1.1 " + status + " X\r\n");
            List<HttpHeader> headers = new ArrayList<>();
            for (String[] h : responseHeaders) {
                headers.add(Http.header(h[0], h[1]));
                raw.append(h[0]).append(": ").append(h[1]).append("\r\n");
            }
            raw.append("\r\n");
            int bodyOffset = raw.length();
            raw.append(body);
            String rawText = raw.toString();
            ByteArray bytes = Strict.of(ByteArray.class)
                    .returns("length", rawText.length())
                    .answers("indexOf", a -> indexOf(rawText, a))
                    .build();
            String bodyText = body;
            ByteArray bodyBytes = Strict.of(ByteArray.class).returns("length", bodyText.length()).build();
            HttpResponse response = Strict.of(HttpResponse.class)
                    .returns("body", bodyBytes)
                    .returns("bodyToString", bodyText)
                    .returns("statusCode", (short) status)
                    .returns("headers", List.copyOf(headers))
                    .returns("mimeType", mime)
                    .returns("toByteArray", bytes)
                    .returns("bodyOffset", bodyOffset)
                    .build();
            return exchange(request, response, List.of());
        }

        private static int indexOf(String raw, Object[] a) {
            String term = (String) a[0];
            boolean caseSensitive = (Boolean) a[1];
            int from = (Integer) a[2];
            int to = (Integer) a[3];
            String hay = caseSensitive ? raw : raw.toLowerCase(Locale.ROOT);
            String needle = caseSensitive ? term : term.toLowerCase(Locale.ROOT);
            int idx = hay.indexOf(needle, from);
            return idx >= 0 && idx + needle.length() <= to ? idx : -1;
        }

        private static HttpRequestResponse exchange(HttpRequest request, HttpResponse response, List<Marker> markers) {
            HttpRequestResponse[] self = new HttpRequestResponse[1];
            self[0] = Strict.of(HttpRequestResponse.class)
                    .returns("request", request)
                    .returns("response", response)
                    .returns("hasResponse", true)
                    .returns("responseMarkers", markers)
                    .answers("withResponseMarkers", a -> exchange(request, response,
                            a[0] instanceof List<?> l ? l.stream().map(Marker.class::cast).collect(Collectors.toList())
                                    : List.of((Marker[]) a[0])))
                    .build();
            return self[0];
        }
    }

    public static Exchange exchange() {
        return new Exchange();
    }

    /** A request/response pair without a response (e.g. a timed-out request). */
    public static HttpRequestResponse noResponse(String url) {
        HttpRequest request = Strict.of(HttpRequest.class).returns("url", url).build();
        return Strict.of(HttpRequestResponse.class)
                .returns("request", request)
                .returns("hasResponse", false)
                .returns("response", null)
                .build();
    }
}
