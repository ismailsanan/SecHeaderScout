package io.github.ismailsanan.secheaderscout.burp;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.MimeType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import io.github.ismailsanan.secheaderscout.headers.ResponseHeaders;
import io.github.ismailsanan.secheaderscout.model.ResponseSnapshot;

import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/** Converts Montoya HTTP messages into Burp-independent snapshots. */
public final class BurpMessages {

    private BurpMessages() {
    }

    /** {@code true} if the exchange carries a response at all. */
    public static boolean hasResponse(HttpRequestResponse rr) {
        return rr != null && rr.hasResponse() && rr.response() != null;
    }

    /**
     * The single gate for every Burp entry point (passive check, fetcher, site map): a
     * snapshot of an exchange whose response a browser would process, or empty when there
     * is no response or the status line is not 100-599.
     */
    public static Optional<ResponseSnapshot> analysableSnapshot(HttpRequestResponse rr) {
        if (!hasResponse(rr) || !ResponseSnapshot.isValidStatus(rr.response().statusCode())) {
            return Optional.empty();
        }
        HttpRequest request = rr.request();
        HttpResponse response = rr.response();
        ResponseHeaders headers = headersOf(response);
        String url = request.url();
        boolean credentialed = request.hasHeader("Cookie") || request.hasHeader("Authorization");
        // 'secure' is derived from the URL itself, so it can never disagree with the URL that is shown
        return Optional.of(new ResponseSnapshot(url, request.method(), response.statusCode(),
                ResponseSnapshot.isHttpsUrl(url), headers, isHtml(headers, response), credentialed));
    }

    public static ResponseHeaders headersOf(HttpResponse response) {
        List<Map.Entry<String, String>> pairs = new ArrayList<>();
        for (HttpHeader h : response.headers()) {
            pairs.add(new AbstractMap.SimpleImmutableEntry<>(h.name(), h.value()));
        }
        return ResponseHeaders.of(pairs);
    }

    /**
     * Uses the declared Content-Type when present; falls back to Burp's MIME
     * detection only when there is none.
     */
    static boolean isHtml(ResponseHeaders headers, HttpResponse response) {
        String contentType = headers.first("Content-Type").orElse(null);
        if (contentType != null && !contentType.isBlank()) {
            String type = contentType.split(";", 2)[0].trim().toLowerCase(Locale.ROOT);
            return type.equals("text/html") || type.equals("application/xhtml+xml");
        }
        return response.mimeType() == MimeType.HTML;
    }
}
