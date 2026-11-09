package io.github.ismailsanan.secheaderscout.engine;

import java.util.Objects;

/**
 * Facts about a response, other than its headers, that rules need to avoid false
 * positives.
 *
 * @param url                   analysed URL
 * @param urlType               URL classification (user rule or keyword heuristic), taken once in
 *                              {@link #of} so it cannot change mid-evaluation when the user edits rules
 * @param secure                {@code true} if the response was received over HTTPS
 * @param htmlDocument          {@code true} if the response is an HTML document (document-only
 *                              headers such as COOP or Permissions-Policy are irrelevant on
 *                              images, scripts or JSON)
 * @param credentialedRequest   {@code true} if the request carried a Cookie or Authorization header
 */
public record EvaluationContext(
        String url,
        UrlClassifier.UrlType urlType,
        boolean secure,
        boolean htmlDocument,
        boolean credentialedRequest
) {
    public EvaluationContext {
        Objects.requireNonNull(url, "url");
        Objects.requireNonNull(urlType, "urlType");
    }

    public static EvaluationContext of(String url, boolean secure, boolean htmlDocument, boolean credentialedRequest) {
        return new EvaluationContext(url, UrlClassifier.classify(url), secure, htmlDocument, credentialedRequest);
    }
}
