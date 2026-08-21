import burp.api.montoya.http.message.HttpHeader;

import java.util.ArrayList;
import java.util.List;

/**
 * CORS has to be evaluated as a group, the dangerous cases only appear
 * when two headers are combined
 *
 * the four contexts below are OWASP's own from the Secure Headers Project
 * "Prevent CORS misconfiguration issues" section
 *
 *   public   without auth  —> ACAO: *        + ACAC: false   valid
 *   public   with auth     —> impossible, browsers reject * with credentials
 *   restricted without auth—> ACAO: <allowed> + ACAC: false   valid
 *   restricted with auth   —> ACAO: <allowed> + ACAC: true    valid but must not mirror Origin
 */
public class CORSChecker {

    private static final String ACAO  = "access-control-allow-origin";
    private static final String ACAC  = "access-control-allow-credentials";
    private static final String ACAM  = "access-control-allow-methods";
    private static final String ACAH  = "access-control-allow-headers";
    private static final String ACEH  = "access-control-expose-headers";
    private static final String ACMAX = "access-control-max-age";

    public static List<String> check(List<HttpHeader> responseHeaders, ScanContext ctx) {
        List<String> issues = new ArrayList<>();

        String acao = value(responseHeaders, ACAO);
        if (acao == null) return issues;   // no CORS, nothing to say

        String acac  = value(responseHeaders, ACAC);
        String acam  = value(responseHeaders, ACAM);
        String acah  = value(responseHeaders, ACAH);
        String aceh  = value(responseHeaders, ACEH);
        String acmax = value(responseHeaders, ACMAX);

        boolean credentialed = "true".equals(acac);
        boolean wildcard     = acao.equals("*");

<<<<<<< Updated upstream
        // null origin is dangerous — sandboxed iframes and file:// URIs use null
=======
        // a wildcard on a font or CDN file is the intended configuration
        // a wildcard on an application endpoint is a finding
        if (wildcard && ctx.urlType() != UrlClassifier.UrlType.STATIC) {
            if (ctx.setsCookie() || ctx.isSensitive())
                issues.add("CORS: Access-Control-Allow-Origin '*' on an authenticated endpoint —> any origin can read this response");
            else
                issues.add("CORS: Access-Control-Allow-Origin '*' —> any origin can read this response, confirm the data is genuinely public");
        }

        // null is reachable from sandboxed iframes, file:// and data: documents
        // an attacker page can trivially produce Origin: null
>>>>>>> Stashed changes
        if (acao.equals("null"))
            issues.add("CORS: Access-Control-Allow-Origin 'null' —> reachable from a sandboxed iframe, an attacker page can read this response");

        // browsers block this outright, seeing it means the config was never tested
        if (wildcard && credentialed)
            issues.add("CORS: '*' with Allow-Credentials 'true' —> browsers reject this combination, the endpoint is misconfigured");

        // the highest value CORS finding, OWASP explicitly warns against mirroring
        // a single response cannot prove reflection so this is flagged for confirmation
        if (credentialed && !wildcard)
            issues.add("CORS: Allow-Credentials 'true' with origin '" + acao
                    + "' —> resend with Origin: https://evil.example to confirm the server is not mirroring the request Origin, if it is this is an account takeover path");

        // an origin that is not a bare scheme+host is usually a parsing bug
        if (!wildcard && !acao.equals("null")
                && !acao.startsWith("http://") && !acao.startsWith("https://"))
            issues.add("CORS: Access-Control-Allow-Origin '" + acao + "' is not a valid origin —> likely a string concatenation bug in the origin allowlist");

        if (acam != null) {
            if (acam.equals("*"))
                issues.add("CORS: Access-Control-Allow-Methods '*' —> every method permitted, OWASP recommends an explicit list");

            if (credentialed) {
                if (acam.contains("delete"))
                    issues.add("CORS: DELETE permitted with credentials —> cross origin authenticated deletion if the Origin check is weak");
                if (acam.contains("put") || acam.contains("patch"))
                    issues.add("CORS: PUT/PATCH permitted with credentials —> cross origin state change, confirm CSRF defences");
            }
        }

        if (acah != null && acah.equals("*"))
            issues.add("CORS: Access-Control-Allow-Headers '*' —> arbitrary headers accepted, can defeat header based authorisation checks");

        // exposing auth material to script on other origins
        if (aceh != null && (aceh.contains("authorization") || aceh.contains("set-cookie")))
            issues.add("CORS: Access-Control-Expose-Headers exposes '" + aceh + "' —> credential bearing headers readable cross origin");

        if (acmax != null) {
            try {
                long maxAge = Long.parseLong(acmax.trim());
                // OWASP proposes 3600 for public, 10 for restricted
                if (maxAge > 86400)
                    issues.add("CORS: Access-Control-Max-Age " + maxAge + "s —> preflight cached over 24 hours, a policy fix will not reach clients for that long");
            } catch (NumberFormatException e) {
                issues.add("CORS: Access-Control-Max-Age '" + acmax + "' could not be parsed");
            }
        }

        return issues;
    }

    private static String value(List<HttpHeader> headers, String name) {
        return headers.stream()
                .filter(h -> h.name().trim().equalsIgnoreCase(name))
                .map(h -> h.value().trim().toLowerCase())
                .findFirst()
                .orElse(null);
    }
}