import burp.api.montoya.http.message.HttpHeader;

import java.util.ArrayList;
import java.util.List;

// CORS headers need to be checked together as a group
// checking them one at a time misses the dangerous combinations
// for example ACAO: * alone is bad but ACAO: * + ACAC: true is a misconfiguration signal

// and reflected origin + ACAC: true is the most dangerous combo
public class CORSChecker {

    private static final String ACAO  = "access-control-allow-origin";
    private static final String ACAC  = "access-control-allow-credentials";
    private static final String ACAM  = "access-control-allow-methods";
    private static final String ACAH  = "access-control-allow-headers";
    private static final String ACMAX = "access-control-max-age";

    // takes the full response header list so we can check dangerous combinations
    public static List<String> check(List<HttpHeader> responseHeaders) {
        List<String> issues = new ArrayList<>();

        String acao  = getHeaderValue(responseHeaders, ACAO);
        String acac  = getHeaderValue(responseHeaders, ACAC);
        String acam  = getHeaderValue(responseHeaders, ACAM);
        String acah  = getHeaderValue(responseHeaders, ACAH);
        String acmax = getHeaderValue(responseHeaders, ACMAX);

        // no CORS headers present ->  nothing to check
        if (acao == null) return issues;

        // wildcard origin —> any origin can read the response
        if (acao.equals("*"))
            issues.add("CORS: Access-Control-Allow-Origin is '*' —> any origin can read this response");

        // null origin is dangerous — sandboxed iframes and file:// URIs use null
        if (acao.equals("null"))
            issues.add("CORS: Access-Control-Allow-Origin is 'null' —> exploitable via sandboxed iframes or file:// URIs");

        // wildcard + credentials —> browsers reject this but it signals a bad config
        if (acao.equals("*") && "true".equals(acac))
            issues.add("CORS: Access-Control-Allow-Origin '*' with Allow-Credentials 'true' —> misconfiguration, browsers reject this combination");

        // specific origin + credentials —> flag for manual verification of reflected origin
        if (acac != null && acac.equals("true") && !acao.equals("*"))
            issues.add("CORS: Access-Control-Allow-Credentials is 'true' with origin '" + acao + "' —> verify the server does not dynamically reflect the Origin header");

        // wildcard methods —> accepts anything including DELETE PUT PATCH
        if (acam != null) {
            if (acam.equals("*"))
                issues.add("CORS: Access-Control-Allow-Methods is '*' —> all HTTP methods permitted, should be an explicit list");

            // state-changing methods + credentials —> CSRF risk
            if (acac != null && acac.equals("true")) {
                if (acam.contains("delete"))
                    issues.add("CORS: DELETE method allowed with credentials —> high risk for authenticated state change");

                if (acam.contains("put") || acam.contains("patch"))
                    issues.add("CORS: PUT/PATCH methods allowed with credentials —> verify CSRF protections are in place");
            }
        }

        // wildcard headers —> client can send anything including custom auth headers
        if (acah != null && acah.equals("*"))
            issues.add("CORS: Access-Control-Allow-Headers is '*' —> any header allowed, should be an explicit list");

        // preflight cache longer than 24 hours —> policy changes will be slow to take effect
        if (acmax != null) {
            try {
                int maxAge = Integer.parseInt(acmax.trim());
                if (maxAge > 86400)
                    issues.add("CORS: Access-Control-Max-Age is " + maxAge + "s —> preflight cached for more than 24 hours");
            } catch (NumberFormatException e) {
                issues.add("CORS: Access-Control-Max-Age value '" + acmax + "' could not be parsed");
            }
        }

        return issues;
    }

    // pulls a specific header value from the list case insensitively
    // returns null if not present
    private static String getHeaderValue(List<HttpHeader> headers, String name) {
        return headers.stream()
                .filter(h -> h.name().trim().equalsIgnoreCase(name))
                .map(h -> h.value().trim().toLowerCase())
                .findFirst()
                .orElse(null);
    }
}