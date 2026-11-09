package io.github.ismailsanan.secheaderscout.engine.rules;

import io.github.ismailsanan.secheaderscout.engine.Confidence;
import io.github.ismailsanan.secheaderscout.engine.EvaluationContext;
import io.github.ismailsanan.secheaderscout.engine.Finding;
import io.github.ismailsanan.secheaderscout.engine.FindingType;
import io.github.ismailsanan.secheaderscout.engine.HeaderRule;
import io.github.ismailsanan.secheaderscout.engine.Severity;
import io.github.ismailsanan.secheaderscout.headers.ResponseHeaders;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * CORS response headers, evaluated together because the risk lies in their
 * combination. Manual scanner only: Burp's native scanner reports CORS issues
 * and can actively test origin reflection, which a passive check cannot.
 * Absence of CORS headers is never a finding.
 */
public final class CorsRule implements HeaderRule {

    public static final String ACAO = "Access-Control-Allow-Origin";
    static final String ACAC = "Access-Control-Allow-Credentials";
    static final String ACAM = "Access-Control-Allow-Methods";
    static final String ACAH = "Access-Control-Allow-Headers";

    private static final String BACKGROUND =
            "Cross-Origin Resource Sharing (CORS) headers relax the same-origin policy so that other origins can "
                    + "read responses. Overly broad CORS policies, especially combined with credentials, let a "
                    + "malicious site read authenticated data.";
    private static final String REMEDIATION =
            "Allow only an explicit list of trusted origins, never reflect the Origin header without validating "
                    + "it, never allow the 'null' origin, and send Access-Control-Allow-Credentials only to trusted "
                    + "origins.";

    @Override
    public String header() {
        return ACAO;
    }

    @Override
    public boolean expectedOn(EvaluationContext context) {
        return false;
    }

    @Override
    public List<Finding> evaluate(ResponseHeaders headers, EvaluationContext context) {
        List<Finding> out = new ArrayList<>();
        if (!headers.has(ACAO)) {
            return out;
        }
        List<String> origins = headers.listMembers(ACAO);
        String acao = origins.isEmpty() ? "" : origins.get(0).toLowerCase(Locale.ROOT);
        boolean credentials = headers.first(ACAC).map(v -> v.trim().equalsIgnoreCase("true")).orElse(false);

        if (origins.size() > 1) {
            out.add(cors(ACAO, FindingType.INVALID, "CORS: multiple Access-Control-Allow-Origin values",
                    headers.combined(ACAO),
                    "The response sends more than one allowed origin. Browsers reject this and fail the CORS check, "
                            + "which suggests the policy is generated incorrectly (for example by appending the "
                            + "request Origin to a fixed value).",
                    Severity.INFORMATION, Confidence.CERTAIN));
            return out;
        }
        if (acao.equals("null")) {
            out.add(cors(ACAO, FindingType.WEAK, "CORS: null origin allowed", acao,
                    "Access-Control-Allow-Origin is 'null'. Sandboxed iframes and some redirects send the 'null' "
                            + "origin, so any attacker can obtain it and read this response"
                            + (credentials ? " with the victim's credentials." : "."),
                    credentials ? Severity.MEDIUM : Severity.LOW, Confidence.FIRM));
        } else if (acao.equals("*")) {
            if (credentials) {
                out.add(cors(ACAC, FindingType.CONFLICT, "CORS: wildcard origin combined with credentials",
                        "*, credentials=true",
                        "Access-Control-Allow-Origin '*' with Access-Control-Allow-Credentials 'true' is rejected "
                                + "by browsers, so credentialed requests fail. It indicates a misunderstanding of "
                                + "the policy; check whether other endpoints reflect the origin instead.",
                        Severity.INFORMATION, Confidence.CERTAIN));
            } else {
                out.add(cors(ACAO, FindingType.WEAK, "CORS: any origin can read the response", acao,
                        "Access-Control-Allow-Origin is '*', so any site can read this response without "
                                + "credentials. This is fine for public data; check that the response contains "
                                + "nothing sensitive, for example data that depends on network position (intranet).",
                        Severity.INFORMATION, Confidence.TENTATIVE));
            }
        } else if (credentials) {
            out.add(cors(ACAC, FindingType.WEAK, "CORS: credentials allowed for specific origin", acao,
                    "Credentials are allowed for origin '" + acao + "'. If the server reflects arbitrary Origin "
                            + "values here, any site can read authenticated responses. Verify by resending the "
                            + "request with a different Origin header (e.g. in Repeater).",
                    Severity.INFORMATION, Confidence.TENTATIVE));
        }

        String methods = headers.first(ACAM).map(v -> v.toLowerCase(Locale.ROOT)).orElse(null);
        if (methods != null && credentials && !acao.equals("*")
                && (methods.contains("delete") || methods.contains("put") || methods.contains("patch"))) {
            out.add(cors(ACAM, FindingType.WEAK, "CORS: state-changing methods allowed with credentials", methods,
                    "State-changing methods (" + methods + ") are allowed cross-origin with credentials. Make sure "
                            + "the allowed origins are trusted and that these endpoints have CSRF protection.",
                    Severity.INFORMATION, Confidence.TENTATIVE));
        }
        if (headers.first(ACAH).map(v -> v.trim().equals("*")).orElse(false) && !credentials) {
            out.add(cors(ACAH, FindingType.WEAK, "CORS: any request header allowed", "*",
                    "Access-Control-Allow-Headers is '*', so cross-origin requests may carry any header. Prefer "
                            + "an explicit list.",
                    Severity.INFORMATION, Confidence.CERTAIN));
        }
        return out;
    }

    private static Finding cors(String header, FindingType type, String name, String observed, String detail,
                                Severity severity, Confidence confidence) {
        return new Finding(header, type, name, observed, "explicit allow-list of trusted origins", detail,
                BACKGROUND, REMEDIATION, severity, confidence);
    }
}
