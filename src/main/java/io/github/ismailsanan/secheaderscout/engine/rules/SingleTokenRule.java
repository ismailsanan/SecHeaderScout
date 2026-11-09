package io.github.ismailsanan.secheaderscout.engine.rules;

import io.github.ismailsanan.secheaderscout.engine.Confidence;
import io.github.ismailsanan.secheaderscout.engine.EvaluationContext;
import io.github.ismailsanan.secheaderscout.engine.Finding;
import io.github.ismailsanan.secheaderscout.engine.FindingType;
import io.github.ismailsanan.secheaderscout.engine.Severity;
import io.github.ismailsanan.secheaderscout.headers.HeaderSyntax;
import io.github.ismailsanan.secheaderscout.headers.ResponseHeaders;

import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;

/**
 * Base for headers whose value is exactly one token from a fixed set (COOP,
 * COEP, CORP, X-DNS-Prefetch-Control, X-Permitted-Cross-Domain-Policies).
 * Handles duplicates and unknown tokens; how a value is matched against the
 * token set depends on the {@link Mode}.
 */
public abstract class SingleTokenRule extends AbstractHeaderRule {

    /** How a header value is matched against the valid tokens. */
    protected enum Mode {
        /**
         * Legacy headers (X-DNS-Prefetch-Control, X-Permitted-Cross-Domain-Policies):
         * the trimmed value is compared case-insensitively and identical repeats are tolerated.
         */
        CASE_INSENSITIVE,
        /**
         * RFC 8941 structured-field items (COOP, COEP): the token is case-sensitive,
         * may carry parameters such as {@code ;report-to="x"}, and a list is invalid.
         */
        STRUCTURED_ITEM,
        /**
         * Byte-for-byte match (CORP): Fetch compares the combined header value with
         * each valid token exactly, so parameters, case differences or a list make
         * browsers ignore the header.
         */
        EXACT
    }

    private final Set<String> validTokens;
    private final Mode mode;
    /** Sorted, comma-joined valid tokens, so issue text is deterministic across JVM runs. */
    private final String expectedText;

    /**
     * @param validTokens the recognised values; for {@link Mode#CASE_INSENSITIVE} and
     *                    {@link Mode#STRUCTURED_ITEM} they must be lower case
     * @param mode        how values are matched; see {@link Mode}
     * @throws IllegalArgumentException if the token set is empty, contains a blank token,
     *                                  or contains a token that the mode could never match
     */
    protected SingleTokenRule(String header, String background, String recommended, String remediation,
                              Set<String> validTokens, Mode mode) {
        super(header, background, recommended, remediation);
        this.mode = Objects.requireNonNull(mode, "mode");
        this.validTokens = Set.copyOf(Objects.requireNonNull(validTokens, "validTokens"));
        if (this.validTokens.isEmpty()) {
            throw new IllegalArgumentException(header + ": no valid tokens configured");
        }
        for (String token : this.validTokens) {
            if (token.isBlank()) {
                throw new IllegalArgumentException(header + ": blank token configured");
            }
            if (mode != Mode.EXACT && !token.equals(token.toLowerCase(Locale.ROOT))) {
                // values are lower-cased before lookup, so this token could never match
                throw new IllegalArgumentException(header + ": token '" + token + "' must be lower case");
            }
        }
        this.expectedText = String.join(", ", new TreeSet<>(this.validTokens));
    }

    @Override
    protected final void evaluatePresent(ResponseHeaders headers, List<String> values,
                                         EvaluationContext context, List<Finding> out) {
        if (mode == Mode.EXACT) {
            evaluateExact(values, headers, context, out);
            return;
        }
        boolean structuredField = mode == Mode.STRUCTURED_ITEM;
        List<String> members = headers.listMembers(header());
        if (structuredField && hasEmptyMember(values)) {
            out.add(multipleValues(values)); // "same-origin," fails RFC 8941 item parsing
            return;
        }
        if (members.size() > 1) {
            if (members.stream().map(this::token).distinct().count() > 1 || structuredField) {
                out.add(multipleValues(values));
                return;
            }
            // e.g. "off, off" from two identical lines: harmless for non-structured headers
        }
        String raw = members.isEmpty() ? "" : members.get(0);
        String token = token(raw);
        if (!validTokens.contains(token)) {
            out.add(invalid(raw, "The value '" + raw + "' is not a recognised " + header() + " value (expected one of "
                    + expectedText + "). Browsers ignore unrecognised values and apply "
                    + "the default behaviour, so the intended protection is not in effect.", Confidence.CERTAIN));
            return;
        }
        if (structuredField && !bareToken(raw).equals(token)) {
            out.add(invalid(raw, "The value '" + raw + "' uses upper-case characters. " + header()
                    + " is a structured header whose tokens are case-sensitive; '" + token
                    + "' must be sent in lower case or browsers will not recognise it.", Confidence.FIRM));
            return;
        }
        evaluateToken(token, raw, headers, context, out);
    }

    /**
     * Fetch "gets" the header (all field lines joined with ", ") and compares the
     * result byte-for-byte with each valid token; anything else is ignored.
     */
    private void evaluateExact(List<String> values, ResponseHeaders headers, EvaluationContext context,
                               List<Finding> out) {
        String combined = String.join(", ", values);
        if (values.size() > 1 || HeaderSyntax.splitTopLevelKeepEmpty(combined, ',').size() > 1) {
            out.add(multipleValues(values));
            return;
        }
        if (validTokens.contains(combined)) {
            evaluateToken(combined, combined, headers, context, out);
            return;
        }
        String near = HeaderSyntax.itemToken(combined);
        String detail = validTokens.contains(near)
                ? "The value '" + combined + "' is not exactly '" + near + "'. Browsers compare " + header()
                        + " byte-for-byte with " + expectedText + ": parameters, upper-case letters or any other "
                        + "extra characters make them ignore the header, as if it were absent."
                : "The value '" + combined + "' is not a recognised " + header() + " value (expected exactly one "
                        + "of " + expectedText + "). Browsers ignore unrecognised values, as if the header were "
                        + "absent, so the intended protection is not in effect.";
        out.add(invalid(combined, detail, Confidence.CERTAIN));
    }

    /** The one "invalid value" finding of this header (browsers ignore the value). */
    private Finding invalid(String observed, String detail, Confidence confidence) {
        return finding(FindingType.INVALID, header() + " header has an invalid value", observed, detail,
                Severity.LOW, confidence);
    }

    /** Header-specific checks on a syntactically valid, lower-cased token. */
    protected abstract void evaluateToken(String token, String raw, ResponseHeaders headers,
                                          EvaluationContext context, List<Finding> out);

    private String token(String raw) {
        return mode == Mode.STRUCTURED_ITEM ? HeaderSyntax.itemToken(raw) : raw.trim().toLowerCase(Locale.ROOT);
    }

    private static boolean hasEmptyMember(List<String> values) {
        for (String value : values) {
            List<String> parts = HeaderSyntax.splitTopLevelKeepEmpty(value, ',');
            if (parts.size() > 1 && parts.contains("")) {
                return true;
            }
        }
        return false;
    }

    private static String bareToken(String raw) {
        int semi = raw.indexOf(';');
        return (semi >= 0 ? raw.substring(0, semi) : raw).trim();
    }
}
