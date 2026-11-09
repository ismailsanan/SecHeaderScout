package io.github.ismailsanan.secheaderscout.definitions;

import java.util.Objects;

/**
 * One header recommended by the OWASP Secure Headers Project.
 *
 * @param name             header name as published, e.g. {@code Referrer-Policy}
 * @param recommendedValue value recommended by OWASP
 */
public record HeaderDefinition(String name, String recommendedValue) {
    public HeaderDefinition {
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(recommendedValue, "recommendedValue");
    }
}
