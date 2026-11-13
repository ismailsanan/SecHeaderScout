package io.github.ismailsanan.secheaderscout.engine;

/** What kind of problem a finding describes. */
public enum FindingType {
    /** The header is absent where it is expected. */
    MISSING,
    /** The header is present but cannot be parsed, so browsers ignore it. */
    INVALID,
    /** The header is valid but explicitly configured in a weak or unsafe way. */
    WEAK,
    /** The header or a directive is deprecated and no longer honoured by modern browsers. */
    DEPRECATED,
    /** Duplicate header lines or directives, or headers that contradict each other. */
    CONFLICT;

    public boolean isMissing() {
        return this == MISSING;
    }

    /** Name shown to users; {@link #WEAK} reads as "Misconfiguration" in every view. */
    public String label() {
        return switch (this) {
            case MISSING -> "Missing";
            case INVALID -> "Invalid";
            case WEAK -> "Misconfiguration";
            case DEPRECATED -> "Deprecated";
            case CONFLICT -> "Conflict";
        };
    }
}
