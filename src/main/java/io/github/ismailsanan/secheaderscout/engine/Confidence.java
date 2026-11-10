package io.github.ismailsanan.secheaderscout.engine;

/** Finding confidence, mapped 1:1 onto Burp's AuditIssueConfidence by the scanner layer. */
public enum Confidence {
    /** The observed bytes prove the issue (e.g. the header is absent or unparsable). */
    CERTAIN,
    /** Strong evidence, but impact depends on context the extension cannot see. */
    FIRM,
    /** Heuristic, e.g. based on URL classification; verify manually. */
    TENTATIVE
}
