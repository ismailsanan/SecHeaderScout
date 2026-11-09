package io.github.ismailsanan.secheaderscout.engine;

/** Finding severity, mapped 1:1 onto Burp's AuditIssueSeverity by the scanner layer. */
public enum Severity {
    INFORMATION,
    LOW,
    MEDIUM,
    HIGH
}
