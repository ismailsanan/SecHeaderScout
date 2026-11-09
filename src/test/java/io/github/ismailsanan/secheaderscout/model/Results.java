package io.github.ismailsanan.secheaderscout.model;

import io.github.ismailsanan.secheaderscout.engine.Confidence;
import io.github.ismailsanan.secheaderscout.engine.Finding;
import io.github.ismailsanan.secheaderscout.engine.FindingType;
import io.github.ismailsanan.secheaderscout.engine.Severity;
import io.github.ismailsanan.secheaderscout.engine.UrlClassifier;

import java.util.List;
import java.util.Set;

/** Test factory for ScanResult instances. */
public final class Results {

    private Results() {
    }

    public static Finding missing(String header) {
        return new Finding(header, FindingType.MISSING, header + " header not set", null, "recommended",
                "The response does not set " + header, "bg", "fix", Severity.INFORMATION, Confidence.CERTAIN);
    }

    public static Finding weak(String header, String observed) {
        return new Finding(header, FindingType.WEAK, header + " weak", observed, "recommended",
                "detail for " + observed, "bg", "fix", Severity.LOW, Confidence.FIRM);
    }

    public static ScanResult result(String url, List<Finding> findings, Set<String> present) {
        return new ScanResult(url, url, "GET", 200, url.startsWith("https"), false, null, null, null,
                UrlClassifier.classify(url), findings, List.of(), present);
    }

    public static ScanResult fallback(String target, List<Finding> findings) {
        String url = "http://" + target + "/";
        return new ScanResult(target, url, "GET", 200, false, true, 503, "HTTPS returned status 503", null,
                UrlClassifier.classify(url), findings, List.of("HTTP fallback note"), Set.of());
    }
}
