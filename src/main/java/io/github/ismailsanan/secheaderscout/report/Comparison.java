package io.github.ismailsanan.secheaderscout.report;

import io.github.ismailsanan.secheaderscout.engine.Finding;
import io.github.ismailsanan.secheaderscout.engine.FindingType;
import io.github.ismailsanan.secheaderscout.headers.ResponseHeaders;
import io.github.ismailsanan.secheaderscout.model.ScanResult;

import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;

/**
 * Compares the missing headers of one URL in a previous report with a fresh
 * scan of the same URL. Immutable; every verdict is computed once, in the constructor.
 *
 * <p>A header only counts as FIXED if it is now present in the response <em>and</em>
 * not reported as INVALID (browsers ignore an unparseable header, so it is no fix);
 * such headers are listed by {@link #presentButInvalid()}. If a header is absent but
 * no longer reported (for example because the rules became more precise), it counts
 * as NO LONGER CHECKED instead of being presented as a fix.</p>
 *
 * <p>Which verdicts may be given depends on the {@link State}:</p>
 * <ul>
 *   <li>{@link State#NO_BASELINE}: the URL was not analysed in the previous report (error or
 *       incomplete evaluation), so its empty "missing" list means nothing. No verdicts.</li>
 *   <li>{@link State#RESCAN_FAILED}: the rescan produced an error. No verdicts.</li>
 *   <li>{@link State#INCOMPLETE}: a rule crashed during the rescan, so the absence of a
 *       finding proves nothing. Only {@link #stillMissing()} is listed.</li>
 *   <li>{@link State#COMPARED}: all verdicts.</li>
 * </ul>
 */
public final class Comparison {

    /** How much the two scans can be compared. */
    public enum State {
        NO_BASELINE,
        RESCAN_FAILED,
        INCOMPLETE,
        COMPARED
    }

    private final String url;
    private final Set<String> previouslyMissing;
    private final boolean previouslyAnalysed;
    private final ScanResult current;
    private final State state;
    private final List<String> fixed;
    private final List<String> presentButInvalid;
    private final List<String> stillMissing;
    private final List<String> noLongerChecked;
    private final List<String> newlyMissing;

    /**
     * @param url                the URL from the previous report; must equal {@code current.target()}
     * @param previouslyMissing  headers the previous report listed as missing
     * @param previouslyAnalysed {@code false} if the previous report did not analyse this URL
     * @param current            the fresh scan of {@code url}
     */
    public Comparison(String url, Set<String> previouslyMissing, boolean previouslyAnalysed, ScanResult current) {
        this.url = Objects.requireNonNull(url, "url");
        this.current = Objects.requireNonNull(current, "current");
        if (!url.equals(current.target())) {
            throw new IllegalArgumentException("Comparison URL " + url + " does not match the rescanned target "
                    + current.target());
        }
        this.previouslyAnalysed = previouslyAnalysed;
        // sorted once, so every verdict list comes out in a stable order
        this.previouslyMissing = sortedNormalized(previouslyMissing);
        this.state = !previouslyAnalysed ? State.NO_BASELINE
                : current.hasError() ? State.RESCAN_FAILED
                : current.evaluationIncomplete() ? State.INCOMPLETE
                : State.COMPARED;

        Set<String> nowMissing = sortedNormalized(current.missingHeaderNames());
        Set<String> nowInvalid = sortedNormalized(current.findings().stream()
                .filter(f -> f.type() == FindingType.INVALID).map(Finding::header).toList());
        Set<String> present = current.presentHeaders();
        boolean compared = state == State.COMPARED;

        this.fixed = compared ? filter(this.previouslyMissing, h -> present.contains(h) && !nowInvalid.contains(h))
                : List.of();
        this.presentButInvalid = compared ? filter(this.previouslyMissing, h -> present.contains(h) && nowInvalid.contains(h))
                : List.of();
        this.noLongerChecked = compared ? filter(this.previouslyMissing, h -> !nowMissing.contains(h) && !present.contains(h))
                : List.of();
        this.newlyMissing = compared ? filter(nowMissing, h -> !this.previouslyMissing.contains(h)) : List.of();
        // a header still reported missing is a fact even when other rules crashed
        this.stillMissing = compared || state == State.INCOMPLETE
                ? filter(this.previouslyMissing, nowMissing::contains) : List.of();
    }

    /** Comparison against a previous result that was fully analysed. */
    public Comparison(String url, Set<String> previouslyMissing, ScanResult current) {
        this(url, previouslyMissing, true, current);
    }

    /** Comparison of a parsed previous result with its rescan. */
    public static Comparison of(ReportParser.PreviousResult previous, ScanResult current) {
        return new Comparison(previous.url(), previous.missingHeaders(), previous.analysed(), current);
    }

    private static Set<String> sortedNormalized(java.util.Collection<String> headers) {
        return java.util.Collections.unmodifiableSortedSet(headers.stream().map(ResponseHeaders::normalize)
                .collect(Collectors.toCollection(TreeSet::new)));
    }

    private static List<String> filter(Set<String> sorted, java.util.function.Predicate<String> keep) {
        return sorted.stream().filter(keep).toList();
    }

    public String url() {
        return url;
    }

    /** Previously missing headers, normalised and sorted. */
    public Set<String> previouslyMissing() {
        return previouslyMissing;
    }

    public boolean previouslyAnalysed() {
        return previouslyAnalysed;
    }

    public ScanResult current() {
        return current;
    }

    public State state() {
        return state;
    }

    /** The previous report did not analyse this URL, so there is nothing to compare against. */
    public boolean noBaseline() {
        return state == State.NO_BASELINE;
    }

    /** The rescan could not analyse the URL. */
    public boolean rescanFailed() {
        return state == State.RESCAN_FAILED;
    }

    /** The rescan ran, but at least one rule crashed, so missing findings may be missing. */
    public boolean currentIncomplete() {
        return state == State.INCOMPLETE;
    }

    /** No FIXED / NEW / NO LONGER CHECKED verdict can be given. */
    public boolean indeterminate() {
        return state != State.COMPARED;
    }

    /** Previously missing, now present and not reported as invalid. */
    public List<String> fixed() {
        return fixed;
    }

    /** Previously missing, now present but INVALID (ignored by browsers): not fixed. */
    public List<String> presentButInvalid() {
        return presentButInvalid;
    }

    /** Previously missing and still reported missing (also listed when the rescan is incomplete). */
    public List<String> stillMissing() {
        return stillMissing;
    }

    public List<String> noLongerChecked() {
        return noLongerChecked;
    }

    public List<String> newlyMissing() {
        return newlyMissing;
    }

    /** Both scans are trustworthy and nothing changed. */
    public boolean unchanged() {
        return state == State.COMPARED && fixed.isEmpty() && presentButInvalid.isEmpty() && newlyMissing.isEmpty()
                && noLongerChecked.isEmpty();
    }

    @Override
    public String toString() {
        return "Comparison[" + url + ", " + state + "]";
    }
}
