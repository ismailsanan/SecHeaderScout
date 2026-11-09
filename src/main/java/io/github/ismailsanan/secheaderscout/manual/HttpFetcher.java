package io.github.ismailsanan.secheaderscout.manual;

import io.github.ismailsanan.secheaderscout.model.ResponseSnapshot;

import java.util.Objects;

/**
 * Sends a single GET request. Implementations must verify upstream TLS
 * certificates, apply a response timeout, not follow redirects, and report
 * network failures through {@link Result#failure()} rather than by throwing.
 */
@FunctionalInterface
public interface HttpFetcher {

    Result fetch(String url);

    /** Exactly one of {@code response} and {@code failure} is non-null. */
    record Result(ResponseSnapshot response, String failure) {
        public Result {
            if ((response == null) == (failure == null)) {
                throw new IllegalArgumentException("exactly one of response/failure must be set");
            }
        }

        public static Result of(ResponseSnapshot response) {
            return new Result(Objects.requireNonNull(response), null);
        }

        public static Result failed(String failure) {
            return new Result(null, Objects.requireNonNull(failure));
        }

        public boolean ok() {
            return response != null;
        }
    }
}
