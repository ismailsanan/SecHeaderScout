package io.github.ismailsanan.secheaderscout.engine;

/**
 * Where endpoint types are kept between sessions. The Burp implementation saves them in the
 * project file; tests and headless use can keep them in memory.
 */
public interface EndpointRulesStore {

    /** The saved rules, or {@link EndpointRules#DEFAULT} if nothing (usable) was saved. Never throws. */
    EndpointRules load();

    /** Saves {@code rules}; failures are reported by the implementation, never thrown. */
    void save(EndpointRules rules);

    /** A store that remembers nothing across reloads. */
    static EndpointRulesStore inMemory() {
        return new EndpointRulesStore() {
            private EndpointRules saved = EndpointRules.DEFAULT;

            @Override
            public synchronized EndpointRules load() {
                return saved;
            }

            @Override
            public synchronized void save(EndpointRules rules) {
                saved = rules;
            }
        };
    }
}
