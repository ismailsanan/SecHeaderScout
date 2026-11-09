package io.github.ismailsanan.secheaderscout.burp;

import burp.api.montoya.persistence.PersistedObject;
import io.github.ismailsanan.secheaderscout.engine.EndpointRules;
import io.github.ismailsanan.secheaderscout.engine.EndpointRulesStore;
import io.github.ismailsanan.secheaderscout.util.Log;

/**
 * Keeps endpoint types in the Burp project file ({@code api.persistence().extensionData()}), so
 * they belong to the engagement they were made for and survive a Burp restart.
 */
public final class BurpEndpointRulesStore implements EndpointRulesStore {

    static final String KEY = "endpointTypes.v1";

    private final PersistedObject data;
    private final Log log;

    public BurpEndpointRulesStore(PersistedObject data, Log log) {
        this.data = data;
        this.log = log;
    }

    @Override
    public EndpointRules load() {
        try {
            return EndpointRules.deserialize(data.getString(KEY), message -> log.warn("[TYPES] " + message));
        } catch (RuntimeException e) {
            log.error("[TYPES] Could not read saved endpoint types; using the built-in patterns", e);
            return EndpointRules.DEFAULT;
        }
    }

    @Override
    public void save(EndpointRules rules) {
        try {
            if (rules.isDefault()) {
                data.deleteString(KEY);
            } else {
                data.setString(KEY, rules.serialize());
            }
        } catch (RuntimeException e) {
            log.error("[TYPES] Could not save endpoint types to the project", e);
        }
    }
}
