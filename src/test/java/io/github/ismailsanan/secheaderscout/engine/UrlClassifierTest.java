package io.github.ismailsanan.secheaderscout.engine;

import org.junit.jupiter.api.Test;

import static io.github.ismailsanan.secheaderscout.engine.UrlClassifier.UrlType.*;
import static io.github.ismailsanan.secheaderscout.engine.UrlClassifier.classify;
import static org.junit.jupiter.api.Assertions.assertEquals;

class UrlClassifierTest {

    @Test
    void classifiesByPath() {
        assertEquals(LOGOUT, classify("https://a.example/account/logout"));
        assertEquals(LOGIN, classify("https://a.example/Login?x=1"));
        assertEquals(ADMIN, classify("https://a.example/admin/users"));
        assertEquals(API, classify("https://a.example/api/v1/users"));
        assertEquals(PAYMENT, classify("https://a.example/checkout"));
        assertEquals(NORMAL, classify("https://a.example/"));
    }

    @Test
    void ignoresQueryStringAndHost() {
        assertEquals(NORMAL, classify("https://a.example/home?redirect=/logout"));
        assertEquals(NORMAL, classify("https://login.example/"));
    }

    @Test
    void toleratesInvalidUris() {
        assertEquals(LOGOUT, classify("https://a.example/logout?q={bad}"));
        assertEquals(NORMAL, classify(null));
    }
}
