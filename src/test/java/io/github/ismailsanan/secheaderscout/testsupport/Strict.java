package io.github.ismailsanan.secheaderscout.testsupport;

import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * Builds strict fakes of Burp interfaces with {@link Proxy}: only the methods
 * that are explicitly stubbed may be called. Any other call throws, so a test
 * fails if code under test touches something unexpected (for example the
 * network).
 */
public final class Strict<T> {

    private final Class<T> type;
    private final Map<String, Function<Object[], Object>> answers = new HashMap<>();

    private Strict(Class<T> type) {
        this.type = type;
    }

    public static <T> Strict<T> of(Class<T> type) {
        return new Strict<>(type);
    }

    public Strict<T> returns(String method, Object value) {
        answers.put(method, args -> value);
        return this;
    }

    public Strict<T> answers(String method, Function<Object[], Object> answer) {
        answers.put(method, answer);
        return this;
    }

    public T build() {
        return type.cast(Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type}, (proxy, m, args) -> {
            Object[] a = args == null ? new Object[0] : args;
            switch (m.getName()) {
                case "equals":
                    if (a.length == 1) {
                        return proxy == a[0];
                    }
                    break;
                case "hashCode":
                    if (a.length == 0) {
                        return System.identityHashCode(proxy);
                    }
                    break;
                case "toString":
                    if (a.length == 0 && !answers.containsKey("toString")) {
                        return "Strict<" + type.getSimpleName() + ">";
                    }
                    break;
                default:
                    break;
            }
            Function<Object[], Object> answer = answers.get(m.getName());
            if (answer == null) {
                throw new UnsupportedOperationException("Unexpected call: " + type.getSimpleName() + "." + m.getName());
            }
            return answer.apply(a);
        }));
    }
}
