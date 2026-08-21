import java.util.Set;

public class UrlClassifier {

    public enum UrlType {
        LOGOUT,
        LOGIN,
        ADMIN,
        API,
        PAYMENT,
        STATIC,
        NORMAL
    }

    // static assets inherit the same global headers as everything else
    // reporting a missing CSP on favicon.png buries the real findings
    private static final Set<String> STATIC_EXTENSIONS = Set.of(
            ".js", ".mjs", ".css", ".map",
            ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".avif",
            ".woff", ".woff2", ".ttf", ".eot", ".otf",
            ".mp4", ".webm", ".mp3", ".zip"
    );

    // classify URL type based on the path
    // static is checked first because a .js under /admin/ is still just an asset
    // payment before admin because /admin/billing is a payment flow
    public static UrlType classify(String url) {
        if (url == null || url.isBlank()) return UrlType.NORMAL;

        String path = stripQuery(url.toLowerCase());

        if (isStatic(path)) return UrlType.STATIC;

        if (containsAny(path, "/logout", "/signout", "/sign-out", "/log-out"))
            return UrlType.LOGOUT;

        if (containsAny(path, "/login", "/signin", "/sign-in", "/auth/", "/oauth", "/sso"))
            return UrlType.LOGIN;

        if (containsAny(path, "/payment", "/checkout", "/billing", "/invoice", "/cart"))
            return UrlType.PAYMENT;

        if (containsAny(path, "/admin", "/dashboard", "/management", "/console", "/account"))
            return UrlType.ADMIN;

        if (containsAny(path, "/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/"))
            return UrlType.API;

        return UrlType.NORMAL;
    }

    // endpoints handling credentials, sessions or money
    // OWASP ties the Cache-Control no-store requirement to sensitive content
    // not to every response, so this is what gates that check
    public static boolean isSensitive(UrlType type) {
        return type == UrlType.LOGIN
                || type == UrlType.LOGOUT
                || type == UrlType.ADMIN
                || type == UrlType.PAYMENT
                || type == UrlType.API;
    }

    public static String getLabel(UrlType type) {
        return switch (type) {
            case LOGOUT  -> "[LOGOUT]";
            case LOGIN   -> "[LOGIN]";
            case ADMIN   -> "[ADMIN]";
            case API     -> "[API]";
            case PAYMENT -> "[PAYMENT]";
            case STATIC  -> "[STATIC]";
            case NORMAL  -> "";
        };
    }

    // drop the query string so ?redirect=/login doesnt misclassify a page
    private static String stripQuery(String url) {
        int q = url.indexOf('?');
        return q == -1 ? url : url.substring(0, q);
    }

    private static boolean isStatic(String path) {
        for (String ext : STATIC_EXTENSIONS) {
            if (path.endsWith(ext)) return true;
        }
        return false;
    }

    private static boolean containsAny(String path, String... needles) {
        for (String n : needles) {
            if (path.contains(n)) return true;
        }
        return false;
    }
}