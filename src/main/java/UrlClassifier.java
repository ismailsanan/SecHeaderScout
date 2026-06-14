
public class UrlClassifier {

    public enum UrlType {
        LOGOUT,
        LOGIN,
        ADMIN,
        API,
        PAYMENT,
        NORMAL
    }

    public static UrlType classify(String url) {
        String lower = url.toLowerCase();

        if (lower.contains("/logout") ||
                lower.contains("/signout") ||
                lower.contains("/sign-out") ||
                lower.contains("/log-out")) {
            return UrlType.LOGOUT;
        }

        if (lower.contains("/login") ||
                lower.contains("/signin") ||
                lower.contains("/sign-in")) {
            return UrlType.LOGIN;
        }

        if (lower.contains("/admin") ||
                lower.contains("/dashboard") ||
                lower.contains("/management")) {
            return UrlType.ADMIN;
        }

        if (lower.contains("/api/") ||
                lower.contains("/v1/") ||
                lower.contains("/v2/")) {
            return UrlType.API;
        }

        if (lower.contains("/payment") ||
                lower.contains("/checkout") ||
                lower.contains("/billing")) {
            return UrlType.PAYMENT;
        }

        return UrlType.NORMAL;
    }

    public static String getLabel(UrlType type) {
        return switch (type) {
            case LOGOUT  -> " LOGOUT";
            case LOGIN   -> " LOGIN";
            case ADMIN   -> " ADMIN";
            case API     -> " API";
            case PAYMENT -> " PAYMENT";
            case NORMAL  -> "";
        };
    }
}