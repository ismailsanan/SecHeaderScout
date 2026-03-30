import java.util.List;



//list of owasp response headers
//take matti suggestion call the headers dynamically  https://github.com/OWASP/www-project-secure-headers/blob/master/ci/headers_add.json
public class OWASPHeaders {

    public static final List<String> REQUIRED_HEADERS = List.of(
            "X-DNS-Prefetch-Control",
            "Cache-Control",
            "Cross-Origin-Resource-Policy",
            "Cross-Origin-Opener-Policy",
            "Cross-Origin-Embedder-Policy",
            "Clear-Site-Data",
            "Referrer-Policy",
            "X-Permitted-Cross-Domain-Policies",
            "Content-Security-Policy",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Strict-Transport-Security"
    );
}
