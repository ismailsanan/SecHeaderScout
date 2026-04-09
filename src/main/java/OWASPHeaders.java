import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import java.util.List;



//list of owasp response headers
//take matti suggestion call the headers dynamically  https://github.com/OWASP/www-project-secure-headers/blob/master/ci/headers_add.json
public class OWASPHeaders {

    public final MontoyaApi api;

    public OWASPHeaders(MontoyaApi api) {
        this.api = api;
    }

    // static OWASP List
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




    // implement a dynamic solution for the headers by fetching data from  https://raw.github.com/OWASP/www-project-secure-headers/blob/master/ci/headers_add.json
    public final List<String> Dynamic_REQUEST_HEADERS() {

        //HttpRequest request = HttpRequest.httpRequestFromUrl("https://raw.githubusercontent.com/OWASP/www-project-secure-headers/refs/heads/master/ci/headers_add.json");

        //HttpRequestResponse response = api.http().sendRequest(request);

        //Json Structure
        //api.logging().logToOutput(response.hasResponse());
        // use some api util jason structs


        return null;

    };
}
