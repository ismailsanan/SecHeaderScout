
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.List;



public class HeaderChecker {

    private final MontoyaApi api;


    public HeaderChecker(MontoyaApi api) {
        this.api = api;
    }


    public List<String> checkHeaders (String host){

        // build the service
        // HttpService service = HttpService.httpService(host, 443 , true);

        // toDo : implement a method that checks if https is not supported  check for http://
        HttpRequest request = HttpRequest.httpRequestFromUrl("https://" + host + "/" );

        HttpRequestResponse response = api.http().sendRequest(request);

        List<String> responseHeaders = response.response().headers()
                .stream()
                .map(header -> header.name())
                .toList();
        // find missing headers
        List<String> missing = OWASPHeaders.REQUIRED_HEADERS
                .stream()
                .filter(s -> !responseHeaders.contains(s))
                .toList();

        return missing;

    }

}
