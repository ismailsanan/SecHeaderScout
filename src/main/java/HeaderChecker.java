
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

        HttpRequest request = HttpRequest.httpRequestFromUrl("https://" + host + "/" );
        HttpRequestResponse response = api.http().sendRequest(request);

        if (response.response().statusCode() >= 400 && response.response().statusCode() < 600) {
        HttpRequest notsecurerequest = HttpRequest.httpRequestFromUrl("http://" + host + "/" );
        response = api.http().sendRequest(notsecurerequest);

        if(response.response().statusCode() >= 400 && response.response().statusCode() < 600 || !response.hasResponse() ) {
            return List.of("[ERROR] Host Unreachable");
        }
    }

        if(!response.hasResponse()){
            return List.of("[ERROR] Host Unreachable");
        }

        //extract headers
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
