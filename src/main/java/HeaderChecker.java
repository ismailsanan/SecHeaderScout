
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

        //is this the issue ? cant i rewrite this var ?
         HttpRequestResponse fallback = api.http().sendRequest(notsecurerequest);

        if(fallback.response().statusCode() >= 400 && fallback.response().statusCode() < 600 || !fallback.hasResponse() ) {
            return List.of("[ERROR] Host Unreachable");
        }
        List<String>  headers = extractHeader(fallback);
        List<String> missings = findMissing(headers);
        return missings;
    }

        if(!response.hasResponse()){
            return List.of("[ERROR] Host Unreachable");
        }
        List<String>  headers = extractHeader(response);
        List<String> missings = findMissing(headers);

        return missings;

    }

    //extract headers
    private  List<String> extractHeader (HttpRequestResponse res ) {
        List<String> headers = res.response().headers()
                .stream()
                .map(header -> header.name())
                .toList();

        return headers;

    }
    // find missing headers
    private List<String> findMissing (List<String> missingheaders) {


        return OWASPHeaders.REQUIRED_HEADERS
                .stream()
                .filter(s -> !missingheaders.contains(s))
                .toList();
    }


}
