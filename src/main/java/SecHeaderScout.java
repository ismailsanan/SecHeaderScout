import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

import java.util.List;

public class SecHeaderScout implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {

        api.extension().setName("SecHeaderScout");

        // fetch OWASP headers dynamically at startup
        OWASPHeaders owaspHeaders = new OWASPHeaders(api);
        List<String> headers = owaspHeaders.fetchHeaders();

        // create checker and panel
        HeaderChecker checker = new HeaderChecker(api, headers);
        ScanPanel panel = new ScanPanel(api, checker);

        // register tab
        api.userInterface().registerSuiteTab("SecHeaderScout", panel.getPanel());

        // clean unload
        api.extension().registerUnloadingHandler(() ->
                api.logging().logToOutput("SecHeaderScout wishes you fair well :)")
        );

                api.logging().logToOutput("{\\__/}\n" +
                "(●_●)\n" +
                "( >> ) hungry for a shwarma?\n\n ");
    }
}


