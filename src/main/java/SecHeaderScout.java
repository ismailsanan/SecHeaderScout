import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;

public class SecHeaderScout implements BurpExtension {
    @Override
    public void initialize(MontoyaApi api) {

        api.logging().logToOutput("loading ...");
        api.extension().setName("SecHeaderScout");

        ScanPanel scanPanel = new ScanPanel(api);

        api.userInterface().registerSuiteTab(
                "SecHeaderScout",
                scanPanel.getPanel()
        );
        api.logging().logToOutput(" loaded (˶ᵔ ᵕ ᵔ˶)");
    }
}
