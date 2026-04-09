import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

public class SecHeaderScout implements BurpExtension {
    @Override
    public void initialize(MontoyaApi api) {

        api.extension().setName("SecHeaderScout");

        ScanPanel scanPanel = new ScanPanel(api);

        api.userInterface().registerSuiteTab(
                "SecHeaderScout",
                scanPanel.getPanel()
        );
        api.logging().logToOutput("{\\__/}\n" +
                "(●_●)\n" +
                "( >> ) hungry for a shwarma?\n\n ");
    }
}
