import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;

public class SecHeaderScout implements BurpExtension {
    @Override
    public void initialize(MontoyaApi api) {
    api.extension().setName("SecHeaderScout");
    Logging logging  = api.logging();

    // write a message to our output stream
        logging.logToOutput("Hello output.");

    }
}
