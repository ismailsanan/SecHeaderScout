

/**
 * Represents  OWASP recommended security header
 * with its description and recommended value
 */

public class HeaderInfo {

    private final String name;
    private final String description;
    private final String recommended;

    public HeaderInfo(String name, String description, String recommended) {
        this.name = name;
        this.description = description;
        this.recommended = recommended;
    }

    public String getName() {
        return name;
    }

    public String getDescription() {
        return description;
    }

    public String getRecommended() {
        return recommended;
    }
}