package org.ejbca.ui.web.rest.api.io.request;

/**
 * A container for end entity extended information
 */
public class ExtendedInformationRestRequestComponent {

	private String name;
    private String value;

    private ExtendedInformationRestRequestComponent(String name, String value) {
        this.name = name;
        this.value = value;
    }

    public String getName() {
		return name;
	}

	public String getValue() {
		return value;
	}

    public static ExtendedInformationRestRequestComponentBuilder builder() {
        return new ExtendedInformationRestRequestComponentBuilder();
    }

    public static class ExtendedInformationRestRequestComponentBuilder {
    	private String name;
        private String value;

        public ExtendedInformationRestRequestComponentBuilder setName(String name) {
            this.name = name;
            return this;
        }

        public ExtendedInformationRestRequestComponentBuilder setValue(String value) {
            this.value = value;
            return this;
        }

        public ExtendedInformationRestRequestComponent build() {
            return new ExtendedInformationRestRequestComponent(name, value);
        }
    }
}
