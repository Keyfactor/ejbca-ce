/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ui.web.rest.api.io.response;

/**
 * A container for response end entity extended information
 */
public class ExtendedInformationRestResponseComponent {

	private String name;
    private String value;

    private ExtendedInformationRestResponseComponent(String name, String value) {
        this.name = name;
        this.value = value;
    }

    public String getName() {
		return name;
	}

	public String getValue() {
		return value;
	}

    public static ExtendedInformationRestResponseComponentBuilder builder() {
        return new ExtendedInformationRestResponseComponentBuilder();
    }

    public static class ExtendedInformationRestResponseComponentBuilder {
    	private String name;
        private String value;

        public ExtendedInformationRestResponseComponentBuilder setName(String name) {
            this.name = name;
            return this;
        }

        public ExtendedInformationRestResponseComponentBuilder setValue(String value) {
            this.value = value;
            return this;
        }

        public ExtendedInformationRestResponseComponent build() {
            return new ExtendedInformationRestResponseComponent(name, value);
        }
    }
}
