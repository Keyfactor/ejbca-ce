/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
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
