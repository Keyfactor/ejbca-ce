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
package org.ejbca.ui.web.rest.api.io.request;

import io.swagger.annotations.ApiModelProperty;

/**
 * A container for end entity extended information
 */
public class ExtendedInformationRestRequestComponent {

    @ApiModelProperty(value = "Certificate Extension Object Identifier (OID)", example = "1.3.6.1.5.5.7.1.24")
	private String name;
    @ApiModelProperty(value = "OID value", example = "3003020105")
    private String value;

    private ExtendedInformationRestRequestComponent() {}

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
