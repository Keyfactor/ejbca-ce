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


import io.swagger.v3.oas.annotations.media.Schema;
import org.cesecore.certificates.endentity.ExtendedInformation;

import java.util.Objects;

/**
 * A container for response end entity extended information
 */
public class ExtendedInformationRestResponseComponent {

    @Schema(description = "Extended Information property name", example = "1.3.6.1.5.5.7.1.24")
	private String name;
    @Schema(description = "Property value", example = "3003020105")
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

    public boolean isInternalName() {
        return name != null && name.contains(ExtendedInformation.INTERNAL_KEY_PREFIX);
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        ExtendedInformationRestResponseComponent that = (ExtendedInformationRestResponseComponent) o;
        return Objects.equals(name, that.name) && Objects.equals(value, that.value);
    }

    @Override
    public String toString() {
        return "name=" + name + ", value=" + value;
    }

    @Override
    public int hashCode() {
        return Objects.hash(name, value);
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
