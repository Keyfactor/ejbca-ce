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
package org.ejbca.core.model.validation;

public enum LookUpProfile {

    SMIME("SMIME lookup"),
    TLS("TLS lookup"),
    NONE("");

    private final String value;

    LookUpProfile(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
