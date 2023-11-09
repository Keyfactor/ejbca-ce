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
package org.ejbca.ra.dto;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Enum for the different types of objects that can be inspected on the inspect.xhtml page.
 */
public enum InspectType {

    X509("X.509"),
    CVC("CVC"),
    PKCS10("PKCS#10"),
    ASN1("ASN.1"),
    UNKNOWN("Unknown");

    private final String name;

    InspectType(final String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public static List<InspectType> getSupportedTypes() {
        return Arrays.stream(values())
                .filter(type -> !type.equals(UNKNOWN))
                .collect(Collectors.toList());
    }
}
