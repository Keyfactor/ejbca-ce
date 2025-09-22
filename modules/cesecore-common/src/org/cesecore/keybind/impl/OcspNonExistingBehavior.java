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
package org.cesecore.keybind.impl;

import java.util.HashMap;
import java.util.Map;

/**
 * Enum describing the four possible behaviors for an ocsp response for a serial number not found in the database
 */

public enum OcspNonExistingBehavior {
    UNKNOWN("unknown"), 
    GOOD("good"), 
    REVOKED("revoked"), 
    UNAUTHORIZED("unauthorized");
    
    private static final Map<String, OcspNonExistingBehavior> labelLookupMap = new HashMap<>();
    
    static {
        for(OcspNonExistingBehavior ocspNonExistingBehavior : OcspNonExistingBehavior.values()) {
            labelLookupMap.put(ocspNonExistingBehavior.getLabel(), ocspNonExistingBehavior);
        }
    }
    
    private final String label;
    
    private OcspNonExistingBehavior(final String label) {
        this.label = label;
    }

    public String getLabel() {
        return label;
    }
    
    public static OcspNonExistingBehavior fromLabel(final String label) {
        return labelLookupMap.get(label);
    }
}
