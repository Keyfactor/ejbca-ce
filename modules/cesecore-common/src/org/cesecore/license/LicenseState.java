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
package org.cesecore.license;

public enum LicenseState {
    // Not expired and license is for EJBCA. No capacity check done.
    VALID("valid"),
    
    // License file is not found/mounted to container.
    MISSING("EJBCA license is not provided"),
    
    // License is invalid. It does not matter why.
    INVALID("EJBCA license is invalid"),
    
    // show warning messages
    TO_BE_EXPIRED_60_DAYS("EJBCA license expires within _days_ days"),
    
    TO_BE_EXPIRED_30_DAYS("EJBCA license expires within _days_ days"),
    
    TO_BE_EXPIRED_5_DAYS("EJBCA license expires within _days_ days"),
    
    // Expired
    EXPIRED("EJBCA license has expired and will shut down in _days_ days"),
    EXPIRED_LONG_BACK("EJBCA license has expired since _days_ days. Shutting down."),
    
    // Customer is doing something bad e.g. removing libraries or providing their own implementation.
    EJBCA_SETUP_INVALID("Ejbca environment is misconfigured."); 
    
    public static final String TO_BE_EXPIRE_DAYS_TEMPLATE = "_days_";
    
    private String statusMessage;

    private LicenseState(String statusMessage) {
        this.statusMessage = statusMessage;
    }

    public String getStatusMessage() {
        return statusMessage;
    }
    
}
