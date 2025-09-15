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
    TO_BE_EXPIRED_60_DAYS("EJBCA license is to be expired within 60 days"),
    
    TO_BE_EXPIRED_30_DAYS("EJBCA license is to be expired within 30 days"),
    
    TO_BE_EXPIRED_5_DAYS("EJBCA license is to be expired within 5 days"),
    
    // Expired
    EXPIRED("EJBCA license has expired and considered out of compliance"),
    EXPIRED_LONG_BACK("EJBCA license has long expired"),
    
    // Customer is doing something bad e.g. removing libraries or providing their own implementation.
    EJBCA_SETUP_INVALID("Ejbca environment is misconfigured."); 
    
    private String statusMessage;

    private LicenseState(String statusMessage) {
        this.statusMessage = statusMessage;
    }

    public String getStatusMessage() {
        return statusMessage;
    }
    
}
