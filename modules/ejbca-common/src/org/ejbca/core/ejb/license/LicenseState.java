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
package org.ejbca.core.ejb.license;

public enum LicenseState {
    // Not expired and license is for EJBCA. No capacity check done.
    VALID("valid"),
    
    // License file is not found/mounted to container.
    MISSING("not provided"),
    
    // License is invalid. It does not matter why.
    INVALID("is invalid"),
    
    // Useful to start showing warning message
    TO_BE_EXPIRED("to be expired soon"),
    
    // Expired
    EXPIRED("is expired"),
    EXPIRED_LONG_BACK("has long expired"),
    
    // Customer is doing something bad e.g. removing libraries or providing their own implementation.
    EJBCA_SETUP_INVALID("ejbca environment misconfigured"); 
    
    private String statusMessage;

    private LicenseState(String statusMessage) {
        this.statusMessage = statusMessage;
    }

    public String getStatusMessage() {
        return statusMessage;
    }
    
}
