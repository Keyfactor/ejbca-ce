/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
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
