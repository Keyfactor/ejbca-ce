/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.keys.validation;

import java.util.Arrays;
import java.util.Set;
import java.util.TreeSet;

import org.cesecore.certificates.certificateprofile.CertificateProfile;

public class ValidationRequestParameters {
    
    public CertificateProfile certificateProfile;
    
    private boolean validateAcmeAccountUri = false;
    private String acmeAccountUri = "";
    private boolean validateAcmeValidationMethods = false;
    /** Comma separated string with ACME challenge types: http-01,dns-01,... */
    private String acmeValidationMethods = "";
    
    public void setCertificateProfile(CertificateProfile certProfile) {
        certificateProfile = certProfile;
    }
    
    public CertificateProfile getCertificateProfile() {
        return certificateProfile;
    }
    
    public boolean isValidateAcmeAccountUri() {
        return validateAcmeAccountUri;
    }

    public void setValidateAcmeAccountUri(boolean use) {
        this.validateAcmeAccountUri = use;
    }

    public String getAcmeAccountUri() {
        return acmeAccountUri;
    }

    public void setAcmeAccountUri(String accountUri) {
        this.acmeAccountUri = accountUri;
    }

    public boolean isValidateAcmeValidationMethods() {
        return validateAcmeValidationMethods;
    }

    public void setValidateAcmeValidationMethods(boolean use) {
        this.validateAcmeValidationMethods = use;
    }

    public String getAcmeValidationMethods() {
        return acmeValidationMethods;
    }

    public Set<String> getAcmeValidationMethodsAsSet() {
        return acmeValidationMethods != null ? new TreeSet<>(Arrays.asList(acmeValidationMethods.split(","))) : new TreeSet<String>();
    }
    
    public void setAcmeValidationMethods(String validationMethods) {
        this.acmeValidationMethods = validationMethods;
    }

}
