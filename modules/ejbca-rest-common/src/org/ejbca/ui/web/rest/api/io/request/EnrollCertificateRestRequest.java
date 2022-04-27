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

import org.ejbca.core.protocol.rest.EnrollPkcs10CertificateRequest;

/**
 * A class representing the input for certificate enrollment REST method.
 *
 */
public class EnrollCertificateRestRequest {
    private String certificateRequest;
    private String certificateProfileName;
    private String endEntityProfileName;
    private String certificateAuthorityName;
    private String username;
    private String password;
    private String accountBindingId;
    private boolean includeChain;
    
    public EnrollCertificateRestRequest() {
    }
    
    public String getCertificateRequest() {
        return certificateRequest;
    }
    
    public void setCertificateRequest(String certificateRequest) {
        this.certificateRequest = certificateRequest;
    }
    
    public String getCertificateProfileName() {
        return certificateProfileName;
    }

    public void setCertificateProfileName(String certificateProfileName) {
        this.certificateProfileName = certificateProfileName;
    }

    public String getEndEntityProfileName() {
        return endEntityProfileName;
    }

    public void setEndEntityProfileName(String endEntityProfileName) {
        this.endEntityProfileName = endEntityProfileName;
    }

    public String getCertificateAuthorityName() {
        return certificateAuthorityName;
    }

    public void setCertificateAuthorityName(String certificateAuthorityName) {
        this.certificateAuthorityName = certificateAuthorityName;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
    
    public String getAccountBindingId() {
        return accountBindingId;
    }

    public void setAccountBindingId(String accountBindingId) {
        this.accountBindingId = accountBindingId;
    }

    public boolean getIncludeChain() { return includeChain; }

    public void setIncludeChain(final boolean includeChain) {
        this.includeChain = includeChain;
    }

    /**
     * Returns a converter instance for this class.
     *
     * @return instance of converter for this class.
     */
    public static EnrollCertificateRestRequestConverter converter() {
        return new EnrollCertificateRestRequestConverter();
    }

    /**
     * Converter instance for this class.
     */
    public static class EnrollCertificateRestRequestConverter {

        /**
         * Converts a EnrollCertificateRestRequest into EnrollCertificateRestRequest.
         *
         * @param enrollCertificateRestRequest input.
         *
         * @return EnrollCertificateRestRequest instance.
         */
        public EnrollPkcs10CertificateRequest toEnrollPkcs10CertificateRequest(final EnrollCertificateRestRequest enrollCertificateRestRequest) {
            return new EnrollPkcs10CertificateRequest.Builder()
                    .certificateRequest(enrollCertificateRestRequest.getCertificateRequest())
                    .certificateProfileName(enrollCertificateRestRequest.getCertificateProfileName())
                    .endEntityProfileName(enrollCertificateRestRequest.getEndEntityProfileName())
                    .certificateAuthorityName(enrollCertificateRestRequest.getCertificateAuthorityName())
                    .username(enrollCertificateRestRequest.getUsername())
                    .password(enrollCertificateRestRequest.getPassword())
                    .accountBindingId(enrollCertificateRestRequest.getAccountBindingId())
                    .includeChain(enrollCertificateRestRequest.getIncludeChain())
                    .build();
        }
    }

}
