/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ui.web.rest.api.io.request;

import org.ejbca.core.protocol.rest.EnrollPkcs10CertificateRequest;

/**
 * A class representing the input for certificate enrollment REST method.
 *
 * @version $Id: EnrollCertificateRestRequest.java 29081 2018-05-31 07:19:36Z andrey_s_helmes $
 */
public class EnrollCertificateRestRequest {
        
    private String certificateRequest;
    private String certificateProfileName;
    private String endEntityProfileName;
    private String certificateAuthorityName;
    private String username;
    private String password;
    
    
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
                    .build();
        }
    }

}