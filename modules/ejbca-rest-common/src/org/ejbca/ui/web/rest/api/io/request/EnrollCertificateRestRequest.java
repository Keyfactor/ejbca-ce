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

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import com.keyfactor.util.CertTools;
import io.swagger.v3.oas.annotations.media.Schema;
import org.ejbca.core.protocol.rest.EnrollPkcs10CertificateRequest;

/**
 * A class representing the input for certificate enrollment REST method.
 *
 */
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class) 
public class EnrollCertificateRestRequest {
    @Schema(description = "Certificate request", example = "MIICh...V8shQ== OR -----BEGIN CERTIFICATE REQUEST-----\nMIICh...V8shQ==\n-----END CERTIFICATE REQUEST-----")
    private String certificateRequest;
    @Schema(description = "Certificate profile name", example = "ENDUSER")
    private String certificateProfileName;
    @Schema(description = "End Entity profile name", example = "ExampleEEP")
    private String endEntityProfileName;
    @Schema(description = "Certificate Authority (CA) name", example = "ExampleCA")
    private String certificateAuthorityName;
    @Schema(description = "Username", example = "JohnDoe")
    private String username;
    @Schema(description = "Password", example = "foo123")
    private String password;
    @Schema(description = "Account Binding ID", example = "1234567890")
    private String accountBindingId;
    private boolean includeChain;
    @Schema(description = "Email", example = "john.doe@example.com")
    private String email;
    @Schema(description = "Response Format (DER format is default)", example = "DER")
    private String responseFormat ="DER";

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
    
    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getResponseFormat() {
        return responseFormat;
    }

    public void setResponseFormat(String responseFormat) {
        this.responseFormat = responseFormat;
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
                    .certificateRequest(CertTools.encapsulateCsr(enrollCertificateRestRequest.getCertificateRequest()))
                    .certificateProfileName(enrollCertificateRestRequest.getCertificateProfileName())
                    .endEntityProfileName(enrollCertificateRestRequest.getEndEntityProfileName())
                    .certificateAuthorityName(enrollCertificateRestRequest.getCertificateAuthorityName())
                    .username(enrollCertificateRestRequest.getUsername())
                    .password(enrollCertificateRestRequest.getPassword())
                    .accountBindingId(enrollCertificateRestRequest.getAccountBindingId())
                    .includeChain(enrollCertificateRestRequest.getIncludeChain())
                    .email(enrollCertificateRestRequest.getEmail())
                    .responseFormat(enrollCertificateRestRequest.getResponseFormat())
                    .build();
        }
    }

}
