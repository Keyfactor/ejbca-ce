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
 * A class representing the input for certificate request REST method.
 */
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class) 
public class CertificateRequestRestRequest {
    @Schema(description = "Certificate request", example = "MIICh...V8shQ== OR -----BEGIN CERTIFICATE REQUEST-----\nMIICh...V8shQ==\n-----END CERTIFICATE REQUEST-----")
    private String certificateRequest;
    @Schema(description = "Username", example = "JohnDoe")
    private String username;
    @Schema(description = "Password", example = "foo123")
    private String password;
    private boolean includeChain;
    @Schema(description = "Certificate Authority (CA) name", example = "ExampleCA")
    private String certificateAuthorityName;
    @Schema(description = "Certificate Request Type", example = "PUBLICKEY, PKCS10, CRMF, SPKAC, or CVC")
    private String certificateRequestType;
    
    public CertificateRequestRestRequest() {
    }
    
    public String getCertificateRequest() {
        return certificateRequest;
    }
    
    public void setCertificateRequest(String certificateRequest) {
        this.certificateRequest = certificateRequest;
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

    public boolean getIncludeChain() { 
        return includeChain; 
    }

    public void setIncludeChain(final boolean includeChain) {
        this.includeChain = includeChain;
    }
    
    public String getCertificateAuthorityName() {
        return certificateAuthorityName;
    }

    public void setCertificateAuthorityName(String certificateAuthorityName) {
        this.certificateAuthorityName = certificateAuthorityName;
    }

    public String getCertificateRequestType() {
        return certificateRequestType;
    }

    public void setCertificateRequestType(String certificateRequestType) {
        this.certificateRequestType = certificateRequestType;
    }

    /**
     * Returns a converter instance for this class.
     *
     * @return instance of converter for this class.
     */
    public static CertificateRequestRestRequestConverter converter() {
        return new CertificateRequestRestRequestConverter();
    }

    /**
     * Converter instance for this class.
     */
    public static class CertificateRequestRestRequestConverter {

        /**
         * Converts a CertificateRequestRestRequest into EnrollPkcs10CertificateRequest.
         *
         * @param certificateRequestRestRequest input.
         *
         * @return EnrollCertificateRestRequest instance.
         */
        public EnrollPkcs10CertificateRequest toEnrollPkcs10CertificateRequest(final CertificateRequestRestRequest certificateRequestRestRequest) {
            return new EnrollPkcs10CertificateRequest.Builder()
                    .certificateRequest(getFormatedRequestString(certificateRequestRestRequest))
                    .username(certificateRequestRestRequest.getUsername())
                    .password(certificateRequestRestRequest.getPassword())
                    .includeChain(certificateRequestRestRequest.getIncludeChain())
                    .certificateAuthorityName(certificateRequestRestRequest.getCertificateAuthorityName())
                    .requestType(certificateRequestRestRequest.getCertificateRequestType())
                    .build();
        }

        private static String getFormatedRequestString(CertificateRequestRestRequest certificateRequestRestRequest) {
            String certificateRequestData = switch (certificateRequestRestRequest.getCertificateRequestType()) {
                case "PUBLICKEY", "CRMF" -> certificateRequestRestRequest.certificateRequest;
                case "SPKAC" -> certificateRequestRestRequest.certificateRequest.replace("SPKAC=", "");
                case "CVC" -> certificateRequestRestRequest.certificateRequest
                        .replace("-----BEGIN CERTIFICATE-----", "")
                        .replace("-----END CERTIFICATE-----", "");
                default -> CertTools.encapsulateCsr(certificateRequestRestRequest.getCertificateRequest());
            };
            return certificateRequestData;
        }
    }
}
