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

import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

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
    @Schema(description = "Overwrite Subject Distinguished Name", example = "CN=John Doe,SURNAME=Doe,GIVENNAME=John,C=SE", required=false)
    private String subjectDn;
    private List<ExtendedInformationRestRequestComponent> extensionData;
    private List<ExtendedInformationRestRequestComponent> customData;
    @Schema(description = "Valid start time", example = "ISO 8601 Date string, eg. '2023-06-15 14:07:09'", required=false)
    private String startTime;
    @Schema(description = "Valid end time", example = "ISO 8601 Date string, eg. '2023-06-15 14:07:09'", required=false)
    private String endTime;

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

    public String getSubjectDn() {
        return subjectDn;
    }

    public void setSubjectDn(String subjectDn) {
        this.subjectDn = subjectDn;
    }

    public List<ExtendedInformationRestRequestComponent> getExtensionData() {
        return extensionData;
    }

    public void setExtensionData(List<ExtendedInformationRestRequestComponent> extensionData) {
        this.extensionData = extensionData;
    }

    public List<ExtendedInformationRestRequestComponent> getCustomData() {
        return customData;
    }

    public void setCustomData(List<ExtendedInformationRestRequestComponent> customData) {
        this.customData = customData;
    }

    public String getStartTime() {
        return startTime;
    }

    public void setStartTime(String startTime) {
        this.startTime = startTime;
    }

    public String getEndTime() {
        return endTime;
    }

    public void setEndTime(String endTime) {
        this.endTime = endTime;
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
         * Converts a EnrollCertificateRestRequest into EnrollPkcs10CertificateRequest.
         *
         * @param enrollCertificateRestRequest input.
         *
         * @return EnrollPkcs10CertificateRequest instance.
         */
        public EnrollPkcs10CertificateRequest toEnrollPkcs10CertificateRequest(final EnrollCertificateRestRequest enrollCertificateRestRequest) {
            final List<Map.Entry<String, String>> extendedData = new ArrayList<>();
            List<ExtendedInformationRestRequestComponent> extensions = enrollCertificateRestRequest.getExtensionData();
            if (extensions != null && !extensions.isEmpty()) {
                extensions.forEach(extension -> {
                    extendedData.add(new AbstractMap.SimpleEntry<>(extension.getName(),extension.getValue()));
                });
            }

            final List<Map.Entry<String, String>> customData = new ArrayList<>();
            List<ExtendedInformationRestRequestComponent> components = enrollCertificateRestRequest.getCustomData();
            if (components != null && !components.isEmpty()) {
                components.forEach(component -> {
                    customData.add(new AbstractMap.SimpleEntry<>(component.getName(),component.getValue()));
                });
            }

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
                    .subjectDn(enrollCertificateRestRequest.getSubjectDn())
                    .extendedData(extendedData)
                    .customData(customData)
                    .startTime(enrollCertificateRestRequest.getStartTime())
                    .endTime(enrollCertificateRestRequest.getEndTime())
                    .build();
        }
    }

}
