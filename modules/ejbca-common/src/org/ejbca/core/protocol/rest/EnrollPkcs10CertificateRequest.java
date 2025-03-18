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
package org.ejbca.core.protocol.rest;

import java.io.Serializable;
import java.util.List;
import java.util.Map;

import org.cesecore.certificates.certificate.CertificateConstants;

/**
 * A DTO class representing the input for certificate enrollment.
 *
 */
public class EnrollPkcs10CertificateRequest implements Serializable {
    private static final long serialVersionUID = 1L;
    
    private String certificateRequest;
    private String certificateProfileName;
    private String endEntityProfileName;
    private String certificateAuthorityName;
    private String username;
    private String password;
    private String accountBindingId;
    private boolean includeChain;
    
    private String email;
    private String responseFormat;

    private int requestType;

    private String subjectDn;
    private List<Map.Entry<String, String>> extendedData;
    private List<Map.Entry<String, String>> customData;
    private String startTime;
    private String endTime;

    public String getCertificateRequest() {
        return certificateRequest;
    }

    public String getCertificateProfileName() {
        return certificateProfileName;
    }

    public String getEndEntityProfileName() {
        return endEntityProfileName;
    }

    public String getCertificateAuthorityName() {
        return certificateAuthorityName;
    }
    
    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }
    
    public String getAccountBindingId() {
        return accountBindingId;
    }

    public boolean getIncludeChain() { return includeChain; }

    public String getEmail() {
        return email;
    }

    public String getResponseFormat() {
        return responseFormat;
    }

    public int getRequestType() {
        return requestType;
    }

    public String getSubjectDn() {
        return subjectDn;
    }

    public List<Map.Entry<String, String>> getExtendedData() {
        return extendedData;
    }

    public List<Map.Entry<String, String>> getCustomData() {
        return customData;
    }

    public String getStartTime() {
        return startTime;
    }

    public String getEndTime() {
        return endTime;
    }

    public static class Builder {
        private String certificateRequest;
        private String certificateProfileName;
        private String endEntityProfileName;
        private String certificateAuthorityName;
        private String username;
        private String password;
        private String accountBindingId;
        private boolean includeChain;
        private String email;
        private String responseFormat;
        private int requestType;
        private String subjectDn;
        private List<Map.Entry<String, String>> extendedData;
        private List<Map.Entry<String, String>> customData;
        private String startTime;
        private String endTime;

        public Builder certificateRequest(final String certificateRequest) {
            this.certificateRequest = certificateRequest;
            return this;
        }

        public Builder certificateProfileName(final String certificateProfileName) {
            this.certificateProfileName = certificateProfileName;
            return this;
        }

        public Builder endEntityProfileName(final String endEntityProfileName) {
            this.endEntityProfileName = endEntityProfileName;
            return this;
        }

        public Builder certificateAuthorityName(final String certificateAuthorityName) {
            this.certificateAuthorityName = certificateAuthorityName;
            return this;
        }

        public Builder username(final String username) {
            this.username = username;
            return this;
        }

        public Builder password(final String password) {
            this.password = password;
            return this;
        }
        
        public Builder accountBindingId(final String accountBindingId) {
            this.accountBindingId = accountBindingId;
            return this;
        }


        public Builder includeChain(final boolean includeChain) {
            this.includeChain = includeChain;
            return this;
        }
        
        public Builder email(final String email) {
            this.email = email;
            return this;
        }

        public Builder responseFormat(String responseFormat) {
            this.responseFormat = responseFormat;
            return this;
        }

        public Builder requestType(String requestType) {
            if (requestType == null) {
                this.requestType = CertificateConstants.CERT_REQ_TYPE_PKCS10;
                return this;
            }
            switch (requestType) {
                case "PUBLICKEY":
                    this.requestType = CertificateConstants.CERT_REQ_TYPE_PUBLICKEY;
                    break;
                case "CRMF":
                    this.requestType = CertificateConstants.CERT_REQ_TYPE_CRMF;
                    break;
                case "SPKAC":
                    this.requestType = CertificateConstants.CERT_REQ_TYPE_SPKAC;
                    break;
                case "CVC":
                    this.requestType = CertificateConstants.CERT_REQ_TYPE_CVC;
                    break;
                case "PKCS10":
                default:
                    this.requestType = CertificateConstants.CERT_REQ_TYPE_PKCS10;
                    break;
            }
            return this;
        }

        public Builder subjectDn(final String subjectDn) {
            this.subjectDn = subjectDn;
            return this;
        }

        public Builder extendedData(final List<Map.Entry<String, String>> extendedData) {
            this.extendedData = extendedData;
            return this;
        }

        public Builder customData(final List<Map.Entry<String, String>> customData) {
            this.customData = customData;
            return this;
        }

        public Builder startTime(final String startTime) {
            this.startTime = startTime;
            return this;
        }

        public Builder endTime(final String endTime) {
            this.endTime = endTime;
            return this;
        }

        public EnrollPkcs10CertificateRequest build() {
            return new EnrollPkcs10CertificateRequest(this);
        }
    }
    
    private EnrollPkcs10CertificateRequest(final Builder builder) {
        this.certificateRequest = builder.certificateRequest;
        this.certificateProfileName = builder.certificateProfileName;
        this.endEntityProfileName = builder.endEntityProfileName;
        this.certificateAuthorityName = builder.certificateAuthorityName;
        this.username = builder.username;
        this.password = builder.password;
        this.accountBindingId = builder.accountBindingId;
        this.includeChain = builder.includeChain;
        this.email = builder.email;
        this.responseFormat = builder.responseFormat;
        this.requestType = builder.requestType;
        this.subjectDn = builder.subjectDn;
        this.extendedData = builder.extendedData;
        this.customData = builder.customData;
        this.startTime = builder.startTime;
        this.endTime = builder.endTime;
    }
}
