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

/**
 * A DTO class representing the input for certificate enrollment.
 *
 * @version $Id: EnrollPkcs10CertificateRequest.java 28909 2018-05-10 12:16:53Z tarmo_r_helmes $
 */
public class EnrollPkcs10CertificateRequest implements Serializable {
    
    private static final long serialVersionUID = 1L;
    
    private String certificateRequest;
    private String certificateProfileName;
    private String endEntityProfileName;
    private String certificateAuthorityName;
    private String username;
    private String password;


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

    public static class Builder {
        private String certificateRequest;
        private String certificateProfileName;
        private String endEntityProfileName;
        private String certificateAuthorityName;
        private String username;
        private String password;

        public Builder certificateRequest(String certificateRequest) {
            this.certificateRequest = certificateRequest;
            return this;
        }

        public Builder certificateProfileName(String certificateProfileName) {
            this.certificateProfileName = certificateProfileName;
            return this;
        }

        public Builder endEntityProfileName(String endEntityProfileName) {
            this.endEntityProfileName = endEntityProfileName;
            return this;
        }

        public Builder certificateAuthorityName(String certificateAuthorityName) {
            this.certificateAuthorityName = certificateAuthorityName;
            return this;
        }

        public Builder username(String username) {
            this.username = username;
            return this;
        }

        public Builder password(String password) {
            this.password = password;
            return this;
        }

        public EnrollPkcs10CertificateRequest build() {
            return new EnrollPkcs10CertificateRequest(this);
        }
    }
    
    private EnrollPkcs10CertificateRequest(Builder builder) {
        this.certificateRequest = builder.certificateRequest;
        this.certificateProfileName = builder.certificateProfileName;
        this.endEntityProfileName = builder.endEntityProfileName;
        this.certificateAuthorityName = builder.certificateAuthorityName;
        this.username = builder.username;
        this.password = builder.password;
    }
}
