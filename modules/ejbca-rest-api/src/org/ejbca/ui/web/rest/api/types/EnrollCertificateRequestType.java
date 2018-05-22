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
package org.ejbca.ui.web.rest.api.types;

/**
 * A class representing the input for certificate enrollment REST method.
 *
 * @version $Id: EnrollCertificateRequestType.java 28909 2018-05-10 12:16:53Z tarmo_r_helmes $
 */
public class EnrollCertificateRequestType {
        
    private String certificateRequest;
    private Integer certificateProfileId;
    private Integer endEntityProfileId; 
    private Integer certificateAuthorityId;
    private String username;
    private String password;
    
    
    public EnrollCertificateRequestType() {
        
    }
    
    public String getCertificateRequest() {
        return certificateRequest;
    }
    public void setCertificateRequest(String certificateRequest) {
        this.certificateRequest = certificateRequest;
    }
    public Integer getCertificateProfileId() {
        return certificateProfileId;
    }
    public void setCertificateProfileId(Integer certificateProfileId) {
        this.certificateProfileId = certificateProfileId;
    }
    public Integer getEndEntityProfileId() {
        return endEntityProfileId;
    }
    public void setEndEntityProfileId(Integer endEntityProfileId) {
        this.endEntityProfileId = endEntityProfileId;
    }
    public Integer getCertificateAuthorityId() {
        return certificateAuthorityId;
    }
    public void setCertificateAuthorityId(Integer certificateAuthorityId) {
        this.certificateAuthorityId = certificateAuthorityId;
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
}