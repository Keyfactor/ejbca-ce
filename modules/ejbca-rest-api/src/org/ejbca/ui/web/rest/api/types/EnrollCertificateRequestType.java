package org.ejbca.ui.web.rest.api.types;

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