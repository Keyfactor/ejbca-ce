package org.ejbca.ui.web.rest.api.types;

public class EnrollCertificateRequestType {
        
    String certificateRequest;
    Integer certificateProfileId;
    Integer endEntityProfileId; 
    Integer certificateAuthorityId;

    /*
    public EnrollCertificateRequestType(String certificateRequest, Integer certificateProfileId, Integer endEntityProfileId, Integer certificateAuthorityId) {
        this.certificateRequest = certificateRequest;
        this.certificateProfileId = certificateProfileId;
        this.endEntityProfileId = endEntityProfileId;
        this.certificateAuthorityId = certificateAuthorityId;
    }
    */
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
}