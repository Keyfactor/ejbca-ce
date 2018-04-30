package org.ejbca.core.ejb.dto;

import java.io.Serializable;
import java.util.Date;

public class CertRevocationDto implements Serializable {
    
    private static final long serialVersionUID = 1L;
    
    String issuerDN;
    String certificateSN;
    int reason;
    Date revocationDate; 
    int certificateProfileId;
    boolean checkDate;
    
    
    public CertRevocationDto(String issuerDN, String certificateSN, int reason) {
        this.issuerDN = issuerDN;
        this.certificateSN = certificateSN;
        this.reason = reason;
    }

    public CertRevocationDto(String issuerDN, String certificateSN) {
        this.issuerDN = issuerDN;
        this.certificateSN = certificateSN;
    }
    
    public String getIssuerDN() {
        return issuerDN;
    }
    
    public void setIssuerDN(String issuerDN) {
        this.issuerDN = issuerDN;
    }
    
    public String getCertificateSN() {
        return certificateSN;
    }
    
    public void setCertificateSN(String certificateSN) {
        this.certificateSN = certificateSN;
    }
    
    public int getReason() {
        return reason;
    }
    
    public void setReason(int reason) {
        this.reason = reason;
    }
    
    public Date getRevocationDate() {
        return revocationDate;
    }

    public void setRevocationDate(Date revocationDate) {
        this.revocationDate = revocationDate;
    }

    public int getCertificateProfileId() {
        return certificateProfileId;
    }
    
    public void setCertificateProfileId(int certificateProfileId) {
        this.certificateProfileId = certificateProfileId;
    }
    
    public boolean isCheckDate() {
        return checkDate;
    }
    
    public void setCheckDate(boolean checkDate) {
        this.checkDate = checkDate;
    }
}
