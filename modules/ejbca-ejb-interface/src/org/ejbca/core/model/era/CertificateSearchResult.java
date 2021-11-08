/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.model.era;

/**
 * A class representing certificate data for the usage as REST interface.
 */
public class CertificateSearchResult {
    
    public CertificateSearchResult(String fingerprint, String caFingerprint, String issuerDN, String subjectDN, String subjectAltName,
            String subjectKeyId, Integer certificateProfileId, Integer endEntityProfileId, Long notBefore, Long expireDate, Long revocationDate,
            Integer revocationReason, String serialNumber, Integer status, String tag, Integer type, Long updateTime, String username,
            byte[] certificate, byte[] certificateRequest, Integer crlPartitionIndex, String responseFormat) {
        super();
        this.fingerprint = fingerprint;
        this.caFingerprint = caFingerprint;
        this.issuerDN = issuerDN;
        this.subjectDN = subjectDN;
        this.subjectAltName = subjectAltName;
        this.subjectKeyId = subjectKeyId;
        this.certificateProfileId = certificateProfileId;
        this.endEntityProfileId = endEntityProfileId;
        this.notBefore = notBefore;
        this.expireDate = expireDate;
        this.revocationDate = revocationDate;
        this.revocationReason = revocationReason;
        this.serialNumber = serialNumber;
        this.status = status;
        this.tag = tag;
        this.type = type;
        this.updateTime = updateTime;
        this.username = username;
        this.certificate = certificate;
        this.certificateRequest = certificateRequest;
        this.crlPartitionIndex = crlPartitionIndex;
        this.responseFormat = responseFormat;
    }

    private String fingerprint;
    
    private String caFingerprint;
    
    private String issuerDN;
    
    private String subjectDN;
    
    private String subjectAltName;
    
    private String subjectKeyId;
    
    private Integer certificateProfileId;
    
    private Integer endEntityProfileId;
    
    private Long notBefore;
    
    private Long expireDate;
    
    private Long revocationDate;
    
    private Integer revocationReason;
    
    private String serialNumber;
    
    private Integer status;
    
    private String tag;
    
    private Integer type;
    
    private Long updateTime;
    
    private String username;
    
    private byte[] certificate;
    
    private byte[] certificateRequest;
    
    private Integer crlPartitionIndex;
    
    private String responseFormat;

    public String getFingerprint() {
        return fingerprint;
    }

    public String getCaFingerprint() {
        return caFingerprint;
    }

    public String getIssuerDN() {
        return issuerDN;
    }

    public String getSubjectDN() {
        return subjectDN;
    }

    public String getSubjectAltName() {
        return subjectAltName;
    }

    public String getSubjectKeyId() {
        return subjectKeyId;
    }

    public Integer getCertificateProfileId() {
        return certificateProfileId;
    }

    public Integer getEndEntityProfileId() {
        return endEntityProfileId;
    }

    public Long getNotBefore() {
        return notBefore;
    }

    public Long getExpireDate() {
        return expireDate;
    }

    public Long getRevocationDate() {
        return revocationDate;
    }

    public Integer getRevocationReason() {
        return revocationReason;
    }

    public String getSerialNumber() {
        return serialNumber;
    }

    public Integer getStatus() {
        return status;
    }

    public String getTag() {
        return tag;
    }

    public Integer getType() {
        return type;
    }

    public Long getUpdateTime() {
        return updateTime;
    }

    public String getUsername() {
        return username;
    }

    public byte[] getCertificate() {
        return certificate;
    }

    public byte[] getCertificateRequest() {
        return certificateRequest;
    }

    public Integer getCrlPartitionIndex() {
        return crlPartitionIndex;
    }

    public String getResponseFormat() {
        return responseFormat;
    }

}
