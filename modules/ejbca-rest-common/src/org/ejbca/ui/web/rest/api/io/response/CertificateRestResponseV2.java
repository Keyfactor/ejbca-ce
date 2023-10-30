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
package org.ejbca.ui.web.rest.api.io.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import io.swagger.annotations.ApiModelProperty;

/**
 * A class representing general information about a certificate and its CertificateData 
 * for the usage as REST response.
 */
@JsonPropertyOrder({ "fingerprint", "cAFingerprint", "certificateProfileId", "endEntityProfileId", 
    "expireDate", "issuerDN", "notBefore", "revocationDate", "revocationReason", "serialNumber", 
    "status", "subjectAltName", "subjectDN", "subjectKeyId", "tag", "type", "updateTime", "username", 
    "certificate", "certificateRequest", "crlPartitionIndex", "invalidityDate" })
public class CertificateRestResponseV2 {

    @ApiModelProperty(value = "Certificate fingerprint", example = "123abc456def789ghi123klm456nop789qrs123t")
    @JsonInclude(JsonInclude.Include.ALWAYS)
    @JsonProperty("fingerprint") // ECA-11791
    private String fingerprint;

    @ApiModelProperty(value = "Certificate Authority fingerprint", example = "abc123def456ghi789klm123nop456qrs789tvx1")
    @JsonInclude(JsonInclude.Include.ALWAYS)
    @JsonProperty("cAFingerprint") // ECA-11791
    private String caFingerprint;

    @ApiModelProperty(value = "Issuer Distinguished Name", example = "CN=ExampleCA")
    @JsonInclude(JsonInclude.Include.ALWAYS)
    @JsonProperty("issuerDN") // ECA-11791
    private String issuerDN;

    @ApiModelProperty(value = "Subject Distinguished Name", example = "CN=John Doe,SURNAME=Doe,GIVENNAME=John,C=SE")
    @JsonInclude(JsonInclude.Include.ALWAYS)
    @JsonProperty("subjectDN") // ECA-11791
    private String subjectDN;

    @ApiModelProperty(value = "Subject Alternative Name (SAN)", example = "rfc822Name=john.doe@example.com")
    @JsonInclude(JsonInclude.Include.ALWAYS)
    @JsonProperty("subjectAltName") // ECA-11791
    private String subjectAltName;

    @ApiModelProperty(value = "Subject Key Identifier", example = "z123abc456def789ghi123klm456nop789qrs123")
    @JsonInclude(JsonInclude.Include.ALWAYS)
    @JsonProperty("subjectKeyId") // ECA-11791
    private String subjectKeyId;

    @ApiModelProperty(value = "Certificate Profile Identifier", example = "1")
    @JsonInclude(JsonInclude.Include.ALWAYS)
    @JsonProperty("certificateProfileId") // ECA-11791
    private Integer certificateProfileId;

    @ApiModelProperty(value = "End Entity Profile Identifier", example = "1")
    @JsonInclude(JsonInclude.Include.ALWAYS)
    @JsonProperty("endEntityProfileId") // ECA-11791
    private Integer endEntityProfileId;
    
    @ApiModelProperty(value = "Certificate Profile Name", example = "ENDUSER")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonProperty("certificateProfile") // ECA-11791
    private String certificateProfile;

    @ApiModelProperty(value = "End Entity Profile Name", example = "EMPTY")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonProperty("endEntityProfile") // ECA-11791
    private String endEntityProfile;

    @ApiModelProperty(value = "Date at which certificate became valid", example = "1659952800011")
    @JsonInclude(JsonInclude.Include.ALWAYS)
    @JsonProperty("notBefore") // ECA-11791
    private Long notBefore;

    @ApiModelProperty(value = "Date after which certificate should be considered expired", example = "2147483647000")
    @JsonInclude(JsonInclude.Include.ALWAYS)
    @JsonProperty("expireDate") // ECA-11791
    private Long expireDate;

    @ApiModelProperty(value = "Revocation date", example = "-1")
    @JsonInclude(JsonInclude.Include.ALWAYS)
    @JsonProperty("revocationDate") // ECA-11791
    private Long revocationDate = -1L;

    @ApiModelProperty(value = "Revocation reason", example = "-1", allowableValues = "-1, 0, 1, 2, 3, 4, 5, 6, 8, 9, 10")
    @JsonInclude(JsonInclude.Include.ALWAYS)
    @JsonProperty("revocationReason") // ECA-11791
    private Integer revocationReason = -1;

    @ApiModelProperty(value = "Hex Serial Number", example = "1234567890ABCDEF")
    @JsonInclude(JsonInclude.Include.ALWAYS)
    @JsonProperty("serialNumber") // ECA-11791
    private String serialNumber;

    @ApiModelProperty(value = "Certificate status", example = "20")
    @JsonInclude(JsonInclude.Include.ALWAYS)
    @JsonProperty("status") // ECA-11791
    private Integer status;
    
    @JsonInclude(JsonInclude.Include.ALWAYS)
    @JsonProperty("tag") // ECA-11791
    private String tag;
    
    @JsonInclude(JsonInclude.Include.ALWAYS)
    @JsonProperty("type") // ECA-11791
    private Integer type;

    @ApiModelProperty(value = "Update time", example = "1659967133000")
    @JsonInclude(JsonInclude.Include.ALWAYS)
    @JsonProperty("udpateTime") // ECA-11791
    private Long updateTime;

    @ApiModelProperty(value = "Username", example = "JohnDoe")
    @JsonInclude(JsonInclude.Include.ALWAYS)
    @JsonProperty("username") // ECA-11791
    private String username;

    @ApiModelProperty(value = "Base64 encoded certificate", example = "TUlJR...t2A==")
    @JsonInclude(JsonInclude.Include.ALWAYS)
    @JsonProperty("base64Cert") // ECA-11791
    private byte[] certificate;

    @ApiModelProperty(value = "Certificate request", example = "-----BEGIN CERTIFICATE REQUEST-----\nMIICh...V8shQ==\n-----END CERTIFICATE REQUEST-----")
    @JsonInclude(JsonInclude.Include.ALWAYS)
    @JsonProperty("certificateRequest") // ECA-11791
    private String certificateRequest;

    @ApiModelProperty(value = "CRL partition index", example = "1")

    @JsonInclude(JsonInclude.Include.ALWAYS)
    @JsonProperty("crlPartitionIndex") // ECA-11791
    private Integer crlPartitionIndex;

    @ApiModelProperty(value = "Invalidity date", example = "-1")
    private Long invalidityDate;

    private CertificateRestResponseV2(final CertificateRestResponseBuilderV2 builder) {
        this.fingerprint = builder.fingerprint;
        this.caFingerprint = builder.cAFingerprint;
        this.issuerDN = builder.issuerDN;
        this.subjectDN = builder.subjectDN;
        this.subjectAltName = builder.subjectAltName;
        this.subjectKeyId = builder.subjectKeyId;
        this.certificateProfileId = builder.certificateProfileId;
        this.endEntityProfileId = builder.endEntityProfileId;
        this.certificateProfile = builder.certificateProfile;
        this.endEntityProfile = builder.endEntityProfile;
        this.expireDate = builder.expireDate;
        this.notBefore = builder.notBefore;
        this.revocationDate = builder.revocationDate;
        this.revocationReason = builder.revocationReason;
        this.serialNumber = builder.serialNumber;
        this.status = builder.status;
        this.tag = builder.tag;
        this.type = builder.type;
        this.updateTime = builder.updateTime;
        this.username = builder.username;
        this.certificate = builder.certificate;
        this.certificateRequest = builder.certificateRequest;
        this.crlPartitionIndex = builder.crlPartitionIndex;
        this.invalidityDate = builder.invalidityDate;
    }

    /**
     * Return a builder instance for this class.
     *
     * @return builder instance for this class.
     */
    public static CertificateRestResponseBuilderV2 builder() {
        return new CertificateRestResponseBuilderV2();
    }

    public byte[] getCertificate() {
        // Base64 serialized string as byte array --> already done here.
        return certificate;
    }
    
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
    
    public String getCertificateProfile() {
        return certificateProfile;
    }

    public String getEndEntityProfile() {
        return endEntityProfile;
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

    public String getCertificateRequest() {
        return certificateRequest;
    }

    public Integer getCrlPartitionIndex() {
        return crlPartitionIndex;
    }

    public String getSerialNumber() {
        return serialNumber;
    }

    public Long getInvalidityDate() {
        return invalidityDate;
    }
    
    public static class CertificateRestResponseBuilderV2 {
        
        private String fingerprint;
        private String cAFingerprint;
        private String issuerDN;
        private String subjectDN;
        private String subjectAltName;
        private String subjectKeyId;
        private Integer certificateProfileId;
        private Integer endEntityProfileId;
        private String certificateProfile;
        private String endEntityProfile;
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
        private String certificateRequest;
        private Integer crlPartitionIndex;
        private Long invalidityDate;
        
        private CertificateRestResponseBuilderV2() {
        }

        public CertificateRestResponseBuilderV2 setFingerprint(String fingerprint) {
            this.fingerprint = fingerprint;
            return this;
        }
        
        public CertificateRestResponseBuilderV2 setCAFingerprint(String cAFingerprint) {
            this.cAFingerprint = cAFingerprint;
            return this;
        }
        
        public CertificateRestResponseBuilderV2 setIssuerDN(String issuerDN) {
            this.issuerDN = issuerDN;
            return this;
        }
        
        public CertificateRestResponseBuilderV2 setSubjectDN(String subjectDN) {
            this.subjectDN = subjectDN;
            return this;
        }
        
        public CertificateRestResponseBuilderV2 setSubjectAltName(String san) {
            this.subjectAltName = san;
            return this;
        }
        
        public CertificateRestResponseBuilderV2 setSubjectKeyId(String subjectKeyId) {
            this.subjectKeyId = subjectKeyId;
            return this;
        }
        
        public CertificateRestResponseBuilderV2 setCertificateProfileId(Integer id) {
            this.certificateProfileId = id;
            return this;
        }
        
        public CertificateRestResponseBuilderV2 setEndEntityProfileId(Integer id) {
            this.endEntityProfileId = id;
            return this;
        }
        
        public CertificateRestResponseBuilderV2 setCertificateProfile(String name) {
            this.certificateProfile = name;
            return this;
        }
        
        public CertificateRestResponseBuilderV2 setEndEntityProfile(String name) {
            this.endEntityProfile = name;
            return this;
        }
        
        public CertificateRestResponseBuilderV2 setNotBefore(Long millis) {
            this.notBefore = millis;
            return this;
        }
        
        public CertificateRestResponseBuilderV2 setExpireDate(Long millis) {
            this.expireDate = millis;
            return this;
        }
        
        public CertificateRestResponseBuilderV2 setRevocationDate(Long millis) {
            this.revocationDate = millis;
            return this;
        }
        
        public CertificateRestResponseBuilderV2 setRevocationReason(Integer reason) {
            this.revocationReason = reason;
            return this;
        }

        public CertificateRestResponseBuilderV2 setSerialNumber(String serialNumber) {
            this.serialNumber = serialNumber;
            return this;
        }

        public CertificateRestResponseBuilderV2 setStatus(Integer status) {
            this.status = status;
            return this;
        }
        
        public CertificateRestResponseBuilderV2 setTag(String tag) {
            this.tag = tag;
            return this;
        }
        
        public CertificateRestResponseBuilderV2 setType(Integer type) {
            this.type = type;
            return this;
        }
        
        public CertificateRestResponseBuilderV2 setUpdateTime(Long millis) {
            this.updateTime = millis;
            return this;
        }

        public CertificateRestResponseBuilderV2 setUsername(String username) {
            this.username = username;
            return this;
        }
        
        public CertificateRestResponseBuilderV2 setCertificate(byte[] certificate) {
            this.certificate = certificate;
            return this;
        }
        
        public CertificateRestResponseBuilderV2 setCertificateRequest(String certificateRequest) {
            this.certificateRequest = certificateRequest;
            return this;
        }
        
        public CertificateRestResponseBuilderV2 setCrlPartitionIndex(Integer index) {
            this.crlPartitionIndex = index;
            return this;
        }

        public CertificateRestResponseBuilderV2 setInvalidityDate(long millis) {
            this.invalidityDate = millis;
            return this;
        }
        
        public CertificateRestResponseV2 build() {
            return new CertificateRestResponseV2(this);
        }
    }
}
