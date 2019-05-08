/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.certificate;

import java.io.Serializable;

import javax.persistence.ColumnResult;
import javax.persistence.Entity;
import javax.persistence.PostLoad;
import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;
import javax.persistence.SqlResultSetMapping;
import javax.persistence.SqlResultSetMappings;
import javax.persistence.Table;
import javax.persistence.Transient;

import org.apache.commons.lang.ObjectUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.dbprotection.DatabaseProtectionException;
import org.cesecore.dbprotection.ProtectionStringBuilder;
import org.cesecore.util.CertTools;
import org.cesecore.util.StringTools;

/**
 * Representation of a revoked throw-away certificate and related information.
 *
 * @version $Id: NoConflictCertificateData.java 28264 2018-04-09 15:56:54Z tarmo $
 */
@Entity
@Table(name = "NoConflictCertificateData")
@SqlResultSetMappings(value = {
        @SqlResultSetMapping(name = "RevokedNoConflictCertInfoSubset", columns = { @ColumnResult(name = "fingerprint"), @ColumnResult(name = "serialNumber"),
                @ColumnResult(name = "expireDate"), @ColumnResult(name = "revocationDate"), @ColumnResult(name = "revocationReason") }),
        @SqlResultSetMapping(name = "NoConflictCertificateInfoSubset", columns = { @ColumnResult(name = "issuerDN"), @ColumnResult(name = "subjectDN"),
                @ColumnResult(name = "cAFingerprint"), @ColumnResult(name = "status"), @ColumnResult(name = "type"),
                @ColumnResult(name = "serialNumber"),
                @ColumnResult(name = "notBefore"), @ColumnResult(name = "expireDate"), @ColumnResult(name = "revocationDate"),
                @ColumnResult(name = "revocationReason"), @ColumnResult(name = "username"), @ColumnResult(name = "tag"),
                @ColumnResult(name = "certificateProfileId"), @ColumnResult(name = "endEntityProfileId"), @ColumnResult(name = "updateTime"),
                @ColumnResult(name = "subjectKeyId"), @ColumnResult(name = "subjectAltName") }),
        @SqlResultSetMapping(name = "NoConflictCertificateInfoSubset2", columns = { @ColumnResult(name = "fingerprint"), @ColumnResult(name = "subjectDN"),
                @ColumnResult(name = "cAFingerprint"), @ColumnResult(name = "status"), @ColumnResult(name = "type"),
                @ColumnResult(name = "notBefore"), @ColumnResult(name = "expireDate"), @ColumnResult(name = "revocationDate"),
                @ColumnResult(name = "revocationReason"), @ColumnResult(name = "username"), @ColumnResult(name = "tag"),
                @ColumnResult(name = "certificateProfileId"), @ColumnResult(name = "endEntityProfileId"), @ColumnResult(name = "updateTime"),
                @ColumnResult(name = "subjectKeyId"), @ColumnResult(name = "subjectAltName") }),
        @SqlResultSetMapping(name = "NoConflictCertificateFingerprintUsernameSubset", columns = { @ColumnResult(name = "fingerprint"), @ColumnResult(name = "username") }) })
public class NoConflictCertificateData extends BaseCertificateData implements Serializable {
    
    private static final long serialVersionUID = 1L;

    private static final Logger log = Logger.getLogger(NoConflictCertificateData.class);

    private static final int LATEST_PROTECT_VERSON = 5;

    private String id;
    private String issuerDN;
    private String subjectDN;
    private String subjectAltName = null;  // @since EJBCA 6.6.0
    private String fingerprint = "";
    private String cAFingerprint;
    private int status = 0;
    private int type = 0;
    private String serialNumber;
    private Long notBefore = null;  // @since EJBCA 6.6.0
    private long expireDate = 0;
    private long revocationDate = 0;
    private int revocationReason = 0;
    private String base64Cert;
    private String username;
    private String tag;
    private Integer certificateProfileId;
    private Integer endEntityProfileId = null;  // @since EJBCA 6.6.0
    private Integer crlPartitionIndex = null; // @since EJBCA 7.1.0
    private long updateTime = 0;
    private String subjectKeyId;
    private String certificateRequest;  // @since EJBCA 7.0.0
    private int rowVersion = 0;
    private String rowProtection;
    
    
    /**
     * Copy Constructor
     */
    public NoConflictCertificateData(final NoConflictCertificateData copy) {
        setId(copy.getId());
        setBase64Cert(copy.getBase64Cert());
        setFingerprint(copy.getFingerprint());
        setSubjectDN(copy.getSubjectDN());
        setIssuerDN(copy.getIssuerDN());
        setSubjectAltName(copy.getSubjectAltName());
        setSerialNumber(copy.getSerialNumber());
        setUsername(copy.getUsername());
        setStatus(copy.getStatus());
        setType(copy.getType());
        setCaFingerprint(copy.getCaFingerprint());
        setNotBefore(copy.getNotBefore());
        setExpireDate(copy.getExpireDate());
        setRevocationDate(copy.getRevocationDate());
        setRevocationReason(copy.getRevocationReason());
        setUpdateTime(copy.getUpdateTime());
        setCertificateProfileId(copy.getCertificateProfileId());
        setEndEntityProfileId(copy.getEndEntityProfileId());
        setCrlPartitionIndex(copy.getCrlPartitionIndex());
        setSubjectKeyId(copy.getSubjectKeyId());
        setTag(copy.getTag());
        setCertificateRequest(copy.getCertificateRequest());
        setRowVersion(copy.getRowVersion());
        setRowProtection(copy.getRowProtection());
    }

    public NoConflictCertificateData() {
        
    }
    
    /**
     * Generated GUID for the table entry
     * 
     * @return id
     */
    public String getId() {
        return id;
    }

    /** Generated GUID for the table entry
     * 
     * @param id
     */
    public void setId(String id) {
        this.id = id;
    }

    @Override
    public String getFingerprint() {
        return fingerprint;
    }

    @Override
    public void setFingerprint(String fingerprint) {
        this.fingerprint = fingerprint;
    }

    @Override
    public String getIssuerDN() {
        return issuerDN;
    }

    @Override
    public void setIssuerDN(String issuerDN) {
        this.issuerDN = issuerDN;
    }

    @Override
    public String getSubjectDN() {
        return subjectDN;
    }

    /**
     * Use setSubject instead
     *
     * @param subjectDN subject dn
     * @see #setSubject(String)
     */
    public void setSubjectDN(String subjectDN) {
        this.subjectDN = subjectDN;
    }

    /** @return Subject Alternative Name from the certificate if it was saved at the time of issuance. */
    @Transient
    public String getSubjectAltNameNeverNull() {
        final String subjectAltName = getSubjectAltName();
        return subjectAltName == null ? "" : subjectAltName;
    }

    @Override
    public String getSubjectAltName() {
        return subjectAltName;
    }
    public void setSubjectAltName(final String subjectAltName) {
        this.subjectAltName = subjectAltName;
    }

    @Override
    public String getCaFingerprint() {
        return cAFingerprint;
    }

    @Override
    public void setCaFingerprint(String cAFingerprint) {
        this.cAFingerprint = cAFingerprint;
    }

    @Override
    public int getStatus() {
        return status;
    }

    @Override
    public void setStatus(int status) {
        this.status = status;
    }

    @Override
    public int getType() {
        return type;
    }

    @Override
    public void setType(int type) {
        this.type = type;
    }

    @Override
    public String getSerialNumber() {
        return serialNumber;
    }

    @Override
    public void setSerialNumber(String serialNumber) {
        this.serialNumber = serialNumber;
    }

    @Override
    public Long getNotBefore() {
        return notBefore;
    }
    public void setNotBefore(final Long notBefore) {
        this.notBefore = notBefore;
    }

    @Override
    public long getExpireDate() {
        return expireDate;
    }

    @Override
    public void setExpireDate(long expireDate) {
        this.expireDate = expireDate;
    }

    @Override
    public long getRevocationDate() {
        return revocationDate;
    }

    @Override
    public void setRevocationDate(long revocationDate) {
        this.revocationDate = revocationDate;
    }

    @Override
    public int getRevocationReason() {
        return revocationReason;
    }

    @Override
    public void setRevocationReason(int revocationReason) {
        this.revocationReason = revocationReason;
    }

    @Override
    public String getBase64Cert() {
        return this.getZzzBase64Cert();
    }

    /**
     * The certificate itself
     *
     * @param base64Cert base64 encoded certificate
     */
    public void setBase64Cert(String base64Cert) {
        this.setZzzBase64Cert(base64Cert);
    }

    /**
     * Horrible work-around due to the fact that Oracle needs to have (LONG and) CLOB values last in order to avoid ORA-24816.
     *
     * Since Hibernate sorts columns by the property names, naming this Z-something will apparently ensure that this column is used last.
     * @deprecated Use {@link #getBase64Cert()} instead
     */
    @Deprecated
    public String getZzzBase64Cert() {
        return base64Cert;
    }
    
    /** @deprecated Use {@link #setBase64Cert(String)} instead */
    @Deprecated
    public void setZzzBase64Cert(final String zzzBase64Cert) {
        this.base64Cert = zzzBase64Cert;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public void setUsername(String username) {
        this.username = StringTools.stripUsername(username);
    }

    @Override
    public String getTag() {
        return tag;
    }

    /**
     * tag in database. This field was added for the 3.9.0 release, but is not used yet.
     *
     * @param tag tag
     */
    public void setTag(String tag) {
        this.tag = tag;
    }

    @Override
    public Integer getCertificateProfileId() {
        return certificateProfileId;
    }

    @Override
    public void setCertificateProfileId(Integer certificateProfileId) {
        this.certificateProfileId = certificateProfileId;
    }

    @Override
    public Long getUpdateTime() {
        return updateTime;
    }

    // Hibernate + Oracle ignores nullable=false so we can expect null-objects as input after upgrade. TODO: Verify if still true!
    @Override
    public void setUpdateTime(Long updateTime) {
        this.updateTime = (updateTime == null ? this.updateTime : updateTime);
    }

    @Override
    public String getSubjectKeyId() {
        return subjectKeyId;
    }

    /**
     * The ID of the public key of the certificate
     */
    public void setSubjectKeyId(String subjectKeyId) {
        this.subjectKeyId = subjectKeyId;
    }
    
    @Override
    public int getRowVersion() {
        return rowVersion;
    }

    public void setRowVersion(int rowVersion) {
        this.rowVersion = rowVersion;
    }
    
    @Override
    public String getRowProtection() {
        return this.getZzzRowProtection();
    }

    @Override
    public void setRowProtection(String rowProtection) {
        this.setZzzRowProtection(rowProtection);
    }

    /**
     * Horrible work-around due to the fact that Oracle needs to have (LONG and) CLOB values last in order to avoid ORA-24816.
     *
     * Since Hibernate sorts columns by the property names, naming this Z-something will apparently ensure that this column is used last.
     * @deprecated Use {@link #getRowProtection()} instead
     */
    @Deprecated
    public String getZzzRowProtection() {
        return rowProtection;
    }
    /** @deprecated Use {@link #setRowProtection(String)} instead */
    @Deprecated
    public void setZzzRowProtection(final String zzzRowProtection) {
        this.rowProtection = zzzRowProtection;
    }
    
    @Override
    public void setIssuer(String dn) {
        setIssuerDN(CertTools.stringToBCDNString(dn));
    }

    @Override
    public void setSubject(String dn) {
        setSubjectDN(CertTools.stringToBCDNString(dn));
    }

    @Override
    public void setEndEntityProfileId(final Integer endEntityProfileId) {
        this.endEntityProfileId = endEntityProfileId;
    }
    
    @Override
    public Integer getEndEntityProfileId() {
        return endEntityProfileId;
    }

    @Override
    public Integer getCrlPartitionIndex() {
        return crlPartitionIndex != null ? crlPartitionIndex : 0;
    }

    @Override
    public void setCrlPartitionIndex(final Integer crlPartitionIndex) {
        this.crlPartitionIndex = crlPartitionIndex;
    }
    
    @Override
    public String getCertificateRequest() {
        return this.getZzzCertificateRequest();
    }
    
    @Override
    public void setCertificateRequest(String certificateRequest) {
        this.setZzzCertificateRequest(certificateRequest);
    }
    

    /**
     * Horrible work-around due to the fact that Oracle needs to have (LONG and) CLOB values last in order to avoid ORA-24816.
     *
     * Since Hibernate sorts columns by the property names, naming this Z-something will apparently ensure that this column is used last.
     * @deprecated Use {@link #getCertificateRequest()} instead
     */
    @Deprecated
    public String getZzzCertificateRequest() {
        return this.certificateRequest;
    }
    
    /** @deprecated Use {@link #setCertificateRequest(String)} instead */
    @Deprecated
    public void setZzzCertificateRequest(String certificateRequest) {
        this.certificateRequest = certificateRequest;
    }
    
    
    // Comparators

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof NoConflictCertificateData)) {
            return false;
        }
        return equals((NoConflictCertificateData) obj, true);
    }

    public boolean equals(NoConflictCertificateData certificateData, boolean mode, boolean strictStatus) {
        if (mode) {
            return equalsNonSensitive(certificateData, strictStatus);
        }
        return equals(certificateData, strictStatus);
    }

    private boolean equals(NoConflictCertificateData certificateData, boolean strictStatus) {
        if (!equalsNonSensitive(certificateData, strictStatus)) {
            return false;
        }
        if ( this.base64Cert==null && certificateData.base64Cert==null ) {
            return true; // test before shows that fingerprint is equal and then both objects must refer to same row in Base64CertData
        }
        if ( this.base64Cert==null || certificateData.base64Cert==null ) {
            return false; // one is null and the other not null
        }
        if (!this.base64Cert.equals(certificateData.base64Cert)) {
            return false;
        }
        return true;
    }

    private boolean equalsNonSensitive(NoConflictCertificateData certificateData, boolean strictStatus) {
        
        if (!id.equals(certificateData.id)) {
            return false;
        }
        if (!issuerDN.equals(certificateData.issuerDN)) {
            return false;
        }
        if (!subjectDN.equals(certificateData.subjectDN)) {
            return false;
        }
        if (!fingerprint.equals(certificateData.fingerprint)) {
            return false;
        }
        if (!cAFingerprint.equals(certificateData.cAFingerprint)) {
            return false;
        }
        if (!equalsStatus(certificateData, strictStatus)) {
            return false;
        }
        if (type != certificateData.type) {
            return false;
        }
        if (!serialNumber.equals(certificateData.serialNumber)) {
            return false;
        }
        if (notBefore==null) {
            if (certificateData.notBefore!=null) {
                return false;
            }
        } else {
            if (!notBefore.equals(certificateData.notBefore)) {
                return false;
            }
        }
        if (expireDate != certificateData.expireDate) {
            return false;
        }
        if (revocationDate != certificateData.revocationDate) {
            return false;
        }
        if (revocationReason != certificateData.revocationReason) {
            return false;
        }
        if (!username.equals(certificateData.username)) {
            return false;
        }
        if (tag == null && certificateData.tag != null) {
            return false;
        }
        if (tag != null && !tag.equals(certificateData.tag)) {
            return false;
        }
        if (certificateProfileId == null && certificateData.certificateProfileId != null) {
            return false;
        }
        if (certificateProfileId != null && !certificateProfileId.equals(certificateData.certificateProfileId)) {
            return false;
        }
        if (endEntityProfileId==null) {
            if (certificateData.endEntityProfileId!=null) {
                return false;
            }
        } else {
            if (!endEntityProfileId.equals(certificateData.endEntityProfileId)) {
                return false;
            }
        }
        if (!ObjectUtils.defaultIfNull(crlPartitionIndex, 0).equals(ObjectUtils.defaultIfNull(certificateData.crlPartitionIndex, 0))) {
            return false;
        }
        if (updateTime != certificateData.updateTime) {
            return false;
        }
        if (subjectAltName==null) {
            if (certificateData.subjectAltName!=null) {
                return false;
            }
        } else {
            if (!subjectAltName.equals(certificateData.subjectAltName)) {
                return false;
            }
        }
        if (!StringUtils.equals(certificateRequest, certificateData.certificateRequest)) {
            return false;
        }
        return true;
    }
    
    @Override
    public int hashCode() {
        return fingerprint.hashCode() * 11;
    }

    //
    // Start Database integrity protection methods
    //

    @Transient
    @Override
    protected String getProtectString(final int version) {
    	final ProtectionStringBuilder build = new ProtectionStringBuilder(3000);
        // What is important to protect here is the data that we define, id, name and certificate profile data
        // rowVersion is automatically updated by JPA, so it's not important, it is only used for optimistic locking
        build.append(getFingerprint()).append(getIssuerDN());
        if (version >= 5) {
            // In version 5 (EJBCA 7.1.0) the crlPartitionIndex column is added
            build.append(getCrlPartitionIndex());
        }
        if (version >= 4) {
            // This field was actually added in EJBCA 7.0.0, but wasn't added here until 7.1.0.
            // So version 4 will never appear in the database, only 5 or later.
            // We check for version 4 in case we would need to backport this change to 7.0.x, independently of the change in version 5.
            build.append(getCertificateRequest());
        }
        if (version>=3) {
            // From version 3 for EJBCA 6.7 we always use empty String here to allow future migration between databases when this value is unset
            build.append(getSubjectDnNeverNull());
        } else {
            build.append(getSubjectDN());
        }
        build.append(getCaFingerprint()).append(getStatus()).append(getType())
                .append(getSerialNumber()).append(getExpireDate()).append(getRevocationDate()).append(getRevocationReason()).append(getBase64Cert())
                .append(getUsername()).append(getTag()).append(getCertificateProfileId()).append(getUpdateTime()).append(getSubjectKeyId());
        if (version>=2) {
            // In version 2 for EJBCA 6.6 the following columns where added
            build.append(String.valueOf(getNotBefore()));
            build.append(String.valueOf(getEndEntityProfileId()));
            if (version>=3) {
                // From version 3 for EJBCA 6.7 we always use empty String here to allow future migration between databases when this value is unset
                build.append(getSubjectAltNameNeverNull());
            } else {
                build.append(String.valueOf(getSubjectAltName()));
            }
        }
        if (log.isDebugEnabled()) {
            // Some profiling
            if (build.length() > 3000) {
                log.debug("CertificateData.getProtectString gives size: " + build.length());
            }
        }
        return build.toString();
    }

    @Transient
    @Override
    protected int getProtectVersion() {
        return LATEST_PROTECT_VERSON;
    }

    @PrePersist
    @PreUpdate
    @Override
    protected void protectData() throws DatabaseProtectionException {
        super.protectData();
    }

    @PostLoad
    @Override
    protected void verifyData() throws DatabaseProtectionException {
        super.verifyData();
    }

    @Override
    @Transient
    protected String getRowId() {
        return getFingerprint();
    }
    
    //
    // End Database integrity protection methods
    //
}
