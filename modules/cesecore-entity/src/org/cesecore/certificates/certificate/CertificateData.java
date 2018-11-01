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
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.Date;
import java.util.List;

import javax.persistence.ColumnResult;
import javax.persistence.Entity;
import javax.persistence.EntityManager;
import javax.persistence.PostLoad;
import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;
import javax.persistence.Query;
import javax.persistence.SqlResultSetMapping;
import javax.persistence.SqlResultSetMappings;
import javax.persistence.Table;
import javax.persistence.Transient;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.dbprotection.ProtectionStringBuilder;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.StringTools;

/**
 * Representation of a certificate and related information.
 *
 * @version $Id$
 */
@Entity
@Table(name = "CertificateData")
@SqlResultSetMappings(value = {
        @SqlResultSetMapping(name = "RevokedCertInfoSubset", columns = { @ColumnResult(name = "fingerprint"), @ColumnResult(name = "serialNumber"),
                @ColumnResult(name = "expireDate"), @ColumnResult(name = "revocationDate"), @ColumnResult(name = "revocationReason") }),
        @SqlResultSetMapping(name = "CertificateInfoSubset", columns = { @ColumnResult(name = "issuerDN"), @ColumnResult(name = "subjectDN"),
                @ColumnResult(name = "cAFingerprint"), @ColumnResult(name = "status"), @ColumnResult(name = "type"),
                @ColumnResult(name = "serialNumber"),
                @ColumnResult(name = "notBefore"), @ColumnResult(name = "expireDate"), @ColumnResult(name = "revocationDate"),
                @ColumnResult(name = "revocationReason"), @ColumnResult(name = "username"), @ColumnResult(name = "tag"),
                @ColumnResult(name = "certificateProfileId"), @ColumnResult(name = "endEntityProfileId"), @ColumnResult(name = "updateTime"),
                @ColumnResult(name = "subjectKeyId"), @ColumnResult(name = "subjectAltName") }),
        @SqlResultSetMapping(name = "CertificateInfoSubset2", columns = { @ColumnResult(name = "fingerprint"), @ColumnResult(name = "subjectDN"),
                @ColumnResult(name = "cAFingerprint"), @ColumnResult(name = "status"), @ColumnResult(name = "type"),
                @ColumnResult(name = "notBefore"), @ColumnResult(name = "expireDate"), @ColumnResult(name = "revocationDate"),
                @ColumnResult(name = "revocationReason"), @ColumnResult(name = "username"), @ColumnResult(name = "tag"),
                @ColumnResult(name = "certificateProfileId"), @ColumnResult(name = "endEntityProfileId"), @ColumnResult(name = "updateTime"),
                @ColumnResult(name = "subjectKeyId"), @ColumnResult(name = "subjectAltName") }),
        @SqlResultSetMapping(name = "FingerprintUsernameSubset", columns = { @ColumnResult(name = "fingerprint"), @ColumnResult(name = "username") }) })
public class CertificateData extends BaseCertificateData implements Serializable {

    private static final long serialVersionUID = -8493105317760641442L;

    private static final Logger log = Logger.getLogger(CertificateData.class);

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
    private long updateTime = 0;
    private String subjectKeyId;
    private int rowVersion = 0;
    private String rowProtection;

    /**
     * Entity holding info about a certificate. Create by sending in the certificate, which extracts (from the cert) fingerprint (primary key),
     * subjectDN, issuerDN, serial number, expiration date. Status, Type, CAFingerprint, revocationDate and revocationReason are set to default values
     * (CERT_UNASSIGNED, USER_INVALID, null, null and REVOCATION_REASON_UNSPECIFIED) and should be set using the respective set-methods.
     *
     * NOTE! Never use this constructor without considering the useBase64CertTable below!
     *
     * @param certificate the (X509)Certificate to be stored in the database. If the property "database.useSeparateCertificateTable" is true then it should be null.
     * @param enrichedpubkey possibly an EC public key enriched with the full set of parameters, if the public key in the certificate does not have
     *            parameters. Can be null if RSA or certificate public key contains all parameters.
     * @param username the username in UserData to map the certificate to
     * @param cafp CA certificate fingerprint, can be null
     * @param status status of the certificate, active, revoked etcc, i.e. CertificateConstants.CERT_ACTIVE etc
     * @param type the user type the certificate belongs to, i.e. EndEntityTypes.USER_ENDUSER etc
     * @param certprofileid certificate profile id, can be 0 for "no profile"
     * @param endEntityProfileId end entity profile id, can be 0 for "no profile"
     * @param tag a custom tag to map the certificate to any custom defined tag
     * @param updatetime the time the certificate was updated in the database, i.e. System.currentTimeMillis().
     * @param storeCertificate true if the certificate should be stored in this table in the base&4Cert column, false if certificate data isn't to be stored in this table. NOTE: If false and the data should be stored in Base64CertData then the caller must store the certificate in Base64CertData as well.
     * @param storeSubjectAltName true if the subjectAltName column should be populated with the Subject Alternative Name of the certificate
     */
    public CertificateData(Certificate certificate, PublicKey enrichedpubkey, String username, String cafp, int status, int type, int certprofileid, int endEntityProfileId,
            String tag, long updatetime, boolean storeCertificate, boolean storeSubjectAltName) {
        // Extract all fields to store with the certificate.
        try {
            if (storeCertificate ) {
                setBase64Cert(new String(Base64.encode(certificate.getEncoded())));
            }

            String fp = CertTools.getFingerprintAsString(certificate);
            setFingerprint(fp);

            // Make sure names are always looking the same
            setSubjectDN(CertTools.getSubjectDN(certificate));
            setIssuerDN(CertTools.getIssuerDN(certificate));
            if (storeSubjectAltName) {
                setSubjectAltName(CertTools.getSubjectAlternativeName(certificate));
            }
            if (log.isDebugEnabled()) {
                log.debug("Creating CertificateData, subjectDN=" + getSubjectDnNeverNull() + ", subjectAltName=" + getSubjectAltNameNeverNull() + ", issuer=" + getIssuerDN() + ", fingerprint=" + fp+", storeSubjectAltName="+storeSubjectAltName);
            }
            setSerialNumber(CertTools.getSerialNumber(certificate).toString());

            setUsername(username);
            // Values for status and type
            setStatus(status);
            setType(type);
            setCaFingerprint(cafp);
            final Date notBefore = CertTools.getNotBefore(certificate);
            if (notBefore==null) {
                setNotBefore(null);
            } else {
                setNotBefore(notBefore.getTime());
            }
            setExpireDate(CertTools.getNotAfter(certificate));
            setRevocationDate(-1L);
            setRevocationReason(RevokedCertInfo.NOT_REVOKED);
            setUpdateTime(updatetime); // (new Date().getTime());
            setCertificateProfileId(certprofileid);
            setEndEntityProfileId(Integer.valueOf(endEntityProfileId));
            // Create a key identifier
            PublicKey pubk = certificate.getPublicKey();
            if (enrichedpubkey != null) {
                pubk = enrichedpubkey;
            }
            // Creating the KeyId may just throw an exception, we will log this but store the cert and ignore the error
            String keyId = null;
            try {
                keyId = new String(Base64.encode(KeyTools.createSubjectKeyId(pubk).getKeyIdentifier(), false));
            } catch (Exception e) {
                log.warn("Error creating subjectKeyId for certificate with fingerprint '" + fp + ": ", e);
            }
            setSubjectKeyId(keyId);
            setTag(tag);
        } catch (CertificateEncodingException cee) {
            final String msg = "Can't extract DER encoded certificate information.";
            log.error(msg, cee);
            throw new RuntimeException(msg);
        }
    }

    /**
     * Copy Constructor
     */
    public CertificateData(final BaseCertificateData copy) {
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
        setSubjectKeyId(copy.getSubjectKeyId());
        setTag(copy.getTag());
        setRowVersion(copy.getRowVersion());
        setRowProtection(copy.getRowProtection());
    }

    public CertificateData() {
        
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
    
    
    
    //
    // Public business methods used to help us manage certificates
    //
    
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
    
    
    // Comparators

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof CertificateData)) {
            return false;
        }
        return equals((CertificateData) obj, true);
    }

    public boolean equals(CertificateData certificateData, boolean mode, boolean strictStatus) {
        if (mode) {
            return equalsNonSensitive(certificateData, strictStatus);
        }
        return equals(certificateData, strictStatus);
    }

    private boolean equals(CertificateData certificateData, boolean strictStatus) {
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

    private boolean equalsNonSensitive(CertificateData certificateData, boolean strictStatus) {
        if (!issuerDN.equals(certificateData.issuerDN)) {
            return false;
        }
        if (!subjectDN.equals(certificateData.subjectDN)) {
            return false;
        }
        if (!fingerprint.equals(certificateData.fingerprint)) {
            return false;
        }
        if (!StringUtils.equals(cAFingerprint, certificateData.cAFingerprint)) {
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
        if (!StringUtils.equals(username, certificateData.username)) {
            return false;
        }
        if (!StringUtils.equals(tag, certificateData.tag)) {
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
        if (updateTime != certificateData.updateTime) {
            return false;
        }
        if (!StringUtils.equals(subjectAltName, certificateData.subjectAltName)) {
            return false;
        }
        return true;
    }

    @Override
    public int hashCode() {
        return fingerprint.hashCode() * 11;
    }

    public void updateWith(CertificateData certificateData, boolean inclusionMode) {
        issuerDN = certificateData.issuerDN;
        subjectDN = certificateData.subjectDN;
        fingerprint = certificateData.fingerprint;
        cAFingerprint = certificateData.cAFingerprint;
        status = certificateData.status;
        type = certificateData.type;
        serialNumber = certificateData.serialNumber;
        expireDate = certificateData.expireDate;
        revocationDate = certificateData.revocationDate;
        revocationReason = certificateData.revocationReason;
        setUsername(certificateData.username);
        tag = certificateData.tag;
        certificateProfileId = certificateData.certificateProfileId;
        updateTime = certificateData.updateTime;
        base64Cert = inclusionMode ? null : certificateData.base64Cert;
    }

    
    //
    // Search functions (deprecated, use methods in CertificateDataSession instead)
    //

    /** @deprecated Since 6.13.0. Use method in CertificateDataSession instead */
    @Deprecated
    public static CertificateData findByFingerprint(EntityManager entityManager, String fingerprint) {
        return entityManager.find(CertificateData.class, fingerprint);
    }

    /**
     * Get next batchSize row ordered by fingerprint. Used by OcspMonitoringTool.
     *
     * @param certificateProfileId
     * @param currentFingerprint
     * @param batchSize
     * @return List of certificates
     */
    @SuppressWarnings("unchecked")
    public static List<CertificateData> getNextBatch(EntityManager entityManager, int certificateProfileId, String currentFingerprint, int batchSize) {
        final Query query = entityManager
                .createQuery("SELECT a FROM CertificateData a WHERE a.fingerprint>:currentFingerprint AND a.certificateProfileId=:certificateProfileId ORDER BY a.fingerprint ASC");
        query.setParameter("certificateProfileId", certificateProfileId);
        query.setParameter("currentFingerprint", currentFingerprint);
        query.setMaxResults(batchSize);
        return query.getResultList();
    }

    /** Returns the number of entries with the given certificate profile. Used by OcspMonitoringTool. */
    public static long getCount(EntityManager entityManager, int certificateProfileId) {
        final Query countQuery = entityManager
                .createQuery("SELECT COUNT(a) FROM CertificateData a WHERE a.certificateProfileId=:certificateProfileId");
        countQuery.setParameter("certificateProfileId", certificateProfileId);
        return ((Long) countQuery.getSingleResult()).longValue(); // Always returns a result
    }

    /** Returns a list of Certificate Profile IDs that are used in certificates. Used by OcspMonitoringTool. */
    @SuppressWarnings("unchecked")
    public static List<Integer> getUsedCertificateProfileIds(EntityManager entityManager) {
        final Query query = entityManager.createQuery("SELECT DISTINCT a.certificateProfileId FROM CertificateData a ORDER BY a.certificateProfileId");
        return query.getResultList();
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
        return 3;
    }

    @PrePersist
    @PreUpdate
    @Override
    protected void protectData() {
        super.protectData();
    }

    @PostLoad
    @Override
    protected void verifyData() {
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
