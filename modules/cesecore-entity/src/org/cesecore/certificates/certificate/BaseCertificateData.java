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

import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Date;

import javax.persistence.EntityManager;
import javax.persistence.Transient;

import org.apache.commons.lang.ClassUtils;
import org.apache.log4j.Logger;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.dbprotection.ProtectedData;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;

/**
 * Used as base class for NoConflictCertificateData and CertificateData to group the common logic for those entites
 *
 * @version $Id: ProtectedCertificateData.java 28264 2018-04-09 15:56:54Z tarmo $
 */
public abstract class BaseCertificateData extends ProtectedData {

    private static final Logger log = Logger.getLogger(BaseCertificateData.class);

    /**
     * The certificate itself
     *
     * @return base64 encoded certificate
     */
    public abstract String getBase64Cert();
    
    /**
     * Fingerprint of certificate
     *
     * @return fingerprint
     */
    public abstract String getFingerprint();
    
    /**
     * Use getSubjectDnNeverNull() for consistent access, since Oracle will treat empty Strings as NULL.
     *
     * @return value as it is stored in the database
     */
    public abstract String getSubjectDN();
    
    /**
     * DN of issuer of certificate
     *
     * @return issuer dn
     */
    public abstract String getIssuerDN();
    
    /**
     * Serialnumber formated as BigInteger.toString()
     *
     * @return serial number
     */
    public abstract String getSerialNumber();
    
    /**
     * username in database
     *
     * @return username
     */
    public abstract String getUsername();
    
    /**
     * Use getSubjectAltNameNeverNull() for consistent access, since Oracle will treat empty Strings as null.
     *
     * @return value as it is stored in the database
     */
    public abstract String getSubjectAltName();
    
    /**
     * Certificate Profile Id that was used to issue this certificate.
     *
     * @return certificateProfileId
     */
    public abstract Integer getCertificateProfileId();
    
    /**
     * status of certificate, ex CertificateConstants.CERT_ACTIVE
     *
     * @see CertificateConstants#CERT_ACTIVE etc
     *
     * @return status
     */
    public abstract int getStatus();
    
    /** @returns the number of milliseconds since 1970-01-01 00:00:00 GMT until the certificate was issued or null if the information is not known. */
    public abstract Long getNotBefore();
    
    /** @returns the number of milliseconds since 1970-01-01 00:00:00 GMT until the certificate expires. */
    public abstract long getExpireDate();
    
    /**
     * Set to revocation reason if status == CERT_REVOKED
     *
     * @return revocation reason, RevokedCertInfo.NOT_REVOKED etc
     * @see RevokedCertInfo#NOT_REVOKED etc
     */
    public abstract int getRevocationReason();
    
    /**
     * Set to date when revocation occured if status == CERT_REVOKED. Format == Date.getTime()
     *
     * @return revocation date
     */
    public abstract long getRevocationDate();
    
    /**
     * The ID of the public key of the certificate
     */
    public abstract String getSubjectKeyId();
    
    /**
     * The time this row was last updated.
     *
     * @return updateTime
     */
    public abstract Long getUpdateTime();
    
    /** @return the end entity profile this certificate was issued under or null if the information is not available. */
    public abstract Integer getEndEntityProfileId();
    
    /** CRL partition index. Zero or null if not using CRL partitions */
    public abstract Integer getCrlPartitionIndex();
    
    /**
     * Fingerprint of CA certificate
     *
     * @return fingerprint
     */
    public abstract String getCaFingerprint();
    
    /**
     * What type of user the certificate belongs to, ex CertificateConstants.CERTTYPE_ENDENTITY
     *
     * @return user type
     */
    public abstract int getType();
    
    /**
     * tag in database. This field was added for the 3.9.0 release, but is not used yet.
     *
     * @return tag
     */
    public abstract String getTag();
    
    public abstract int getRowVersion();
    
    public abstract String getCertificateRequest();
    
    
    //
    // Setters to call when changing revocation status
    //
    
    /**
     * status of certificate, ex CertificateConstants.CERT_ACTIVE
     *
     * @param status status
     */
    public abstract void setStatus(int status);
    
    /**
     * What type of user the certificate belongs to, ex CertificateConstants.CERTTYPE_ENDENTITY
     *
     * @param type type
     */
    public abstract void setType(int type);
    
    /**
     * Date formated as milliseconds since 1970 (== Date.getTime())
     *
     * @param expireDate expire date
     */
    public abstract void setExpireDate(long expireDate);
    
    /**
     * Set to date when revocation occurred if status == CERT_REVOKED. Format == Date.getTime()
     *
     * @param revocationDate revocation date
     */
    public abstract void setRevocationDate(long revocationDate);
    
    /**
     * Set to revocation reason if status == CERT_REVOKED
     *
     * @param revocationReason revocation reason
     */
    public abstract void setRevocationReason(int revocationReason);
    
    /**
     * The time this row was last updated.
     */
    public abstract void setUpdateTime(Long updateTime);
    
    //
    // The setters below should in general only be used when adding the certificate data entry
    //
    
    /**
     * Sets serial number (formated as BigInteger.toString())
     *
     * @param serialNumber serial number formated as BigInteger.toString()
     */
    public abstract void setSerialNumber(String serialNumber);
    
    /**
     * Fingerprint of certificate
     *
     * @param fingerprint fingerprint
     */
    public abstract void setFingerprint(String fingerprint);
    
    /**
     * DN of issuer of certificate
     *
     * @param issuerDN issuer dn
     */
    public abstract void setIssuer(String issuerDN);
    
    /**
     * Use setIssuer instead
     *
     * @param issuerDN issuer dn
     * @see #setIssuer(String)
     */
    public abstract void setIssuerDN(String issuerDN);
    
    /**
     * DN of subject in certificate
     *
     * @param subjectDN subject dn
     */
    public abstract void setSubject(String subjectDN);
    
    /**
     * username in database
     *
     * @param username username
     */
    public abstract void setUsername(String username);
    
    /**
     * Certificate Profile Id that was used to issue this certificate.
     *
     * @param certificateProfileId certificateProfileId
     */
    public abstract void setCertificateProfileId(Integer certificateProfileId);
    public abstract void setEndEntityProfileId(Integer endEntityProfileId);

    /** CRL partition index. Zero or null if not using CRL partitions */
    public abstract void setCrlPartitionIndex(Integer crlPartitionIndex);

    /**
     * Fingerprint of CA certificate
     *
     * @param cafp fingerprint
     */
    public abstract void setCaFingerprint(String cafp);
    
    public abstract void setCertificateRequest(String certificateRequest);
    
    /**
     * expire date of certificate
     *
     * @param expireDate expire date
     */
    public void setExpireDate(Date expireDate) {
        if (expireDate == null) {
            setExpireDate(-1L);
        } else {
            setExpireDate(expireDate.getTime());
        }
    }
    
    /**
     * date the certificate was revoked
     *
     * @param revocationDate revocation date
     */
    public void setRevocationDate(Date revocationDate) {
        if (revocationDate == null) {
            setRevocationDate(-1L);
        } else {
            setRevocationDate(revocationDate.getTime());
        }
    }

    /**
     * return the current class name
     *  
     * @return name (without package info) of the current class
     */
    protected final String getClassName() {
        return ClassUtils.getShortCanonicalName(this.getClass());
    }
    
    /**
     * Return the certificate. From this table if contained here. From {link Base64CertData} if contained there.
     * @param entityManager To be used if the cert is in the {@link Base64CertData} table.
     * @return The certificate
     */
    @Transient
    public String getBase64Cert(EntityManager entityManager) {
        if (getBase64Cert() != null && getBase64Cert().length() > 0) {
            return getBase64Cert(); // the cert was in this table.
        }
        // try the other table.
        final Base64CertData res = Base64CertData.findByFingerprint(entityManager, getFingerprint());
        if (res == null) {
            String message = "No " + 
                    getClassName() + 
                    " found with fingerprint " + 
                    getFingerprint() + 
                    " for '" + 
                    getSubjectDN() + 
                    "' issued by '" +  
                    getIssuerDN() + 
                    "'.";
            log.info(message);
            return null;
        }
        // it was in the other table.
        return res.getBase64Cert();
    }
    
    /**
     * Returns the certificate as an object.
     *
     * @return The certificate or null if it doesn't exist or is blank/null in the database
     */
    @Transient
    public Certificate getCertificate(EntityManager entityManager) {
        try {
            String certEncoded = getBase64Cert(entityManager);
            if (certEncoded == null || certEncoded.isEmpty()) {
                if (log.isDebugEnabled()) {
                    log.debug(getClassName() + " data was null or empty. Fingerprint of certificate: " + getFingerprint());
                }
                return null;
            }
            return CertTools.getCertfromByteArray(Base64.decode(certEncoded.getBytes()), Certificate.class);
        } catch (CertificateException ce) {
            log.error("Can't decode certificate.", ce);
            return null;
        }
    }
    
    /**
     * Returns the certificate as an object.
     *
     * @return The certificate or null if it doesn't exist or is blank/null in the database
     */
    @Transient
    public Certificate getCertificate(final Base64CertData base64CertData) {
        try {
            String certEncoded = null;
            if (getBase64Cert() != null && getBase64Cert().length()>0 ) {
                certEncoded = getBase64Cert();
            } else if (base64CertData!=null) {
                certEncoded = base64CertData.getBase64Cert();
            }
            if (certEncoded==null || certEncoded.isEmpty()) {
                if (log.isDebugEnabled()) {
                    String message = getClassName() + " data was null or empty. Fingerprint of certificate: " + getFingerprint();
                    log.debug(message);
                }
                return null;
            }
            return CertTools.getCertfromByteArray(Base64.decode(certEncoded.getBytes()), Certificate.class);
        } catch (CertificateException ce) {
            log.error("Can't decode " + getClassName() + ".", ce);
            return null;
        }
    }
    
    /**
     * Serialnumber formated as BigInteger.toString(16).toUpperCase(), or just as it is in DB if not encodable to hex.
     *
     * @return serial number in hex format
     */
    @Transient
    public String getSerialNumberHex() throws NumberFormatException {
        try {
            return new BigInteger(getSerialNumber(), 10).toString(16).toUpperCase();
        } catch (NumberFormatException e) {
            return getSerialNumber();
        }
    }
    
    /** @return the end entity profile this certificate was issued under or 0 if the information is not available. */
    @Transient
    public int getEndEntityProfileIdOrZero() {
        return getEndEntityProfileId() == null ? EndEntityConstants.NO_END_ENTITY_PROFILE : getEndEntityProfileId();
    }
    
    /**
     * DN of subject in certificate
     *
     * @return subject dn. If it is null, return empty string
     */
    @Transient
    public String getSubjectDnNeverNull() {
        final String subjectDn = getSubjectDN();
        return subjectDn == null ? "" : subjectDn;
    }
    
    /**
     * Compare the status field of this and another CertificateData object.
     *
     * @param strict will treat NOTIFIED as ACTIVE and ARCHIVED as REVOKED if set to false
     */
    public boolean equalsStatus(final BaseCertificateData certificateData, final boolean strict) {
        final int status = getStatus();
        final int otherStatus = certificateData.getStatus();
        if (strict) {
            return status == otherStatus;
        }
        if (status == otherStatus) {
            return true;
        }
        if ((status == CertificateConstants.CERT_ACTIVE || status == CertificateConstants.CERT_NOTIFIEDABOUTEXPIRATION)
                && (otherStatus == CertificateConstants.CERT_ACTIVE || otherStatus == CertificateConstants.CERT_NOTIFIEDABOUTEXPIRATION)) {
            return true;
        }
        if ((status == CertificateConstants.CERT_REVOKED || status == CertificateConstants.CERT_ARCHIVED)
                && (otherStatus == CertificateConstants.CERT_REVOKED || otherStatus == CertificateConstants.CERT_ARCHIVED)) {
            return true;
        }
        return false;
    }
}
