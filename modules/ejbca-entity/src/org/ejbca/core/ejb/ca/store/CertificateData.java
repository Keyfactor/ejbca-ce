/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.core.ejb.ca.store;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import javax.persistence.Column;
import javax.persistence.ColumnResult;
import javax.persistence.Entity;
import javax.persistence.EntityManager;
import javax.persistence.Id;
import javax.persistence.Lob;
import javax.persistence.Query;
import javax.persistence.SqlResultSetMapping;
import javax.persistence.SqlResultSetMappings;
import javax.persistence.Table;
import javax.persistence.Transient;

import org.apache.log4j.Logger;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.ca.store.CertificateInfo;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.ejbca.util.StringTools;
import org.ejbca.util.keystore.KeyTools;

/**
 * Representation of a certificate and related information.
 * 
 * @version $Id$
 */ 
@Entity
@Table(name="CertificateData")
@SqlResultSetMappings(value={
	@SqlResultSetMapping(name="RevokedCertInfoSubset", columns={
		@ColumnResult(name="fingerprint"), @ColumnResult(name="serialNumber"), @ColumnResult(name="expireDate"), @ColumnResult(name="revocationDate"),
		@ColumnResult(name="revocationReason")
	}),
	@SqlResultSetMapping(name="CertificateInfoSubset", columns={
		@ColumnResult(name="issuerDN"), @ColumnResult(name="subjectDN"), @ColumnResult(name="cAFingerprint"), @ColumnResult(name="status"),
		@ColumnResult(name="type"), @ColumnResult(name="serialNumber"), @ColumnResult(name="expireDate"), @ColumnResult(name="revocationDate"),
		@ColumnResult(name="revocationReason"), @ColumnResult(name="username"), @ColumnResult(name="tag"), @ColumnResult(name="certificateProfileId"),
		@ColumnResult(name="updateTime")
	}),
	@SqlResultSetMapping(name="FingerprintUsernameSubset", columns={
			@ColumnResult(name="fingerprint"), @ColumnResult(name="username")
	})
})
public class CertificateData implements Serializable {

	private static final long serialVersionUID = -8493105317760641442L;

    // Constants used to construct KeyUsage
    /**
     * @see org.ejbca.core.ejb.ca.sign.ISignSessionRemote
     */
    public static final int digitalSignature = (1 << 7);
    public static final int nonRepudiation = (1 << 6);
    public static final int keyEncipherment = (1 << 5);
    public static final int dataEncipherment = (1 << 4);
    public static final int keyAgreement = (1 << 3);
    public static final int keyCertSign = (1 << 2);
    public static final int cRLSign = (1 << 1);
    public static final int encipherOnly = (1 << 0);
    public static final int decipherOnly = (1 << 15);

	private static final Logger log = Logger.getLogger(CertificateData.class);

	private String issuerDN;
	private String subjectDN;
	private String fingerprint = "";
	private String cAFingerprint;
	private int status = 0;
	private int type = 0;
	private String serialNumber;
	private long expireDate = 0;
	private long revocationDate = 0;
	private int revocationReason = 0;
	private String base64Cert;
	private String username;
	private String tag;
	private Integer certificateProfileId;
	private long updateTime = 0;
	private String subjectKeyId;

	/**
	 * Entity holding info about a certificate. Create by sending in the certificate, which
	 * extracts (from the cert) fingerprint (primary key), subjectDN, issuerDN, serial number,
	 * expiration date. Status, Type, CAFingerprint, revocationDate and revocationReason are set
	 * to default values (CERT_UNASSIGNED, USER_INVALID, null, null and
	 * REVOKATION_REASON_UNSPECIFIED) and should be set using the respective set-methods.
	 *
	 * @param incert the (X509)Certificate to be stored in the database.
     * @param enrichedpubkey possibly an EC public key enriched with the full set of parameters, if the public key in the certificate does not have parameters. Can be null if RSA or certificate public key contains all parameters.
	 */
	public CertificateData(Certificate incert, PublicKey enrichedpubkey) {
		// Extract all fields to store with the certificate.
		try {
            String b64Cert = new String(Base64.encode(incert.getEncoded()));
            setBase64Cert(b64Cert);

            String fp = CertTools.getFingerprintAsString(incert);
            setFingerprint(fp);

            // Make sure names are always looking the same
            setSubjectDN(CertTools.getSubjectDN(incert));
            setIssuerDN(CertTools.getIssuerDN(incert));
            if (log.isDebugEnabled()) {
                log.debug("Creating certdata, subject=" + getSubjectDN() + ", issuer=" + getIssuerDN()+", fingerprint="+fp);            	
            }
            setSerialNumber(CertTools.getSerialNumber(incert).toString());

            // Default values for status and type
            setStatus(SecConst.CERT_UNASSIGNED);
            setType(SecConst.USER_INVALID);
            setCaFingerprint(null);
            setExpireDate(CertTools.getNotAfter(incert));
            setRevocationDate(-1L);
            setRevocationReason(RevokedCertInfo.NOT_REVOKED);
            setUpdateTime(0L);	//(new Date().getTime());
            setCertificateProfileId(0);
            // Create a key identifier
            PublicKey pubk = incert.getPublicKey();
            if (enrichedpubkey != null) {
            	pubk = enrichedpubkey;
            }
            // Creating the KeyId may just throw an exception, we will log this but store the cert and ignore the error
            String keyId = null;
            try {
            	keyId = new String(Base64.encode(KeyTools.createSubjectKeyId(pubk).getKeyIdentifier(),false));
            } catch (Exception e) {
            	log.warn("Error creating subjectKeyId for certificate with fingerprint '"+fp+": ", e);
            }
            setSubjectKeyId(keyId);
		} catch (CertificateEncodingException cee) {
			log.error("Can't extract DER encoded certificate information.", cee);
			// TODO should throw an exception
		}
	}

	public CertificateData() { }

	/**
	 * DN of issuer of certificate
	 * @return issuer dn
	 */
	@Column(name="issuerDN")
	public String getIssuerDN() { return issuerDN; }

	/**
	 * Use setIssuer instead
	 * @param issuerDN issuer dn
	 * @see #setIssuer(String)
	 */
	private void setIssuerDN(String issuerDN) { this.issuerDN = issuerDN; }

	/**
	 * DN of subject in certificate
	 * @return subject dn
	 */
	@Column(name="subjectDN")
	public String getSubjectDN() { return subjectDN; }

	/**
	 * Use setSubject instead
	 * @param subjectDN subject dn
	 * @see #setSubject(String)
	 */
	private void setSubjectDN(String subjectDN) { this.subjectDN = subjectDN; }

	/**
	 * Fingerprint of certificate
	 * @return fingerprint
	 */
	@Id
	@Column(name="fingerprint")
	public String getFingerprint() { return fingerprint; }

	/**
	 * Fingerprint of certificate
	 * @param fingerprint fingerprint
	 */
	public void setFingerprint(String fingerprint) { this.fingerprint = fingerprint; }

	/**
	 * Fingerprint of CA certificate
	 * @return fingerprint
	 */
	@Column(name="cAFingerprint")
	public String getCaFingerprint() { return cAFingerprint; }

	/**
	 * Fingerprint of CA certificate
	 * @param cAFingerprint fingerprint
	 */
	public void setCaFingerprint(String cAFingerprint) { this.cAFingerprint = cAFingerprint; }

	/**
	 * status of certificate, ex CertificateData.CERT_ACTIVE
	 * @return status
	 */
	@Column(name="status", nullable=false)
	public int getStatus() { return status; }

	/**
	 * status of certificate, ex CertificateData.CERT_ACTIVE
	 * @param status status
	 */
	public void setStatus(int status) { this.status = status; }

	/**
	 * What type of user the certificate belongs to, ex SecConst.USER_ENDUSER
	 * @return user type
	 */
	@Column(name="type", nullable=false)
	public int getType() { return type; }

	/**
	 * What type of user the certificate belongs to, ex SecConst.USER_ENDUSER
	 * @param type type
	 */
	public void setType(int type) { this.type = type; }

	/**
	 * Serialnumber formated as BigInteger.toString()
	 * @return serial number
	 */
	@Column(name="serialNumber")
	public String getSerialNumber() { return serialNumber; }

	/**
	 * Serialnumber formated as BigInteger.toString()
	 * @param serialNumber serial number
	 */
	public void setSerialNumber(String serialNumber) { this.serialNumber = serialNumber; }

	/**
	 * Date formated as seconds since 1970 (== Date.getTime())
	 * @return expire date
	 */
	@Column(name="expireDate", nullable=false)
	public long getExpireDate() { return expireDate; }

	/**
	 * Date formated as seconds since 1970 (== Date.getTime())
	 * @param expireDate expire date
	 */
	public void setExpireDate(long expireDate) { this.expireDate = expireDate; }

	/**
	 * Set to date when revocation occured if status == CERT_REVOKED. Format == Date.getTime()
	 * @return revocation date
	 */
	@Column(name="revocationDate", nullable=false)
	public long getRevocationDate() { return revocationDate; }

	/**
	 * Set to date when revocation occurred if status == CERT_REVOKED. Format == Date.getTime()
	 * @param revocationDate revocation date
	 */
	public void setRevocationDate(long revocationDate) { this.revocationDate = revocationDate; }

	/**
	 * Set to revocation reason if status == CERT_REVOKED
	 * @return revocation reason
	 */
	@Column(name="revocationReason", nullable=false)
	public int getRevocationReason() { return revocationReason; }

	/**
	 * Set to revocation reason if status == CERT_REVOKED
	 * @param revocationReason revocation reason
	 */
	public void setRevocationReason(int revocationReason) { this.revocationReason = revocationReason; }

	/**
	 * The certificate itself
	 * @return base64 encoded certificate
	 */
	// DB2: VARCHAR(8000) [8000], Derby: LONG VARCHAR [32,700 characters], Informix: TEXT (2147483648 b?), Ingres: CLOB [2GB], MSSQL: TEXT [2,147,483,647 bytes], MySQL: TEXT [65535 chars], Oracle: CLOB [4G chars], Sybase: TEXT [2,147,483,647 chars]  
	@Column(name="base64Cert", length=8000)
	@Lob
	public String getBase64Cert() { return base64Cert; } 

	/**
	 * The certificate itself
	 * @param base64Cert base64 encoded certificate
	 */
	public void setBase64Cert(String base64Cert) { this.base64Cert = base64Cert; }

	/**
	 * username in database
	 * @return username
	 */
	@Column(name="username")
	public String getUsername() { return username; }

	/**
	 * username in database
	 * @param username username
	 */
	public void setUsername(String username) { this.username = StringTools.strip(username); }

	/**
	 * tag in database. This field was added for the 3.9.0 release, but is not used yet.
	 * @return tag
	 */
	@Column(name="tag")
	public String getTag() { return tag; }

	/**
	 * tag in database. This field was added for the 3.9.0 release, but is not used yet.
	 * @param username tag
	 */
	public void setTag(String tag) { this.tag = tag; }

    /**
     * Certificate Profile Id that was used to issue this certificate.
     *
     * @return certificateProfileId
     */
	@Column(name="certificateProfileId")
    public Integer getCertificateProfileId() { return certificateProfileId; }

    /**
     * Certificate Profile Id that was used to issue this certificate.
     *
     * @param certificateProfileId certificateProfileId
     */
    public void setCertificateProfileId(Integer certificateProfileId) { this.certificateProfileId = certificateProfileId; }

    /**
     * The time this row was last updated.
     *
     * @return updateTime
     */
	@Column(name="updateTime", nullable=false)
    public long getUpdateTime() { return updateTime; }

    /**
     * The time this row was last updated.
     */
	// Hibernate + Oracle ignores nullable=false so we can expect null-objects as input after upgrade
    public void setUpdateTime(Long updateTime) { this.updateTime = (updateTime==null?this.updateTime:updateTime); }

    /**
     * The ID of the public key of the certificate
     */
	@Column(name="subjectKeyId")
    public String getSubjectKeyId() { return subjectKeyId; }

    /**
     * The ID of the public key of the certificate
     */
	public void setSubjectKeyId(String subjectKeyId) { this.subjectKeyId = subjectKeyId; }


	//
	// Public business methods used to help us manage certificates
	//

	/**
	 * certificate itself
	 * @return certificate
	 */
	@Transient
	public Certificate getCertificate() {
		Certificate cert = null;
		try {
            cert = CertTools.getCertfromByteArray(Base64.decode(getBase64Cert().getBytes()));
		} catch (CertificateException ce) {
			log.error("Can't decode certificate.", ce);
			return null;
		}
		return cert;
	}

	/**
	 * certificate itself
	 * @param incert certificate
	 */
	public void setCertificate(Certificate incert) {
		try {
			String b64Cert = new String(Base64.encode(incert.getEncoded()));
			setBase64Cert(b64Cert);
			X509Certificate tmpcert = (X509Certificate) incert;
			String fp = CertTools.getFingerprintAsString(tmpcert);
			setFingerprint(fp);
			setSubjectDN(CertTools.getSubjectDN(tmpcert));
			setIssuerDN(CertTools.getIssuerDN(tmpcert));
			setSerialNumber(tmpcert.getSerialNumber().toString());
		} catch (CertificateEncodingException cee) {
			log.error("Can't extract DER encoded certificate information.", cee);
		}
	}

	/**
	 * DN of issuer of certificate
	 * @param dn issuer dn
	 */
	public void setIssuer(String dn) {
		setIssuerDN(CertTools.stringToBCDNString(dn));
	}

	/**
	 * DN of subject in certificate
	 * @param dn subject dn
	 */
	public void setSubject(String dn) {
		setSubjectDN(CertTools.stringToBCDNString(dn));
	}

	/**
	 * expire date of certificate
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
	 * @param revocationDate revocation date
	 */
	public void setRevocationDate(Date revocationDate) {
		if (revocationDate == null) {
			setRevocationDate(-1L);
		} else {
			setRevocationDate(revocationDate.getTime());
		}
	}
	
	// Comparators
	
	public boolean equals(Object obj) {
		return equals((CertificateData) obj);
	}

	public boolean equals(CertificateData certificateData, boolean mode, boolean strictStatus) {
		if (mode) {
			return equalsNonSensitive(certificateData, strictStatus);
		}
		return equals(certificateData, strictStatus);
	}

	public boolean equals(CertificateData certificateData, boolean strictStatus) {
		if (!equalsNonSensitive(certificateData, strictStatus)) { return false; }
		if (!base64Cert.equals(certificateData.base64Cert)) { return false; }
		return true;
	}
	
	public boolean equalsNonSensitive(CertificateData certificateData, boolean strictStatus) {
		if (!issuerDN.equals(certificateData.issuerDN)) { return false; }
		if (!subjectDN.equals(certificateData.subjectDN)) { return false; }
		if (!fingerprint.equals(certificateData.fingerprint)) { return false; }
		if (!cAFingerprint.equals(certificateData.cAFingerprint)) { return false; }
		if (!equalsStatus(certificateData, strictStatus)) { return false; }
		if (type!=certificateData.type) { return false; }
		if (!serialNumber.equals(certificateData.serialNumber)) { return false; }
		if (expireDate!=certificateData.expireDate) { return false; }
		if (revocationDate!=certificateData.revocationDate) { return false; }
		if (revocationReason!=certificateData.revocationReason) { return false; }
		if (!username.equals(certificateData.username)) { return false; }
		if (tag==null && certificateData.tag!=null) { return false; }
		if (tag!=null && !tag.equals(certificateData.tag)) { return false; }
		if (certificateProfileId==null && certificateData.certificateProfileId!=null) { return false; }
		if (certificateProfileId!=null && !certificateProfileId.equals(certificateData.certificateProfileId)) { return false; }
		if (updateTime!=certificateData.updateTime) { return false; }
		return true;
	}

	/**
	 * Compare the status field of this and another CertificateData object.
	 * @param strict will treat NOTIFIED as ACTIVE and ARCHIVED as REVOKED if set to false
	 */
	public boolean equalsStatus(CertificateData certificateData, boolean strict) {
		if (strict) {
			return status==certificateData.status;
		}
		if (status==certificateData.status) { return true; }
		if ((status==SecConst.CERT_ACTIVE || status==SecConst.CERT_NOTIFIEDABOUTEXPIRATION) &&
				(certificateData.status==SecConst.CERT_ACTIVE || certificateData.status==SecConst.CERT_NOTIFIEDABOUTEXPIRATION)) {
			return true;
		}
		if ((status==SecConst.CERT_REVOKED || status==SecConst.CERT_ARCHIVED) &&
				(certificateData.status==SecConst.CERT_REVOKED || certificateData.status==SecConst.CERT_ARCHIVED)) {
			return true;
		}
		return false;
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
		username = certificateData.username;
		tag = certificateData.tag;
		certificateProfileId = certificateData.certificateProfileId;
		updateTime = certificateData.updateTime;
		base64Cert = inclusionMode ? null : certificateData.base64Cert;
	}

	//
	// Search functions. 
	//

	/** @return the found entity instance or null if the entity does not exist */
	public static CertificateData findByFingerprint(EntityManager entityManager, String fingerprint) {
		return entityManager.find(CertificateData.class, fingerprint);
	}

	/** @return return the query results as a List. */
	public static List<CertificateData> findByExpireDate(EntityManager entityManager, long expireDate) {
		Query query = entityManager.createQuery("SELECT a FROM CertificateData a WHERE a.expireDate<:expireDate");
		query.setParameter("expireDate", expireDate);
		return query.getResultList();
	}

	/** @return return the query results as a List. */
	public static List<CertificateData> findBySubjectDNAndIssuerDN(EntityManager entityManager, String subjectDN, String issuerDN) {
		Query query = entityManager.createQuery("SELECT a FROM CertificateData a WHERE a.subjectDN=:subjectDN AND a.issuerDN=:issuerDN");
		query.setParameter("subjectDN", subjectDN);
		query.setParameter("issuerDN", issuerDN);
		return query.getResultList();
	}
	
	/** @return return the query results as a List. */
	public static List<CertificateData> findBySubjectDN(EntityManager entityManager, String subjectDN) {
		Query query = entityManager.createQuery("SELECT a FROM CertificateData a WHERE a.subjectDN=:subjectDN");
		query.setParameter("subjectDN", subjectDN);
		return query.getResultList();
	}

	/** @return return the query results as a List. */
	public static List<CertificateData> findBySerialNumber(EntityManager entityManager, String serialNumber) {
		Query query = entityManager.createQuery("SELECT a FROM CertificateData a WHERE a.serialNumber=:serialNumber");
		query.setParameter("serialNumber", serialNumber);
		return query.getResultList();
	}

	/** @return return the query results as a List. */
	public static List<CertificateData> findByIssuerDNSerialNumber(EntityManager entityManager, String issuerDN, String serialNumber) {
		Query query = entityManager.createQuery("SELECT a FROM CertificateData a WHERE a.issuerDN=:issuerDN AND a.serialNumber=:serialNumber");
		query.setParameter("issuerDN", issuerDN);
		query.setParameter("serialNumber", serialNumber);
		return query.getResultList();
	}

	/** @return return the query results as a List. */
	public static List<CertificateData> findByUsername(EntityManager entityManager, String username) {
		Query query = entityManager.createQuery("SELECT a FROM CertificateData a WHERE a.username=:username");
		query.setParameter("username", username);
		return query.getResultList();
	}

	/** @return return the query results as a List. */
	public static List<CertificateData> findByUsernameAndStatus(EntityManager entityManager, String username, int status) {
		Query query = entityManager.createQuery("SELECT a FROM CertificateData a WHERE a.username=:username AND a.status=:status ORDER BY a.expireDate DESC, a.serialNumber DESC");
		query.setParameter("username", username);
		query.setParameter("status", status);
		return query.getResultList();
	}

	/** @return return the query results as a List. */
	// TODO: When only JPA is used, check if we can refactor this method to SELECT DISTINCT a.username FROM ...
	public static List<CertificateData> findByIssuerDNAndSubjectKeyId(EntityManager entityManager, String issuerDN, String subjectKeyId) {
		Query query = entityManager.createQuery("SELECT a FROM CertificateData a WHERE a.issuerDN=:issuerDN AND a.subjectKeyId=:subjectKeyId");
		query.setParameter("issuerDN", issuerDN);
		query.setParameter("subjectKeyId", subjectKeyId);
		return query.getResultList();
	}

	/** @return return the query results as a List<String>. */
	public static List<String> findFingerprintsByIssuerDN(EntityManager entityManager, String issuerDN) {
		Query query = entityManager.createQuery("SELECT a.fingerprint FROM CertificateData a WHERE a.issuerDN=:issuerDN");
		query.setParameter("issuerDN", issuerDN);
		return query.getResultList();
	}

	/**
	 * Get next batchSize row ordered by fingerprint
	 * @param entityManager
	 * @param certificateProfileId
	 * @param currentFingerprint
	 * @param batchSize
	 * @return
	 */
	public static List<CertificateData> getNextBatch(EntityManager entityManager, int certificateProfileId, String currentFingerprint, int batchSize) {
		Query query = entityManager.createQuery("SELECT a FROM CertificateData a WHERE a.fingerprint>:currentFingerprint AND a.certificateProfileId=:certificateProfileId order by a.fingerprint asc");
		query.setParameter("certificateProfileId", certificateProfileId);
		query.setParameter("currentFingerprint", currentFingerprint);
		query.setMaxResults(batchSize);
		return query.getResultList();
	}
	
	/**
	 * Get next batchSize row ordered by fingerprint
	 * @param entityManager
	 * @param certificateProfileId
	 * @param currentFingerprint
	 * @param batchSize
	 * @return
	 */
	public static List<CertificateData> getNextBatch(EntityManager entityManager, String currentFingerprint, int batchSize) {
		Query query = entityManager.createQuery("SELECT a FROM CertificateData a WHERE a.fingerprint>:currentFingerprint order by a.fingerprint asc");
		query.setParameter("currentFingerprint", currentFingerprint);
		query.setMaxResults(batchSize);
		return query.getResultList();
	}
	
	/** @return the number of entries with the given parameter  */
	public static long getCount(EntityManager entityManager, int certificateProfileId) {
		Query countQuery = entityManager.createQuery("SELECT COUNT(a) FROM CertificateData a WHERE a.certificateProfileId=:certificateProfileId");
		countQuery.setParameter("certificateProfileId", certificateProfileId);
		return (Long) countQuery.getSingleResult();
	}
	
	/** @return the number of entries with the given parameter  */
	public static long getCount(EntityManager entityManager) {
		Query countQuery = entityManager.createQuery("SELECT COUNT(a) FROM CertificateData a");
		return (Long) countQuery.getSingleResult();
	}
	
	/** @return return the query results as a List. */
	public static List<Integer> getUsedCertificateProfileIds(EntityManager entityManager) {
		Query query = entityManager.createQuery("SELECT DISTINCT certificateProfileId FROM CertificateData ORDER BY certificateProfileId");
	    return query.getResultList();
	}

	/** @return return the query results as a List<RevokedCertInfo>. */
	public static List<RevokedCertInfo> getRevokedCertInfos(EntityManager entityManager, String issuerDN, long lastbasecrldate) {
		Query query;
		if (lastbasecrldate > 0) {
			query = entityManager.createNativeQuery("SELECT a.fingerprint, a.serialNumber, a.expireDate, a.revocationDate, a.revocationReason FROM CertificateData a WHERE "
	    			+ "a.issuerDN=:issuerDN AND a.revocationDate>:revocationDate AND (a.status=:status1 OR (a.status=:status2 AND a.revocationReason=:revocationReason))", "RevokedCertInfoSubset");
			query.setParameter("issuerDN", issuerDN);
			query.setParameter("revocationDate", lastbasecrldate);
			query.setParameter("status1", SecConst.CERT_REVOKED);
			query.setParameter("status2", SecConst.CERT_ACTIVE);
			query.setParameter("revocationReason", RevokedCertInfo.REVOKATION_REASON_REMOVEFROMCRL);
		} else {
			query = entityManager.createNativeQuery("SELECT a.fingerprint, a.serialNumber, a.expireDate, a.revocationDate, a.revocationReason FROM CertificateData a WHERE "
					+ "a.issuerDN=:issuerDN AND a.status=:status", "RevokedCertInfoSubset");
			query.setParameter("issuerDN", issuerDN);
			query.setParameter("status", SecConst.CERT_REVOKED);
		}
		List<Object[]> incompleteCertificateDatas = query.getResultList();
		List<RevokedCertInfo> revokedCertInfos = new ArrayList<RevokedCertInfo>();
		for (Object[] current : incompleteCertificateDatas) {
			// The order of the results are defined by the SqlResultSetMapping annotation
			String fingerprint = (String) current[0];
			BigInteger serialNumber = new BigInteger((String)current[1]);
			Date expireDate = new Date(((BigInteger)current[2]).longValue());
			Date revocationDate = new Date(((BigInteger)current[3]).longValue());
			int revocationReason = (((Integer)current[4])).intValue();
			revokedCertInfos.add(new RevokedCertInfo(fingerprint, serialNumber, revocationDate, revocationReason, expireDate));
		}
	    return revokedCertInfos;
	}
	
	public static List<String> findUsernamesByExpireTimeWithLimit(EntityManager entityManager, long minExpireTime, long maxExpireTime) {
		// TODO: Would it be more effective to drop the NOT NULL of this query and remove it from the result?
		Query query = entityManager.createQuery("SELECT DISTINCT a.username FROM CertificateData a WHERE a.expireDate>=:minExpireTime AND a.expireDate<:maxExpireTime AND (a.status=:status1 OR a.status=:status2) AND a.username NOT NULL");
		query.setParameter("minExpireTime", minExpireTime);
		query.setParameter("maxExpireTime", maxExpireTime);
		query.setParameter("status1", SecConst.CERT_ACTIVE);
		query.setParameter("status2", SecConst.CERT_NOTIFIEDABOUTEXPIRATION);
		query.setMaxResults(SecConst.MAXIMUM_QUERY_ROWCOUNT);
		return query.getResultList();
	}

	public static List<Certificate> findCertificatesByIssuerDnAndSerialNumbers(EntityManager entityManager, String issuerDN, Collection<BigInteger> serialNumbers) {
        List<Certificate> certificateList = new ArrayList<Certificate>();
        StringBuffer sb = new StringBuffer();
        Iterator<BigInteger> iter = serialNumbers.iterator();
        while (iter.hasNext()) {
        	sb.append(", '");
        	// Make sure this is really a BigInteger passed in as (untrusted param)
        	BigInteger serno = iter.next();
        	sb.append(serno.toString());
        	sb.append("'");
        }
        // to save the repeating if-statement in the above closure not to add ', ' as the first characters in the StringBuffer we remove the two chars here :)
        sb.delete(0, ", ".length());
        Query query = entityManager.createQuery("SELECT DISTINCT a.base64Cert FROM CertificateData a WHERE a.issuerDN=:issuerDN AND serialNumber IN (" + sb.toString() + ")");
		query.setParameter("issuerDN", issuerDN);
        List<String> base64CertificateList = query.getResultList();
        for (String base64Certificate : base64CertificateList) {
    		try {
                certificateList.add(CertTools.getCertfromByteArray(Base64.decode(base64Certificate.getBytes())));
    		} catch (CertificateException ce) {
    			log.error("Can't decode certificate.", ce);
    			// Continue with the rest of the results, even if this one exploded..
    		}
        }
		return certificateList;
	}

	/** @return the CertificateInfo representation (all fields except the actual cert) */
	public static CertificateInfo getCertificateInfo(EntityManager entityManager, String fingerprint) {
		CertificateInfo ret = null;
		Query query = entityManager.createNativeQuery(
				"SELECT a.issuerDN, a.subjectDN, a.cAFingerprint, a.status, a.type, a.serialNumber, a.expireDate, a.revocationDate, a.revocationReason, "
				+ "a.username, a.tag, a.certificateProfileId, a.updateTime FROM CertificateData a WHERE a.fingerprint=:fingerprint", "CertificateInfoSubset");
			query.setParameter("fingerprint", fingerprint);
		List<Object[]> resultList = (List<Object[]>) query.getResultList();
		if (!resultList.isEmpty()) {
			Object[] fields = resultList.get(0);
			// The order of the results are defined by the SqlResultSetMapping annotation
			String issuerDN = (String) fields[0];
			String subjectDN = (String) fields[1];
			String cafp = (String) fields[2];
			int status = ((Integer)fields[3]).intValue();
			int type = ((Integer)fields[4]).intValue();
			String serno = (String) fields[5];
			long expireDate = ((BigInteger)fields[6]).longValue();
			long revocationDate = ((BigInteger)fields[7]).longValue();
			int revocationReason = ((Integer)fields[8]).intValue();
			String username = (String) fields[9];
			String tag = (String) fields[10];
			int cProfId = ((Integer)fields[11]).intValue();
			long updateTime = (fields[12]==null?0:((BigInteger)fields[12]).longValue());	// Might be null in an upgraded installation
	        ret = new CertificateInfo(fingerprint, cafp, serno, issuerDN, subjectDN, status, type, expireDate, revocationDate, revocationReason, username, tag, cProfId, updateTime);				
		}
		return ret;
	}

	/** @return the number of certificates that had their status changed from On Hold to Revoked for this issuer. */
	public static int revokeOnHoldPermanently(EntityManager entityManager, String issuerDN) {
		Query query = entityManager.createQuery("UPDATE CertificateData a SET a.status=:status1 WHERE a.issuerDN=:issuerDN AND a.status=:status2");
		query.setParameter("status1", SecConst.CERT_REVOKED);
		query.setParameter("issuerDN", issuerDN);
		query.setParameter("status2", SecConst.CERT_TEMP_REVOKED);
		return query.executeUpdate();
	}

	/** @return the number of certificates that had their status changed from On Hold to Revoked for this issuer. */
	public static int revokeAllNonRevokedCertificates(EntityManager entityManager, String issuerDN, int reason) {
		Query query = entityManager.createQuery("UPDATE CertificateData SET status=:status1, revocationDate=:revocationDate, revocationReason=:revocationReason WHERE issuerDN=:issuerDN AND status <> :status2");
		query.setParameter("status1", SecConst.CERT_REVOKED);
		query.setParameter("revocationDate", new Date().getTime());
		query.setParameter("revocationReason", reason);
		query.setParameter("issuerDN", issuerDN);
		query.setParameter("status2", SecConst.CERT_REVOKED);
		return query.executeUpdate();
	}

	/** @return a List<Certificate> of SecConst.CERT_ACTIVE and CERT_NOTIFIEDABOUTEXPIRATION certs that have one of the specified types. */
	public static List<Certificate> findActiveCertificatesByType(EntityManager entityManager, String certificateTypes) {
        List<Certificate> certificateList = new ArrayList<Certificate>();
        Query query = entityManager.createQuery("SELECT DISTINCT a.base64Cert FROM CertificateData a WHERE (status=:status1 or status=:status2) AND type IN (" + certificateTypes + ")");
		query.setParameter("status1", SecConst.CERT_ACTIVE);
		query.setParameter("status2", SecConst.CERT_NOTIFIEDABOUTEXPIRATION);
        List<String> base64CertificateList = query.getResultList();
		for (String base64Certificate : base64CertificateList) {
    		try {
                certificateList.add(CertTools.getCertfromByteArray(Base64.decode(base64Certificate.getBytes())));
    		} catch (CertificateException ce) {
    			log.error("Can't decode certificate.", ce);
    			// Continue with the rest of the results, even if this one exploded..
    		}
        }
		return certificateList;
	}

	/** @return a List<Certificate> of SecConst.CERT_ACTIVE and CERT_NOTIFIEDABOUTEXPIRATION certs that have one of the specified types for the given issuer. */
	public static List<Certificate> findActiveCertificatesByTypeAndIssuer(EntityManager entityManager, String certificateTypes, String issuerDN) {
        List<Certificate> certificateList = new ArrayList<Certificate>();
        Query query = entityManager.createQuery("SELECT DISTINCT a.base64Cert FROM CertificateData a WHERE (status=:status1 or status=:status2) AND type IN (" + certificateTypes + ") AND issuerDN=:issuerDN");
		query.setParameter("status1", SecConst.CERT_ACTIVE);
		query.setParameter("status2", SecConst.CERT_NOTIFIEDABOUTEXPIRATION);
		query.setParameter("issuerDN", issuerDN);
        List<String> base64CertificateList = query.getResultList();
		for (String base64Certificate : base64CertificateList) {
    		try {
                certificateList.add(CertTools.getCertfromByteArray(Base64.decode(base64Certificate.getBytes())));
    		} catch (CertificateException ce) {
    			log.error("Can't decode certificate.", ce);
    			// Continue with the rest of the results, even if this one exploded..
    		}
        }
		return certificateList;
	}

    /**
     * Fetch a List of all certificate fingerprints and corresponding username
     * @return [0] = (String) fingerprint, [1] = (String) username
     */
	public static List<Object[]> findExpirationInfo(EntityManager entityManager, String cASelectString, long activeNotifiedExpireDateMin, long activeNotifiedExpireDateMax, long activeExpireDateMin) {
        // We can not select the base64 certificate data here, because it may be a LONG data type which we can't simply select.
        // TODO: Still true for JPA?
		Query query = entityManager.createNativeQuery(
				"SELECT DISTINCT fingerprint, username" + " FROM CertificateData WHERE (" + cASelectString + ") AND "
                + "(expireDate>:activeNotifiedExpireDateMin) AND" + "(expireDate<:activeNotifiedExpireDateMax) AND (status=:status1"
                + " OR status=:status2) AND (expireDate>=:activeExpireDateMin OR " + "status=:status3)", "FingerprintUsernameSubset");
		query.setParameter("activeNotifiedExpireDateMin", activeNotifiedExpireDateMin);
		query.setParameter("activeNotifiedExpireDateMax", activeNotifiedExpireDateMax);
		query.setParameter("status1", SecConst.CERT_ACTIVE);
		query.setParameter("status2", SecConst.CERT_NOTIFIEDABOUTEXPIRATION);
		query.setParameter("activeExpireDateMin", activeExpireDateMin);
		query.setParameter("status3", SecConst.CERT_ACTIVE);
		return query.getResultList();
	}

	/** @return true if a row with the given fingerprint was updated */
	public static boolean updateStatus(EntityManager entityManager, String fingerprint, int status) {
		Query query = entityManager.createQuery("UPDATE CertificateData a SET a.status=:status WHERE a.fingerprint=:fingerprint");
		query.setParameter("status", status);
		query.setParameter("fingerprint", fingerprint);
		return query.executeUpdate() == 1;
	}
}
