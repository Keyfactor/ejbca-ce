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
import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.util.Date;

import javax.persistence.Entity;
import javax.persistence.EntityManager;
import javax.persistence.Query;
import javax.persistence.Table;
import javax.persistence.Transient;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.QueryResultWrapper;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;

/**
 * Representation of a CRL.
 * 
 * @version $Id$
 */
@Entity
@Table(name="CRLData")
public class CRLData implements Serializable {

	private static final long serialVersionUID = 1L;
	private static final Logger log = Logger.getLogger(CRLData.class);

	private int cRLNumber;
	private int deltaCRLIndicator;
	private String issuerDN;
	private String fingerprint;
	private String cAFingerprint;
	private long thisUpdate;
	private long nextUpdate;
	private String base64Crl;
	private int rowVersion = 0;
	private String rowProtection;

	/**
	 * Entity holding info about a CRL. Create by sending in the CRL, which extracts (from the
	 * crl) fingerprint (primary key), CRLNumber, issuerDN, thisUpdate, nextUpdate. CAFingerprint
	 * is the hash of the CA certificate.
	 *
	 * @param incrl the (X509)CRL to be stored in the database.
	 * @param number monotonically increasnig CRL number
	 */
	public CRLData(byte[] incrl, int number, String issuerDN, Date thisUpdate, Date nextUpdate, String cafingerprint, int deltaCRLIndicator) {
    	String b64Crl = new String(Base64.encode(incrl));
    	setBase64Crl(b64Crl);
    	String fp = CertTools.getFingerprintAsString(incrl);
    	setFingerprint(fp);
    	// Make sure names are always looking the same
    	String issuer = CertTools.stringToBCDNString(issuerDN);
    	setIssuerDN(issuer);
    	if (log.isDebugEnabled()) {
    		log.debug("Creating crldata, fp="+fp+", issuer=" + issuer+", crlNumber="+number+", deltaCRLIndicator="+deltaCRLIndicator);
    	}
    	setCaFingerprint(cafingerprint);
    	setCrlNumber(number);
    	setThisUpdate(thisUpdate);
    	setNextUpdate(nextUpdate);
    	setDeltaCRLIndicator(deltaCRLIndicator);
	}
	
	public CRLData() { }
	
	//@Column
	public int getCrlNumber() { return cRLNumber; }
	public void setCrlNumber(int cRLNumber) { this.cRLNumber = cRLNumber; }

	//@Column
	public int getDeltaCRLIndicator() { return deltaCRLIndicator; }
	public void setDeltaCRLIndicator(int deltaCRLIndicator) { this.deltaCRLIndicator = deltaCRLIndicator; }

	//@Column
	public String getIssuerDN() { return issuerDN; }
	/**
	 * Use setIssuer instead
	 * @see #setIssuer(String)
	 */
	public void setIssuerDN(String issuerDN) { this.issuerDN = issuerDN; }

	//@Id @Column
	public String getFingerprint() { return fingerprint; }
	public void setFingerprint(String fingerprint) { this.fingerprint = fingerprint; }

	//@Column
	public String getCaFingerprint() { return cAFingerprint; }
	public void setCaFingerprint(String cAFingerprint) { this.cAFingerprint = cAFingerprint; }

	//@Column
	public long getThisUpdate() { return thisUpdate; }
	/**
	 * Date formated as seconds since 1970 (== Date.getTime())
	 */
	public void setThisUpdate(long thisUpdate) { this.thisUpdate = thisUpdate; }

	//@Column
	public long getNextUpdate() { return nextUpdate; }
	/**
	 * Date formated as seconds since 1970 (== Date.getTime())
	 */
	public void setNextUpdate(long nextUpdate) { this.nextUpdate = nextUpdate; }

	//@Column @Lob
	public String getBase64Crl() { return base64Crl; }
	public void setBase64Crl(String base64Crl) { this.base64Crl = base64Crl; }

	//@Version @Column
	public int getRowVersion() { return rowVersion; }
	public void setRowVersion(int rowVersion) { this.rowVersion = rowVersion; }

	//@Column @Lob
	public String getRowProtection() { return rowProtection; }
	public void setRowProtection(String rowProtection) { this.rowProtection = rowProtection; }

	//
	// Public methods used to help us manage CRLs
	//
	@Transient
	public X509CRL getCRL() {
		X509CRL crl = null;
		try {
			String b64Crl = getBase64Crl();
			crl = CertTools.getCRLfromByteArray(Base64.decode(b64Crl.getBytes()));
		} catch (CRLException ce) {
			log.error("Can't decode CRL.", ce);
			return null;
		} 
		return crl;
	}
	public void setCRL(X509CRL incrl) {
		try {
			String b64Crl = new String(Base64.encode((incrl).getEncoded()));
			setBase64Crl(b64Crl);
		} catch (CRLException ce) {
			log.error("Can't extract DER encoded CRL.", ce);
		}
	}
	@Transient
    public byte[] getCRLBytes() {
    	byte[] crl = null;
    	String b64Crl = getBase64Crl();
    	crl = Base64.decode(b64Crl.getBytes());
    	return crl;
    }

	public void setIssuer(String dn) {
		setIssuerDN(CertTools.stringToBCDNString(dn));
	}

	public void setThisUpdate(Date thisUpdate) {
		if (thisUpdate == null) {
			setThisUpdate(-1L);
		}
		setThisUpdate(thisUpdate.getTime());
	}

	public void setNextUpdate(Date nextUpdate) {
		if (nextUpdate == null) {
			setNextUpdate(-1L);
		}
		setNextUpdate(nextUpdate.getTime());
	}

	//
	// Search functions. 
	//

	/** @return the found entity instance or null if the entity does not exist */
	public static CRLData findByFingerprint(EntityManager entityManager, String fingerprint) {
		return entityManager.find(CRLData.class, fingerprint);
	}
	
	/**
	 * @throws javax.persistence.NonUniqueResultException if more than one entity with the name exists
	 * @return the found entity instance or null if the entity does not exist
	 */
	public static CRLData findByIssuerDNAndCRLNumber(EntityManager entityManager, String issuerDN, int crlNumber) {
		final Query query = entityManager.createQuery("SELECT a FROM CRLData a WHERE a.issuerDN=:issuerDN AND a.crlNumber=:crlNumber");
		query.setParameter("issuerDN", issuerDN);
		query.setParameter("crlNumber", crlNumber);
		return (CRLData) QueryResultWrapper.getResultAndSwallowNoResultException(query);
	}

	/**
	 * @return the highest CRL number or null if no CRL for the specified issuer exists.
	 */
	public static Integer findHighestCRLNumber(EntityManager entityManager, String issuerDN, boolean deltaCRL) {
		Integer ret;
		if (deltaCRL) {
			final Query query = entityManager.createQuery("SELECT MAX(a.crlNumber) FROM CRLData a WHERE a.issuerDN=:issuerDN AND a.deltaCRLIndicator>0");
			query.setParameter("issuerDN", issuerDN);
			ret = (Integer) QueryResultWrapper.getResultAndSwallowNoResultException(query);
		} else {
			final Query query = entityManager.createQuery("SELECT MAX(a.crlNumber) FROM CRLData a WHERE a.issuerDN=:issuerDN AND a.deltaCRLIndicator=-1");
			query.setParameter("issuerDN", issuerDN);
			ret = (Integer) QueryResultWrapper.getResultAndSwallowNoResultException(query);
		}
    	return ret;
	}
}
