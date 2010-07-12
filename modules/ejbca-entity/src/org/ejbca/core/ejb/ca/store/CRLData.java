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

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.EntityManager;
import javax.persistence.Id;
import javax.persistence.Lob;
import javax.persistence.Query;
import javax.persistence.Table;
import javax.persistence.Transient;

import org.apache.log4j.Logger;
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
	
	/**
	 * Entity holding info about a CRL. Create by sending in the CRL, which extracts (from the
	 * crl) fingerprint (primary key), CRLNumber, issuerDN, thisUpdate, nextUpdate. CAFingerprint
	 * are set to default values (null) and should be set using the respective set-methods.
	 *
	 * @param incrl the (X509)CRL to be stored in the database.
	 * @param number monotonically increasnig CRL number
	 */
	public CRLData(X509CRL incrl, int number) {
		// Exctract all fields to store with the certificate.
		try {
			String b64Crl = new String(Base64.encode(incrl.getEncoded()));
			setBase64Crl(b64Crl);
			setFingerprint(CertTools.getFingerprintAsString(incrl));
			// Make sure names are always looking the same
			setIssuerDN(CertTools.getIssuerDN(incrl));
			log.debug("Creating crldata, issuer=" + getIssuerDN());
			// Default values for cafp
			setCaFingerprint(null);
			setCrlNumber(number);
			setThisUpdate(incrl.getThisUpdate());
			setNextUpdate(incrl.getNextUpdate());
		} catch (CRLException ce) {
			log.error("Can't extract DER encoded CRL.", ce);
		}
	}
	
	public CRLData() { }
	
	@Column(name="cRLNumber", nullable=false)
	public int getCrlNumber() { return cRLNumber; }
	public void setCrlNumber(int cRLNumber) { this.cRLNumber = cRLNumber; }

	@Column(name="deltaCRLIndicator", nullable=false)
	public int getDeltaCRLIndicator() { return deltaCRLIndicator; }
	public void setDeltaCRLIndicator(int deltaCRLIndicator) { this.deltaCRLIndicator = deltaCRLIndicator; }

	@Column(name="issuerDN")
	public String getIssuerDN() { return issuerDN; }
	/**
	 * Use setIssuer instead
	 * @see #setIssuer(String)
	 */
	private void setIssuerDN(String issuerDN) { this.issuerDN = issuerDN; }

	@Id
	@Column(name="fingerprint")
	public String getFingerprint() { return fingerprint; }
	public void setFingerprint(String fingerprint) { this.fingerprint = fingerprint; }

	@Column(name="cAFingerprint")
	public String getCaFingerprint() { return cAFingerprint; }
	public void setCaFingerprint(String cAFingerprint) { this.cAFingerprint = cAFingerprint; }

	@Column(name="thisUpdate", nullable=false)
	public long getThisUpdate() { return thisUpdate; }
	/**
	 * Date formated as seconds since 1970 (== Date.getTime())
	 */
	public void setThisUpdate(long thisUpdate) { this.thisUpdate = thisUpdate; }

	@Column(name="nextUpdate", nullable=false)
	public long getNextUpdate() { return nextUpdate; }
	/**
	 * Date formated as seconds since 1970 (== Date.getTime())
	 */
	public void setNextUpdate(long nextUpdate) { this.nextUpdate = nextUpdate; }

	// DB2: CLOB(100M), Derby: CLOB, Informix: TEXT, Ingres: CLOB, Hsql: VARCHAR, MSSQL: TEXT [65535 chars], MySQL: LONGTEXT, Oracle: CLOB, Sapdb: LONG, Sybase: TEXT
	@Column(name="base64Crl", length=65535)
	@Lob
	public String getBase64Crl() { return base64Crl; }
	public void setBase64Crl(String base64Crl) { this.base64Crl = base64Crl; }

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

	public static CRLData findByFingerprint(EntityManager entityManager, String fingerprint) {
		return entityManager.find(CRLData.class,  fingerprint);
	}
	
	public static CRLData findByIssuerDNAndCRLNumber(EntityManager entityManager, String issuerDN, int crlNumber) {
		Query query = entityManager.createQuery("from CRLData a WHERE a.issuerDN=:issuerDN AND a.crlNumber=:crlNumber");
		query.setParameter("issuerDN", issuerDN);
		query.setParameter("crlNumber", crlNumber);
		return (CRLData) query.getSingleResult();
	}
}
