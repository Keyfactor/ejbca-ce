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
import java.io.UnsupportedEncodingException;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.Date;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.EntityManager;
import javax.persistence.Id;
import javax.persistence.Query;
import javax.persistence.Table;
import javax.persistence.Transient;

import org.apache.log4j.Logger;
import org.ejbca.core.model.ca.store.CertReqHistory;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.util.CertTools;
import org.ejbca.util.StringTools;

/**
 * Representation of historical information about the data user to create a certificate.
 * 
 * @version $Id$
 */ 
@Entity
@Table(name="CertReqHistoryData")
public class CertReqHistoryData implements Serializable {

	private static final long serialVersionUID = 1L;
	private static final Logger log = Logger.getLogger(CertReqHistoryData.class);

	private String issuerDN;
	private String fingerprint;
	private String serialNumber;
	private long timestamp;
	private String userDataVO;
	private String username;

	/**
	 * Entity Bean holding info about a request data at the time the certificate was issued.
	 * 
	 * @param incert the certificate issued
	 * @param UserDataVO, the data used to issue the certificate. 
	 */
	public CertReqHistoryData(Certificate incert, UserDataVO useradmindata) {
		// Exctract fields to store with the certificate.
        String fingerprint = CertTools.getFingerprintAsString(incert);
		setFingerprint(fingerprint);
        setIssuerDN(CertTools.getIssuerDN(incert));
        if (log.isDebugEnabled()) {
        	log.debug("Creating certreqhistory data, serial=" + CertTools.getSerialNumberAsString(incert) + ", issuer=" + getIssuerDN());
        }
        setSerialNumber(CertTools.getSerialNumber(incert).toString());
        setTimestamp(new Date().getTime());
		setUsername(useradmindata.getUsername());
		try {
			// Save the user admin data in xml encoding.
			java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
			java.beans.XMLEncoder encoder = new java.beans.XMLEncoder(baos);
			encoder.writeObject(useradmindata);
			encoder.close();
			if (log.isDebugEnabled()) {
				log.debug("useradmindata: \n" + baos.toString("UTF8"));
			}
			setUserDataVO(baos.toString("UTF8"));            
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
			throw new RuntimeException(e);    	                                              
		} 
	}

	public CertReqHistoryData() { }
	
	/**
	 * DN of issuer of certificate
	 * Should not be used outside of entity bean, use getCertReqHistory instead
	 * @return issuer dn
	 */
	@Column(name="issuerDN")
	private String getIssuerDN() { return issuerDN; }
	/**
	 * Use setIssuer instead
	 * @param issuerDN issuer dn
	 */
	private void setIssuerDN(String issuerDN) { this.issuerDN =issuerDN; }

	/**
	 * Fingerprint of certificate
	 * Should not be used outside of entity bean, use getCertReqHistory instead
	 * @return fingerprint
	 */
	@Id
	@Column(name="fingerprint")
	private String getFingerprint() { return fingerprint; }
	/**
	 * Fingerprint of certificate
	 * Shouldn't be set after creation.
	 * @param fingerprint fingerprint
	 */
	private void setFingerprint(String fingerprint) { this.fingerprint = fingerprint; }

	/**
	 * Serialnumber formated as BigInteger.toString()
	 * Should not be used outside of entity bean, use getCertReqHistory instead
	 * @return serial number
	 */
	@Column(name="serialNumber")
	private String getSerialNumber() { return serialNumber; }

	/**
	 * Serialnumber formated as BigInteger.toString()
	 * Shouldn't be set after creation.
	 * @param serialNumber serial number
	 */
	private void setSerialNumber(String serialNumber) { this.serialNumber = serialNumber; }

	/**
	 * Date formated as seconds since 1970 (== Date.getTime())
	 * Should not be used outside of entity bean, use getCertReqHistory instead
	 * @return timestamp 
	 */
	@Column(name="timestamp", nullable=false)
	private long getTimestamp() { return timestamp; }

	/**
	 * Date formated as seconds since 1970 (== Date.getTime())
	 * Shouldn't be set after creation.
	 * @param timestamp when certificate request info was stored
	 */
	private void setTimestamp(long timestamp) { this.timestamp = timestamp; }

	/**
	 * UserDataVO in xmlencoded String format
	 * Should not be used outside of entity bean, use getCertReqHistory instead
	 * @return  xmlencoded encoded UserDataVO
	 */
	@Column(name="userDataVO", length=17*1024*1024) // TODO: @ejb.persistence jdbc-type="LONGVARCHAR"
	//@Lob
	private String getUserDataVO() { return userDataVO; }

	/**
	 * UserDataVO in  xmlencoded String format
	 * Shouldn't be set after creation.
	 * @param userDataVO xmlencoded encoded UserDataVO
	 */
	private void setUserDataVO(String userDataVO) { this.userDataVO = userDataVO; }

	/**
	 * username in database
	 * Should not be used outside of entity bean, use getCertReqHistory instead
	 * @return username
	 */
	@Column(name="username")
	private String getUsername() { return username; }

	/**
	 * username
	 * Shouldn't be set after creation.
	 * @param username username
	 */
	private void setUsername(String username) { this.username = StringTools.strip(username); }

	//
	// Public business methods used to help us manage certificates
	//

	/**
	 * Returns the value object containing the information of the entity bean.
	 * This is the method that should be used to retreive cert req history 
	 * correctly.
	 * @return certificate request history object
	 */
	@Transient
	public CertReqHistory getCertReqHistory() {
	    java.beans.XMLDecoder decoder;
		try {
		  decoder = new java.beans.XMLDecoder(new java.io.ByteArrayInputStream(getUserDataVO().getBytes("UTF8")));
		} catch (UnsupportedEncodingException e) {
		  throw new RuntimeException(e);	// There is no nice way to recover from this
		}
		UserDataVO useradmindata  = (UserDataVO) decoder.readObject();	
		decoder.close();
        return new CertReqHistory(this.getFingerprint(),this.getSerialNumber(), this.getIssuerDN(), this.getUsername(),
        		new Date(this.getTimestamp()), useradmindata);
	}

	//
	// Search functions. 
	//

	public static CertReqHistoryData findById(EntityManager entityManager, String fingerprint) {
		return entityManager.find(CertReqHistoryData.class, fingerprint);
	}
	
	public static Collection<CertReqHistoryData> findByIssuerDNSerialNumber(EntityManager entityManager, String issuerDN, String serialNumber) {
		Query query = entityManager.createQuery("from CertReqHistoryData a WHERE a.issuerDN=:issuerDN AND a.serialNumber=:serialNumber");
		query.setParameter("issuerDN", issuerDN);
		query.setParameter("serialNumber", serialNumber);
		return query.getResultList();
	}

	public static Collection<CertReqHistoryData> findByUsername(EntityManager entityManager, String username) {
		Query query = entityManager.createQuery("from CertReqHistoryData a WHERE a.username=:username");
		query.setParameter("username", username);
		return query.getResultList();
	}
}
