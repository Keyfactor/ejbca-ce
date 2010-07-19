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

package org.ejbca.core.ejb.keyrecovery;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.Collection;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.EntityManager;
import javax.persistence.Id;
import javax.persistence.IdClass;
import javax.persistence.Lob;
import javax.persistence.Query;
import javax.persistence.Table;
import javax.persistence.Transient;

import org.apache.log4j.Logger;
import org.ejbca.util.Base64;
import org.ejbca.util.StringTools;

/**
 * Representation of a certificates key recovery data.
 * 
 * @version $Id$
 */
@Entity
@Table(name="KeyRecoveryData")
@IdClass(KeyRecoveryDataPK.class)
public class KeyRecoveryData implements Serializable {

	private static final long serialVersionUID = 1L;
	private static final Logger log = Logger.getLogger(KeyRecoveryData.class);

	private String certSN;
	private String issuerDN;
	private String username;
	private boolean markedAsRecoverable;
	private String keyData;

	/**
	 * Entity holding key recovery data of users certificate.
	 *
	 * @param certificatesn of certificate the keys are belonging to.
	 * @param issuerdn issuerdn of certificate the keys are belonging to.
	 * @param username of the owner of the keys.
	 * @param keydata the actual keydata.
	 */
	public KeyRecoveryData(BigInteger certificatesn, String issuerdn, String username, byte[] keydata) {
		setCertificateSN(certificatesn);
		setIssuerDN(issuerdn);
		setUsername(username);
		setMarkedAsRecoverable(false);
		setKeyDataFromByteArray(keydata);
		log.debug("Created Key Recoverydata for user " + username);
	}

	public KeyRecoveryData() { }

	@Id
	@Column(name="certSN")
	public String getCertSN() { return certSN; }
	public void setCertSN(String certSN) { this.certSN = certSN; }

	@Id
	@Column(name="issuerDN")
	public String getIssuerDN() { return issuerDN; }
	public void setIssuerDN(String issuerDN) { this.issuerDN = issuerDN; }

	@Column(name="username")
	public String getUsername() { return username; }
	public void setUsername(String username) { this.username = StringTools.strip(username); }

	@Column(name="markedAsRecoverable", nullable=false)
	public boolean getMarkedAsRecoverable() { return markedAsRecoverable; }
	public void setMarkedAsRecoverable(boolean markedAsRecoverable) { this.markedAsRecoverable = markedAsRecoverable; }

	// DB2: VARCHAR(8000) [8000], Derby: LONG VARCHAR [32,700 characters], Informix: TEXT (2147483648 b?), Ingres: CLOB [2GB], MSSQL: TEXT [2,147,483,647 bytes], MySQL: TEXT [65535 chars], Oracle: CLOB [4G chars], Sybase: TEXT [2,147,483,647 chars]  
	@Column(name="keyData", length=8000)
	@Lob
	public String getKeyData() { return keyData; } 
	public void setKeyData(String keyData) { this.keyData = keyData; }

	@Transient
	public BigInteger getCertificateSN() {
		return new BigInteger(getCertSN(), 16);
	}
	public void setCertificateSN(BigInteger certificatesn) {
		setCertSN(certificatesn.toString(16));
	}

	@Transient
	public byte[] getKeyDataAsByteArray() {
		return Base64.decode(this.getKeyData().getBytes());
	}
	public void setKeyDataFromByteArray(byte[] keydata) {
		setKeyData(new String(Base64.encode(keydata)));
	}

	//
    // Search functions. 
    //

    public static KeyRecoveryData findByPK(EntityManager entityManager, KeyRecoveryDataPK pk) {
    	return entityManager.find(KeyRecoveryData.class,  pk);
    }

    public static KeyRecoveryData findByUsername(EntityManager entityManager, String username) {
    	Query query = entityManager.createQuery("from KeyRecoveryData a WHERE a.username=:username");
    	query.setParameter("username", username);
    	return (KeyRecoveryData) query.getSingleResult();
    }    
	 
    public static Collection<KeyRecoveryData> findByUserMark(EntityManager entityManager, String usermark) {
    	Query query = entityManager.createQuery("from KeyRecoveryData a WHERE a.username=:usermark AND a.markedAsRecoverable=TRUE");
    	query.setParameter("usermark", usermark);
    	return query.getResultList();
    }    
}
