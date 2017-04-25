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

package org.ejbca.core.ejb.keyrecovery;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.List;

import javax.persistence.Entity;
import javax.persistence.EntityManager;
import javax.persistence.PostLoad;
import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;
import javax.persistence.Query;
import javax.persistence.Table;
import javax.persistence.Transient;

import org.apache.log4j.Logger;
import org.cesecore.dbprotection.ProtectedData;
import org.cesecore.dbprotection.ProtectionStringBuilder;
import org.cesecore.util.Base64;
import org.cesecore.util.StringTools;

/**
 * Representation of a certificates key recovery data.
 * 
 * @version $Id$
 */
@Entity
@Table(name="KeyRecoveryData")
public class KeyRecoveryData extends ProtectedData implements Serializable {

	private static final long serialVersionUID = 1L;
	private static final Logger log = Logger.getLogger(KeyRecoveryData.class);

	private KeyRecoveryDataPK keyRecoveryDataPK;
	private String username;
	private Boolean markedAsRecoverableBool;
	private Integer markedAsRecoverableInt;
	private String keyData;
    private int cryptoTokenId = 0;
    private String keyAlias;
    private String publicKeyId;
	private int rowVersion = 0;
	private String rowProtection;
	
	/**
	 * Entity holding key recovery data of users certificate.
	 *
	 * @param certificatesn of certificate the keys are belonging to.
	 * @param issuerdn issuerdn of certificate the keys are belonging to.
	 * @param username of the owner of the keys.
	 * @param cryptoTokenId the id of the cryptoToken that holds the key protecting this key recovery entry
     * @param keyAlias the alias of the key protecting this key recovery entry
     * @param publicKeyId the keyId (same as subjectKeyId of a certificateData) of key protecting this key recovery entry
	 * @param keydata the actual keydata.
	 */
	public KeyRecoveryData(final BigInteger certificatesn, final String issuerdn, final String username, final byte[] keydata, final int cryptoTokenId, final String keyAlias, final String publicKeyId) {
		setKeyRecoveryDataPK(new KeyRecoveryDataPK(certificatesn.toString(16), issuerdn));
		setUsername(username);
		setMarkedAsRecoverable(false);
		setKeyDataFromByteArray(keydata);
		setCryptoTokenId(cryptoTokenId);
		setKeyAlias(keyAlias);
		setPublicKeyId(publicKeyId);
		if (log.isDebugEnabled()) {
		    log.debug("Created Key Recoverydata for user " + username);
		}
	}

	public KeyRecoveryData() { }

	public KeyRecoveryDataPK getKeyRecoveryDataPK() { return keyRecoveryDataPK; }
	public void setKeyRecoveryDataPK(KeyRecoveryDataPK keyRecoveryDataPK) { this.keyRecoveryDataPK = keyRecoveryDataPK; }
	
	@Transient
	public String getIssuerDN() { return keyRecoveryDataPK.issuerDN; }

	//@Column
	public String getUsername() { return username; }
	public void setUsername(String username) { this.username = StringTools.stripUsername(username); }

	@Transient
	public boolean getMarkedAsRecoverable() {
		Boolean markB = getMarkedAsRecoverableBool();
		if (markB != null) {
			return markB.booleanValue();
		}
		Integer markI = getMarkedAsRecoverableInt();
		if (markI != null) {
			return markI.intValue() == 1;
		}
		throw new RuntimeException("Could not retreive KeyRecoveryData.markedAsRecoverable from database.");
	}
	public void setMarkedAsRecoverable(boolean markedAsRecoverable) {
		setMarkedAsRecoverableBool(Boolean.valueOf(markedAsRecoverable));
		setMarkedAsRecoverableInt(markedAsRecoverable ? 1 : 0);
	}

	/**
	 * Use getMarkedAsRecoverable() instead of this method!
	 * Ingres:     Transient
	 * Non-ingres: Mapped to "markedAsRecoverable" 
	 */
	public Boolean getMarkedAsRecoverableBool() { return markedAsRecoverableBool; }
	public void setMarkedAsRecoverableBool(Boolean markedAsRecoverableBool) { this.markedAsRecoverableBool = markedAsRecoverableBool; }

	/**
	 * Use getMarkedAsRecoverable() instead of this method!
	 * Ingres:     Mapped to "markedAsRecoverable"
	 * Non-ingres: Transient 
	 */
	public Integer getMarkedAsRecoverableInt() { return markedAsRecoverableInt; }
	public void setMarkedAsRecoverableInt(Integer markedAsRecoverableInt) { this.markedAsRecoverableInt = markedAsRecoverableInt; }
	
	
	//@Column @Lob
	public String getKeyData() { return keyData; } 
	public void setKeyData(String keyData) { this.keyData = keyData; }

	//@Version @Column
    public int getCryptoTokenId() { return cryptoTokenId; }
    public void setCryptoTokenId(int cryptoTokenId) { this.cryptoTokenId = cryptoTokenId; }

    //@Version @Column
    public String getKeyAlias() {return keyAlias; }
    public void setKeyAlias(String keyAlias) { this.keyAlias = keyAlias; }

    //@Version @Column
    public String getPublicKeyId() {return publicKeyId; }
    public void setPublicKeyId(String publicKeyId) { this.publicKeyId = publicKeyId; }

	//@Version @Column
	public int getRowVersion() { return rowVersion; }
	public void setRowVersion(int rowVersion) { this.rowVersion = rowVersion; }

	//@Column @Lob
	@Override
	public String getRowProtection() { return rowProtection; }
	@Override
	public void setRowProtection(String rowProtection) { this.rowProtection = rowProtection; }

	@Transient
	public BigInteger getCertificateSN() {
		return new BigInteger(keyRecoveryDataPK.getCertSN(), 16);
	}
	/*public void setCertificateSN(BigInteger certificatesn) {
		keyRecoveryDataPK.setCertSN(certificatesn.toString(16));
	}*/
	
	@Transient
	public byte[] getKeyDataAsByteArray() {
		return Base64.decode(this.getKeyData().getBytes());
	}

    public void setKeyDataFromByteArray(byte[] keydata) {
		setKeyData(new String(Base64.encode(keydata)));
	}

    //
    // Start Database integrity protection methods
    //

    @Transient
    @Override
    protected String getProtectString(final int version) {
        final ProtectionStringBuilder build = new ProtectionStringBuilder();
        // rowVersion is automatically updated by JPA, so it's not important, it is only used for optimistic locking
        build.append(getKeyRecoveryDataPK().getIssuerDN()).append(getKeyRecoveryDataPK().getCertSN()).append(getUsername()).append(getMarkedAsRecoverable()).append(getKeyData());
        return build.toString();
    }

    @Transient
    @Override
    protected int getProtectVersion() {
        return 1;
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
        return new ProtectionStringBuilder().append(getKeyRecoveryDataPK().getIssuerDN()).append(getKeyRecoveryDataPK().getCertSN()).toString();
    }

    //
    // End Database integrity protection methods
    //

	//
    // Search functions. 
    //

	/** @return the found entity instance or null if the entity does not exist */
    public static KeyRecoveryData findByPK(EntityManager entityManager, KeyRecoveryDataPK pk) {
    	return entityManager.find(KeyRecoveryData.class, pk);
    }

	/** @return return the query results as a List. */
    @SuppressWarnings("unchecked")
    public static List<KeyRecoveryData> findByUsername(EntityManager entityManager, String username) {
    	Query query = entityManager.createQuery("SELECT a FROM KeyRecoveryData a WHERE a.username=:username");
    	query.setParameter("username", username);
    	return query.getResultList();
    }    
	 
	/** @return return the query results as a List. */
    @SuppressWarnings("unchecked")
    public static List<KeyRecoveryData> findByUserMark(EntityManager entityManager, String usermark) {
    	List<KeyRecoveryData> ret = null;
    	try {
        	Query query = entityManager.createQuery("SELECT a FROM KeyRecoveryData a WHERE a.username=:usermark AND a.markedAsRecoverableBool=TRUE");
        	query.setParameter("usermark", usermark);
    		ret = query.getResultList();
    	} catch (Exception e) {
    		if (log.isDebugEnabled()) {
        		log.debug("If database does not support boolean (like Ingres) we would expect an Exception here. Trying to treat markedAsRecoverable as an Integer.", e);
    		}
        	Query query = entityManager.createQuery("SELECT a FROM KeyRecoveryData a WHERE a.username=:usermark AND a.markedAsRecoverableInt=1");
        	query.setParameter("usermark", usermark);
    		ret = query.getResultList();
    	}
    	return ret;
    }    
}
