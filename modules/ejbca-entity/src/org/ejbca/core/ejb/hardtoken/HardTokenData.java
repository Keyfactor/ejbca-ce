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

package org.ejbca.core.ejb.hardtoken;

import java.io.Serializable;
import java.util.Date;
import java.util.LinkedHashMap;
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
import org.cesecore.util.JBossUnmarshaller;
import org.cesecore.util.StringTools;

/**
 * Representation of a hard token.
 * 
 * @version $Id$
 */
@Entity
@Table(name="HardTokenData")
public class HardTokenData extends ProtectedData implements Serializable {

	private static final long serialVersionUID = 1L;
	private static final Logger log = Logger.getLogger(HardTokenData.class);

    public static final String ENCRYPTEDDATA = "ENCRYPTEDDATA";

	private String tokenSN;
	private String username;
	private long cTime;
	private long mTime;
	private int tokenType;
	private String significantIssuerDN;
	private Serializable data;
	private int rowVersion = 0;
	private String rowProtection;

	/**
	 * Entity holding data of a hard token issuer.
	 */
	public HardTokenData(String tokensn, String username, Date createtime, Date modifytime, int tokentype, String significantissuerdn, LinkedHashMap<?, ?> data) {
		setTokenSN(tokensn);
		setUsername(username);
		setCtime(createtime.getTime());
		setMtime(modifytime.getTime());
		setTokenType(tokentype);
		setSignificantIssuerDN(significantissuerdn);
		setData(data);
		log.debug("Created Hard Token "+ tokensn );
	}
	
	public HardTokenData() { }
	
	//@Id @Column
	public String getTokenSN() { return tokenSN; }
	public void setTokenSN(String tokenSN) { this.tokenSN = tokenSN; }

	//@Column
	public String getUsername() { return username; }
	public void setUsername(String username) { this.username = StringTools.stripUsername(username); }

	//@Column
	public long getCtime() { return cTime; }
	public void setCtime(long createTime) { this.cTime = createTime; }

	//@Column
	public long getMtime() { return mTime; } 
	public void setMtime(long modifyTime) { this.mTime = modifyTime; }

	//@Column
	public int getTokenType() { return tokenType; }
	public void setTokenType(int tokenType) { this.tokenType = tokenType; }

	//@Column
	public String getSignificantIssuerDN() { return significantIssuerDN; }
	public void setSignificantIssuerDN(String significantIssuerDN) { this.significantIssuerDN = significantIssuerDN; }

	//@Column @Lob
	public Serializable getDataUnsafe() { return data; }
	/** DO NOT USE! Stick with setData(HashMap data) instead. */
	public void setDataUnsafe(Serializable data) { this.data = data; }

	//@Version @Column
	public int getRowVersion() { return rowVersion; }
	public void setRowVersion(int rowVersion) { this.rowVersion = rowVersion; }

	//@Column @Lob
	@Override
	public String getRowProtection() { return rowProtection; }
	@Override
	public void setRowProtection(String rowProtection) { this.rowProtection = rowProtection; }

	@Transient
	public LinkedHashMap<?, ?> getData() {
		return JBossUnmarshaller.extractLinkedHashMap(getDataUnsafe());
	}
	public void setData(LinkedHashMap<?, ?> data) { setDataUnsafe(JBossUnmarshaller.serializeObject(data)); }

	@Transient
	public Date getCreateTime() { return new Date(getCtime()); }
	public void setCreateTime(Date createtime){ setCtime(createtime.getTime()); }

	@Transient
	public Date getModifyTime(){ return new Date(getCtime()); }
	public void setModifyTime(Date modifytime){ setMtime(modifytime.getTime()); }

    //
    // Start Database integrity protection methods
    //

    @Transient
    @Override
    protected String getProtectString(final int version) {
        final ProtectionStringBuilder build = new ProtectionStringBuilder();
        // rowVersion is automatically updated by JPA, so it's not important, it is only used for optimistic locking
        build.append(getTokenSN()).append(getUsername()).append(getCtime()).append(getMtime()).append(getTokenType()).append(getSignificantIssuerDN());
        LinkedHashMap<?, ?> data = getData();
        // We must have special handling here if the data is encrypted because the byte[] is a binary byte array 
        // in this case, when doing getData().toString in this case a reference to the byte array is printed, and 
        // this is different for every invocation so signature verification fail.
        final String dataStr;
        if (data.get(ENCRYPTEDDATA) != null) {
            byte[] encdata = (byte[]) data.get(org.ejbca.core.ejb.hardtoken.HardTokenData.ENCRYPTEDDATA);
            dataStr = new String(Base64.encode(encdata, false));
        } else {
            dataStr = getData().toString(); 
        }
        build.append(dataStr);
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
        return String.valueOf(getTokenSN());
    }

    //
    // End Database integrity protection methods
    //

	//
    // Search functions. 
    //

	/** @return the found entity instance or null if the entity does not exist */
    public static HardTokenData findByTokenSN(EntityManager entityManager, String tokenSN) {
    	return entityManager.find(HardTokenData.class, tokenSN);
    }

	/** @return return the query results as a List. */
    @SuppressWarnings("unchecked")
    public static List<HardTokenData> findByUsername(EntityManager entityManager, String username) {
    	Query query = entityManager.createQuery("SELECT a FROM HardTokenData a WHERE a.username=:username");
    	query.setParameter("username", username);
    	return query.getResultList();
    }

	/** @return return a List<String> of all usernames where the searchPattern matches the token serial number. */
    @SuppressWarnings("unchecked")
    public static List<String> findUsernamesByHardTokenSerialNumber(EntityManager entityManager, String searchPattern, int maxResults) {
        Query query = entityManager.createNativeQuery("SELECT DISTINCT a.username FROM HardTokenData a WHERE tokenSN LIKE :search");
        // To use parameterized values in LIKE queries we must put the % in the parameter
        final String parameter = "%" + searchPattern + "%";
        query.setParameter("search", parameter);
    	query.setMaxResults(maxResults);
    	return query.getResultList();
	}

	/** @return return the query results as a List. */
    @SuppressWarnings("unchecked")
    public static List<String> findAllTokenSN(EntityManager entityManager) {
    	return entityManager.createQuery("SELECT a.tokenSN FROM HardTokenData a").getResultList();
    }
}
