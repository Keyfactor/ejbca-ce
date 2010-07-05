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

package org.ejbca.core.ejb.protect;

import java.io.Serializable;
import java.util.Date;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.EntityManager;
import javax.persistence.Id;
import javax.persistence.Query;
import javax.persistence.Table;
import javax.persistence.Transient;

/**
 * Representation of a table protection entry in the database.
 * 
 * @version $Id$
 */
@Entity
@Table(name="TableProtectData")
public class TableProtectData implements Serializable {

	private static final long serialVersionUID = 1L;
	public static final String KEYTYPE_HMAC = "HMAC";
	public static final int CURRENT_VERSION = 1;

	private String id;
	private int version;
	private int hashVersion;
	private String protectionAlg;
	private String hash;
	private String signature;
	private long time;
	private String dbKey;
	private String dbType;
	private String keyType;

	public TableProtectData(String id, int hashVersion, String alg, String hash, String signature, Date time, String dbKey, String dbType, String keyType) {
		setId(id);
		setVersion(CURRENT_VERSION);
		setHashVersion(hashVersion);
		setProtectionAlg(alg);
		setHash(hash);
		setSignature(signature);
		setTime(time.getTime());
		setDbKey(dbKey);
		setDbType(dbType);
		setKeyType(keyType);
	}

	public TableProtectData() { }

	/** Primary Key. */
	@Id
	@Column(name="id")
	public String getId() { return id; }
	public void setId(String id) { this.id = id; }

	/** Versioning of the protection rows (this row), so that the underlying database table can be upgraded and still verified. */
	@Column(name="version", nullable=false)
	public int getVersion() { return version; }
	public void setVersion(int version) { this.version = version; }

	/** Versioning of the protected row, so the underlying database table can be extended and still verified */
	@Column(name="hashVersion", nullable=false)
	public int getHashVersion() { return hashVersion; }
	public void setHashVersion(int hashVersion) { this.hashVersion = hashVersion; }

	/** hmac, rsaWithSHA1 etc. Also used to implicitly define the key type of the protection key. */
	@Column(name="protectionAlg")
	public String getProtectionAlg() { return protectionAlg; }
	public void setProtectionAlg(String protectionAlg) { this.protectionAlg = protectionAlg; }

	/** Hash of the row data from the underlying table to be protected. */
	@Column(name="hash")
	public String getHash() { return hash; }
	public void setHash(String hash) { this.hash = hash; }

	/** Actual signature. */
	@Column(name="signature")
	public String getSignature() { return signature; }
	public void setSignature(String signature) { this.signature = signature; }

	@Column(name="time", nullable=false)
	public long getTime() { return time; }
	public void setTime(long time) { this.time = time; }

	/** Database key of the underlying row that is protected, used to find the row for verification. */
	@Column(name="dbKey")
	public String getDbKey() { return dbKey; }
	public void setDbKey(String dbKey) { this.dbKey = dbKey; }

	/** Type of object protected, determined by the OBJECT, for example LOGENTRY. */
	@Column(name="dbType")
	public String getDbType() { return dbType; }
	public void setDbType(String dbType) { this.dbType = dbType; }

	/** Type of key which the reference refers to. */
	@Column(name="keyType")
	public String getKeyType() { return keyType; }
	public void setKeyType(String keyType) { this.keyType = keyType; }

	@Transient
	public Date getTimeAsDate() {
		return new Date(getTime());
	}

	//
	// Search functions. 
	//

	public static TableProtectData findById(EntityManager entityManager, String id) {
		return entityManager.find(TableProtectData.class,  id);
	}

	public static TableProtectData findByDbTypeAndKey(EntityManager entityManager, String dbType, String dbKey) {
		Query query = entityManager.createQuery("from TableProtectDataBean a WHERE a.dbType=:dbType AND a.dbKey=:dbKey");
		query.setParameter("dbType", dbType);
		query.setParameter("dbKey", dbKey);
		return (TableProtectData) query.getSingleResult();
	}
}
