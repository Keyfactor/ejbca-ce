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

package org.ejbca.core.ejb.authorization;

import java.io.Serializable;

import javax.persistence.Entity;
import javax.persistence.EntityManager;
import javax.persistence.Query;
import javax.persistence.Table;
import javax.persistence.Transient;

import org.apache.log4j.Logger;
import org.ejbca.core.model.authorization.AdminEntity;

/**
 * Representation of an admin entity in EJBCA authorization module.
 * 
 * @version $Id$
 */
@Entity
@Table(name="AdminEntityData")
public class AdminEntityData implements Serializable {

	private static final long serialVersionUID = 1L;
	private static final Logger log = Logger.getLogger(AdminEntityData.class);

	private int pK;
	private int matchWith;
	private int matchType;
	private String matchValue;
	private Integer cAId;
	private int rowVersion = 0;
	private String rowProtection;

	public AdminEntityData(final String admingroupname, final int caid, final int matchwith, final int matchtype, final String matchvalue) {
		final AdminEntityDataPK adminEntityDataPK = new AdminEntityDataPK(admingroupname, caid, matchwith, matchtype, matchvalue);
		setPrimeKey(adminEntityDataPK.hashCode());
		setMatchWith(matchwith);
		setMatchType(matchtype);
		setMatchValue(matchvalue);
        setCaId(caid);
        if (log.isDebugEnabled()) {
        	log.debug("Created admin entity "+ matchvalue);
        }
	}
	
	public AdminEntityData() { 
		// used in schema tests 
	}

	// TODO: Rename method PrimeKey is a company. A Primary Key is used to find an entity. 
	//@Id @Column
	public int getPrimeKey() { return pK; }
	public final void setPrimeKey(final int primKey) { this.pK = primKey; } 

	//@Column
	public int getMatchWith() { return matchWith; }
	public void setMatchWith(int matchWith) { this.matchWith = matchWith; }

	//@Column
	public int getMatchType() { return matchType; }
	public void setMatchType(int matchType) { this.matchType = matchType; }

	//@Column
	public String getMatchValue() { return matchValue; }
	public void setMatchValue(String matchValue) { this.matchValue = matchValue; }
	
	//@Column
	public Integer getCaId() { return cAId; }
	public void setCaId(Integer caId) { this.cAId = caId; }

	//@Version @Column
	public int getRowVersion() { return rowVersion; }
	public void setRowVersion(final int rowVersion) { this.rowVersion = rowVersion; }

	//@Column @Lob
	public String getRowProtection() { return rowProtection; }
	public void setRowProtection(final String rowProtection) { this.rowProtection = rowProtection; }

	@Transient
	public AdminEntity getAdminEntity() {
		return new AdminEntity(getMatchWith(), getMatchType(), getMatchValue(), getCaId());
	}

	//
	// Search functions. 
	//

	/** @return the found entity instance or null if the entity does not exist */
	public static AdminEntityData findByPrimeKey(final EntityManager entityManager, final AdminEntityDataPK adminEntityDataPK) {
		return entityManager.find(AdminEntityData.class, adminEntityDataPK.hashCode());
	}
	
	/** @return the found entity instance or null if the entity does not exist */
	public static AdminEntityData findByPrimeKey(final EntityManager entityManager, final String adminGroupName, final int cAId, final int matchWith, final int matchType, final String matchValue) {
		return entityManager.find(AdminEntityData.class, new AdminEntityDataPK(adminGroupName, cAId, matchWith, matchType, matchValue));
	}

	/** @return return the count. */
	public static long findCountByCaId(final EntityManager entityManager, final int caId) {
		final Query query = entityManager.createQuery("SELECT COUNT(a) FROM AdminEntityData a WHERE a.caId=:caId");
		query.setParameter("caId", caId);
		return ((Long)query.getSingleResult()).longValue();
	}
}
