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

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.EntityManager;
import javax.persistence.Id;
import javax.persistence.IdClass;
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
@IdClass(AdminEntityDataPK.class)
public class AdminEntityData implements Serializable {

	private static final long serialVersionUID = 1L;
	private static final Logger log = Logger.getLogger(AdminEntityData.class);

	private int pK;
	private int matchWith;
	private int matchType;
	private String matchValue;
	private Integer cAId;
	
	public AdminEntityData(String admingroupname, int caid, int matchwith, int matchtype, String matchvalue) {
		AdminEntityDataPK adminEntityDataPK = new AdminEntityDataPK(admingroupname, caid, matchwith, matchtype, matchvalue);
		setPrimeKey(adminEntityDataPK.getPrimeKey());
		setMatchWith(matchwith);
		setMatchType(matchtype);
		setMatchValue(matchvalue);
        setCaId(caid);
		log.debug("Created admin entity "+ matchvalue);
	}
	
	public AdminEntityData() { }

	@Id
	@Column(name="pK")
	public int getPrimeKey() { return pK; }
	public void setPrimeKey(int primKey) { this.pK = primKey; } 

	@Column(name="matchWith", nullable=false)
	public int getMatchWith() { return matchWith; }
	public void setMatchWith(int matchWith) { this.matchWith = matchWith; }

	@Column(name="matchType", nullable=false)
	public int getMatchType() { return matchType; }
	public void setMatchType(int matchType) { this.matchType = matchType; }

	@Column(name="matchValue")
	public String getMatchValue() { return matchValue; }
	public void setMatchValue(String matchValue) { this.matchValue = matchValue; }
	
	@Column(name="cAId")
	public Integer getCaId() { return cAId; }
	public void setCaId(Integer caId) { this.cAId = caId; }

	@Transient
	public AdminEntity getAdminEntity() {
		return new AdminEntity(getMatchWith(), getMatchType(), getMatchValue(), getCaId());
	}

	//
	// Search functions. 
	//

	public static AdminEntityData findByPrimeKey(EntityManager entityManager, AdminEntityDataPK adminEntityDataPK) {
		return entityManager.find(AdminEntityData.class, adminEntityDataPK);
	}
	
	public static AdminEntityData findByPrimeKey(EntityManager entityManager, String adminGroupName, int cAId, int matchWith, int matchType, String matchValue) {
		return entityManager.find(AdminEntityData.class, new AdminEntityDataPK(adminGroupName, cAId, matchWith, matchType, matchValue));
	}

}
