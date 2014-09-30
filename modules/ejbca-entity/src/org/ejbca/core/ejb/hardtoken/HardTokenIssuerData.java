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
import org.cesecore.util.JBossUnmarshaller;
import org.cesecore.util.QueryResultWrapper;
import org.ejbca.core.model.hardtoken.HardTokenIssuer;

// TODO: This class might need additional merging with org.ejbca.core.model.hardtoken.HardTokenIssuerData, org.ejbca.core.model.hardtoken.HardTokenIssuer

/**
 * Representation of a hard token issuer.
 * 
 * @version $Id$
 */
@Entity
@Table(name="HardTokenIssuerData")
public class HardTokenIssuerData extends ProtectedData implements Serializable {

	private static final long serialVersionUID = 1L;
	private static final Logger log = Logger.getLogger(HardTokenIssuerData.class);

	private int id;
	private String alias;
	private int roleId;
	private Serializable data;
	private int rowVersion = 0;
	private String rowProtection;

	/**
	 * Entity holding data of a hard token issuer.
	 */
	public HardTokenIssuerData(int id, String alias, int roleId,  HardTokenIssuer issuerdata) {
		setId(id);
		setAlias(alias);
		setAdminGroupId(roleId);
		setHardTokenIssuer(issuerdata);
		log.debug("Created Hard Token Issuer "+ alias );
	}
	
	public HardTokenIssuerData() { }
			
	//@Id @Column
	public int getId() { return id; }
	public void setId(int id) { this.id = id; }

	//@Column
	public String getAlias() { return alias; }
	public void setAlias(String alias) { this.alias = alias; }

	//@Column
	public int getAdminGroupId() { return roleId; } 
	public void setAdminGroupId(int adminGroupId) { this.roleId = adminGroupId; }

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
	private LinkedHashMap<?, ?> getData() {
		return JBossUnmarshaller.extractLinkedHashMap(getDataUnsafe());
	}
	private void setData(LinkedHashMap<?, ?> data) { setDataUnsafe(JBossUnmarshaller.serializeObject(data)); }

	/**
	 * Method that returns the hard token issuer data and updates it if nessesary.
	 */
	@Transient
	public HardTokenIssuer getHardTokenIssuer(){
		HardTokenIssuer returnval = new HardTokenIssuer();
		returnval.loadData(getData());
		return returnval;
	}

	/**
	 * Method that saves the hard token issuer data to database.
	 */
	public void setHardTokenIssuer(HardTokenIssuer hardtokenissuer){
		setData((LinkedHashMap<?, ?>) hardtokenissuer.saveData());
	}

    //
    // Start Database integrity protection methods
    //

    @Transient
    @Override
    protected String getProtectString(final int version) {
        final ProtectionStringBuilder build = new ProtectionStringBuilder();
        // rowVersion is automatically updated by JPA, so it's not important, it is only used for optimistic locking
        build.append(getId()).append(getAlias()).append(getAdminGroupId()).append(getData());
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
        return String.valueOf(getId());
    }

    //
    // End Database integrity protection methods
    //

	//
	// Search functions. 
	//

	/** @return the found entity instance or null if the entity does not exist */
	public static HardTokenIssuerData findByPK(EntityManager entityManager, Integer pk) {
		return entityManager.find(HardTokenIssuerData.class, pk);
	}

	/**
	 * @throws javax.persistence.NonUniqueResultException if more than one entity with the name exists
	 * @return the found entity instance or null if the entity does not exist
	 */
	public static HardTokenIssuerData findByAlias(EntityManager entityManager, String alias) {
		final Query query = entityManager.createQuery("SELECT a FROM HardTokenIssuerData a WHERE a.alias=:alias");
		query.setParameter("alias", alias);
		return (HardTokenIssuerData) QueryResultWrapper.getSingleResult(query);
	}

	/** @return return the query results as a List. */
	@SuppressWarnings("unchecked")
    public static List<HardTokenIssuerData> findAll(EntityManager entityManager) {
		final Query query = entityManager.createQuery("SELECT a FROM HardTokenIssuerData a");
		return query.getResultList();
	}
}
