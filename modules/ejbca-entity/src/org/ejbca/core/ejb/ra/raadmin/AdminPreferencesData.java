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

package org.ejbca.core.ejb.ra.raadmin;

import java.io.Serializable;
import java.util.LinkedHashMap;
import java.util.List;

import javax.persistence.Entity;
import javax.persistence.EntityManager;
import javax.persistence.PostLoad;
import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;
import javax.persistence.Table;
import javax.persistence.Transient;

import org.apache.log4j.Logger;
import org.cesecore.dbprotection.ProtectedData;
import org.cesecore.dbprotection.ProtectionStringBuilder;
import org.cesecore.util.JBossUnmarshaller;
import org.ejbca.core.model.ra.raadmin.AdminPreference;

/**
 * Representation of admin's preferences.
 * 
 * @version $Id$
 */
@Entity
@Table(name="AdminPreferencesData")
public class AdminPreferencesData extends ProtectedData implements Serializable {

	private static final long serialVersionUID = 1L;
	private static final Logger log = Logger.getLogger(AdminPreferencesData.class);

	private String id;
	private Serializable data;
	private int rowVersion = 0;
	private String rowProtection;

	/**
	 * Entity holding data of admin preferences.
	 *
	 * @param id the serialnumber.
	 * @param adminpreference is the AdminPreference.
	 */
	public AdminPreferencesData(String id, AdminPreference adminpreference) {
		setId(id);
		setAdminPreference(adminpreference);
		log.debug("Created admin preference " + id);
	}
	
	public AdminPreferencesData() { }

	//@Id @Column
	public String getId() { return id; }
	public void setId(String id) { this.id = id; }

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
	 * Method that returns the admin's preferences and updates it if necessary.
	 */
	@Transient
	public AdminPreference getAdminPreference() {
		AdminPreference returnval = new AdminPreference();
		returnval.loadData(getData());
		return returnval;
	}
	/**
	 * Method that saves the admin preference to database.
	 */
	public void setAdminPreference(AdminPreference adminpreference) {
		setData((LinkedHashMap<?, ?>) adminpreference.saveData());
	}

    //
    // Start Database integrity protection methods
    //

    @Transient
    @Override
    protected String getProtectString(final int version) {
        final ProtectionStringBuilder build = new ProtectionStringBuilder();
        // rowVersion is automatically updated by JPA, so it's not important, it is only used for optimistic locking
        build.append(getId()).append(getData());
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
        return getId();
    }

    //
    // End Database integrity protection methods
    //

	//
	// Search functions. 
	//

	/** @return the found entity instance or null if the entity does not exist */
	public static AdminPreferencesData findById(EntityManager entityManager, String id) {
		return entityManager.find(AdminPreferencesData.class, id);
	}

	/** @return return the query results as a List. */
	@SuppressWarnings("unchecked")
    public static List<AdminPreferencesData> findAll(final EntityManager entityManager) {
		return (List<AdminPreferencesData>) entityManager.createQuery("SELECT a FROM AdminPreferencesData a").getResultList();
	}
}
