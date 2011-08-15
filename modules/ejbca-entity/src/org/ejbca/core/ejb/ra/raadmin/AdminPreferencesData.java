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

package org.ejbca.core.ejb.ra.raadmin;

import java.io.Serializable;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;

import javax.persistence.Entity;
import javax.persistence.EntityManager;
import javax.persistence.Table;
import javax.persistence.Transient;

import org.apache.log4j.Logger;
import org.cesecore.util.JBossUnmarshaller;
import org.ejbca.core.model.ra.raadmin.AdminPreference;

/**
 * Representation of admin's preferences.
 * 
 * @version $Id$
 */
@Entity
@Table(name="AdminPreferencesData")
public class AdminPreferencesData implements Serializable {

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
	public String getRowProtection() { return rowProtection; }
	public void setRowProtection(String rowProtection) { this.rowProtection = rowProtection; }

	@Transient
	private HashMap getData() {
		HashMap ret = null;
		// When the wrong class is given it can either return null, or throw an exception
		try {
			ret = JBossUnmarshaller.extractObject(LinkedHashMap.class, getDataUnsafe());
			if (ret != null) {
				return ret;
			}
		} catch (ClassCastException e) {
			// NOPMD: pass through to the end line
		}
		// If this is an old record, before we switched to LinkedHashMap, we have to try that, we should get a ClassCastException or null from above...
		return new LinkedHashMap(JBossUnmarshaller.extractObject(HashMap.class, getDataUnsafe()));
	}
	private void setData(HashMap data) { setDataUnsafe(JBossUnmarshaller.serializeObject(data)); }

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
		setData((HashMap) adminpreference.saveData());
	}

	//
	// Search functions. 
	//

	/** @return the found entity instance or null if the entity does not exist */
	public static AdminPreferencesData findById(EntityManager entityManager, String id) {
		return entityManager.find(AdminPreferencesData.class, id);
	}

	/** @return return the query results as a List. */
	public static List<AdminPreferencesData> findAll(final EntityManager entityManager) {
		return entityManager.createQuery("SELECT a FROM AdminPreferencesData a").getResultList();
	}
}
