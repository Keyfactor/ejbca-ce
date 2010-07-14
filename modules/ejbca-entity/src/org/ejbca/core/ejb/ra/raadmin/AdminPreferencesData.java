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

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.EntityManager;
import javax.persistence.Id;
import javax.persistence.Lob;
import javax.persistence.Table;
import javax.persistence.Transient;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.JBossUnmarshaller;
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

	@Id
	@Column(name="id")
	public String getId() { return id; }
	public void setId(String id) { this.id = id; }

	// EJBCA 3.x: DB2: BLOB(200K), Derby: , Informix: BLOB, Ingres: BLOB, MSSQL: , MySQL: , Oracle: , Postgres: BYTEA, Sapdb: , Sybase: IMAGE
	// EJBCA 4.x:
	@Column(name="data", length=200*1024)
	@Lob
	public Serializable getDataUnsafe() {
		HashMap h = JBossUnmarshaller.extractObject(HashMap.class, data);	// This is a workaround for JBoss J2EE CMP Serialization
		if (h != null) {
			setDataUnsafe(h);
		}
		return data;
	}
	/** DO NOT USE! Stick with setData(HashMap data) instead. */
	public void setDataUnsafe(Serializable data) { this.data = data; }

	@Transient
	private HashMap getData() { return (HashMap) getDataUnsafe(); }
	private void setData(HashMap data) { setDataUnsafe(data); }

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

	public static AdminPreferencesData findById(EntityManager entityManager, String id) {
		return entityManager.find(AdminPreferencesData.class, id);
	}
}
