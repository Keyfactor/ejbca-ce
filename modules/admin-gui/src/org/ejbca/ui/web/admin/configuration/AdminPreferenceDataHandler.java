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

package org.ejbca.ui.web.admin.configuration;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.ejbca.core.ejb.ra.raadmin.AdminPreferenceSession;
import org.ejbca.core.model.ra.raadmin.AdminPreference;
import org.ejbca.core.model.util.EjbLocalHelper;

/**
 * A class handling the storage of a admins preferences. Currently all admin preferences are
 * saved to a database.
 *
 * @author  Philip Vendil
 * @version $Id$
 */
public class AdminPreferenceDataHandler implements java.io.Serializable {

	private static final long serialVersionUID = 1L;

	private AdminPreferenceSession raadminsession;
	private AuthenticationToken administrator;

	/** Creates a new instance of AdminPreferences */
	public AdminPreferenceDataHandler(AuthenticationToken administrator) {
		raadminsession = new EjbLocalHelper().getRaAdminSession();
		this.administrator = administrator;
	}

	/** Retrieves the admin from the database or null if the admin does not exist. */
	public AdminPreference getAdminPreference(String certificatefingerprint) {
		AdminPreference returnvalue=null;
		try {
			returnvalue = raadminsession.getAdminPreference(administrator, certificatefingerprint);
		} catch(Exception e) {
		}
		return returnvalue;
	}

	/** Adds a admin preference to the database */
	public void addAdminPreference(String certificatefingerprint, AdminPreference adminpreference) throws AdminExistsException {
		if (!raadminsession.addAdminPreference(administrator, certificatefingerprint, adminpreference)) {
			throw new AdminExistsException("Admin already exists in the database.");
		}
	}

	/** Changes the admin preference for the given admin. */
	public void changeAdminPreference(String certificatefingerprint, AdminPreference adminpreference) throws AdminDoesntExistException {
		if (!raadminsession.changeAdminPreference(administrator, certificatefingerprint, adminpreference)) {
			throw new AdminDoesntExistException("Admin does not exist in the database.");
		}
	}

	/** Changes the admin preference for the given admin, without performing any logging. */
	public void changeAdminPreferenceNoLog(String certificatefingerprint, AdminPreference adminpreference) throws AdminDoesntExistException {
		if (!raadminsession.changeAdminPreferenceNoLog(administrator, certificatefingerprint, adminpreference)) {
			throw new AdminDoesntExistException("Admin does not exist in the database.");
		}
	}    

	/** Checks if admin preference exists in database. */
	public boolean existsAdminPreference(String certificatefingerprint) {
		return raadminsession.existsAdminPreference(administrator, certificatefingerprint);
	}

	/** Returns the default administrator preference. */
	public AdminPreference getDefaultAdminPreference() {
		return raadminsession.getDefaultAdminPreference(administrator);  
	}

	/** Saves the default administrator preference. */
	public void saveDefaultAdminPreference(AdminPreference adminpreference) {
		raadminsession.saveDefaultAdminPreference(administrator, adminpreference);  
	}
}
