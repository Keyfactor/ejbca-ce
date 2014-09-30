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

package org.ejbca.ui.web.admin.configuration;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.core.ejb.ra.raadmin.AdminPreferenceSessionLocal;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ra.raadmin.AdminPreference;
import org.ejbca.core.model.util.EjbLocalHelper;

/**
 * A class handling the storage of a admins preferences. Currently all admin preferences are
 * saved to a database.
 *
 * @version $Id$
 */
public class AdminPreferenceDataHandler implements java.io.Serializable {

	private static final long serialVersionUID = 2L;

	private AdminPreferenceSessionLocal raadminsession;
	private X509CertificateAuthenticationToken administrator;

	/** Creates a new instance of AdminPreferences */
	public AdminPreferenceDataHandler(X509CertificateAuthenticationToken administrator) {
		raadminsession = new EjbLocalHelper().getRaAdminSession();
		this.administrator = administrator;
	}

	/** Retrieves the admin from the database or null if the admin does not exist. */
	public AdminPreference getAdminPreference(String certificatefingerprint) {
		AdminPreference returnvalue=null;
		try {
			returnvalue = raadminsession.getAdminPreference(certificatefingerprint);
		} catch(Exception e) {
		}
		return returnvalue;
	}

	/** Adds a admin preference to the database */
	public void addAdminPreference(String certificatefingerprint, AdminPreference adminpreference) throws AdminExistsException {
		if (!raadminsession.addAdminPreference(administrator, adminpreference)) {
			throw new AdminExistsException("Admin already exists in the database.");
		}
	}

	/** Changes the admin preference for the given admin. */
	public void changeAdminPreference(String certificatefingerprint, AdminPreference adminpreference) throws AdminDoesntExistException {
		if (!raadminsession.changeAdminPreference(administrator, adminpreference)) {
			throw new AdminDoesntExistException("Admin does not exist in the database.");
		}
	}

	/** Changes the admin preference for the given admin, without performing any logging. */
	public void changeAdminPreferenceNoLog(String certificatefingerprint, AdminPreference adminpreference) throws AdminDoesntExistException {
		if (!raadminsession.changeAdminPreferenceNoLog(administrator, adminpreference)) {
			throw new AdminDoesntExistException("Admin does not exist in the database.");
		}
	}    

	/** Checks if admin preference exists in database. */
	public boolean existsAdminPreference(String certificatefingerprint) {
		return raadminsession.existsAdminPreference(certificatefingerprint);
	}

	/** Returns the default administrator preference. */
	public AdminPreference getDefaultAdminPreference() {
		return raadminsession.getDefaultAdminPreference();  
	}

    /** Saves the default administrator preference. 
     * @param adminpreference The {@link AdminPreference} to save as default.
     * @throws AuthorizationDeniedException if the local {@link AuthenticationToken} wasn't authorized to {@link AccessRulesConstants}.ROLE_ROOT
     */
    public void saveDefaultAdminPreference(AdminPreference adminpreference) throws AuthorizationDeniedException {
        raadminsession.saveDefaultAdminPreference(administrator, adminpreference);
    }
}
