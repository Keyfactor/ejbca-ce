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

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.ejbca.core.model.ra.raadmin.AdminPreference;

/** Session bean to handle RA administration, which means admin preferences, global configuration and such.
 * 
 * @version $Id$
 */
public interface RaAdminSession {
    
    /**
     * Finds the admin preference belonging to a certificate serialnumber.
     * Returns null if admin doesn't exists.
     */
    AdminPreference getAdminPreference(AuthenticationToken admin, String certificatefingerprint);

    /**
     * Adds a admin preference to the database. Returns false if admin already
     * exists.
     */
    boolean addAdminPreference(AuthenticationToken admin, String certificatefingerprint, AdminPreference adminpreference);

    /**
     * Changes the admin preference in the database. Returns false if admin
     * doesn't exists.
     */
    boolean changeAdminPreference(AuthenticationToken admin, String certificatefingerprint, AdminPreference adminpreference);

    /**
     * Changes the admin preference in the database. Returns false if admin
     * doesn't exists.
     */
    boolean changeAdminPreferenceNoLog(AuthenticationToken admin, String certificatefingerprint, AdminPreference adminpreference);

    /** Checks if a admin preference exists in the database. */
    boolean existsAdminPreference(AuthenticationToken admin, String certificatefingerprint);

    /** Function that returns the default admin preference. */
    AdminPreference getDefaultAdminPreference(AuthenticationToken admin);

    /** Function that saves the default admin preference. */
    void saveDefaultAdminPreference(AuthenticationToken admin, AdminPreference defaultadminpreference);

}
