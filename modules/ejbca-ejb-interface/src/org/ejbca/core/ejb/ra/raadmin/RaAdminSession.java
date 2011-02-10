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

import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.raadmin.AdminPreference;
import org.ejbca.core.model.ra.raadmin.GlobalConfiguration;

/** Session bean to handle RA administration, which means admin preferences, global configuration and such.
 * 
 * @version $Id$
 */
public interface RaAdminSession {
    
    /**
     * Finds the admin preference belonging to a certificate serialnumber.
     * Returns null if admin doesn't exists.
     */
    AdminPreference getAdminPreference(Admin admin, String certificatefingerprint);

    /**
     * Adds a admin preference to the database. Returns false if admin already
     * exists.
     */
    boolean addAdminPreference(Admin admin, String certificatefingerprint, AdminPreference adminpreference);

    /**
     * Changes the admin preference in the database. Returns false if admin
     * doesn't exists.
     */
    boolean changeAdminPreference(Admin admin, String certificatefingerprint, AdminPreference adminpreference);

    /**
     * Changes the admin preference in the database. Returns false if admin
     * doesn't exists.
     */
    boolean changeAdminPreferenceNoLog(Admin admin, String certificatefingerprint, AdminPreference adminpreference);

    /** Checks if a admin preference exists in the database. */
    boolean existsAdminPreference(Admin admin, String certificatefingerprint);

    /** Function that returns the default admin preference. */
    AdminPreference getDefaultAdminPreference(Admin admin);

    /** Function that saves the default admin preference. */
    void saveDefaultAdminPreference(Admin admin, AdminPreference defaultadminpreference);

    /**
     * Flushes the cached GlobalConfiguration value and reads the current one
     * from persistence.
     * 
     * @return a fresh GlobalConfiguration from persistence, or null of no such
     *         configuration exists.
     */
    GlobalConfiguration flushCache();
    
    /**
     * Retrieves the cached GlobalConfiguration. This cache is updated from
     * persistence either by the time specified by
     * {@link #MIN_TIME_BETWEEN_GLOBCONF_UPDATES} or when {@link #flushCache()}
     * is executed. This method should be used in all cases where a quick
     * response isn't necessary, otherwise use {@link #flushCache()}.
     * 
     * @return the cached GlobalConfiguration value.
     */
    GlobalConfiguration getCachedGlobalConfiguration(Admin admin);

    /** Saves the GlobalConfiguration. */
    void saveGlobalConfiguration(Admin admin, GlobalConfiguration globconf);

    /** Clear and load global configuration cache. */
    void flushGlobalConfigurationCache();


}
