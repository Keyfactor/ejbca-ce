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
    org.ejbca.core.model.ra.raadmin.AdminPreference getAdminPreference(Admin admin, java.lang.String certificatefingerprint);

    /**
     * Adds a admin preference to the database. Returns false if admin already
     * exists.
     */
    boolean addAdminPreference(Admin admin, java.lang.String certificatefingerprint,
            org.ejbca.core.model.ra.raadmin.AdminPreference adminpreference);

    /**
     * Changes the admin preference in the database. Returns false if admin
     * doesn't exists.
     */
    boolean changeAdminPreference(Admin admin, java.lang.String certificatefingerprint,
            org.ejbca.core.model.ra.raadmin.AdminPreference adminpreference);

    /**
     * Changes the admin preference in the database. Returns false if admin
     * doesn't exists.
     */
    boolean changeAdminPreferenceNoLog(Admin admin, java.lang.String certificatefingerprint,
            org.ejbca.core.model.ra.raadmin.AdminPreference adminpreference);

    /**
     * Checks if a admin preference exists in the database.
     */
    boolean existsAdminPreference(Admin admin, java.lang.String certificatefingerprint);

    /**
     * Function that returns the default admin preference.
     * 
     * @throws javax.ejb.EJBException
     *             if a communication or other error occurs.
     */
    org.ejbca.core.model.ra.raadmin.AdminPreference getDefaultAdminPreference(Admin admin);

    /**
     * Function that saves the default admin preference.
     * 
     * @throws javax.ejb.EJBException
     *             if a communication or other error occurs.
     */
    void saveDefaultAdminPreference(Admin admin, org.ejbca.core.model.ra.raadmin.AdminPreference defaultadminpreference);

    /**
     * Flushes the cached GlobalConfiguration value and reads the current one
     * from persitence.
     * 
     * @return a fresh GlobalConfiguration from persistence, or null of no such
     *         configuration exists.
     */
    GlobalConfiguration flushCache();
    
    /**
     * Loads the global configuration from the database.
     * 
     * @throws javax.ejb.EJBException
     *             if a communication or other error occurs.
     */
    org.ejbca.core.model.ra.raadmin.GlobalConfiguration getCachedGlobalConfiguration(Admin admin);

    /**
     * Saves the globalconfiguration
     * 
     * @throws javax.ejb.EJBException
     *             if a communication or other error occurs.
     */
    void saveGlobalConfiguration(Admin admin, org.ejbca.core.model.ra.raadmin.GlobalConfiguration globconf);

    /**
     * Clear and load global configuration cache.
     */
    void flushGlobalConfigurationCache();


}
