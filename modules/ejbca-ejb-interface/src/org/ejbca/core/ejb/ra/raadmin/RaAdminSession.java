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

import java.util.Collection;
import java.util.HashMap;

import javax.ejb.EJBException;

import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.GlobalConfiguration;

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
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    org.ejbca.core.model.ra.raadmin.AdminPreference getDefaultAdminPreference(Admin admin);

    /**
     * Function that saves the default admin preference.
     * 
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    void saveDefaultAdminPreference(Admin admin, org.ejbca.core.model.ra.raadmin.AdminPreference defaultadminpreference);

    /**
     * A method designed to be called at startuptime to (possibly) upgrade end
     * entity profiles. This method will read all End Entity Profiles and as a
     * side-effect upgrade them if the version if changed for upgrade. Can have
     * a side-effect of upgrading a profile, therefore the Required transaction
     * setting.
     * 
     * @param admin
     *            administrator calling the method
     */
    void initializeAndUpgradeProfiles(Admin admin);

    /**
     * Adds a profile to the database.
     * 
     * @param admin
     *            administrator performing task
     * @param profilename
     *            readable profile name
     * @param profile
     *            profile to be added
     */
    void addEndEntityProfile(Admin admin, java.lang.String profilename, org.ejbca.core.model.ra.raadmin.EndEntityProfile profile)
            throws org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException;

    /**
     * Adds a profile to the database.
     * 
     * @param admin
     *            administrator performing task
     * @param profileid
     *            internal ID of new profile, use only if you know it's right.
     * @param profilename
     *            readable profile name
     * @param profile
     *            profile to be added
     */
    void addEndEntityProfile(Admin admin, int profileid, java.lang.String profilename,
            org.ejbca.core.model.ra.raadmin.EndEntityProfile profile) throws org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException;

    /**
     * Adds a end entity profile to a group with the same content as the
     * original profile.
     */
    void cloneEndEntityProfile(Admin admin, java.lang.String originalprofilename, java.lang.String newprofilename)
            throws org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException;

    /**
     * Removes an end entity profile from the database.
     * 
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    void removeEndEntityProfile(Admin admin, java.lang.String profilename);

    /**
     * Renames a end entity profile
     */
    void renameEndEntityProfile(Admin admin, java.lang.String oldprofilename, java.lang.String newprofilename)
            throws org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException;

    /**
     * Updates profile data
     */
    void changeEndEntityProfile(Admin admin, java.lang.String profilename,
            org.ejbca.core.model.ra.raadmin.EndEntityProfile profile);

    /** Do not use, use changeEndEntityProfile instead.
     * Used internally for testing only. Updates a profile without flushing caches.
     */
    void internalChangeEndEntityProfileNoFlushCache(Admin admin, String profilename, EndEntityProfile profile);

    /**
     * Retrives a Collection of id:s (Integer) to authorized profiles.
     */
    Collection<Integer> getAuthorizedEndEntityProfileIds(Admin admin);

    /**
     * Method creating a hashmap mapping profile id (Integer) to profile name
     * (String).
     */
    HashMap<Integer, String> getEndEntityProfileIdToNameMap(Admin admin);

    /**
     * Clear and reload end entity profile caches.
     */
    void flushProfileCache();

    /**
     * Finds a end entity profile by id.
     */
    EndEntityProfile getEndEntityProfile(Admin admin, int id);

    /**
     * Finds a end entity profile by id.
     * 
     * @return null if profile isn't found
     */
    EndEntityProfile getEndEntityProfile(Admin admin, java.lang.String profilename);

    /**
     * Returns a end entity profiles id, given it's profilename
     * 
     * @return the id or 0 if profile cannot be found.
     */
    int getEndEntityProfileId(Admin admin, java.lang.String profilename);

    /**
     * Returns a end entity profiles name given it's id.
     * 
     * @return profilename or null if profile id doesn't exists.
     */
    String getEndEntityProfileName(Admin admin, int id);

    /**
     * Method to check if a certificateprofile exists in any of the end entity
     * profiles. Used to avoid desyncronization of certificate profile data.
     * 
     * @param certificateprofileid
     *            the certificatetype id to search for.
     * @return true if certificateprofile exists in any of the end entity
     *         profiles.
     */
    boolean existsCertificateProfileInEndEntityProfiles(Admin admin, int certificateprofileid);

    /**
     * Method to check if a CA exists in any of the end entity profiles. Used to
     * avoid desyncronization of CA data.
     * 
     * @param caid
     *            the caid to search for.
     * @return true if ca exists in any of the end entity profiles.
     */
    boolean existsCAInEndEntityProfiles(Admin admin, int caid);
  
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
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    org.ejbca.core.model.ra.raadmin.GlobalConfiguration getCachedGlobalConfiguration(Admin admin);

    /**
     * Saves the globalconfiguration
     * 
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    void saveGlobalConfiguration(Admin admin, org.ejbca.core.model.ra.raadmin.GlobalConfiguration globconf);

    /**
     * Clear and load global configuration cache.
     */
    void flushGlobalConfigurationCache();

    int findFreeEndEntityProfileId();
}
