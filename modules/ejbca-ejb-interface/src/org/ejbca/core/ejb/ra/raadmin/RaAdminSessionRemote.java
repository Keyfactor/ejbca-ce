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

import javax.ejb.Remote;

/**
 * Remote interface for RaAdminSession.
 */
@Remote
public interface RaAdminSessionRemote {
    /**
     * Finds the admin preference belonging to a certificate serialnumber.
     * Returns null if admin doesn't exists.
     */
    public org.ejbca.core.model.ra.raadmin.AdminPreference getAdminPreference(org.ejbca.core.model.log.Admin admin, java.lang.String certificatefingerprint)
            throws java.rmi.RemoteException;

    /**
     * Adds a admin preference to the database. Returns false if admin already
     * exists.
     */
    public boolean addAdminPreference(org.ejbca.core.model.log.Admin admin, java.lang.String certificatefingerprint,
            org.ejbca.core.model.ra.raadmin.AdminPreference adminpreference) throws java.rmi.RemoteException;

    /**
     * Changes the admin preference in the database. Returns false if admin
     * doesn't exists.
     */
    public boolean changeAdminPreference(org.ejbca.core.model.log.Admin admin, java.lang.String certificatefingerprint,
            org.ejbca.core.model.ra.raadmin.AdminPreference adminpreference) throws java.rmi.RemoteException;

    /**
     * Changes the admin preference in the database. Returns false if admin
     * doesn't exists.
     */
    public boolean changeAdminPreferenceNoLog(org.ejbca.core.model.log.Admin admin, java.lang.String certificatefingerprint,
            org.ejbca.core.model.ra.raadmin.AdminPreference adminpreference) throws java.rmi.RemoteException;

    /**
     * Checks if a admin preference exists in the database.
     */
    public boolean existsAdminPreference(org.ejbca.core.model.log.Admin admin, java.lang.String certificatefingerprint) throws java.rmi.RemoteException;

    /**
     * Function that returns the default admin preference.
     * 
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    public org.ejbca.core.model.ra.raadmin.AdminPreference getDefaultAdminPreference(org.ejbca.core.model.log.Admin admin) throws java.rmi.RemoteException;

    /**
     * Function that saves the default admin preference.
     * 
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    public void saveDefaultAdminPreference(org.ejbca.core.model.log.Admin admin, org.ejbca.core.model.ra.raadmin.AdminPreference defaultadminpreference)
            throws java.rmi.RemoteException;

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
    public void initializeAndUpgradeProfiles(org.ejbca.core.model.log.Admin admin) throws java.rmi.RemoteException;

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
    public void addEndEntityProfile(org.ejbca.core.model.log.Admin admin, java.lang.String profilename, org.ejbca.core.model.ra.raadmin.EndEntityProfile profile)
            throws org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException, java.rmi.RemoteException;

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
    public void addEndEntityProfile(org.ejbca.core.model.log.Admin admin, int profileid, java.lang.String profilename,
            org.ejbca.core.model.ra.raadmin.EndEntityProfile profile) throws org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException,
            java.rmi.RemoteException;

    /**
     * Adds a end entity profile to a group with the same content as the
     * original profile.
     */
    public void cloneEndEntityProfile(org.ejbca.core.model.log.Admin admin, java.lang.String originalprofilename, java.lang.String newprofilename)
            throws org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException, java.rmi.RemoteException;

    /**
     * Removes an end entity profile from the database.
     * 
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    public void removeEndEntityProfile(org.ejbca.core.model.log.Admin admin, java.lang.String profilename) throws java.rmi.RemoteException;

    /**
     * Renames a end entity profile
     */
    public void renameEndEntityProfile(org.ejbca.core.model.log.Admin admin, java.lang.String oldprofilename, java.lang.String newprofilename)
            throws org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException, java.rmi.RemoteException;

    /**
     * Updates profile data
     */
    public void changeEndEntityProfile(org.ejbca.core.model.log.Admin admin, java.lang.String profilename,
            org.ejbca.core.model.ra.raadmin.EndEntityProfile profile) throws java.rmi.RemoteException;

    /**
     * Retrives a Collection of id:s (Integer) to authorized profiles.
     */
    public java.util.Collection getAuthorizedEndEntityProfileIds(org.ejbca.core.model.log.Admin admin) throws java.rmi.RemoteException;

    /**
     * Method creating a hashmap mapping profile id (Integer) to profile name
     * (String).
     */
    public java.util.HashMap getEndEntityProfileIdToNameMap(org.ejbca.core.model.log.Admin admin) throws java.rmi.RemoteException;

    /**
     * Finds a end entity profile by id.
     */
    public org.ejbca.core.model.ra.raadmin.EndEntityProfile getEndEntityProfile(org.ejbca.core.model.log.Admin admin, int id) throws java.rmi.RemoteException;

    /**
     * Finds a end entity profile by id.
     * 
     * @return null if profile isn't found
     */
    public org.ejbca.core.model.ra.raadmin.EndEntityProfile getEndEntityProfile(org.ejbca.core.model.log.Admin admin, java.lang.String profilename)
            throws java.rmi.RemoteException;

    /**
     * Returns a end entity profiles id, given it's profilename
     * 
     * @return the id or 0 if profile cannot be found.
     */
    public int getEndEntityProfileId(org.ejbca.core.model.log.Admin admin, java.lang.String profilename) throws java.rmi.RemoteException;

    /**
     * Returns a end entity profiles name given it's id.
     * 
     * @return profilename or null if profile id doesn't exists.
     */
    public java.lang.String getEndEntityProfileName(org.ejbca.core.model.log.Admin admin, int id) throws java.rmi.RemoteException;

    /**
     * Method to check if a certificateprofile exists in any of the end entity
     * profiles. Used to avoid desyncronization of certificate profile data.
     * 
     * @param certificateprofileid
     *            the certificatetype id to search for.
     * @return true if certificateprofile exists in any of the end entity
     *         profiles.
     */
    public boolean existsCertificateProfileInEndEntityProfiles(org.ejbca.core.model.log.Admin admin, int certificateprofileid) throws java.rmi.RemoteException;

    /**
     * Method to check if a CA exists in any of the end entity profiles. Used to
     * avoid desyncronization of CA data.
     * 
     * @param caid
     *            the caid to search for.
     * @return true if ca exists in any of the end entity profiles.
     */
    public boolean existsCAInEndEntityProfiles(org.ejbca.core.model.log.Admin admin, int caid) throws java.rmi.RemoteException;

    /**
     * Loads the global configuration from the database.
     * 
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    public org.ejbca.core.model.ra.raadmin.GlobalConfiguration loadGlobalConfiguration(org.ejbca.core.model.log.Admin admin) throws java.rmi.RemoteException;

    /**
     * Saves the globalconfiguration
     * 
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    public void saveGlobalConfiguration(org.ejbca.core.model.log.Admin admin, org.ejbca.core.model.ra.raadmin.GlobalConfiguration globalconfiguration)
            throws java.rmi.RemoteException;

    public int findFreeEndEntityProfileId() throws java.rmi.RemoteException;
}
