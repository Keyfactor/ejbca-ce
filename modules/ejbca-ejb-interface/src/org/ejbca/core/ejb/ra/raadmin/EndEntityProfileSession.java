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
import java.util.Map;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException;

/** Session bean for managing End Entity Profiles.
 * 
 * @author Mike Kushner
 * @version $Id$
 */
public interface EndEntityProfileSession {

    static final String EMPTY_ENDENTITYPROFILENAME = "EMPTY";

    /**
     * Adds a profile to the database.
     * 
     * @param admin administrator performing task
     * @param profilename readable profile name
     * @param profile profile to be added
     * @throws AuthorizationDeniedException 
     */
    void addEndEntityProfile(AuthenticationToken admin, String profilename, EndEntityProfile profile) throws EndEntityProfileExistsException, AuthorizationDeniedException;

    /**
     * Adds a profile to the database.
     * 
     * @param admin administrator performing task
     * @param profileid internal ID of new profile, use only if you know it's
     *            right.
     * @param profilename readable profile name
     * @param profile profile to be added
     * @throws AuthorizationDeniedException 
     */
    void addEndEntityProfile(AuthenticationToken admin, int profileid, String profilename, EndEntityProfile profile) throws EndEntityProfileExistsException, AuthorizationDeniedException;

    /**
     * Adds a end entity profile to a group with the same content as the
     * original profile.
     * @throws AuthorizationDeniedException 
     */
    void cloneEndEntityProfile(AuthenticationToken admin, String originalprofilename, String newprofilename) throws EndEntityProfileExistsException, AuthorizationDeniedException;

    /** @return an unused end id number. */
    int findFreeEndEntityProfileId();

    /**
     * Removes an end entity profile from the database, does not throw any
     * errors if the profile does not exist.
     * @throws AuthorizationDeniedException 
     */
    void removeEndEntityProfile(AuthenticationToken admin, String profilename) throws AuthorizationDeniedException;

    /** Renames a end entity profile. 
     * @throws AuthorizationDeniedException */
    void renameEndEntityProfile(AuthenticationToken admin, String oldprofilename, String newprofilename) throws EndEntityProfileExistsException, AuthorizationDeniedException;

    /** Updates profile data. 
     * @throws AuthorizationDeniedException */
    void changeEndEntityProfile(AuthenticationToken admin, String profilename, EndEntityProfile profile) throws AuthorizationDeniedException;

    /**
     * Do NOT use, use changeEndEntityProfile instead. Used internally for
     * testing only. Updates a profile without flushing caches.
     * @throws AuthorizationDeniedException 
     */
    void internalChangeEndEntityProfileNoFlushCache(AuthenticationToken admin, String profilename, EndEntityProfile profile) throws AuthorizationDeniedException;

    /** Retrieves a Collection of id:s (Integer) to authorized profiles. */
    Collection<Integer> getAuthorizedEndEntityProfileIds(AuthenticationToken admin);

    /** @return mapping of profile id (Integer) to profile name (String). */
    Map<Integer, String> getEndEntityProfileIdToNameMap(AuthenticationToken admin);

    /** Clear and reload end entity profile caches. */
    void flushProfileCache();

    /**
     * Finds a end entity profile by id.
     * @return EndEntityProfile (cloned) or null if it does not exist
     */
    EndEntityProfile getEndEntityProfile(AuthenticationToken admin, int id);

    /**
     * Get a copy of an EndEntityProfile.
     * @return EndEntityProfile (cloned) or null if it does not exist
     */
    EndEntityProfile getEndEntityProfile(AuthenticationToken admin, java.lang.String profilename);

    /**
     * Returns a end entity profiles id, given it's profilename
     * @return the id or 0 if profile cannot be found.
     */
    int getEndEntityProfileId(AuthenticationToken admin, java.lang.String profilename);

    /**
     * Returns a end entity profiles name given it's id.
     * @return profile's name or null if profile id does not exist.
     */
    String getEndEntityProfileName(AuthenticationToken admin, int id);

    /**
     * Method to check if a CertificateProfile exists in any of the end entity
     * profiles. Used to avoid desynchronization of certificate profile data.
     * 
     * @param certificateprofileid the CertificateProfile's id to search for.
     * @return true if CertificateProfile exists in any EndEntityProfile.
     */
    boolean existsCertificateProfileInEndEntityProfiles(AuthenticationToken admin, int certificateprofileid);

    /**
     * Method to check if a CA exists in any of the end entity profiles. Used to
     * avoid desynchronization of CA data.
     * 
     * @param caid the caid to search for.
     * @return true if CA exists in any of the end entity profiles.
     */
    boolean existsCAInEndEntityProfiles(AuthenticationToken admin, int caid);

    /**
     * A method designed to be called at startup time to (possibly) upgrade end
     * entity profiles. This method will read all End Entity Profiles and as a
     * side-effect upgrade them if the version if changed for upgrade. Can have
     * a side-effect of upgrading a profile, therefore the Required transaction
     * setting.
     * 
     * @param admin administrator calling the method
     */
    void initializeAndUpgradeProfiles(AuthenticationToken admin);

}
