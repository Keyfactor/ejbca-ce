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
package org.ejbca.core.ejb.ra.raadmin;

import java.util.Collection;
import java.util.List;
import java.util.Map;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileNotFoundException;

/** Session bean for managing End Entity Profiles.
 * 
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
    void addEndEntityProfile(AuthenticationToken admin, String profilename, EndEntityProfile profile) throws EndEntityProfileExistsException,
            AuthorizationDeniedException;

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
    void addEndEntityProfile(AuthenticationToken admin, int profileid, String profilename, EndEntityProfile profile)
            throws EndEntityProfileExistsException, AuthorizationDeniedException;

    /**
     * Adds a end entity profile to a group with the same content as the
     * original profile.
     * @throws AuthorizationDeniedException 
     */
    void cloneEndEntityProfile(AuthenticationToken admin, String originalprofilename, String newprofilename) throws EndEntityProfileExistsException,
            AuthorizationDeniedException;

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
    void renameEndEntityProfile(AuthenticationToken admin, String oldprofilename, String newprofilename) throws EndEntityProfileExistsException,
            AuthorizationDeniedException;

    /** Updates profile data. 
     * @throws AuthorizationDeniedException 
     * @throws EndEntityProfileNotFoundException if sought end entity profile was not found.
     */
    void changeEndEntityProfile(AuthenticationToken admin, String profilename, EndEntityProfile profile) throws AuthorizationDeniedException, EndEntityProfileNotFoundException;

    /**
     * Do NOT use, use changeEndEntityProfile instead. Used internally for
     * testing only. Updates a profile without flushing caches.
     * 
     * TODO: Move this method out of production code.
     * 
     * @throws AuthorizationDeniedException 
     * @throws EndEntityProfileNotFoundException if sought end entity profile was not found.
     */
    void internalChangeEndEntityProfileNoFlushCache(AuthenticationToken admin, String profilename, EndEntityProfile profile)
            throws AuthorizationDeniedException, EndEntityProfileNotFoundException;

    /** Retrieves a Collection of id:s (Integer) to authorized profiles. */
    Collection<Integer> getAuthorizedEndEntityProfileIds(AuthenticationToken admin);

    /**
     * Retrives a list of ids to profiles with non-existent CA ids, if the admin has root rule access.
     * Otherwise an empty list is returned.
     */
    List<Integer> getAuthorizedEndEntityProfileIdsWithMissingCAs(final AuthenticationToken admin);

    /** @return mapping of profile id (Integer) to profile name (String). */
    Map<Integer, String> getEndEntityProfileIdToNameMap();

    /** Clear and reload end entity profile caches. */
    void flushProfileCache();

    /**
     * Finds a end entity profile by id.
     * @return EndEntityProfile (cloned) or null if it does not exist
     */
    EndEntityProfile getEndEntityProfile(int id);

    /**
     * Get a copy of an EndEntityProfile.
     * @return EndEntityProfile (cloned) or null if it does not exist
     */
    EndEntityProfile getEndEntityProfile(String profilename);

    /**
     * Returns a end entity profile's ID, given its name
     * @return the id
     * @throws EndEntityProfileNotFoundException if profile wasn't found
     */
    int getEndEntityProfileId(String profilename) throws EndEntityProfileNotFoundException;

    /**
     * Returns a end entity profiles name given it's id.
     * @return profile's name or null if profile id does not exist.
     */
    String getEndEntityProfileName(int id);

    /**
     * Method to check if a CertificateProfile exists in any of the end entity
     * profiles. Used to avoid desynchronization of certificate profile data.
     * 
     * @param certificateprofileid the CertificateProfile's id to search for.
     * @return  a collection of EndEntityProfile names using the sought CertificateProfile
     */
    List<String> getEndEntityProfilesUsingCertificateProfile(int certificateprofileid);

    /**
     * Method to check if a CA exists in any of the end entity profiles. Used to
     * avoid desynchronization of CA data.
     * @param caid the caid to search for.
     * 
     * @return true if CA exists in any of the end entity profiles.
     */
    boolean existsCAInEndEntityProfiles(int caid);

}
