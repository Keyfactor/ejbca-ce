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

    /**
     * Adds a profile to the database. Will automatically set a valid ID. 
     *
     * 
     * @param admin administrator performing task
     * @param profilename readable profile name
     * @param profile profile to be added
     * @return the ID of the end entity profile added. 
     * @throws AuthorizationDeniedException if admin was not authorized to add end entity profiles
     * @throws EndEntityProfileExistsException if a profile of the given name already exists
     * 
     */
    int addEndEntityProfile(AuthenticationToken admin, String profilename, EndEntityProfile profile) throws EndEntityProfileExistsException,
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

    /** Retrieves a Collection of id:s (Integer) to authorized profiles. 
     * @param admin the administrator for whom to get the profile Ids he/she has access to
     * @param endentityAccessRule an access rule which is required on the profile in order for it to be returned, for example AccessRulesConstants.CREATE_END_ENTITY to only return profiles for which the admin have create rights
     * @return Collection of end entity profile id:s (Integer)
     */
    Collection<Integer> getAuthorizedEndEntityProfileIds(AuthenticationToken admin, String endentityAccessRule);

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
     * Checks if the administrator is authorized to the given end entity profile.
     *
     * @param admin Administrator
     * @param id Profile ID
     * @return true if authorized, false if not.
     */
    boolean isAuthorizedToView(final AuthenticationToken admin, final int id);

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
     * Fetches available certificate profiles associated with an end entity profile.
     *
     * No authorization required.
     *
     * @param admin the authentication of the caller.
     * @param entityProfileId id of the end entity profile.
     * @return a map of available certificate profiles names and IDs or an empty map.
     * @throws EndEntityProfileNotFoundException if a profile with the ID entityProfileId could not be found
     * @throws AuthorizationDeniedException if the authorization was denied (still not thrown).
     */
    Map<String, Integer> getAvailableCertificateProfiles(AuthenticationToken admin, int entityProfileId) throws EndEntityProfileNotFoundException;
    
    /**
     * Fetches the available CAs associated with an end entity profile.
     *
     * Authorization requirements:<pre>
     * - /administrator
     * - /endentityprofilesrules/&lt;end entity profile&gt;
     * </pre>
     *
     * @param admin the authentication of the caller.
     * @param entityProfileId id of the end entity profile.
     * @return a map of available CA names and IDs or an empty map.
     * @throws AuthorizationDeniedException if the authorization was denied (still not thrown).
     * @throws EndEntityProfileNotFoundException if the end entity could not be found.
     */
    Map<String,Integer> getAvailableCasInProfile(AuthenticationToken admin, final int entityProfileId) throws AuthorizationDeniedException, EndEntityProfileNotFoundException;
    
    /**
     * Method to check if a CA exists in any of the end entity profiles. Used to
     * avoid desynchronization of CA data.
     * @param caid the caid to search for.
     * 
     * @return true if CA exists in any of the end entity profiles.
     */
    boolean existsCAInEndEntityProfiles(int caid);

    /**
     * Fetches the profile specified by profileId and profileType in XML format.
     *
     * Authorization requirements:<pre>
     * - /administrator
     * - /endentityprofilesrules/&lt;end entity profile&gt;
     * - /ca/&lt;ca name&gt;
     * </pre>
     *
     * For detailed documentation for how to parse an End Entity Profile XML, see the org.ejbca.core.model.ra.raadmin.EndEntity class.
     *
     * @param profileId ID of the profile we want to retrieve.
     * @return a byte array containing the specified profile in XML format.
     * @throws AuthorizationDeniedException if the requesting admin wasn't authorized to the profile or any of the CA's therein
     * @throws EndEntityProfileNotFoundException if the profile was not found
     */
    byte[] getProfileAsXml(AuthenticationToken authenticationToken, int profileId) throws AuthorizationDeniedException, EndEntityProfileNotFoundException;
}
