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

import java.io.IOException;
import java.util.Map;

import javax.ejb.Local;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.model.ra.UnknownProfileTypeException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;

/**
 * @version $Id$
 */
@Local
public interface EndEntityProfileSessionLocal extends EndEntityProfileSession {

    /**
     * A method designed to be called at startup time to (possibly) upgrade end
     * entity profiles. This method will read all End Entity Profiles and as a
     * side-effect upgrade them if the version if changed for upgrade. Can have
     * a side-effect of upgrading a profile, therefore the Required transaction
     * setting.
     */
    void initializeAndUpgradeProfiles();

    /** Helper method that checks if an administrator is authorized to all CAs present in the profiles "available CAs"
     * 
     * @param admin administrator to check.
     * @param profile the profile to check
     * @throws AuthorizationDeniedException if admin is not authorized to one of the available CAs in the profile
     */
    void authorizedToProfileCas(AuthenticationToken admin, EndEntityProfile profile) throws AuthorizationDeniedException;
    
    /**
     * Fetches available certificate profiles associated with an end entity profile.
     *
     * Authorization requirements:<pre>
     * - /administrator
     * - /endentityprofilesrules/&lt;end entity profile&gt;
     * </pre>
     *
     * @param admin the authentication of the caller.
     * @param entityProfileId id of the end entity profile.
     * @return a map of available certificate profiles names and IDs or an empty map.
     * @throws AuthorizationDeniedException if the authorization was denied.
     * @throws EjbcaException if an error occured.
     */
    Map<String, Integer> getAvailableCertificateProfiles(AuthenticationToken admin, int entityProfileId) throws AuthorizationDeniedException, EjbcaException;
    
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
     * @throws AuthorizationDeniedException if the authorization was denied.
     * @throws EjbcaException any EjbcaException.
     */
    Map<String,Integer> getAvailableCAsInProfile(AuthenticationToken admin, final int entityProfileId) throws AuthorizationDeniedException, EjbcaException;
    
    
    /** WARNING: This method must only be used when doing read_only operation on the profile. Otherwise
     * any changes to the profile will affect the profile in the cache and thus affect all other threads.
     * 
     * Use the normal getEndEntityProfile for all edit operations, followed by a changeEndEntityProfile if you want to persist your changes and make 
     * them visible for other threads.
     * 
     * This method exists only for speed purposes since a clone() done by the proper getEndEntityProfile method is slightly expensive.
     * 
     * Finds a end entity profile by id.
     * @return EndEntityProfile (shared in cache) or null if it does not exist
     */
    EndEntityProfile getEndEntityProfileNoClone(int id);

    /** WARNING: This method must only be used when doing read_only operation on the profile. Otherwise
     * any changes to the profile will affect the profile in the cache and thus affect all other threads.
     * 
     * Use the normal getEndEntityProfile for all edit operations, followed by a changeEndEntityProfile if you want to persist your changes and make 
     * them visible for other threads.
     * 
     * This method exists only for speed purposes since a clone() done by the proper getEndEntityProfile method is slightly expensive.
     * 
     * Finds an EndEntityProfile by name.
     * @return EndEntityProfile (shared in cache) or null if it does not exist
     */
    EndEntityProfile getEndEntityProfileNoClone(java.lang.String profilename);

    /**
     * Fetches the profile specified by profileId and profileType in XML format.
     *
     * Authorization requirements:<pre>
     * - /administrator
     * - /endentityprofilesrules/&lt;end entity profile&gt;
     * </pre>
     *
     * For detailed documentation for how to parse an End Entity Profile XML, see the org.ejbca.core.model.ra.raadmin.EndEntity class.
     *
     * @param authenticationToken the administrator performing the action.
     * @param profileId ID of the profile we want to retrieve.
     * @param profileType The type of the profile we want to retrieve. 'eep' for End Entity Profiles and 'cp' for Certificate Profiles.
     * @return a byte array containing the specified profile in XML format.
     * @throws AuthorizationDeniedException if client isn't authorized to request.
     * @throws UnknownProfileTypeException if the profile type is not known.
     * @throws EjbcaException any EjbcaException.
     * @throws IOException if the XML profile data could not be encoded.
     */
     byte[] getProfile(AuthenticationToken authenticationToken, int profileId, String profileType)
                 throws AuthorizationDeniedException, UnknownProfileTypeException, EjbcaException, IOException;
}
