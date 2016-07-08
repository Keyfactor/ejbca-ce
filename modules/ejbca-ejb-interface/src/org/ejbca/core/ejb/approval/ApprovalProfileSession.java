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
package org.ejbca.core.ejb.approval;

import java.util.List;
import java.util.Map;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.approval.profile.ApprovalProfile;

/** Session bean to manage approval profiles, i.e. add, remove, find
 * 
 * In order to add or edit ApprovalProfiles the admin needs access to:
 * - /ca_functionality/ (StandardRules.CAFUNCTIONALITY)
 * 
 * TODO: Generate a separate session beans specifically for performing CRUD operations on ProfileData objects, agnostic of their end purpose. This 
 *       bean is sufficient for now though.
 * 
 * @version $Id$
 */
public interface ApprovalProfileSession {

    /**
     * Adds an approval profile to the database.
     * 
     * @param admin administrator performing the task
     * @param profile the profile to be added
     * @return the generated approval profile id
     * @throws ApprovalProfileExistsException
     * @throws AuthorizationDeniedException if current administrator is not authorized to modify profiles
     */
    int addApprovalProfile(final AuthenticationToken admin, final ApprovalProfile profile) throws ApprovalProfileExistsException, AuthorizationDeniedException;
    
    /**
     * Updates approval profile data
     * 
     * @param admin Administrator performing the operation
     * @throws AuthorizationDeniedException if current administrator is not authorized to modify profiles
     * @throws AuthorizationDeniedException
     */
    void changeApprovalProfile(final AuthenticationToken admin, final ApprovalProfile profile) throws AuthorizationDeniedException;

    /**
     * Adds an approval profile with the same content as the original approval profile.
     * 
     * @param admin Administrator performing the operation
     * @param orgname name of original approval profile
     * @param newname name of new approval profile
     * @throws ApprovalProfileExistsException
     * @throws ApprovalProfileDoesNotExistException
     * @throws AuthorizationDeniedException if current administrator is not authorized to modify profiles
     */
    void cloneApprovalProfile(final AuthenticationToken admin, final ApprovalProfile profile, final String newname) 
            throws ApprovalProfileExistsException, ApprovalProfileDoesNotExistException, AuthorizationDeniedException;

    /**
     * Retrieves a Collection of id:s (Integer) to authorized profiles. Only profiles that the specified administrator is 
     * authorized to will be returned. 
     * 
     * @param admin Administrator performing the operation
     * @return List of id:s (Integer)
     */
    List<Integer> getAuthorizedApprovalProfileIds(final AuthenticationToken admin);

    /**
     * Finds an approval profile by id.
     * 
     * @param id approval profile id
     * @return Approval profile (cloned) or null if it can not be found.
     */
    ApprovalProfile getApprovalProfile(final int id);

    /**
     * Returns an approval profile's name given it's id.
     * 
     * @param id approval profile id
     * @return approval profile name or null if approval profile id does not exist.
     */
    String getApprovalProfileName(final int id);

    /**
     * Method creating a Map mapping profile id (Integer) to profile name
     * (String).
     * 
     * @return a Map mapping profile id (Integer) to profile name (String) 
     */
    Map<Integer, String> getApprovalProfileIdToNameMap();
    
    /**
     * Renames an approval profile
     * 
     * @param admin Administrator performing the operation
     * @param profile the profile to rename
     * @param newname the new name of the approval profile
     * @throws ApprovalProfileExistsException if a profile of that name already exists
     * @throws ApprovalProfileDoesNotExistException if the profile to be renamed hasn't been persisted.
     * @throws AuthorizationDeniedException if current administrator is not authorized to rename profiles
     */
    void renameApprovalProfile(final AuthenticationToken admin, final ApprovalProfile profile, final String newname)
            throws ApprovalProfileExistsException, ApprovalProfileDoesNotExistException, AuthorizationDeniedException;

    /**
     * Removes an approval profile from the database, does not throw any errors if the profile does not exist.
     *
     * @param admin Administrator performing the operation
     * @param profile the approval profile to remove
     * @throws AuthorizationDeniedException if current administrator is not authorized to modify profiles
     */
    void removeApprovalProfile(final AuthenticationToken admin, final ApprovalProfile profile) throws AuthorizationDeniedException;
    
    /**
     * Removes an approval profile from the database, does not throw any errors if the profile does not exist.
     *
     * @param admin Administrator performing the operation
     * @param id the ID of the approval profile to remove
     * @throws AuthorizationDeniedException if current administrator is not authorized to modify profiles
     */
    void removeApprovalProfile(final AuthenticationToken admin, final int id) throws AuthorizationDeniedException;

    /**
     * Forces the profile cache to rebuild. 
     */
    void forceProfileCacheRebuild();

}
