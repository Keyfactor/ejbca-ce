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
import org.ejbca.core.model.approval.ApprovalProfile;

/** Session bean to manage approval profiles, i.e. add, remove, find
 * 
 * In order to add or edit ApprovalProfiles the admin needs access to:
 * - /ca_functionality/ (StandardRules.CAFUNCTIONALITY
 * 
 * @version $Id$
 */
public interface ApprovalProfileSession {

    /**
     * Adds an approval profile to the database.
     * 
     * @param admin administrator performing the task
     * @param name readable name of new approval profile
     * @param profile the profile to be added
     * @return the generated approval profile id
     * @throws ApprovalProfileExistsException
     * @throws AuthorizationDeniedException
     */
    int addApprovalProfile(AuthenticationToken admin, String name, ApprovalProfile profile) throws ApprovalProfileExistsException, AuthorizationDeniedException;
    
    /**
     * Updates approval profile data
     * 
     * @param admin Administrator performing the operation
     * @param name readable name of the approval profile to be changed
     * @param profile the changed profile
     * @throws AuthorizationDeniedException
     */
    void changeApprovalProfile(AuthenticationToken admin, String name, ApprovalProfile profile) throws AuthorizationDeniedException;

    /** Clear and reload approval profile caches. */
    void forceProfileCacheExpire();

    /**
     * Adds an approval profile with the same content as the original approval profile.
     * 
     * @param admin Administrator performing the operation
     * @param orgname name of original approval profile
     * @param newname name of new approval profile
     * @throws ApprovalProfileExistsException
     * @throws ApprovalProfileDoesNotExistException
     * @throws AuthorizationDeniedException
     */
    void cloneApprovalProfile(AuthenticationToken admin, String orgname, String newname) 
            throws ApprovalProfileExistsException, ApprovalProfileDoesNotExistException, AuthorizationDeniedException;

    /**
     * Retrieves a Collection of id:s (Integer) to authorized profiles. Only profiles that the specified administrator is 
     * authorized to will be returned. 
     * 
     * @param admin Administrator performing the operation
     * @return List of id:s (Integer)
     */
    List<Integer> getAuthorizedApprovalProfileIds(AuthenticationToken admin);

    /**
     * Finds an approval profile by id.
     * 
     * @param id approval profile id
     * @return Approval profile (cloned) or null if it can not be found.
     */
    ApprovalProfile getApprovalProfile(int id);

    /**
     * Retrieves a named approval profile or null if none was found.
     * 
     * @param name approval profile name
     * @return Approval profile (cloned) or null if it can not be found.
     */
    ApprovalProfile getApprovalProfile(String name);

    /**
     * Returns an approval profile id, given it's approval profile name.
     * 
     * @param name approval profile name
     * @return the id or 0 if approval profile cannot be found.
     * @throws ApprovalProfileDoesNotExistException
     */
    int getApprovalProfileId(String name) throws ApprovalProfileDoesNotExistException;

    /**
     * Returns an approval profile's name given it's id.
     * 
     * @param id approval profile id
     * @return approval profile name or null if approval profile id does not exist.
     */
    String getApprovalProfileName(int id);

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
     * @param oldname the name of the approval profile to rename
     * @param newname the new name of the approval profile
     * @throws ApprovalProfileExistsException
     * @throws ApprovalProfileDoesNotExistException
     * @throws AuthorizationDeniedException
     */
    void renameApprovalProfile(AuthenticationToken admin, String oldname, String newname)
            throws ApprovalProfileExistsException, ApprovalProfileDoesNotExistException, AuthorizationDeniedException;

    /**
     * Removes an approval profile from the database, does not throw any errors if the profile does not exist.
     *
     * @param admin Administrator performing the operation
     * @param name the name of the approval profile to remove
     * @throws AuthorizationDeniedException
     */
    void removeApprovalProfile(AuthenticationToken admin, String name) throws AuthorizationDeniedException;
    
    /**
     * Removes an approval profile from the database, does not throw any errors if the profile does not exist.
     *
     * @param admin Administrator performing the operation
     * @param id the ID of the approval profile to remove
     * @throws AuthorizationDeniedException
     */
    void removeApprovalProfile(AuthenticationToken admin, int id) throws AuthorizationDeniedException;

    /**
     * Forces the profile cache to rebuild. 
     */
    void forceProfileCacheRebuild();

}
