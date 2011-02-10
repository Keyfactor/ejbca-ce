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
package org.cesecore.core.ejb.authorization;

import java.util.Collection;
import java.util.List;

import org.ejbca.core.model.authorization.AccessRule;
import org.ejbca.core.model.authorization.AdminGroup;
import org.ejbca.core.model.authorization.AdminGroupExistsException;
import org.ejbca.core.model.log.Admin;

/**
 * @version $Id$
 */
public interface AdminGroupSession {

    /** Adds a Collection of AccessRule to an an admin group. */
    public void addAccessRules(Admin admin, String admingroupname, Collection<AccessRule> accessrules);
    
    /**
     * Method to add an AdminGroup.
     * 
     * @param admingroupname name of new AdminGroup, have to be unique.
     * @throws AdminGroupExistsException if AdminGroup already exists.
     */
    public void addAdminGroup(Admin admin, String admingroupname) throws AdminGroupExistsException;
    

    /**
     * Method to check if an administrator exists in the specified AdminGroup.
     * @return true if administrator exists in group
     */
    public boolean existsAdministratorInGroup(Admin admin, int admingrouppk);
    
    /**
     * Initializes this session bean manually, primarily for use from the CLI.
     * @throws AdminGroupExistsException 
     */
    public void init(Admin admin, int caid, String superAdminCN) throws AdminGroupExistsException;
    
    /**
     * Method to get a reference to a AdminGroup.
     * @return The AdminGroup, null if it doesn't exist. 
     */
    public AdminGroup getAdminGroup(Admin admin, String admingroupname);
    
    /**
     * Returns a Collection of AdminGroup the administrator is authorized to.
     * <p/>
     * SuperAdmin is authorized to all groups Other admins are only authorized
     * to the groups containing a subset of authorized CA that the admin himself
     * is authorized to.
     * <p/>
     * The AdminGroup objects only contains only name and caid and no accessdata
     * 
     * @param admin The current administrator
     * @param availableCaIds A Collection<Integer> of all CA Ids
     */
    public Collection<AdminGroup> getAuthorizedAdminGroupNames(Admin admin, Collection<Integer> availableCaIds);
    
    /**
     * Removes a Collection of (String) containing accessrules to remove from
     * admin group.
     */
    public void removeAccessRules(Admin admin, String admingroupname, List<String> accessrules);

    /** Replaces a group's accessrules with a new set of rules */
    public void replaceAccessRules(Admin admin, String admingroupname, Collection<AccessRule> accessrules);
    
    /** Method to remove a AdminGroup. */
    public void removeAdminGroup(Admin admin, String admingroupname);
    
    /**
     * Renames an AdminGroup.
     * @throws AdminGroupExistsException if AdminGroup already exists.
     */
    public void renameAdminGroup(Admin admin, String oldname, String newname) throws AdminGroupExistsException;
    
}
