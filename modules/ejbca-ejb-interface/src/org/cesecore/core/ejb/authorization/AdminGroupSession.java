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

import org.ejbca.core.model.authorization.AdminGroup;
import org.ejbca.core.model.authorization.AdminGroupExistsException;
import org.ejbca.core.model.log.Admin;

/**
 * @version $Id$
 */
public interface AdminGroupSession {

    /**
     * Method to add an admingroup.
     * 
     * @param admingroupname
     *            name of new admingroup, have to be unique.
     * @throws AdminGroupExistsException
     *             if admingroup already exists.
     */
    public void addAdminGroup(Admin admin, String admingroupname)
            throws AdminGroupExistsException;
    

    /**
     * Method to check if an administrator exists in the specified admingroup.
     * 
     * @return true if administrator exists in group
     */
    public boolean existsAdministratorInGroup(Admin admin, int admingrouppk);
    
    /**
     * Initializes this session bean manually, primarily for use from the CLI.
     * @throws AdminGroupExistsException 
     */
    public void init(Admin admin, int caid, String superAdminCN) throws AdminGroupExistsException;
    
    /**
     * Method to get a reference to a admingroup.
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
     * @param admin
     *            The current administrator
     * @param availableCaIds
     *            A Collection<Integer> of all CA Ids
     */
    public Collection<AdminGroup> getAuthorizedAdminGroupNames(Admin admin, Collection<Integer> availableCaIds);
    
    /**
     * Method to remove a admingroup.
     */
    public void removeAdminGroup(Admin admin, String admingroupname);
    
    /**
     * Metod to rename a admingroup
     * 
     * @throws AdminGroupExistsException
     *             if admingroup already exists.
     */
    public void renameAdminGroup(Admin admin, String oldname, String newname)
            throws AdminGroupExistsException;
    
}
