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

import org.ejbca.core.model.authorization.AdminEntity;
import org.ejbca.core.model.log.Admin;

/**
 * 
 * @version $Id$
 */
public interface AdminEntitySession {
 
    /**
     * Adds a Collection of AdminEnity to the admingroup. Changes their values
     * if they already exists. Does not give any errors if the admin group does
     * not exist.
     */
    public void addAdminEntities(Admin admin, String admingroupname, Collection<AdminEntity> adminentities);
    
    /** Removes a Collection of AdminEntity from the administrator group. */
    public void removeAdminEntities(Admin admin, String admingroupname, Collection<AdminEntity> adminentities);
    
}
