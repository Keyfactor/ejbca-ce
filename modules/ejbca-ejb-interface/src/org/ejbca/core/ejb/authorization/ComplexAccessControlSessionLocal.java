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
package org.ejbca.core.ejb.authorization;

import java.util.Collection;

import javax.ejb.Local;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.roles.RoleData;

/**
 * @version $Id$
 * 
 */
@Local
public interface ComplexAccessControlSessionLocal extends ComplexAccessControlSession {

    /**
     * Returns a Collection of role names authorized to the resource,
     * it also only returns only the admin groups the administrator is authorized to edit.
     */
    public Collection<RoleData> getAuthorizedAdminGroups(AuthenticationToken admin, String resource);

    void initializeAuthorizationModule();
}
