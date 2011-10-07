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
package org.ejbca.core.ejb.roles;

import java.util.Collection;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.roles.RoleData;
import org.cesecore.roles.RoleNotFoundException;

/**
 * This interface contains methods that couldn't bee added to RoleManagementSession
 * 
 * @version $Id$
 *
 */
public interface ComplexRoleManagementSession {

    /**
     * Replaces the existing access rules in the given role by removing the old ones and adding the list of new ones.
     * 
     * @param authenticationToken for authorization purposes.
     * @param role the role in question.
     * @param accessRules A Collection of access rules to replace with.
     * @return the same role.
     * @throws AuthorizationDeniedException if authorization was denied.
     * @throws RoleNotFoundException if the supplied role was not found in persistence. 
     */
    RoleData replaceAccessRulesInRole(AuthenticationToken authenticationToken, final RoleData role, final Collection<AccessRuleData> accessRules)
            throws AuthorizationDeniedException, RoleNotFoundException;
    
}
