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
package org.ejbca.core.ejb.authorization;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.roles.RoleExistsException;

/**
 * @version $Id$
 */
@Deprecated // Use AuthorizationSystemSession
public interface ComplexAccessControlSession {
	
	/** Initializes the authorization module with a superadmin rule matching the given caid and superadminCN
	 * 
	 * @param admin AuthenticationToken of the admin adding the rule
	 * @param caid the ca id of the CA issuing the SuperAdmin certificate
	 * @param superAdminCN the CN of the superadmin to match in the rule
	 * @throws AuthorizationDeniedException 
	 * @throws RoleExistsException 
     * @deprecated superseded by AuthorizationSystemSessionLocal.initializeAuthorizationModule() and use of RoleSession and RoleMemberSession
	 */
    @Deprecated
    void initializeAuthorizationModule(AuthenticationToken admin, int caid, String superAdminCN) throws RoleExistsException, AuthorizationDeniedException;
}
