/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.roles.management;

import java.security.cert.Certificate;
import java.util.Collection;

import javax.ejb.Local;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.roles.RoleData;
import org.cesecore.roles.RoleExistsException;
import org.cesecore.roles.RoleNotFoundException;

/**
 * Local interface for RoleManagementSession.
 * 
 * @version $Id$
 *
 */
@Local
public interface RoleManagementSessionLocal extends RoleManagementSession {

    /** Method used to initialize an initial role with access to edit roles, i.e. a superadmin "/" rule, and "editroles".
     * If only would have EDITROLES rule, the admin could only edit roles with the EDITROLE rule.
     * LocalOnly, should only be used from test code.
     *  
     * @throws RoleExistsException if the role already exist
     */
    void initializeAccessWithCert(AuthenticationToken authenticationToken, String roleName, Certificate certificate) throws RoleExistsException, RoleNotFoundException;
    
    /**
     * @return a Collection of role names authorized to the resource,
     * it also only returns only the roles the administrator is authorized to edit.
     */
    Collection<RoleData> getAuthorizedRoles(AuthenticationToken admin, String resource);

}
