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
import java.security.cert.X509Certificate;
import java.util.List;

import javax.ejb.Remote;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.mock.authentication.tokens.TestX509CertificateAuthenticationToken;
import org.cesecore.roles.RoleExistsException;
import org.cesecore.roles.RoleNotFoundException;

/**
 * Remote interface for RoleManagementSession
 * 
 * @version $Id$
 *
 */
@Remote
public interface RoleInitializationSessionRemote {

    /** Method used to initialize an initial role with access to edit roles, i.e. a superadmin "/" rule, and "editroles".
    * If only would have EDITROLES rule, the admin could only edit roles with the EDITROLE rule.
    * LocalOnly, should only be used from test code.
    *  
    * @throws RoleExistsException if the role already exist
    */
    @Deprecated
    void initializeAccessWithCert(AuthenticationToken authenticationToken, String roleName, Certificate certificate) throws RoleExistsException,
            RoleNotFoundException, AuthorizationDeniedException;

    /** @return a new an AuthenticationToken that is RoleMember of a new Role with the requested access rights */
    TestX509CertificateAuthenticationToken createAuthenticationTokenAndAssignToNewRole(String subjectDn, String roleNameSpace, String roleName, List<String> resourcesAllowed,
            List<String> resourcesDenied) throws RoleExistsException;

    /** Assign the provided certificate as RoleMember of a new Role with the requested access rights */
    void createRoleAndAddCertificateAsRoleMember(X509Certificate x509Certificate, String roleNameSpace, String roleName,
            List<String> resourcesAllowed, List<String> resourcesDenied) throws RoleExistsException;

    /** Remove any role that the provided authentication token is a RoleMember of (note that this will match regular X509CertificateAuthenticationToken so be careful) */
    void removeAllAuthenticationTokensRoles(TestX509CertificateAuthenticationToken authenticationToken);
}
