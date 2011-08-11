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

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.roles.RoleData;

/**
 * @version $Id$
 *
 */
public interface ComplexAccessControlSession {
    /**
     * Retrieves a list of the roles which the given subject is authorized to edit, by checking if that subject has rights to the CA's behind all
     * access user aspects in that role, and all CA-based rules
     * 
     * @param authenticationToken An authentication token for the subject
     * @return a list of roles which the subject is authorized to edit.
     */
    Collection<RoleData> getAllRolesAuthorizedToEdit(AuthenticationToken authenticationToken);

    /**
     * Examines if the current user is authorized to edit a role. It checks all access user aspects (and checks access to the CA's issuing them), as
     * well as all CA based rules within the role.
     * 
     * @param authenticationToken an authentication token for the subject to check
     * @param role the role to check against.
     * @return true if the subject has access.
     */
    boolean isAuthorizedToEditRole(AuthenticationToken authenticationToken, RoleData role);

    /**
     * Method used to return an Collection of Integers indicating which end entity profiles the administrator is authorized to view.
     * 
     * @param admin, the administrator
     * @param rapriviledge should be one of the end entity profile authorization constants defined in AvailableAccessRules.
     * @param availableEndEntityProfileId a list of available EEP ids to test for authorization
     */
    Collection<Integer> getAuthorizedEndEntityProfileIds(AuthenticationToken admin, String rapriviledge,
            Collection<Integer> availableEndEntityProfileId);

    /**
     * Method used to collect an administrators available access rules based on which rule he himself is authorized to.
     * 
     * @param admin is the administrator calling the method.
     * @param availableCaIds A Collection<Integer> of all CA IDs
     * @param enableendentityprofilelimitations Include End Entity Profile access rules
     * @param usehardtokenissuing Include Hard Token access rules
     * @param usekeyrecovery Include Key Recovery access rules
     * @param authorizedEndEntityProfileIds A Collection<Integer> of all authorized End Entity Profile IDs
     * @param authorizedUserDataSourceIds A Collection<Integer> of all authorized user data sources IDs
     * @return a Collection of strings representing the available access rules.
     */
    Collection<String> getAuthorizedAvailableAccessRules(AuthenticationToken authenticationToken,
            boolean enableendentityprofilelimitations, boolean usehardtokenissuing, boolean usekeyrecovery,
            Collection<Integer> authorizedEndEntityProfileIds, Collection<Integer> authorizedUserDataSourceIds, String[] customaccessrules);
}
