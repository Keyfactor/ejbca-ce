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

import java.util.Collection;
import java.util.Map;
import java.util.Set;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.roles.RoleExistsException;

/**
 * @version $Id$
 *
 */
public interface ComplexAccessControlSession {
	
	/** Initializes the authorization module with a superadmin rule matching the given caid and superadminCN
	 * 
	 * @param admin AuthenticationToken of the admin adding the rule
	 * @param caid the ca id of the CA issuing the SuperAdmin certificate
	 * @param superAdminCN the CN of the superadmin to match in the rule
	 * @throws AuthorizationDeniedException 
	 * @throws RoleExistsException 
	 */
    void initializeAuthorizationModule(AuthenticationToken admin, int caid, String superAdminCN) throws RoleExistsException, AuthorizationDeniedException;

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
     * @return a LinkedHashMap of strings representing the available access rules, keyed by category
     */
    Map<String, Set<String>> getAuthorizedAvailableAccessRules(AuthenticationToken authenticationToken,
            boolean enableendentityprofilelimitations, boolean usehardtokenissuing, boolean usekeyrecovery,
            Collection<Integer> authorizedEndEntityProfileIds, Collection<Integer> authorizedUserDataSourceIds, String[] customaccessrules);
}
