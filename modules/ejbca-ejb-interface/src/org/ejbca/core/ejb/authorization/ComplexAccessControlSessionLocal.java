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

import javax.ejb.Local;

import org.cesecore.authentication.tokens.AuthenticationToken;

/**
 * @version $Id$
 * 
 */
@Local
public interface ComplexAccessControlSessionLocal extends ComplexAccessControlSession {

    public static final String SUPERADMIN_ROLE = "Super Administrator Role";
    public static final String TEMPORARY_SUPERADMIN_ROLE = "Temporary Super Administrator Group";
    
    /**
     * Creates a super administrator role and a default CLI user. A role and default CLI user is needed in order
     * to do operations with the CLI (command line interface).  
     */
    void createSuperAdministrator();
    
    /** 
     * initializes the authorization module, if no roles or CAs exists in the system. This is done during startup 
     * so that we can use the CLI after this to install and configure the system further.
     * This method only performs any operation of RoleData and CAData both have no entries. 
     * 
     * @return true if initialization was done. This also means that this is a fresh installation of EJBCA.
     * @deprecated superseded by AuthorizationSystemSessionLocal.initializeAuthorizationModule()
     */
    @Deprecated
    boolean initializeAuthorizationModule();
    
    /**
     * Method to check if an end entity profile exists in any end entity profile
     * rules. Used to avoid desynchronization of profilerules.
     * 
     * @param profileid the profile id to search for.
     * @return true if profile exists in any of the accessrules.
     */
    boolean existsEndEntityProfileInRules(int profileid);
    
    /**
     * Method used to collect all access rules, but will perform authorization checks on CAs, and EEPs and CPs dependent on CAs. Is used by
     * the advanced roles administration page in the UI to display all rules without leaking information about CA's.
     * 
     * @param admin is the administrator calling the method.
     * @param availableCaIds A Collection<Integer> of all CA IDs
     * @param enableendentityprofilelimitations Include End Entity Profile access rules
     * @param usehardtokenissuing Include Hard Token access rules
     * @param usekeyrecovery Include Key Recovery access rules
     * @param authorizedEndEntityProfileIds A Collection<Integer> of all authorized End Entity Profile IDs
     * @param authorizedUserDataSourceIds A Collection<Integer> of all authorized user data sources IDs
     * @param 
     * @return a LinkedHashMap of strings representing the available access rules, keyed by category
     */
    Map<String, Set<String>> getAllAccessRulesRedactUnauthorizedCas(AuthenticationToken authenticationToken, boolean enableendentityprofilelimitations,
            boolean usehardtokenissuing, boolean usekeyrecovery, Collection<Integer> authorizedEndEntityProfileIds,
            Collection<Integer> authorizedUserDataSourceIds, String[] customaccessrules);
   
}
