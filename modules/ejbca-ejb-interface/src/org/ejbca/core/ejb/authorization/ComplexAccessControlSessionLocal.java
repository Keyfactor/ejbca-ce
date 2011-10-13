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

    public static final String SUPERADMIN_ROLE = "Super Administrator Role";
    
    /**
     * Returns a Collection of role names authorized to the resource,
     * it also only returns only the admin groups the administrator is authorized to edit.
     */
    Collection<RoleData> getAuthorizedAdminGroups(AuthenticationToken admin, String resource);

    /**
     * Creates a super administrator role and a default CLI user. A role and default CLI user is needed in order
     * to do operations with the CLI (command line interface).  
     */
    void createSuperAdministrator();
    
    /** 
     * initializes the authorization module, if no roles or CAs exists in the system. This is done during startup 
     * so that we can use the CLI after this to install and configure the system further.
     * This method only performs any operation of RoleData and CAData both have no entries. 
     */
    void initializeAuthorizationModule();
    
    /**
     * Method to check if an end entity profile exists in any end entity profile
     * rules. Used to avoid desynchronization of profilerules.
     * 
     * @param profileid the profile id to search for.
     * @return true if profile exists in any of the accessrules.
     */
    boolean existsEndEntityProfileInRules(int profileid);
    
    /**
     * Help function to existsCAInRules, checks if ca id exists among
     * accessrules.
     */
    boolean existsCaInAccessRules(int caid);
    
    /**
     * Checks if caid exists among entities in
     * AccessUserAspectData.
     */
     boolean existsCAInAccessUserAspects(int caId);
}
