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

import org.ejbca.core.model.log.Admin;

public interface AuthorizationSession {

    /**
     * Method to check if a user is authorized to a certain resource.
     * 
     * @param admin
     *            the administrator about to be authorized, see
     *            Admin class.
     * @param resource
     *            the resource to check authorization for.
     * @return true if authorized
     */
    public boolean isAuthorized(Admin admin, String resource);

    /**
     * Method to check if a user is authorized to a certain resource without
     * performing any logging.
     * 
     * @param admin
     *            the administrator about to be authorized, see
     *            Admin class.
     * @param resource
     *            the resource to check authorization for.
     * @return true if authorized, false if not.
     */
    public boolean isAuthorizedNoLog(Admin admin, String resource);

    /**
     * Method to check if a group is authorized to a resource.
     * 
     * @return true if authorized
     */
    public boolean isGroupAuthorized(Admin admin, int adminGroupId, String resource);

    /**
     * Method to check if a group is authorized to a resource without any
     * logging.
     * 
     * @return true if authorized
     */
    public boolean isGroupAuthorizedNoLog(int adminGroupId, String resource);
   

    public boolean isAuthorizedToGroup(Admin administrator, String admingroupname);

    /**
     * Method used to collect an administrators available access rules based on
     * which rule he himself is authorized to.
     * 
     * @param admin
     *            is the administrator calling the method.
     * @param availableCaIds
     *            A Collection<Integer> of all CA Ids
     * @param enableendentityprofilelimitations
     *            Include End Entity Profile access rules
     * @param usehardtokenissuing
     *            Include Hard Token access rules
     * @param usekeyrecovery
     *            Include Key Recovery access rules
     * @param authorizedEndEntityProfileIds
     *            A Collection<Integer> of all auhtorized End Entity Profile ids
     * @param authorizedUserDataSourceIds
     *            A Collection<Integer> of all auhtorized user data sources ids
     * @return a Collection of String containing available accessrules.
     */
    public Collection<String> getAuthorizedAvailableAccessRules(Admin admin, Collection<Integer> availableCaIds,
            boolean enableendentityprofilelimitations, boolean usehardtokenissuing, boolean usekeyrecovery, Collection<Integer> authorizedEndEntityProfileIds,
            Collection<Integer> authorizedUserDataSourceIds);

    /**
     * Method used to return an Collection of Integers indicating which CAids a
     * administrator is authorized to access.
     * 
     * @param admin
     *            The current administrator
     * @param availableCaIds
     *            A Collection<Integer> of all CA Ids
     * @return Collection of Integer
     */
    public Collection<Integer> getAuthorizedCAIds(Admin admin, Collection<Integer> availableCaIds);

    /**
     * Method used to return an Collection of Integers indicating which end
     * entity profiles the administrator is authorized to view.
     * 
     * @param admin
     *            the administrator
     * @param rapriviledge
     *            should be one of the end entity profile authorization constans
     *            defined in AccessRulesConstants.
     * @param authorizedEndEntityProfileIds
     *            A Collection<Integer> of all auhtorized EEP ids
     */
    public Collection<Integer> getAuthorizedEndEntityProfileIds(Admin admin, String rapriviledge,
            Collection<Integer> availableEndEntityProfileId);

    /**
     * Method to check if an end entity profile exists in any end entity profile
     * rules. Used to avoid desyncronization of profilerules.
     * 
     * @param profileid
     *            the profile id to search for.
     * @return true if profile exists in any of the accessrules.
     */
    public boolean existsEndEntityProfileInRules(Admin admin, int profileid);
    

    /**
     * Method to check if a ca exists in any ca specific rules. Used to avoid
     * desyncronization of CA rules when ca is removed
     * 
     * @param caid
     *            the ca id to search for.
     * @return true if ca exists in any of the accessrules.
     */
    public boolean existsCAInRules(Admin admin, int caid);

    /**
     * Method to force an update of the autorization rules without any wait.
     */
    public void forceRuleUpdate(Admin admin);
    
    /**
     * Clear and load authorization rules cache.
     */
    public void flushAuthorizationRuleCache();
    

}
