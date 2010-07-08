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

import org.ejbca.core.model.authorization.AdminGroup;
import org.ejbca.core.model.authorization.AdminGroupExistsException;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.log.Admin;

public interface AuthorizationSession {

    /**
     * Method to initialize authorization bean, must be called directly after
     * creation of bean. Should only be called once.
     */
    public void initialize(Admin admin, int caid, String superAdminCN) throws AdminGroupExistsException;

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
    public boolean isAuthorized(Admin admin, String resource) throws AuthorizationDeniedException;

    /**
     * Method to check if a user is authorized to a certain resource without
     * performing any logging.
     * 
     * @param admin
     *            the administrator about to be authorized, see
     *            Admin class.
     * @param resource
     *            the resource to check authorization for.
     * @return true if authorized, but not false if not authorized, throws
     *         exception instead so return value can safely be ignored.
     */
    public boolean isAuthorizedNoLog(Admin admin, String resource) throws AuthorizationDeniedException;

    /**
     * Method to check if a group is authorized to a resource.
     * 
     * @return true if authorized
     */
    public boolean isGroupAuthorized(Admin admin, int adminGroupId, String resource)
            throws AuthorizationDeniedException;

    /**
     * Method to check if a group is authorized to a resource without any
     * logging.
     * 
     * @return true if authorized
     */
    public boolean isGroupAuthorizedNoLog(int adminGroupId, String resource) throws AuthorizationDeniedException;

    /**
     * Method to check if an administrator exists in the specified admingroup.
     * 
     * @return true if administrator exists in group
     */
    public boolean existsAdministratorInGroup(Admin admin, int admingrouppk);

    /**
     * Method to add an admingroup.
     * 
     * @param admingroupname
     *            name of new admingroup, have to be unique.
     * @throws AdminGroupExistsException
     *             if admingroup already exists.
     */
    public void addAdminGroup(Admin admin, String admingroupname)
            throws AdminGroupExistsException;

    /**
     * Method to remove a admingroup.
     */
    public void removeAdminGroup(Admin admin, String admingroupname);

    /**
     * Metod to rename a admingroup
     * 
     * @throws AdminGroupExistsException
     *             if admingroup already exists.
     */
    public void renameAdminGroup(Admin admin, String oldname, String newname)
            throws AdminGroupExistsException;

    /**
     * Method to get a reference to a admingroup.
     */
    public AdminGroup getAdminGroup(Admin admin, String admingroupname);

    /**
     * Returns a Collection of AdminGroup the administrator is authorized to.
     * <p/>
     * SuperAdmin is authorized to all groups Other admins are only authorized
     * to the groups containing a subset of authorized CA that the admin himself
     * is authorized to.
     * <p/>
     * The AdminGroup objects only contains only name and caid and no accessdata
     * 
     * @param admin
     *            The current administrator
     * @param availableCaIds
     *            A Collection<Integer> of all CA Ids
     */
    public Collection getAuthorizedAdminGroupNames(Admin admin, Collection availableCaIds);

    /**
     * Adds a Collection of AccessRule to an an admin group.
     */
    public void addAccessRules(Admin admin, String admingroupname, Collection accessrules);

    /**
     * Removes a Collection of (String) containing accessrules to remove from
     * admin group.
     */
    public void removeAccessRules(Admin admin, String admingroupname, Collection accessrules);

    /**
     * Replaces a groups accessrules with a new set of rules
     */
    public void replaceAccessRules(Admin admin, String admingroupname, Collection accessrules);

    /**
     * Adds a Collection of AdminEnity to the admingroup. Changes their values
     * if they already exists.
     */
    public void addAdminEntities(Admin admin, String admingroupname, Collection adminentities);

    /**
     * Removes a Collection of AdminEntity from the administrator group.
     */
    public void removeAdminEntities(Admin admin, String admingroupname, Collection adminentities);

    public void isAuthorizedToGroup(Admin administrator, String admingroupname)
            throws AuthorizationDeniedException;

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
    public Collection getAuthorizedAvailableAccessRules(Admin admin, Collection availableCaIds,
            boolean enableendentityprofilelimitations, boolean usehardtokenissuing, boolean usekeyrecovery, Collection authorizedEndEntityProfileIds,
            Collection authorizedUserDataSourceIds);

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
    public Collection getAuthorizedCAIds(Admin admin, Collection availableCaIds);

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
    public Collection getAuthorizedEndEntityProfileIds(Admin admin, String rapriviledge,
            Collection availableEndEntityProfileId);

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
}
