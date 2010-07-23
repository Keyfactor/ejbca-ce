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
 
package org.ejbca.ui.web.admin.configuration;

import java.util.Collection;
import java.util.Iterator;

import org.ejbca.core.ejb.authorization.AuthorizationSessionLocal;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionLocal;
import org.ejbca.core.model.authorization.AccessRule;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.authorization.AdminGroup;
import org.ejbca.core.model.authorization.AdminGroupExistsException;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.log.Admin;


/**
 * A class handling the authorization data. 
 *
 * @author  Philip Vendil
 * @version $Id$
 */
public class AuthorizationDataHandler implements java.io.Serializable {
	
	private CAAdminSessionLocal caAdminSession;
    private AuthorizationSessionLocal authorizationsession;
    private Admin administrator;    
    private Collection authorizedadmingroups;
    private InformationMemory informationmemory;

    /** Creates a new instance of ProfileDataHandler */
    public AuthorizationDataHandler(Admin administrator, InformationMemory informationmemory, AuthorizationSessionLocal authorizationsession, CAAdminSessionLocal caAdminSession) {       
       this.authorizationsession = authorizationsession;
       this.caAdminSession = caAdminSession;
       this.administrator = administrator;
       this.informationmemory = informationmemory;
   }

    /**
     * Method to check if a admin is authorized to a resource
     *
     * @param admin information about the administrator to be authorized.
     * @param resource the resource to look up.
     * @return true if authorizes
     * @throws AuthorizationDeniedException when authorization is denied.
     */
    public boolean isAuthorized(Admin admin, String resource) throws AuthorizationDeniedException{
      return authorizationsession.isAuthorized(admin, resource);  
    }

    /**
     * Method to check if a admin is authorized to a resource without performing any logging.
     *
     * @param admin information about the administrator to be authorized.
     * @param resource the resource to look up.
     * @return true if authorizes
     * @throws AuthorizationDeniedException when authorization is denied.
     */
    public boolean isAuthorizedNoLog(Admin admin, String resource) throws AuthorizationDeniedException{
      return authorizationsession.isAuthorizedNoLog(admin, resource);
    }

    // Methods used with admingroup data
        /** Method to add a new admingroup to the administrator priviledges data.*/
    public void addAdminGroup(String name) throws AdminGroupExistsException, AuthorizationDeniedException{
		// Authorized to edit administrative priviledges
	  authorizationsession.isAuthorized(administrator, "/system_functionality/edit_administrator_privileges");
      authorizationsession.addAdminGroup(administrator, name);
      informationmemory.administrativePriviledgesEdited();
	  this.authorizedadmingroups = null;
    }

    /** Method to remove a admingroup.*/
    public void removeAdminGroup(String name) throws AuthorizationDeniedException{
      authorizedToEditAdministratorPrivileges(name);
      authorizationsession.removeAdminGroup(administrator, name);
      informationmemory.administrativePriviledgesEdited();
	  this.authorizedadmingroups = null;
    }

    /** Method to rename a admingroup. */
    public void renameAdminGroup(String oldname, String newname) throws AdminGroupExistsException, AuthorizationDeniedException{
      authorizedToEditAdministratorPrivileges(oldname);
      authorizationsession.renameAdminGroup(administrator, oldname, newname);
      informationmemory.administrativePriviledgesEdited();
	  this.authorizedadmingroups = null;
    }

    /** 
     * Method returning a Collection of authorized AdminGroups.
     * Only the fields admingroup name and CA id is filled in these objects.
     */
    public Collection getAdminGroupNames(){ 
      if (this.authorizedadmingroups==null) {
        this.authorizedadmingroups = authorizationsession.getAuthorizedAdminGroupNames(administrator, caAdminSession.getAvailableCAs(administrator));    
      }
      return this.authorizedadmingroups;
    }
    
    /**
     * Returns the given AdminGroup with it's authorization data
     * 
     * @throws AuthorizationDeniedException if admininstrator isn't authorized to 
     * access admingroup.
     */
    public AdminGroup getAdminGroup(String admingroupname) throws AuthorizationDeniedException {
      authorizedToEditAdministratorPrivileges(admingroupname);
      return authorizationsession.getAdminGroup(administrator, admingroupname);
    }

    /** 
     * Method to add a Collection of AccessRule to an admingroup.
     * @throws AuthorizationDeniedException when administrator is't authorized to edit this CA
     * or when administrator tries to add accessrules he isn't authorized to.
     */
    public void addAccessRules(String admingroupname, Collection accessrules) throws AuthorizationDeniedException{
      authorizedToEditAdministratorPrivileges(admingroupname);
      authorizedToAddAccessRules(accessrules);
      authorizationsession.addAccessRules(administrator, admingroupname, accessrules);
      informationmemory.administrativePriviledgesEdited();
    }

    /** 
     * Method to remove an collection of access rules from a admingroup.
     * 
     * @param accessrules a Collection of String containing accesssrules to remove.
     * @throws AuthorizationDeniedException when administrator is't authorized to edit this CA.
     */
    public void removeAccessRules(String admingroupname, Collection accessrules) throws AuthorizationDeniedException {
      authorizedToEditAdministratorPrivileges(admingroupname);
      authorizationsession.removeAccessRules(administrator, admingroupname, accessrules);
      informationmemory.administrativePriviledgesEdited();
    }

    /** 
     * Method to replace an collection of access rules in a admingroup.
     * 
     * @param accessrules a Collection of String containing accesssrules to replace.
     * @throws AuthorizationDeniedException when administrator is't authorized to edit this CA.
     */
    public void replaceAccessRules(String admingroupname, Collection accessrules) throws AuthorizationDeniedException {
    	authorizedToEditAdministratorPrivileges(admingroupname);
    	authorizationsession.replaceAccessRules(administrator, admingroupname, accessrules);
    	informationmemory.administrativePriviledgesEdited();
    }
    
    
    /**
     * Method returning all the available access rules authorized to administrator to manage.
     *
     * @returns a Collection of String with available access rules.
     */
    public Collection getAvailableAccessRules(){
      return this.informationmemory.getAuthorizedAccessRules();
    }
    
      /** 
       * Method to add a Collection of AdminEntity to an admingroup.
       *
       * @throws AuthorizationDeniedException if administrator isn't authorized to edit CAs 
       * administrative privileges.
       */
    public void addAdminEntities(String admingroupname, Collection adminentities) throws AuthorizationDeniedException{
      authorizedToEditAdministratorPrivileges(admingroupname);	  
      authorizationsession.addAdminEntities(administrator, admingroupname, adminentities);    
      informationmemory.administrativePriviledgesEdited();
    }

        
      /** 
       * Method to remove a Collection of AdminEntity from an admingroup.
       *
       * @throws AuthorizationDeniedException if administrator isn't authorized to edit CAs 
       * administrative privileges.
       */
    public void removeAdminEntities(String admingroupname, Collection adminentities) throws AuthorizationDeniedException{
      authorizedToEditAdministratorPrivileges(admingroupname);
      authorizationsession.removeAdminEntities(administrator, admingroupname, adminentities);     
      informationmemory.administrativePriviledgesEdited();
    }


    private void authorizedToEditAdministratorPrivileges(String admingroup) throws AuthorizationDeniedException{
       // Authorized to edit administrative privileges
      authorizationsession.isAuthorizedNoLog(administrator, AccessRulesConstants.REGULAR_EDITADMINISTRATORPRIVILEDGES);
      // Authorized to group
      authorizationsession.isAuthorizedToGroup(administrator, admingroup);
      // Check if admin group is among available admin groups
      Iterator iter = getAdminGroupNames().iterator();
      boolean exists = false;
      while (iter.hasNext()) {
        AdminGroup next = (AdminGroup) iter.next();  
        if (next.getAdminGroupName().equals(admingroup)) {
          exists = true;
        }
      }
      if (!exists) {
        throw new AuthorizationDeniedException("Admingroup not among authorized admingroups.");
      }
    }
    
    private void authorizedToAddAccessRules(Collection accessrules) throws AuthorizationDeniedException{
      Iterator iter = accessrules.iterator();
      while (iter.hasNext()) {
        if (!this.informationmemory.getAuthorizedAccessRules().contains(((AccessRule) iter.next()).getAccessRule())) {  
          throw new AuthorizationDeniedException("Accessruleset contained non authorized access rules");
        }
      }
    }
}
