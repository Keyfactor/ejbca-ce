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
import java.util.List;

import org.apache.log4j.Logger;
import org.cesecore.core.ejb.authorization.AdminEntitySession;
import org.cesecore.core.ejb.authorization.AdminGroupSession;
import org.ejbca.core.ejb.authorization.AuthorizationSession;
import org.ejbca.core.ejb.ca.caadmin.CaSession;
import org.ejbca.core.model.authorization.AccessRule;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.authorization.AdminGroup;
import org.ejbca.core.model.authorization.AdminGroupExistsException;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.authorization.Authorizer;
import org.ejbca.core.model.log.Admin;


/**
 * A class handling the authorization data. 
 *
 * @author  Philip Vendil
 * @version $Id$
 */
public class AuthorizationDataHandler implements java.io.Serializable {
	
    private static final long serialVersionUID = 1L;
    
    private static final Logger log = Logger.getLogger(AuthorizationDataHandler.class);
    
    private CaSession caSession;
    private AuthorizationSession authorizationsession;
    private AdminEntitySession adminEntitySession;
    private AdminGroupSession adminGroupSession;
    private Admin administrator;
    private Collection<AdminGroup> authorizedadmingroups;
    private InformationMemory informationmemory;

    /** Creates a new instance of ProfileDataHandler */
    public AuthorizationDataHandler(Admin administrator, InformationMemory informationmemory, AdminEntitySession adminEntitySession,
            AdminGroupSession adminGroupSession, AuthorizationSession authorizationsession, CaSession caSession) {
        this.adminEntitySession = adminEntitySession;
        this.adminGroupSession = adminGroupSession;
        this.authorizationsession = authorizationsession;
        this.administrator = administrator;
        this.informationmemory = informationmemory;
        this.caSession = caSession;
    }

    /**
     * Method to check if a admin is authorized to a resource
     *
     * @param admin information about the administrator to be authorized.
     * @param resource the resource to look up.
     * @return true if authorizes
     * @throws AuthorizationDeniedException when authorization is denied.
     */
    public boolean isAuthorized(Admin admin, String resource) {
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
    public boolean isAuthorizedNoLog(Admin admin, String resource) {
      return authorizationsession.isAuthorizedNoLog(admin, resource);
    }

    // Methods used with admingroup data
    /** Method to add a new admingroup to the administrator privileges data. */
    public void addAdminGroup(String name) throws AdminGroupExistsException, AuthorizationDeniedException {
        // Authorized to edit administrative priviledges
        if (!authorizationsession.isAuthorized(administrator, "/system_functionality/edit_administrator_privileges")) {
            Authorizer.throwAuthorizationException(administrator, "/system_functionality/edit_administrator_privileges", null);
        }
        adminGroupSession.addAdminGroup(administrator, name);
        informationmemory.administrativePriviledgesEdited();
        this.authorizedadmingroups = null;
    }

    /** Method to remove a admingroup.*/
    public void removeAdminGroup(String name) throws AuthorizationDeniedException{
      authorizedToEditAdministratorPrivileges(name);
      adminGroupSession.removeAdminGroup(administrator, name);
      informationmemory.administrativePriviledgesEdited();
	  this.authorizedadmingroups = null;
    }

    /** Method to rename a admingroup. */
    public void renameAdminGroup(String oldname, String newname) throws AdminGroupExistsException, AuthorizationDeniedException{
      authorizedToEditAdministratorPrivileges(oldname);
      adminGroupSession.renameAdminGroup(administrator, oldname, newname);
      informationmemory.administrativePriviledgesEdited();
	  this.authorizedadmingroups = null;
    }

    /** 
     * Method returning a Collection of authorized AdminGroups.
     * Only the fields admingroup name and CA id is filled in these objects.
     */
    public Collection<AdminGroup> getAdminGroupNames(){ 
      if (this.authorizedadmingroups==null) {
        this.authorizedadmingroups = adminGroupSession.getAuthorizedAdminGroupNames(administrator, caSession.getAvailableCAs(administrator));    
      }
      return this.authorizedadmingroups;
    }
    
    /**
     * Returns the given AdminGroup with it's authorization data
     * 
     * @throws AuthorizationDeniedException if administrator isn't authorized to 
     * access admingroup.
     */
    public AdminGroup getAdminGroup(String admingroupname) throws AuthorizationDeniedException {
      authorizedToEditAdministratorPrivileges(admingroupname);
      return adminGroupSession.getAdminGroup(administrator, admingroupname);
    }

    /** 
     * Method to add a Collection of AccessRule to an admingroup.
     * @throws AuthorizationDeniedException when administrator is't authorized to edit this CA
     * or when administrator tries to add accessrules he isn't authorized to.
     */
    public void addAccessRules(String admingroupname, Collection accessrules) throws AuthorizationDeniedException{
      authorizedToEditAdministratorPrivileges(admingroupname);
      authorizedToAddAccessRules(accessrules);
      adminGroupSession.addAccessRules(administrator, admingroupname, accessrules);
      informationmemory.administrativePriviledgesEdited();
    }

    /** 
     * Method to remove an collection of access rules from a admingroup.
     * 
     * @param accessrules a Collection of String containing accesssrules to remove.
     * @throws AuthorizationDeniedException when administrator is't authorized to edit this CA.
     */
    public void removeAccessRules(String admingroupname, List<String> accessrules) throws AuthorizationDeniedException {
      authorizedToEditAdministratorPrivileges(admingroupname);
      adminGroupSession.removeAccessRules(administrator, admingroupname, accessrules);
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
    	adminGroupSession.replaceAccessRules(administrator, admingroupname, accessrules);
    	informationmemory.administrativePriviledgesEdited();
    }
    
    
    /**
     * Method returning all the available access rules authorized to administrator to manage.
     *
     * @returns a Collection of String with available access rules.
     */
    public Collection<String> getAvailableAccessRules(){
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
      adminEntitySession.addAdminEntities(administrator, admingroupname, adminentities);    
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
      adminEntitySession.removeAdminEntities(administrator, admingroupname, adminentities);     
      informationmemory.administrativePriviledgesEdited();
    }


    private void authorizedToEditAdministratorPrivileges(String admingroup) throws AuthorizationDeniedException{
       // Authorized to edit administrative privileges     
        if (!authorizationsession.isAuthorizedNoLog(administrator, AccessRulesConstants.REGULAR_EDITADMINISTRATORPRIVILEDGES)) {
            Authorizer.throwAuthorizationException(administrator, AccessRulesConstants.REGULAR_EDITADMINISTRATORPRIVILEDGES, null);
        }
        // Authorized to group
        if (!authorizationsession.isAuthorizedToGroup(administrator, admingroup)) {
            throw new AuthorizationDeniedException("Admin " + administrator + " not authorized to group "
                    + admingroup);
        }
      // Check if admin group is among available admin groups
      boolean exists = false;
      for(AdminGroup next : getAdminGroupNames()) {
        if (next.getAdminGroupName().equals(admingroup)) {
          exists = true;
        }
      }
      if (!exists) {
          if(log.isDebugEnabled()) {
              log.debug("Admingroup " + admingroup + " not among authorized admingroups.");
          }
        throw new AuthorizationDeniedException("Admingroup " + admingroup + " not among authorized admingroups.");
      }
    }
    
    private void authorizedToAddAccessRules(Collection<AccessRule> accessrules) throws AuthorizationDeniedException{
      Iterator<AccessRule> iter = accessrules.iterator();
      while (iter.hasNext()) {
        if (!this.informationmemory.getAuthorizedAccessRules().contains(iter.next().getAccessRule())) {  
          throw new AuthorizationDeniedException("Accessruleset contained non authorized access rules");
        }
      }
    }
}
