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
 
package se.anatom.ejbca.webdist.webconfiguration;

import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;

import se.anatom.ejbca.authorization.AccessRule;
import se.anatom.ejbca.authorization.AdminGroup;
import se.anatom.ejbca.authorization.AdminGroupExistsException;
import se.anatom.ejbca.authorization.AuthenticationFailedException;
import se.anatom.ejbca.authorization.AuthorizationDeniedException;
import se.anatom.ejbca.authorization.AvailableAccessRules;
import se.anatom.ejbca.authorization.IAuthorizationSessionLocal;
import se.anatom.ejbca.log.Admin;


/**
 * A class handling the authorization data. 
 *
 * @author  Philip Vendil
 * @version $Id: AuthorizationDataHandler.java,v 1.19 2005-02-11 13:12:17 anatom Exp $
 */
public class AuthorizationDataHandler {

    /** Creates a new instance of ProfileDataHandler */
    public AuthorizationDataHandler(Admin administrator, InformationMemory informationmemory, IAuthorizationSessionLocal authorizationsession){       
       this.authorizationsession = authorizationsession;
              
       this.administrator = administrator;
       this.informationmemory = informationmemory;
   }
    // Public methods.
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

    /**
     * Method that authenticates a certificate by checking validity and lookup if certificate is revoked.
     * 
     * @param certificate the certificate to be authenticated.
     *
     * @throws AuthenticationFailedException if authentication failed.
     */
    public void authenticate(X509Certificate certificate) throws AuthenticationFailedException {
      authorizationsession.authenticate(certificate);
    }

    // Methods used with admingroup data
        /** Method to add a new admingroup to the administrator priviledges data.*/
    public void addAdminGroup(String name, int caid) throws AdminGroupExistsException, AuthorizationDeniedException{
		// Authorized to edit administrative priviledges
	  authorizationsession.isAuthorized(administrator, "/system_functionality/edit_administrator_privileges");
		// Authorized to given CA.
	  authorizationsession.isAuthorized(administrator, AvailableAccessRules.CAPREFIX + caid);
      authorizationsession.addAdminGroup(administrator, name,caid);
      informationmemory.administrativePriviledgesEdited();
	  this.authorizedadmingroups = null;
    }

    /** Method to remove a admingroup.*/
    public void removeAdminGroup(String name, int caid) throws AuthorizationDeniedException{
      authorizedToEditAdministratorPrivileges(name, caid);
      authorizationsession.removeAdminGroup(administrator, name,caid);
      informationmemory.administrativePriviledgesEdited();
	  this.authorizedadmingroups = null;
    }

    /** Method to rename a admingroup. */
    public void renameAdminGroup(String oldname, String newname, int caid) throws AdminGroupExistsException, AuthorizationDeniedException{
      authorizedToEditAdministratorPrivileges(oldname, caid);
      authorizationsession.renameAdminGroup(administrator, oldname, caid, newname);
      informationmemory.administrativePriviledgesEdited();
	  this.authorizedadmingroups = null;
    }

    /** 
     * Method returning a Collection of authorized AdminGroups.
     * Only the fields admingroupname and CA id is filled in these objects.
     */
   
    public Collection getAdminGroupNames(){ 
      if(this.authorizedadmingroups==null)
        this.authorizedadmingroups= authorizationsession.getAuthorizedAdminGroupNames(administrator);    
        
      return this.authorizedadmingroups;
    }
    
    /**
     * Returns the given AdminGroup with it's authorization data
     * 
     * @throws AuthorizationDeniedException if admininstrator isn't authorized to 
     * access admingroup.
     */
    public AdminGroup getAdminGroup(String admingroupname, int caid) throws AuthorizationDeniedException {
      authorizedToEditAdministratorPrivileges(admingroupname, caid);
      
      return authorizationsession.getAdminGroup(administrator, admingroupname, caid);
    }

    /** 
     * Method to add a Collection of AccessRule to an admingroup.
     * @throws AuthorizationDeniedException when administrator is't authorized to edit this CA
     * or when administrator tries to add accessrules he isn't authorized to.
     */
    public void addAccessRules(String admingroupname, int caid, Collection accessrules) throws AuthorizationDeniedException{
      authorizedToEditAdministratorPrivileges(admingroupname, caid);
      authorizedToAddAccessRules(accessrules);
      authorizationsession.addAccessRules(administrator, admingroupname, caid, accessrules);
      informationmemory.administrativePriviledgesEdited();
    }

    /** 
     * Method to remove an collection of access rules from a admingroup.
     * 
     * @param accessrules a Collection of String containing accesssrules to remove.
     * @throws AuthorizationDeniedException when administrator is't authorized to edit this CA.
     */
    public void removeAccessRules(String admingroupname,int caid, Collection accessrules) throws AuthorizationDeniedException {
      authorizedToEditAdministratorPrivileges(admingroupname, caid);
      authorizationsession.removeAccessRules(administrator, admingroupname, caid, accessrules);
      informationmemory.administrativePriviledgesEdited();
    }

    /** 
     * Method to replace an collection of access rules in a admingroup.
     * 
     * @param accessrules a Collection of String containing accesssrules to replace.
     * @throws AuthorizationDeniedException when administrator is't authorized to edit this CA.
     */
    public void replaceAccessRules(String admingroupname,int caid, Collection accessrules) throws AuthorizationDeniedException {
    	authorizedToEditAdministratorPrivileges(admingroupname, caid);
    	authorizationsession.replaceAccessRules(administrator, admingroupname, caid, accessrules);
    	informationmemory.administrativePriviledgesEdited();
    }
    
    
    /**
     * Method réturning all the available access rules authorized to administrator to manage.
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
       * administrative priviledges.
       */
    public void addAdminEntities(String admingroupname, int caid, Collection adminentities) throws AuthorizationDeniedException{
      authorizedToEditAdministratorPrivileges(admingroupname, caid);	  
	       
      authorizationsession.addAdminEntities(administrator, admingroupname, caid, adminentities);    
      informationmemory.administrativePriviledgesEdited();
    }

        
      /** 
       * Method to remove a Collection of AdminEntity from an admingroup.
       *
       * @throws AuthorizationDeniedException if administrator isn't authorized to edit CAs 
       * administrative priviledges.
       */
    public void removeAdminEntities(String admingroupname, int caid, Collection adminentities) throws AuthorizationDeniedException{
      authorizedToEditAdministratorPrivileges(admingroupname, caid);
      authorizationsession.removeAdminEntities(administrator, admingroupname, caid, adminentities);     
      informationmemory.administrativePriviledgesEdited();
    }


    private void authorizedToEditAdministratorPrivileges(String admingroup, int caid) throws AuthorizationDeniedException{
       // Authorized to edit administrative priviledges
      authorizationsession.isAuthorizedNoLog(administrator, "/system_functionality/edit_administrator_privileges");
      // Authorized to given CA.
      authorizationsession.isAuthorizedNoLog(administrator, AvailableAccessRules.CAPREFIX + caid);     
      // Check if admin group is among available admin groups
      Iterator iter = getAdminGroupNames().iterator();
      boolean exists = false;
      while(iter.hasNext()){
        AdminGroup next = (AdminGroup) iter.next();  
        if(next.getAdminGroupName().equals(admingroup) && next.getCAId() == caid)
          exists = true;
      }
      
      if(!exists)
        throw new AuthorizationDeniedException("Admingroup not among authorized admingroups.");  
    }
    
    private void authorizedToAddAccessRules(Collection accessrules) throws AuthorizationDeniedException{
      Iterator iter = accessrules.iterator();
      while(iter.hasNext())
        if(!this.informationmemory.getAuthorizedAccessRules().contains(((AccessRule) iter.next()).getAccessRule()))  
          throw new AuthorizationDeniedException("Accessruleset contained non authorized access rules"); 
    }
   



    // Private fields
    private IAuthorizationSessionLocal  authorizationsession;
    private Admin                       administrator;    
    private Collection                  authorizedadmingroups;
    private InformationMemory           informationmemory;
}
