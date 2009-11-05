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
 
package org.ejbca.core.model.authorization;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;

import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionLocal;
import org.ejbca.core.ejb.ra.userdatasource.IUserDataSourceSessionLocal;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.raadmin.GlobalConfiguration;

/**
 * 
 *
 * @version $Id$
 */
public class AvailableAccessRules {
                                                        
    /** Creates a new instance of AvailableAccessRules */
    public AvailableAccessRules(Admin admin, Authorizer authorizer, IRaAdminSessionLocal raadminsession, IUserDataSourceSessionLocal userDataSourceSession, String[] customaccessrules) {   
      // Initialize
      this.raadminsession = raadminsession;  
      this.authorizer = authorizer;
      this.userDataSourceSession = userDataSourceSession;
      
      // Get Global Configuration
      GlobalConfiguration globalconfiguration = raadminsession.loadGlobalConfiguration(admin);
      enableendentityprofilelimitations = globalconfiguration.getEnableEndEntityProfileLimitations();
      usehardtokenissuing = globalconfiguration.getIssueHardwareTokens();
      usekeyrecovery = globalconfiguration.getEnableKeyRecovery();        
      
      // Is Admin SuperAdministrator.
      try{
        issuperadministrator = authorizer.isAuthorizedNoLog(admin, "/super_administrator");
      }catch(AuthorizationDeniedException e){
        issuperadministrator=false;
      }
      
      // Get CA:s
      authorizedcaids = new HashSet();
      authorizedcaids.addAll(authorizer.getAuthorizedCAIds(admin));
      
      this.customaccessrules= customaccessrules;
    }
    
    // Public methods 
    /** Returns all the accessrules and subaccessrules from the given subresource */
    public Collection getAvailableAccessRules(Admin admin){
      ArrayList accessrules = new ArrayList();
      
      
      insertAvailableRoleAccessRules(accessrules);
      
      insertAvailableRegularAccessRules(admin, accessrules);
      
      if(enableendentityprofilelimitations) { 
        insertAvailableEndEntityProfileAccessRules(admin, accessrules);
      }

      insertUserDataSourceAccessRules(admin, accessrules);
      
      insertAvailableCAAccessRules(admin, accessrules);
      
      insertCustomAccessRules(admin, accessrules);
      
      
      
      
      return accessrules;
    }
   
    // Private methods
    /**
     * Method that adds all authorized role based access rules.
     */    
    private void insertAvailableRoleAccessRules(ArrayList accessrules){
        
      accessrules.add(AccessRulesConstants.ROLEACCESSRULES[0]);
      accessrules.add(AccessRulesConstants.ROLEACCESSRULES[1]); 
        
      if(issuperadministrator) {  
        accessrules.add(AccessRulesConstants.ROLEACCESSRULES[2]);
      }
    }

    /**
     * Method that adds all regular access rules.
     */    
    
    private void insertAvailableRegularAccessRules(Admin admin, ArrayList accessrules) {
       
      // Insert Standard Access Rules.
      for(int i=0; i < AccessRulesConstants.STANDARDREGULARACCESSRULES.length; i++){
         addAuthorizedAccessRule(admin, AccessRulesConstants.STANDARDREGULARACCESSRULES[i], accessrules);
      }
      for(int i=0; i < AccessRulesConstants.VIEWLOGACCESSRULES.length; i++){
         addAuthorizedAccessRule(admin, AccessRulesConstants.VIEWLOGACCESSRULES[i], accessrules);
      }      
      
        
      if(usehardtokenissuing){
        for(int i=0; i < AccessRulesConstants.HARDTOKENACCESSRULES.length;i++){
           accessrules.add(AccessRulesConstants.HARDTOKENACCESSRULES[i]);           
        }
        addAuthorizedAccessRule(admin, AccessRulesConstants.REGULAR_VIEWHARDTOKENS, accessrules);
        addAuthorizedAccessRule(admin, AccessRulesConstants.REGULAR_VIEWPUKS, accessrules);
      }
        
      if(usekeyrecovery) {
         addAuthorizedAccessRule(admin, AccessRulesConstants.REGULAR_KEYRECOVERY, accessrules);         
      }
    }
    
    
    /**
     * Method that adds all authorized access rules conserning end entity profiles.
     */
    private void insertAvailableEndEntityProfileAccessRules(Admin admin, ArrayList accessrules){
        
        // Add most basic rule if authorized to it.
		try{
		  authorizer.isAuthorizedNoLog(admin, AccessRulesConstants.ENDENTITYPROFILEBASE);  
		  accessrules.add(AccessRulesConstants.ENDENTITYPROFILEBASE);
		}catch(AuthorizationDeniedException e){
          //  Add it to superadministrator anyway
				 if(issuperadministrator) {
				   accessrules.add(AccessRulesConstants.ENDENTITYPROFILEBASE);
				 }
		}
		
        
        // Add all authorized End Entity Profiles                    
        Iterator iter = raadminsession.getAuthorizedEndEntityProfileIds(admin).iterator();
        while(iter.hasNext()){
            
            int profileid = ((Integer) iter.next()).intValue();
            
            // Do not add empty profile, since only superadministrator should have access to it.
            if(profileid != SecConst.EMPTY_ENDENTITYPROFILE){
              // Administrator is authorized to this End Entity Profile, add it.
                try{
                  authorizer.isAuthorizedNoLog(admin, AccessRulesConstants.ENDENTITYPROFILEPREFIX + profileid);  
                  addEndEntityProfile( profileid, accessrules);
                }catch(AuthorizationDeniedException e){}
            }
            
        }
    }
    
    /** 
     * Help Method for insertAvailableEndEntityProfileAccessRules.
     */
    private void addEndEntityProfile(int profileid, ArrayList accessrules){
      accessrules.add(AccessRulesConstants.ENDENTITYPROFILEPREFIX + profileid);      
      for(int j=0;j < AccessRulesConstants.ENDENTITYPROFILE_ENDINGS.length; j++){     
        accessrules.add(AccessRulesConstants.ENDENTITYPROFILEPREFIX + profileid +AccessRulesConstants.ENDENTITYPROFILE_ENDINGS[j]);  
      }         
      if(usehardtokenissuing){ 
        accessrules.add(AccessRulesConstants.ENDENTITYPROFILEPREFIX + profileid + AccessRulesConstants.HARDTOKEN_RIGHTS);
        accessrules.add(AccessRulesConstants.ENDENTITYPROFILEPREFIX + profileid + AccessRulesConstants.HARDTOKEN_PUKDATA_RIGHTS);
      }
      if(usekeyrecovery){ 
        accessrules.add(AccessRulesConstants.ENDENTITYPROFILEPREFIX + profileid + AccessRulesConstants.KEYRECOVERY_RIGHTS);
      }
    }
      
    /**
     * Method that adds all authorized CA access rules.
     */
    private void insertAvailableCAAccessRules(Admin admin, ArrayList accessrules){
      // Add All Authorized CAs
      //if(issuperadministrator)
    	try {
			if (authorizer.isAuthorizedNoLog(admin, AccessRulesConstants.CABASE)) {
			    accessrules.add(AccessRulesConstants.CABASE);
			}
		} catch (AuthorizationDeniedException e) {
		}
		Iterator iter = authorizedcaids.iterator();
		while(iter.hasNext()){
			accessrules.add(AccessRulesConstants.CAPREFIX + ((Integer) iter.next()).intValue());  
		}
    }
    
    /**
     * Method that adds the custom available access rules.
     */
    private void insertCustomAccessRules(Admin admin, ArrayList accessrules){
      for(int i=0; i < customaccessrules.length; i++){
        if(!customaccessrules[i].trim().equals("")) {  
          addAuthorizedAccessRule(admin, customaccessrules[i].trim(), accessrules);
        }
      } 
    }
    
    /**
     * Method that adds the user data source access rules
     */
    private void insertUserDataSourceAccessRules(Admin admin, ArrayList accessrules){
       addAuthorizedAccessRule(admin, AccessRulesConstants.USERDATASOURCEBASE, accessrules);
       
       Iterator iter = userDataSourceSession.getAuthorizedUserDataSourceIds(admin, true).iterator();
       while(iter.hasNext()){
    	   int id = ((Integer) iter.next()).intValue();
    	   addAuthorizedAccessRule(admin,AccessRulesConstants.USERDATASOURCEPREFIX + id + AccessRulesConstants.UDS_FETCH_RIGHTS,accessrules);
    	   addAuthorizedAccessRule(admin,AccessRulesConstants.USERDATASOURCEPREFIX + id + AccessRulesConstants.UDS_REMOVE_RIGHTS,accessrules);    	   
       }       
    }
    
    /**
     * Method that checks if administrator himself is authorized to access rule, and if so adds it to list.
     */    
    private void addAuthorizedAccessRule(Admin admin, String accessrule, ArrayList accessrules){
      try{    	
        authorizer.isAuthorizedNoLog(admin, accessrule);
        accessrules.add(accessrule);
      }catch(AuthorizationDeniedException e){
      }
    }
    
   
    // Private fields
    private Authorizer authorizer;
    private IRaAdminSessionLocal raadminsession;
    private IUserDataSourceSessionLocal userDataSourceSession;
    private boolean issuperadministrator;
    private boolean enableendentityprofilelimitations;
    private boolean usehardtokenissuing;
    private boolean usekeyrecovery;
    private HashSet authorizedcaids;
    private String[] customaccessrules;
    
   
}
