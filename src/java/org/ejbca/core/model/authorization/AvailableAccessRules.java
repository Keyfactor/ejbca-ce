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
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.raadmin.GlobalConfiguration;

/**
 * 
 *
 * @version $Id: AvailableAccessRules.java,v 1.3 2006-07-29 11:26:36 herrvendil Exp $
 */
public class AvailableAccessRules {
        
        // Available end entity profile authorization rules.
    public static final String VIEW_RIGHTS    = "/view_end_entity";
    public static final String EDIT_RIGHTS    = "/edit_end_entity";
    public static final String CREATE_RIGHTS  = "/create_end_entity";
    public static final String DELETE_RIGHTS  = "/delete_end_entity";
    public static final String REVOKE_RIGHTS  = "/revoke_end_entity";
    public static final String HISTORY_RIGHTS = "/view_end_entity_history";
    public static final String APPROVAL_RIGHTS = "/approve_end_entity";

    public static final String  HARDTOKEN_RIGHTS               = "/view_hardtoken";

    public static final String  KEYRECOVERY_RIGHTS             = "/keyrecovery";    
    
        // Endings used in profile authorizxation.
    public static final String[]  ENDENTITYPROFILE_ENDINGS = {VIEW_RIGHTS,EDIT_RIGHTS,CREATE_RIGHTS,DELETE_RIGHTS,REVOKE_RIGHTS,HISTORY_RIGHTS,APPROVAL_RIGHTS};
    
        // Name of end entity profile prefix directory in authorization module.
    public static final String    ENDENTITYPROFILEBASE            = "/endentityprofilesrules";
    public static final String    ENDENTITYPROFILEPREFIX          = "/endentityprofilesrules/";


        // Name of ca prefix directory in access rules.
    public static final String    CABASE            = "/ca";
    public static final String    CAPREFIX          = "/ca/";

    public static final String ROLE_PUBLICWEBUSER                                 = "/public_web_user";
    public static final String ROLE_ADMINISTRATOR                                 = "/administrator";
    public static final String ROLE_SUPERADMINISTRATOR                            = "/super_administrator";
    
    
    public static final String REGULAR_CAFUNCTIONALTY                             = "/ca_functionality";
    public static final String REGULAR_CABASICFUNCTIONS                           = "/ca_functionality/basic_functions";
    public static final String REGULAR_ACTIVATECA                                 = "/ca_functionality/basic_functions/activate_ca";    
    public static final String REGULAR_VIEWCERTIFICATE                            = "/ca_functionality/view_certificate";    
    public static final String REGULAR_APPROVECAACTION                            = "/ca_functionality/approve_caaction";
    public static final String REGULAR_CREATECRL                                  = "/ca_functionality/create_crl";    
    public static final String REGULAR_EDITCERTIFICATEPROFILES                    = "/ca_functionality/edit_certificate_profiles";    
    public static final String REGULAR_CREATECERTIFICATE                          = "/ca_functionality/create_certificate";
    public static final String REGULAR_STORECERTIFICATE                           = "/ca_functionality/store_certificate";    
    public static final String REGULAR_RAFUNCTIONALITY                            = "/ra_functionality";
    public static final String REGULAR_EDITENDENTITYPROFILES                      = "/ra_functionality/edit_end_entity_profiles";
    public static final String REGULAR_EDITUSERDATASOURCES                        = "/ra_functionality/edit_user_data_sources";
    public static final String REGULAR_VIEWENDENTITY                              = "/ra_functionality/view_end_entity";    
    public static final String REGULAR_CREATEENDENTITY                            = "/ra_functionality/create_end_entity";
    public static final String REGULAR_EDITENDENTITY                              = "/ra_functionality/edit_end_entity";
    public static final String REGULAR_DELETEENDENTITY                            = "/ra_functionality/delete_end_entity";
    public static final String REGULAR_REVOKEENDENTITY                            = "/ra_functionality/revoke_end_entity";    
    public static final String REGULAR_VIEWENDENTITYHISTORY                       = "/ra_functionality/view_end_entity_history";
    public static final String REGULAR_APPORVEENDENTITY                           = "/ra_functionality/approve_end_entity";
    public static final String REGULAR_LOGFUNCTIONALITY                           = "/log_functionality"; 
    public static final String REGULAR_VIEWLOG                                    = "/log_functionality/view_log"; 
    public static final String REGULAR_LOGCONFIGURATION                           = "/log_functionality/edit_log_configuration"; 
    public static final String REGULAR_SYSTEMFUNCTIONALITY                        = "/system_functionality";
    public static final String REGULAR_EDITADMINISTRATORPRIVILEDGES               = "/system_functionality/edit_administrator_privileges";
    
    public static final String REGULAR_VIEWHARDTOKENS                             = "/ra_functionality" + HARDTOKEN_RIGHTS;    
    public static final String REGULAR_KEYRECOVERY                                = "/ra_functionality" + KEYRECOVERY_RIGHTS;
    	
    public static final String HARDTOKEN_HARDTOKENFUNCTIONALITY                   = "/hardtoken_functionality";
    public static final String HARDTOKEN_EDITHARDTOKENISSUERS                     = "/hardtoken_functionality/edit_hardtoken_issuers";
    public static final String HARDTOKEN_EDITHARDTOKENPROFILES                    = "/hardtoken_functionality/edit_hardtoken_profiles";
    public static final String HARDTOKEN_ISSUEHARDTOKENS                          = "/hardtoken_functionality/issue_hardtokens";
    public static final String HARDTOKEN_ISSUEHARDTOKENADMINISTRATORS             = "/hardtoken_functionality/issue_hardtoken_administrators";
    
        // Standard Regular Access Rules
    private  final  String[] STANDARDREGULARACCESSRULES = {REGULAR_CAFUNCTIONALTY, 
                                                           REGULAR_CABASICFUNCTIONS,
                                                           REGULAR_ACTIVATECA,
                                                           REGULAR_VIEWCERTIFICATE, 
                                                           REGULAR_CREATECRL,
                                                           REGULAR_EDITCERTIFICATEPROFILES,                                                           
                                                           REGULAR_CREATECERTIFICATE,
                                                           REGULAR_STORECERTIFICATE,
                                                           REGULAR_APPROVECAACTION,
                                                           REGULAR_RAFUNCTIONALITY, 
                                                           REGULAR_EDITENDENTITYPROFILES,
                                                           REGULAR_EDITUSERDATASOURCES,                                                           
                                                           REGULAR_VIEWENDENTITY,
                                                           REGULAR_CREATEENDENTITY, 
                                                           REGULAR_EDITENDENTITY, 
                                                           REGULAR_DELETEENDENTITY,
                                                           REGULAR_REVOKEENDENTITY,
                                                           REGULAR_VIEWENDENTITYHISTORY,
                                                           REGULAR_APPORVEENDENTITY,
                                                           REGULAR_LOGFUNCTIONALITY,
                                                           REGULAR_VIEWLOG,
                                                           REGULAR_LOGCONFIGURATION,
                                                           REGULAR_SYSTEMFUNCTIONALITY,
                                                           REGULAR_EDITADMINISTRATORPRIVILEDGES};
                                                       
        // Role Access Rules
    public static final  String[] ROLEACCESSRULES =       {  ROLE_PUBLICWEBUSER,
           		                                                                          ROLE_ADMINISTRATOR,
			                                                                              ROLE_SUPERADMINISTRATOR};
    
                                                       
    
    
    public static final String[] VIEWLOGACCESSRULES =   { "/log_functionality/view_log/ca_entries",
                                                          "/log_functionality/view_log/ra_entries",
                                                          "/log_functionality/view_log/log_entries",
                                                          "/log_functionality/view_log/publicweb_entries",
                                                          "/log_functionality/view_log/adminweb_entries",
                                                          "/log_functionality/view_log/hardtoken_entries",
                                                          "/log_functionality/view_log/keyrecovery_entries",
                                                          "/log_functionality/view_log/authorization_entries"};
    
                                                        
        // Hard Token specific accessrules used in authorization module.
    public static final String[] HARDTOKENACCESSRULES    = 
       	  {HARDTOKEN_HARDTOKENFUNCTIONALITY,
    		HARDTOKEN_EDITHARDTOKENISSUERS,
			HARDTOKEN_EDITHARDTOKENPROFILES,     
			HARDTOKEN_ISSUEHARDTOKENS,
			HARDTOKEN_ISSUEHARDTOKENADMINISTRATORS};
    

                                                        
                                                        
    /** Creates a new instance of AvailableAccessRules */
    public AvailableAccessRules(Admin admin, Authorizer authorizer, IRaAdminSessionLocal raadminsession, String[] customaccessrules) {   
      // Initialize
      this.raadminsession = raadminsession;  
      this.authorizer = authorizer;
      
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
      
      if(enableendentityprofilelimitations) 
        insertAvailableEndEntityProfileAccessRules(admin, accessrules);

      insertAvailableCAAccessRules(accessrules);
      
      insertCustomAccessRules(admin, accessrules);
      
      
      return accessrules;
    }
   
    // Private methods
    /**
     * Method that adds all authorized role based access rules.
     */    
    private void insertAvailableRoleAccessRules(ArrayList accessrules){
        
      accessrules.add(ROLEACCESSRULES[0]);
      accessrules.add(ROLEACCESSRULES[1]); 
        
      if(issuperadministrator)  
        accessrules.add(ROLEACCESSRULES[2]);
      
    }

    /**
     * Method that adds all regular access rules.
     */    
    
    private void insertAvailableRegularAccessRules(Admin admin, ArrayList accessrules) {
       
      // Insert Standard Access Rules.
      for(int i=0; i < STANDARDREGULARACCESSRULES.length; i++){
         addAuthorizedAccessRule(admin, STANDARDREGULARACCESSRULES[i], accessrules);
      }
      for(int i=0; i < VIEWLOGACCESSRULES.length; i++){
         addAuthorizedAccessRule(admin, VIEWLOGACCESSRULES[i], accessrules);
      }      
      
        
      if(usehardtokenissuing){
        for(int i=0; i < HARDTOKENACCESSRULES.length;i++){
           accessrules.add(HARDTOKENACCESSRULES[i]);           
        }
        addAuthorizedAccessRule(admin, REGULAR_VIEWHARDTOKENS, accessrules);        
      }
        
      if(usekeyrecovery)
         addAuthorizedAccessRule(admin, REGULAR_KEYRECOVERY, accessrules);         
      
    }
    
    
    /**
     * Method that adds all authorized access rules conserning end entity profiles.
     */
    private void insertAvailableEndEntityProfileAccessRules(Admin admin, ArrayList accessrules){
        
        // Add most basic rule if authorized to it.
		try{
		  authorizer.isAuthorizedNoLog(admin, ENDENTITYPROFILEBASE);  
		  accessrules.add(ENDENTITYPROFILEBASE);
		}catch(AuthorizationDeniedException e){
          //  Add it to superadministrator anyway
				 if(issuperadministrator)
				   accessrules.add(ENDENTITYPROFILEBASE);
		}
		
        
        // Add all authorized End Entity Profiles                    
        Iterator iter = raadminsession.getAuthorizedEndEntityProfileIds(admin).iterator();
        while(iter.hasNext()){
            
            int profileid = ((Integer) iter.next()).intValue();
            
            // Do not add empty profile, since only superadministrator should have access to it.
            if(profileid != SecConst.EMPTY_ENDENTITYPROFILE){
              // Administrator is authorized to this End Entity Profile, add it.
                try{
                  authorizer.isAuthorizedNoLog(admin, ENDENTITYPROFILEPREFIX + profileid);  
                  addEndEntityProfile( profileid, accessrules);
                }catch(AuthorizationDeniedException e){}
            }
            
        }
    }
    
    /** 
     * Help Method for insertAvailableEndEntityProfileAccessRules.
     */
    private void addEndEntityProfile(int profileid, ArrayList accessrules){
      accessrules.add(ENDENTITYPROFILEPREFIX + profileid);      
      for(int j=0;j < ENDENTITYPROFILE_ENDINGS.length; j++){     
        accessrules.add(ENDENTITYPROFILEPREFIX + profileid +ENDENTITYPROFILE_ENDINGS[j]);  
      }         
      if(usehardtokenissuing) 
        accessrules.add(ENDENTITYPROFILEPREFIX + profileid + HARDTOKEN_RIGHTS);     
      if(usekeyrecovery) 
        accessrules.add(ENDENTITYPROFILEPREFIX + profileid + KEYRECOVERY_RIGHTS);           
    }
      
    /**
     * Method that adds all authorized CA access rules.
     */
    private void insertAvailableCAAccessRules(ArrayList accessrules){
      // Add All Authorized CAs
      if(issuperadministrator)	
        accessrules.add(CABASE);
      Iterator iter = authorizedcaids.iterator();
      while(iter.hasNext()){
        accessrules.add(CAPREFIX + ((Integer) iter.next()).intValue());  
      }
    }
    
    /**
     * Method that adds the custom available access rules.
     */
    private void insertCustomAccessRules(Admin admin, ArrayList accessrules){
      for(int i=0; i < customaccessrules.length; i++){
        if(!customaccessrules[i].trim().equals(""))  
          addAuthorizedAccessRule(admin, customaccessrules[i].trim(), accessrules);    
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
    private boolean issuperadministrator;
    private boolean enableendentityprofilelimitations;
    private boolean usehardtokenissuing;
    private boolean usekeyrecovery;
    private HashSet authorizedcaids;
    private String[] customaccessrules;
    
   
}
