package se.anatom.ejbca.authorization;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;

import javax.ejb.CreateException;
import javax.naming.NamingException;

import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.ra.raadmin.GlobalConfiguration;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionLocal;

/**
 * 
 *
 * @version $Id: AvailableAccessRules.java,v 1.2 2003-10-01 11:12:07 herrvendil Exp $
 */
public class AvailableAccessRules {
        
        // Available end entity profile authorization rules.
    public static final String VIEW_RIGHTS    = "/view_end_entity";
    public static final String EDIT_RIGHTS    = "/edit_end_entity";
    public static final String CREATE_RIGHTS  = "/create_end_entity";
    public static final String DELETE_RIGHTS  = "/delete_end_entity";
    public static final String REVOKE_RIGHTS  = "/revoke_end_entity";
    public static final String HISTORY_RIGHTS = "/view_end_entity_history";
    

    public static final String  HARDTOKEN_RIGHTS               = "/view_hardtoken";

    public static final String  KEYRECOVERY_RIGHTS             = "/keyrecovery";    
    
        // Endings used in profile authorizxation.
    public static final String[]  ENDENTITYPROFILE_ENDINGS = {VIEW_RIGHTS,EDIT_RIGHTS,CREATE_RIGHTS,DELETE_RIGHTS,REVOKE_RIGHTS,HISTORY_RIGHTS};
    
        // Name of end entity profile prefix directory in authorization module.
    public static final String    ENDENTITYPROFILEPREFIX          = "/endentityprofilesrules/";


        // Name of ca prefix directory in access rules.
    public static final String    CAPREFIX          = "/ca/";
    
    
        // Standard Regular Access Rules
    private  final  String[] STANDARDREGULARACCESSRULES = {"/ca_functionality", 
                                                           "/ca_functionality/basic_functions",
                                                           "/ca_functionality/view_certificate", 
                                                           "/ca_functionality/create_crl",
                                                           "/ca_functionality/edit_certificate_profiles",
                                                           "/ca_functionality/create_certificate",
                                                           "/ca_functionality/store_certificate",
                                                           "/ra_functionality", 
                                                           "/ra_functionality/edit_end_entity_profiles",
                                                           "/ra_functionality/view_end_entity",
                                                           "/ra_functionality/create_end_entity", 
                                                           "/ra_functionality/edit_end_entity", 
                                                           "/ra_functionality/delete_end_entity",
                                                           "/ra_functionality/revoke_end_entity",
                                                           "/ra_functionality/view_end_entity_history",
                                                           "/log_functionality",
                                                           "/log_functionality/view_log",
                                                           "/log_functionality/edit_log_configuration",
                                                           "/system_functionality",
                                                           "/system_functionality/edit_administrator_privileges"};
                                                       
        // Role Access Rules
    public static final  String[] ROLEACCESSRULES =       {  "/public_web_user",
                                                             "/administrator",
                                                             "/super_administrator"};
                                                       
    
    
    public static final String[] VIEWLOGACCESSRULES =   { "/log_functionality/view_log/ca_entries",
                                                          "/log_functionality/view_log/ra_entries",
                                                          "/log_functionality/view_log/log_entries",
                                                          "/log_functionality/view_log/publicweb_entries",
                                                          "/log_functionality/view_log/adminweb_entries",
                                                          "/log_functionality/view_log/hardtoken_entries",
                                                          "/log_functionality/view_log/keyrecovery_entries",
                                                          "/log_functionality/view_log/authorization_entries"};
    
                                                        
        // Hard Token specific accessrules used in authorization module.
    public static final String[] HARDTOKENACCESSRULES    = {"/hardtoken_functionality",
                                                            "/hardtoken_functionality/issue_hardtokens",
                                                            "/hardtoken_functionality/issue_hardtoken_administrators"};
                                                            

                                                        
                                                        
    /** Creates a new instance of AvailableAccessRules */
    public AvailableAccessRules(Admin admin, Authorizer authorizer, IRaAdminSessionLocal raadminsession, String[] customaccessrules) throws NamingException, CreateException {   
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
      // Get End Entity Profiles
      endentityprofiles = raadminsession.getEndEntityProfileIdToNameMap(admin);
      
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
        addAuthorizedAccessRule(admin, "/ra_functionality" + HARDTOKEN_RIGHTS, accessrules);        
      }
        
      if(usekeyrecovery)
         addAuthorizedAccessRule(admin, "/ra_functionality" + KEYRECOVERY_RIGHTS, accessrules);         
      
    }
    
    
    /**
     * Method that adds all authorized access rules conserning end entity profiles.
     */
    private void insertAvailableEndEntityProfileAccessRules(Admin admin, ArrayList accessrules){
        
        // Add most basic rule if authorized to it.
		try{
		  authorizer.isAuthorizedNoLog(admin, "/endentityprofilesrules");  
		  accessrules.add("/endentityprofilesrules");
		}catch(AuthorizationDeniedException e){
          //  Add it to superadministrator anyway
				 if(issuperadministrator)
				   accessrules.add("/endentityprofilesrules");
		}
		
        
        // Add all authorized End Entity Profiles                    
        Iterator iter = raadminsession.getAuthorizedEndEntityProfileIds(admin).iterator();
        while(iter.hasNext()){
            // Check if profiles available CAs is a subset of administrators authorized CAs
            int profileid = ((Integer) iter.next()).intValue();
            
              // Administrator is authorized to this End Entity Profile, add it.
                try{
                  authorizer.isAuthorizedNoLog(admin, ENDENTITYPROFILEPREFIX + profileid);  
                  addEndEntityProfile( profileid, accessrules);
                }catch(AuthorizationDeniedException e){}
            
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
    private HashMap endentityprofiles;
    private HashSet authorizedcaids;
    private String[] customaccessrules;
    
   
}
