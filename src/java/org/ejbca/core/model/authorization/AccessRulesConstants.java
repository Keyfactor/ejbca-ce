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

import org.cesecore.authorization.control.StandardRules;

/**
 * @version $Id$
 */
public abstract class AccessRulesConstants {

    // Available end entity profile authorization rules.
    public static final String VIEW_RIGHTS                                = "/view_end_entity";
    public static final String EDIT_RIGHTS                                = "/edit_end_entity";
    public static final String CREATE_RIGHTS                              = "/create_end_entity";
    public static final String DELETE_RIGHTS                              = "/delete_end_entity";
    public static final String REVOKE_RIGHTS                              = "/revoke_end_entity";
    public static final String HISTORY_RIGHTS                             = "/view_end_entity_history";
    public static final String APPROVAL_RIGHTS                            = "/approve_end_entity";

    public static final String HARDTOKEN_RIGHTS                           = "/view_hardtoken";
    public static final String HARDTOKEN_PUKDATA_RIGHTS                   = "/view_hardtoken/puk_data";

    public static final String  KEYRECOVERY_RIGHTS                        = "/keyrecovery";    
    
    // Endings used in profile authorization.
    public static final String[] ENDENTITYPROFILE_ENDINGS = {VIEW_RIGHTS,EDIT_RIGHTS,CREATE_RIGHTS,DELETE_RIGHTS,REVOKE_RIGHTS,HISTORY_RIGHTS,APPROVAL_RIGHTS};
    
    // Name of end entity profile prefix directory in authorization module.
    public static final String ENDENTITYPROFILEBASE                       = "/endentityprofilesrules";
    public static final String ENDENTITYPROFILEPREFIX                     = "/endentityprofilesrules/";

    // Name of end entity profile prefix directory in authorization module.
    public static final String USERDATASOURCEBASE                         = "/userdatasourcesrules";
    public static final String USERDATASOURCEPREFIX                       = "/userdatasourcesrules/";
    
    public static final String UDS_FETCH_RIGHTS                           = "/fetch_userdata";
    public static final String UDS_REMOVE_RIGHTS                          = "/remove_userdata";
    
    // Endings used in profile authorization.
    public static final String[]  USERDATASOURCE_ENDINGS = {UDS_FETCH_RIGHTS,UDS_REMOVE_RIGHTS};

    // CA access rules are managed in CESecore, see StandardRules

    public static final String ROLE_PUBLICWEBUSER                         = "/public_web_user";
    public static final String ROLE_ADMINISTRATOR                         = "/administrator";
    // ROLE_SUPERADMINISTRATOR is only kept here for legacy reasons */
    public static final String ROLE_SUPERADMINISTRATOR                    = "/super_administrator";
    public static final String ROLE_ROOT                    = "/";
    
    
    public static final String REGULAR_CAFUNCTIONALTY                     = StandardRules.CAFUNCTIONALITY.resource();
    public static final String REGULAR_CABASICFUNCTIONS                   = StandardRules.CAFUNCTIONALITY.resource()+"/basic_functions";
    public static final String REGULAR_ACTIVATECA                         = REGULAR_CABASICFUNCTIONS+"/activate_ca";    
    public static final String REGULAR_RENEWCA                            = StandardRules.CAFUNCTIONALITY.resource()+"/renew_ca";    
    public static final String REGULAR_VIEWCERTIFICATE                    = StandardRules.CAFUNCTIONALITY.resource()+"/view_certificate";    
    public static final String REGULAR_APPROVECAACTION                    = StandardRules.CAFUNCTIONALITY.resource()+"/approve_caaction";
    public static final String REGULAR_CREATECRL                          = StandardRules.CREATECRL.resource();    
    public static final String REGULAR_EDITCERTIFICATEPROFILES            = StandardRules.EDITCERTIFICATEPROFILE.resource();    
    public static final String REGULAR_CREATECERTIFICATE                  = StandardRules.CREATECERT.resource();
    public static final String REGULAR_STORECERTIFICATE                   = StandardRules.CAFUNCTIONALITY.resource()+"/store_certificate";    
    public static final String REGULAR_EDITPUBLISHER                      = StandardRules.CAFUNCTIONALITY.resource()+"/edit_publisher";    
    public static final String REGULAR_RAFUNCTIONALITY                    = "/ra_functionality";
    public static final String REGULAR_EDITENDENTITYPROFILES              = "/ra_functionality/edit_end_entity_profiles";
    public static final String REGULAR_EDITUSERDATASOURCES                = "/ra_functionality/edit_user_data_sources";
    public static final String REGULAR_VIEWENDENTITY                      = "/ra_functionality/view_end_entity";    
    public static final String REGULAR_CREATEENDENTITY                    = "/ra_functionality/create_end_entity";
    public static final String REGULAR_EDITENDENTITY                      = "/ra_functionality/edit_end_entity";
    public static final String REGULAR_DELETEENDENTITY                    = "/ra_functionality/delete_end_entity";
    public static final String REGULAR_REVOKEENDENTITY                    = "/ra_functionality/revoke_end_entity";    
    public static final String REGULAR_VIEWENDENTITYHISTORY               = "/ra_functionality/view_end_entity_history";
    public static final String REGULAR_APPROVEENDENTITY                   = "/ra_functionality/approve_end_entity";
    public static final String REGULAR_LOGFUNCTIONALITY                   = "/log_functionality"; 
    public static final String REGULAR_VIEWLOG                            = "/log_functionality/view_log"; 
    public static final String REGULAR_LOGCONFIGURATION                   = "/log_functionality/edit_log_configuration";
    public static final String REGULAR_LOG_CUSTOM_EVENTS                  = "/log_functionality/log_custom_events"; 
    public static final String REGULAR_SYSTEMFUNCTIONALITY                = "/system_functionality";
    public static final String REGULAR_EDITADMINISTRATORPRIVILEDGES       = "/system_functionality/edit_administrator_privileges";
    public static final String REGULAR_EDITSYSTEMCONFIGURATION            = "/system_functionality/edit_systemconfiguration";

    public static final String REGULAR_VIEWHARDTOKENS                     = "/ra_functionality" + HARDTOKEN_RIGHTS;
    public static final String REGULAR_VIEWPUKS                           = "/ra_functionality" + HARDTOKEN_PUKDATA_RIGHTS;
    public static final String REGULAR_KEYRECOVERY                        = "/ra_functionality" + KEYRECOVERY_RIGHTS;
    	
    public static final String HARDTOKEN_HARDTOKENFUNCTIONALITY           = "/hardtoken_functionality";
    public static final String HARDTOKEN_EDITHARDTOKENISSUERS             = "/hardtoken_functionality/edit_hardtoken_issuers";
    public static final String HARDTOKEN_EDITHARDTOKENPROFILES            = "/hardtoken_functionality/edit_hardtoken_profiles";
    public static final String HARDTOKEN_ISSUEHARDTOKENS                  = "/hardtoken_functionality/issue_hardtokens";
    public static final String HARDTOKEN_ISSUEHARDTOKENADMINISTRATORS     = "/hardtoken_functionality/issue_hardtoken_administrators";
    
    // Standard Regular Access Rules
    public static final String[] STANDARDREGULARACCESSRULES = {REGULAR_CAFUNCTIONALTY, 
                                                           REGULAR_CABASICFUNCTIONS,
                                                           REGULAR_ACTIVATECA,
                                                           REGULAR_RENEWCA,
                                                           REGULAR_VIEWCERTIFICATE, 
                                                           REGULAR_CREATECRL,
                                                           REGULAR_EDITCERTIFICATEPROFILES,                                                           
                                                           REGULAR_CREATECERTIFICATE,
                                                           REGULAR_STORECERTIFICATE,
                                                           REGULAR_EDITPUBLISHER,
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
                                                           REGULAR_APPROVEENDENTITY,
                                                           REGULAR_LOGFUNCTIONALITY,
                                                           REGULAR_LOG_CUSTOM_EVENTS,  
                                                           REGULAR_VIEWLOG,
                                                           REGULAR_LOGCONFIGURATION,
                                                           REGULAR_SYSTEMFUNCTIONALITY,
                                                           REGULAR_EDITADMINISTRATORPRIVILEDGES,
                                                           REGULAR_EDITSYSTEMCONFIGURATION};
                                                       
    // Role Access Rules
    public static final  String[] ROLEACCESSRULES = {ROLE_PUBLICWEBUSER, ROLE_ADMINISTRATOR, ROLE_SUPERADMINISTRATOR};
    
    public static final String[] VIEWLOGACCESSRULES = { "/log_functionality/view_log/ca_entries",
                                                        "/log_functionality/view_log/ra_entries",
                                                        "/log_functionality/view_log/log_entries",
                                                        "/log_functionality/view_log/publicweb_entries",
                                                        "/log_functionality/view_log/adminweb_entries",
                                                        "/log_functionality/view_log/hardtoken_entries",
                                                        "/log_functionality/view_log/keyrecovery_entries",
                                                        "/log_functionality/view_log/authorization_entries",
                                                        "/log_functionality/view_log/approval_entries",
                                                        "/log_functionality/view_log/services_entries",
                                                        "/log_functionality/view_log/custom_entries",
                                                        };
                                                        
    // Hard Token specific accessrules used in authorization module.
    public static final String[] HARDTOKENACCESSRULES = 
       	  {HARDTOKEN_HARDTOKENFUNCTIONALITY,
    		HARDTOKEN_EDITHARDTOKENISSUERS,
			HARDTOKEN_EDITHARDTOKENPROFILES,     
			HARDTOKEN_ISSUEHARDTOKENS,
			HARDTOKEN_ISSUEHARDTOKENADMINISTRATORS};
}
