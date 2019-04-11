/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
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

    // Available end entity authorization rules.
    public static final String VIEW_END_ENTITY = "/view_end_entity";
    public static final String EDIT_END_ENTITY = "/edit_end_entity";
    public static final String CREATE_END_ENTITY = "/create_end_entity";
    public static final String DELETE_END_ENTITY = "/delete_end_entity";
    public static final String REVOKE_END_ENTITY = "/revoke_end_entity";
    public static final String VIEW_END_ENTITY_HISTORY = "/view_end_entity_history";
    public static final String APPROVE_END_ENTITY = "/approve_end_entity";

//    public static final String HARDTOKEN_RIGHTS                           = "/view_hardtoken";
//    public static final String HARDTOKEN_PUKDATA_RIGHTS                   = "/view_hardtoken/puk_data";

    public static final String  KEYRECOVERY_RIGHTS                        = "/keyrecovery";    
    
    // Endings used in profile authorization.
    public static final String[] ENDENTITYPROFILE_ENDINGS = {VIEW_END_ENTITY,EDIT_END_ENTITY,CREATE_END_ENTITY,DELETE_END_ENTITY,REVOKE_END_ENTITY,VIEW_END_ENTITY_HISTORY,APPROVE_END_ENTITY};
    
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

    public static final String ROLE_ADMINISTRATOR                         = "/administrator";
    public static final String REGULAR_ACTIVATECA                         = StandardRules.CAFUNCTIONALITY.resource()+"/activate_ca";
    public static final String REGULAR_VIEWCERTIFICATE                    = StandardRules.CAFUNCTIONALITY.resource()+"/view_certificate";    
    public static final String REGULAR_APPROVECAACTION                    = StandardRules.CAFUNCTIONALITY.resource()+"/approve_caaction";
    public static final String REGULAR_CREATECRL                          = StandardRules.CREATECRL.resource();    
    public static final String REGULAR_CREATECERTIFICATE                  = StandardRules.CREATECERT.resource();
    public static final String REGULAR_EDITPUBLISHER                      = StandardRules.CAFUNCTIONALITY.resource()+"/edit_publisher";   
    public static final String REGULAR_VIEWPUBLISHER                      = StandardRules.CAFUNCTIONALITY.resource()+"/view_publisher";    
    public static final String REGULAR_EDITVALIDATOR                   = StandardRules.VALIDATOREDIT.resource();
    public static final String REGULAR_VIEWVALIDATOR                   = StandardRules.VALIDATORVIEW.resource();
    public static final String REGULAR_EDITBLACKLIST                   = StandardRules.BLACKLISTEDIT.resource();
    public static final String REGULAR_RAFUNCTIONALITY                    = "/ra_functionality";
    public static final String REGULAR_EDITENDENTITYPROFILES              = REGULAR_RAFUNCTIONALITY+"/edit_end_entity_profiles";
    public static final String REGULAR_VIEWENDENTITYPROFILES              = REGULAR_RAFUNCTIONALITY+"/view_end_entity_profiles";
    public static final String REGULAR_EDITUSERDATASOURCES                = REGULAR_RAFUNCTIONALITY + "/edit_user_data_sources";
    public static final String REGULAR_APPROVEENDENTITY                   = REGULAR_RAFUNCTIONALITY + APPROVE_END_ENTITY;
    // REGULAR_REVOKEENDENTITY is used when revoking the certificate of a user
    public static final String REGULAR_REVOKEENDENTITY                    = REGULAR_RAFUNCTIONALITY+REVOKE_END_ENTITY;    
    // The rules below seem to be for rights to certificates, and ae mostly used from WS for token certificates and CMP for token certificates
    // You can question if these are valid and right?
    public static final String REGULAR_VIEWENDENTITY                      = REGULAR_RAFUNCTIONALITY+VIEW_END_ENTITY;
    public static final String REGULAR_CREATEENDENTITY                    = REGULAR_RAFUNCTIONALITY+CREATE_END_ENTITY;
    public static final String REGULAR_EDITENDENTITY                      = REGULAR_RAFUNCTIONALITY+EDIT_END_ENTITY ;
    public static final String REGULAR_DELETEENDENTITY                    = REGULAR_RAFUNCTIONALITY+DELETE_END_ENTITY; // Unused, but exists as "raw" string
    public static final String REGULAR_VIEWENDENTITYHISTORY               = REGULAR_RAFUNCTIONALITY+VIEW_END_ENTITY_HISTORY; // Unused, but exists as "raw" string
    
    //public static final String REGULAR_VIEWHARDTOKENS                     = REGULAR_RAFUNCTIONALITY + HARDTOKEN_RIGHTS;
    //public static final String REGULAR_VIEWPUKS                           = REGULAR_RAFUNCTIONALITY + HARDTOKEN_PUKDATA_RIGHTS;
    public static final String REGULAR_KEYRECOVERY                        = REGULAR_RAFUNCTIONALITY + KEYRECOVERY_RIGHTS;
    public static final String REGULAR_VIEWAPPROVALS                      = REGULAR_RAFUNCTIONALITY+"/view_approvals";

    /** EE version only, reference by String value */
    public static final String REGULAR_PEERCONNECTOR_VIEW                 = "/peer/view";   // org.ejbca.peerconnector.PeerAccessRules.VIEW
    public static final String REGULAR_PEERCONNECTOR_MODIFY               = "/peer/modify"; // org.ejbca.peerconnector.PeerAccessRules.MODIFY
    public static final String REGULAR_PEERCONNECTOR_MANAGE               = "/peer/manage"; // org.ejbca.peerconnector.PeerAccessRules.MANAGE
    public static final String REGULAR_PEERCONNECTOR_INVOKEAPI            = "/ra_master/invoke_api"; // org.ejbca.peerconnector.PeerRaAccessRules.RA_MASTER_INVOKE_API
    
    /**
     * EE version only. Intended for checks required when Peers 
     * module might not be available. When possible, reference 
     * PeerProtocolAccessRules instead.
     **/
    public static final String REGULAR_PEERPROTOCOL_ACME                  = "/protocol/acme"; // org.ejbca.peerconnector.PeerProtocolAccessRules.ACME
    public static final String REGULAR_PEERPROTOCOL_CMP                   = "/protocol/cmp";  // org.ejbca.peerconnector.PeerProtocolAccessRules.CMP
    public static final String REGULAR_PEERPROTOCOL_EST                   = "/protocol/est";  // org.ejbca.peerconnector.PeerProtocolAccessRules.EST
    public static final String REGULAR_PEERPROTOCOL_REST                  = "/protocol/rest"; // org.ejbca.peerconnector.PeerProtocolAccessRules.REST
    public static final String REGULAR_PEERPROTOCOL_SCEP                  = "/protocol/scep"; // org.ejbca.peerconnector.PeerProtocolAccessRules.SCEP
    public static final String REGULAR_PEERPROTOCOL_WS                    = "/protocol/web_services"; // org.ejbca.peerconnector.PeerProtocolAccessRules.WS
    
    // Rules for editing/viewing Service workers
    public static final String SERVICES_BASE                              = "/services";
    public static final String SERVICES_EDIT                              = SERVICES_BASE+"/edit";
    public static final String SERVICES_VIEW                              = SERVICES_BASE+"/view";
    
    // Standard Regular Access Rules
    public static final String[] STANDARDREGULARACCESSRULES = {StandardRules.CAFUNCTIONALITY.resource(), 
                                                           REGULAR_ACTIVATECA,
                                                           StandardRules.CAEDIT.resource(),
                                                           StandardRules.CARENEW.resource(),
                                                           StandardRules.CAVIEW.resource(),
                                                           REGULAR_VIEWCERTIFICATE, 
                                                           REGULAR_CREATECRL,
                                                           StandardRules.CERTIFICATEPROFILEEDIT.resource(),   
                                                           StandardRules.CERTIFICATEPROFILEVIEW.resource(),
                                                           StandardRules.APPROVALPROFILEEDIT.resource(),
                                                           StandardRules.APPROVALPROFILEVIEW.resource(),
                                                           REGULAR_CREATECERTIFICATE,
                                                           REGULAR_EDITPUBLISHER,
                                                           REGULAR_VIEWPUBLISHER,
                                                           REGULAR_EDITVALIDATOR,
                                                           REGULAR_VIEWVALIDATOR,
                                                           REGULAR_EDITBLACKLIST,
                                                           REGULAR_APPROVECAACTION,
                                                           REGULAR_RAFUNCTIONALITY, 
                                                           REGULAR_EDITENDENTITYPROFILES,
                                                           REGULAR_VIEWENDENTITYPROFILES,
                                                           REGULAR_EDITUSERDATASOURCES,                                                           
                                                           REGULAR_VIEWENDENTITY,
                                                           REGULAR_CREATEENDENTITY, 
                                                           REGULAR_EDITENDENTITY, 
                                                           REGULAR_DELETEENDENTITY,
                                                           REGULAR_REVOKEENDENTITY,
                                                           REGULAR_VIEWENDENTITYHISTORY,
                                                           REGULAR_APPROVEENDENTITY,
                                                           REGULAR_VIEWAPPROVALS,
                                                           StandardRules.SYSTEMFUNCTIONALITY.resource(),
                                                           SERVICES_EDIT,
                                                           SERVICES_VIEW,
                                                           StandardRules.EDITROLES.resource(),
                                                           StandardRules.VIEWROLES.resource(),
                                                           StandardRules.SYSTEMCONFIGURATION_EDIT.resource(),
                                                           StandardRules.SYSTEMCONFIGURATION_VIEW.resource(),
                                                           StandardRules.EKUCONFIGURATION_EDIT.resource(),
                                                           StandardRules.EKUCONFIGURATION_VIEW.resource(),
                                                           StandardRules.CUSTOMCERTEXTENSIONCONFIGURATION_EDIT.resource(),
                                                           StandardRules.CUSTOMCERTEXTENSIONCONFIGURATION_VIEW.resource()
                                                           };
                                                       
    // Role Access Rules
    public static final  String[] ROLEACCESSRULES = {ROLE_ADMINISTRATOR, StandardRules.ROLE_ROOT.resource()};
}
