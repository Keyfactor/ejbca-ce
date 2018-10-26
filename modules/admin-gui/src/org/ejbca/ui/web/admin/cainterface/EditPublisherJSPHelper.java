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

package org.ejbca.ui.web.admin.cainterface;

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.TreeSet;

import javax.faces.model.SelectItem;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang.StringUtils;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ca.publisher.ActiveDirectoryPublisher;
import org.ejbca.core.model.ca.publisher.BasePublisher;
import org.ejbca.core.model.ca.publisher.CustomPublisherContainer;
import org.ejbca.core.model.ca.publisher.CustomPublisherProperty;
import org.ejbca.core.model.ca.publisher.GeneralPurposeCustomPublisher;
import org.ejbca.core.model.ca.publisher.ICustomPublisher;
import org.ejbca.core.model.ca.publisher.LdapPublisher;
import org.ejbca.core.model.ca.publisher.LdapPublisher.ConnectionSecurity;
import org.ejbca.core.model.ca.publisher.LdapSearchPublisher;
import org.ejbca.core.model.ca.publisher.LegacyValidationAuthorityPublisher;
import org.ejbca.core.model.ca.publisher.MultiGroupPublisher;
import org.ejbca.core.model.ca.publisher.PublisherConnectionException;
import org.ejbca.core.model.ca.publisher.PublisherConst;
import org.ejbca.core.model.ca.publisher.PublisherDoesntExistsException;
import org.ejbca.core.model.ca.publisher.PublisherExistsException;
import org.ejbca.ui.web.RequestHelper;
import org.ejbca.ui.web.admin.configuration.EjbcaWebBean;


/**
 * Contains help methods used to parse a publisher jsp page requests.
 *
 * @version $Id$
 */
public class EditPublisherJSPHelper {
	
    public static final String ACTION                              = "action";
    public static final String ACTION_EDIT_PUBLISHERS              = "editpublishers";
    public static final String ACTION_EDIT_PUBLISHER               = "editpublisher";

    public static final String ACTION_CHANGE_PUBLISHERTYPE         = "changepublishertype";


    public static final String CHECKBOX_VALUE                     = BasePublisher.TRUE;

//  Used in publishers.jsp
    public static final String BUTTON_EDIT_PUBLISHER              = "buttoneditpublisher";
    public static final String BUTTON_DELETE_PUBLISHER            = "buttondeletepublisher";
    public static final String BUTTON_ADD_PUBLISHER               = "buttonaddpublisher";
    public static final String BUTTON_RENAME_PUBLISHER            = "buttonrenamepublisher";
    public static final String BUTTON_CLONE_PUBLISHER             = "buttonclonepublisher";

    public static final String SELECT_PUBLISHER                   = "selectpublisher";
    public static final String TEXTFIELD_PUBLISHERNAME            = "textfieldpublishername";
    public static final String HIDDEN_PUBLISHERNAME               = "hiddenpublishername";

//  Buttons used in publisher.jsp
    public static final String BUTTON_TESTCONNECTION    = "buttontestconnection";
    public static final String BUTTON_SAVE              = "buttonsave";
    public static final String BUTTON_CANCEL            = "buttoncancel";

    public static final String TYPE_CUSTOM              = "typecustom";
    public static final String TYPE_LDAP                = "typeldap";
    public static final String TYPE_AD                  = "typead";
    public static final String TYPE_LDAP_SEARCH         = "typeldapsearch";

    public static final String HIDDEN_PUBLISHERTYPE      = "hiddenpublishertype";
    public static final String SELECT_PUBLISHERTYPE      = "selectpublishertype";

    public static final String SELECT_APPLICABLECAS      = "selectapplicablecas";
    public static final String TEXTAREA_DESCRIPTION      = "textareadescription";

    public static final String SELECT_CUSTOMCLASS        = "selectcustomclass";
    public static final String TEXTFIELD_CUSTOMCLASSPATH = "textfieldcustomclasspath";
    public static final String TEXTAREA_CUSTOMPROPERTIES = "textareacustomproperties";
    public static final String TEXTAREA_PROPERTIES = "textareaproperties";
    public static final String TEXTAREA_GROUPS                 = "textareagroups";

    public static final String TEXTFIELD_LDAPHOSTNAME          = "textfieldldaphostname";
    public static final String TEXTFIELD_LDAPPORT              = "textfieldldapport";
    public static final String TEXTFIELD_LDAPBASEDN            = "textfieldldapbasedn";
    public static final String TEXTFIELD_LDAPLOGINDN           = "textfieldldaplogindn";
    public static final String TEXTFIELD_LDAPUSEROBJECTCLASS   = "textfieldldapuserobjectclass";
    public static final String TEXTFIELD_LDAPCAOBJECTCLASS     = "textfieldldapcaobjectclass";
    public static final String TEXTFIELD_LDAPUSERCERTATTRIBUTE = "textfieldldapusercertattribute";
    public static final String TEXTFIELD_LDAPCACERTATTRIBUTE   = "textfieldldapcacertattribute";
    public static final String TEXTFIELD_LDAPCRLATTRIBUTE      = "textfieldldapcrlattribute";
    public static final String TEXTFIELD_LDAPDELTACRLATTRIBUTE = "textfieldldapdeltacrlattribute";
    public static final String TEXTFIELD_LDAPARLATTRIBUTE      = "textfieldldaparlattribute";
    public static final String TEXTFIELD_LDAPSEARCHBASEDN      = "textfieldldapsearchbasedn";
    public static final String TEXTFIELD_LDAPSEARCHFILTER      = "textfieldldapsearchfilter";
    public static final String TEXTFIELD_LDAPTIMEOUT           = "textfieldldaptimeout";
    public static final String TEXTFIELD_LDAPREADTIMEOUT       = "textfieldldapreadtimeout";
    public static final String TEXTFIELD_LDAPSTORETIMEOUT      = "textfieldldapstoretimeout";
    public static final String TEXTFIELD_VA_DATASOURCE         = "textfieldvadatasource";
    public static final String PASSWORD_LDAPLOGINPASSWORD      = "textfieldldaploginpassword";
    public static final String PASSWORD_LDAPLOGINPASSWORDPLACEHOLDER = "placeholder";    
    public static final String PASSWORD_LDAPCONFIRMLOGINPWD    = "textfieldldaploginconfirmpwd";
    public static final String RADIO_LDAPCONNECTIONSECURITY    = "radioldapconnectionsecurity";
    public static final String CHECKBOX_LDAPCREATENONEXISTING  = "checkboxldapcreatenonexisting";
    public static final String CHECKBOX_LDAPMODIFYEXISTING     = "checkboxldapmodifyexisting";
    public static final String CHECKBOX_LDAPMODIFYEXISTINGATTRIBUTES     = "checkboxldapmodifyexistingattributes";
    public static final String CHECKBOX_LDAPADDNONEXISTING     = "checkboxldapaddnonexisting";
    public static final String CHECKBOX_LDAP_CREATEINTERMEDIATENODES = "checkboxldapcreateintermediatenodes";
    public static final String CHECKBOX_LDAPADDMULTIPLECERTIFICATES= "checkboxaldapddmultiplecertificates";
    public static final String CHECKBOX_LDAP_REVOKE_REMOVECERTIFICATE = "checkboxldaprevokeremovecertificate";
    public static final String CHECKBOX_LDAP_REVOKE_REMOVEUSERONCERTREVOKE = "checkboxldaprevokeuseroncertrevoke";
    public static final String CHECKBOX_LDAP_SET_USERPASSWORD  = "checkboxldapsetuserpassword";
    public static final String CHECKBOX_ONLYUSEQUEUE           = "textfieldonlyusequeue";
    public static final String CHECKBOX_KEEPPUBLISHEDINQUEUE   = "textfieldkeeppublishedinqueue";
    public static final String CHECKBOX_USEQUEUEFORCRLS        = "textfieldusequeueforcrls";
    public static final String CHECKBOX_USEQUEUEFORCERTIFICATES = "textfieldusequeueforcertificates";
    public static final String CHECKBOX_VA_STORECERT           = "textfieldvastorecert";
    public static final String CHECKBOX_VA_STORECRL            = "textfieldvastorecrl";
    public static final String CHECKBOX_VA_ONLY_PUBLISH_REVOKED = "checkboxonlypublishrevoked";
    
    public static final String SELECT_LDAPUSEFIELDINLDAPDN     = "selectldapusefieldsinldapdn";

    public static final String CHECKBOX_ADUSEPASSWORD          = "checkboxadusepassword";
    public static final String SELECT_ADUSERACCOUNTCONTROL     = "selectaduseraccountcontrol";
    public static final String SELECT_ADSAMACCOUNTNAME         = "selectsamaccountname";
    public static final String TEXTFIELD_ADUSERDESCRIPTION     = "textfieldaduserdescription";

    public static final String PAGE_PUBLISHER                  = "publisherpage.jspf";
    public static final String PAGE_PUBLISHERS                 = "publisherspage.jspf";

    private EjbcaWebBean ejbcawebbean;
    
    private CAInterfaceBean cabean;
    private boolean initialized=false;
    private boolean  publisherexists       = false;
    private boolean  publisherdeletefailed = false;
    private boolean  connectionmessage = false;
    private boolean  connectionsuccessful = false;
    private String   connectionerrormessage = "";
    private BasePublisher publisherdata = null;


    private String publishername = null;
    private Integer publisherId = null;

    /** Creates new LogInterfaceBean */
    public EditPublisherJSPHelper(){
    }
    // Public methods.
    /**
     * Method that initialized the bean.
     *
     * @param request is a reference to the http request.
     */
    public void initialize(HttpServletRequest request, EjbcaWebBean ejbcawebbean,
            CAInterfaceBean cabean) throws  Exception{

        if(!initialized){
            this.cabean = cabean;
            this.ejbcawebbean = ejbcawebbean;
            initialized = true;

        }
    }

    @SuppressWarnings({ "deprecation" })
    public String parseRequest(HttpServletRequest request) throws AuthorizationDeniedException, PublisherDoesntExistsException, PublisherExistsException{
        String includefile = PAGE_PUBLISHERS;
        String publisher = null;
        PublisherDataHandler handler  = cabean.getPublisherDataHandler();
        String action = null;

        try {
            RequestHelper.setDefaultCharacterEncoding(request);
        } catch (UnsupportedEncodingException e1) {
            // itgnore
        }
        action = request.getParameter(ACTION);
        if( action != null){
            if( action.equals(ACTION_EDIT_PUBLISHERS)){
                if( request.getParameter(BUTTON_EDIT_PUBLISHER) != null){
                    publisher = request.getParameter(SELECT_PUBLISHER);
                    if(publisher != null){
                        if(!publisher.trim().equals("")){
                            includefile=PAGE_PUBLISHER;
                            this.publishername = publisher;
                            this.publisherdata = handler.getPublisher(publishername);
                            this.publisherId = publisherdata.getPublisherId();
                        }
                        else{
                            publisher= null;
                        }
                    }
                    if(publisher == null){
                        includefile=PAGE_PUBLISHERS;
                    }
                }
                if( request.getParameter(BUTTON_DELETE_PUBLISHER) != null) {
                    publisher = request.getParameter(SELECT_PUBLISHER);
                    if(publisher != null){
                        if(!publisher.trim().equals("")){
                            setPublisherdeletefailed(handler.removePublisher(publisher));
                        }
                    }
                    includefile=PAGE_PUBLISHERS;
                }
                if( request.getParameter(BUTTON_RENAME_PUBLISHER) != null){
                    // Rename selected publisher and display profilespage.
                    String newpublishername = request.getParameter(TEXTFIELD_PUBLISHERNAME);
                    String oldpublishername = request.getParameter(SELECT_PUBLISHER);
                    if(oldpublishername != null && newpublishername != null){
                        if(!newpublishername.trim().equals("") && !oldpublishername.trim().equals("")){
                            try{
                                handler.renamePublisher(oldpublishername.trim(),newpublishername.trim());
                            }catch( PublisherExistsException e){
                                setPublisherexists(true);
                            }
                        }
                    }
                    includefile=PAGE_PUBLISHERS;
                }
                if( request.getParameter(BUTTON_ADD_PUBLISHER) != null){
                    publisher = request.getParameter(TEXTFIELD_PUBLISHERNAME);
                    if(publisher != null){
                        if(!publisher.trim().equals("")){
                            try{
                                handler.addPublisher(publisher.trim(), new LdapPublisher());
                            }catch( PublisherExistsException e){
                                setPublisherexists(true);
                            }
                        }
                    }
                    includefile=PAGE_PUBLISHERS;
                }
                if( request.getParameter(BUTTON_CLONE_PUBLISHER) != null){
                    String newpublishername = request.getParameter(TEXTFIELD_PUBLISHERNAME);
                    String oldpublishername = request.getParameter(SELECT_PUBLISHER);
                    if(oldpublishername != null && newpublishername != null){
                        if(!newpublishername.trim().equals("") && !oldpublishername.trim().equals("")){
                            handler.clonePublisher(oldpublishername.trim(),newpublishername.trim());
                        }
                    }
                    includefile=PAGE_PUBLISHERS;
                }
            }
            if( action.equals(ACTION_EDIT_PUBLISHER)){
                // Display edit access rules page.
                publisher = request.getParameter(HIDDEN_PUBLISHERNAME);
                this.publishername = publisher;
                if(publisher != null){
                    if(!publisher.trim().equals("")){
                        if (request.getParameter(BUTTON_SAVE) != null || request.getParameter(BUTTON_TESTCONNECTION) != null) {
                            if (publisherdata == null) {
                                int tokentype = Integer.parseInt(request.getParameter(HIDDEN_PUBLISHERTYPE));
                                switch (tokentype) {
                                case PublisherConst.TYPE_CUSTOMPUBLISHERCONTAINER:
                                    publisherdata = new CustomPublisherContainer();
                                    break;
                                case PublisherConst.TYPE_LDAPPUBLISHER:
                                    publisherdata = new LdapPublisher();
                                    break;
                                case PublisherConst.TYPE_LDAPSEARCHPUBLISHER:
                                    publisherdata = new LdapSearchPublisher();
                                    break;
                                case PublisherConst.TYPE_ADPUBLISHER:
                                    publisherdata = new ActiveDirectoryPublisher();
                                    break;
                                case PublisherConst.TYPE_VAPUBLISHER:
                                    publisherdata = null;
                                    break;
                                case PublisherConst.TYPE_MULTIGROUPPUBLISHER:
                                    publisherdata = new MultiGroupPublisher();
                                    break;
                                default:
                                    break;
                                }                     
                            }
                            // Save changes.

                            // General settings
                            String value = request.getParameter(TEXTAREA_DESCRIPTION);
                            if(value != null){
                                value = value.trim();
                                publisherdata.setDescription(value);
                            }
                        	value = request.getParameter(CHECKBOX_ONLYUSEQUEUE);
                        	publisherdata.setOnlyUseQueue(value != null && value.equals(CHECKBOX_VALUE));
                        	value = request.getParameter(CHECKBOX_KEEPPUBLISHEDINQUEUE);
                        	publisherdata.setKeepPublishedInQueue(value != null && value.equals(CHECKBOX_VALUE));
                        	value = request.getParameter(CHECKBOX_USEQUEUEFORCRLS);
                        	publisherdata.setUseQueueForCRLs(value != null && value.equals(CHECKBOX_VALUE));
                        	value = request.getParameter(CHECKBOX_USEQUEUEFORCERTIFICATES);
                        	publisherdata.setUseQueueForCertificates(value != null && value.equals(CHECKBOX_VALUE));

                            if(publisherdata instanceof CustomPublisherContainer){
                                final CustomPublisherContainer custompublisherdata = ((CustomPublisherContainer) publisherdata);
                                String customClass = request.getParameter(TEXTFIELD_CUSTOMCLASSPATH);
                                String selectClass = request.getParameter(SELECT_CUSTOMCLASS);
                                if(selectClass != null && !selectClass.isEmpty()) {
                                    value = selectClass.trim();
                                    custompublisherdata.setClassPath(value);
                                } else if (customClass != null && !customClass.isEmpty()) {
                                    value = customClass.trim();
                                    custompublisherdata.setClassPath(value);
                                } else {
                                    // can happen if the user has Javascript turned off
                                    throw new IllegalArgumentException("No class path selected");
                                }
                                if (custompublisherdata.isCustomUiRenderingSupported()) {
                                    final StringBuilder sb = new StringBuilder();
                                    for (final CustomPublisherProperty customPublisherProperty : custompublisherdata.getCustomUiPropertyList()) {
                                        final String customValue = request.getParameter(customPublisherProperty.getName());
                                        if (customPublisherProperty.getType()==CustomPublisherProperty.UI_BOOLEAN) {
                                            if (customValue==null) {
                                                sb.append(customPublisherProperty.getName()).append('=').append("false").append('\n');
                                            } else {
                                                sb.append(customPublisherProperty.getName()).append('=').append("true").append('\n');
                                            }
                                        } else {
                                            if (customValue!=null) {
                                                sb.append(customPublisherProperty.getName()).append('=').append(customValue).append('\n');
                                            }
                                        }
                                    }
                                    custompublisherdata.setPropertyData(sb.toString());
                                } else {
                                    value = request.getParameter(TEXTAREA_CUSTOMPROPERTIES);
                                    if(value != null){
                                        value = value.trim();
                                        custompublisherdata.setPropertyData(value);
                                    }
                                }
                            }

                            if(publisherdata instanceof LdapPublisher){
                                LdapPublisher ldappublisher = (LdapPublisher) publisherdata;

                                value = request.getParameter(TEXTFIELD_LDAPHOSTNAME);
                                if(value != null){
                                    value = value.trim();
                                    ldappublisher.setHostnames(value);
                                }
                                value = request.getParameter(TEXTFIELD_LDAPPORT);
                                if(value != null){
                                    value = value.trim();
                                    ldappublisher.setPort(value);
                                }
                                value = request.getParameter(TEXTFIELD_LDAPBASEDN);
                                if(value != null){
                                    value = value.trim();
                                    ldappublisher.setBaseDN(value);
                                }
                                value = request.getParameter(TEXTFIELD_LDAPLOGINDN);
                                if(value != null){
                                    value = value.trim();
                                    ldappublisher.setLoginDN(value);
                                }
                                value = request.getParameter(PASSWORD_LDAPLOGINPASSWORD);
                                if(value != null){
                                    value = value.trim();
                                    // If we have a password that wasn't shown in the html page, and this wasn't changed by the user
                                    // we will not edit the old password. This is a "security" feature so we don't send the actual password
                                    // to be available in clear text in the users web browser
                                    if (!PASSWORD_LDAPLOGINPASSWORDPLACEHOLDER.equals(value)) {
                                        ldappublisher.setLoginPassword(value);
                                    }
                                }
                                value = request.getParameter(TEXTFIELD_LDAPTIMEOUT);
                                if(value != null){
                                    value = value.trim();
                                    ldappublisher.setConnectionTimeOut(Integer.parseInt(value));
                                }
                                value = request.getParameter(TEXTFIELD_LDAPREADTIMEOUT);
                                if(value != null){
                                    value = value.trim();
                                    ldappublisher.setReadTimeOut(Integer.parseInt(value));
                                }
                                value = request.getParameter(TEXTFIELD_LDAPSTORETIMEOUT);
                                if(value != null){
                                    value = value.trim();
                                    ldappublisher.setStoreTimeOut(Integer.parseInt(value));
                                }
                                value = request.getParameter(TEXTFIELD_LDAPUSEROBJECTCLASS);
                                if(value != null){
                                    value = value.trim();
                                    ldappublisher.setUserObjectClass(value);
                                }
                                value = request.getParameter(TEXTFIELD_LDAPCAOBJECTCLASS);
                                if(value != null){
                                    value = value.trim();
                                    ldappublisher.setCAObjectClass(value);
                                }
                                value = request.getParameter(TEXTFIELD_LDAPUSERCERTATTRIBUTE);
                                if(value != null){
                                    value = value.trim();
                                    ldappublisher.setUserCertAttribute(value);
                                }
                                value = request.getParameter(TEXTFIELD_LDAPCACERTATTRIBUTE);
                                if(value != null){
                                    value = value.trim();
                                    ldappublisher.setCACertAttribute(value);
                                }
                                value = request.getParameter(TEXTFIELD_LDAPCRLATTRIBUTE);
                                if(value != null){
                                    value = value.trim();
                                    ldappublisher.setCRLAttribute(value);
                                }
                                value = request.getParameter(TEXTFIELD_LDAPDELTACRLATTRIBUTE);
                                if(value != null){
                                	value = value.trim();
                                	ldappublisher.setDeltaCRLAttribute(value);
                                }
                                value = request.getParameter(TEXTFIELD_LDAPARLATTRIBUTE);
                                if(value != null){
                                    value = value.trim();
                                    ldappublisher.setARLAttribute(value);
                                }

                                value = request.getParameter(RADIO_LDAPCONNECTIONSECURITY);
                                if(value != null){
                                    ldappublisher.setConnectionSecurity(ConnectionSecurity.valueOf(value));
                                }

                                value = request.getParameter(CHECKBOX_LDAPCREATENONEXISTING);
                                if(value != null) {
                                    ldappublisher.setCreateNonExistingUsers(value.equals(CHECKBOX_VALUE));
                                }
                                else {
                                    ldappublisher.setCreateNonExistingUsers(false);
                                }
                                value = request.getParameter(CHECKBOX_LDAPMODIFYEXISTING);
                                if(value != null) {
                                    ldappublisher.setModifyExistingUsers(value.equals(CHECKBOX_VALUE));
                                } 
                                else {
                                    ldappublisher.setModifyExistingUsers(false);
                                }
                                value = request.getParameter(CHECKBOX_LDAPMODIFYEXISTINGATTRIBUTES);
                                if(value != null) {
                                    ldappublisher.setModifyExistingAttributes(value.equals(CHECKBOX_VALUE));
                                }
                                else {
                                    ldappublisher.setModifyExistingAttributes(false);
                                }
                                value = request.getParameter(CHECKBOX_LDAPADDNONEXISTING);
                                if(value != null) {
                                    ldappublisher.setAddNonExistingAttributes(value.equals(CHECKBOX_VALUE));
                                }
                                else {
                                    ldappublisher.setAddNonExistingAttributes(false);
                                }
                                value = request.getParameter(CHECKBOX_LDAP_CREATEINTERMEDIATENODES);
                                if(value != null) {
                                    ldappublisher.setCreateIntermediateNodes(value.equals(CHECKBOX_VALUE));
                                }
                                else {
                                    ldappublisher.setCreateIntermediateNodes(false);
                                }
                                value = request.getParameter(CHECKBOX_LDAPADDMULTIPLECERTIFICATES);
                                if(value != null) {
                                    ldappublisher.setAddMultipleCertificates(value.equals(CHECKBOX_VALUE));
                                }
                                else {
                                    ldappublisher.setAddMultipleCertificates(false);
                                }
                                value = request.getParameter(CHECKBOX_LDAP_REVOKE_REMOVECERTIFICATE);
                                if(value != null) {
                                    ldappublisher.setRemoveRevokedCertificates(value.equals(CHECKBOX_VALUE));
                                }
                                else {
                                    ldappublisher.setRemoveRevokedCertificates(false);
                                }
                                value = request.getParameter(CHECKBOX_LDAP_REVOKE_REMOVEUSERONCERTREVOKE);
                                if(value != null) {
                                    ldappublisher.setRemoveUsersWhenCertRevoked(value.equals(CHECKBOX_VALUE));
                                }
                                else {
                                    ldappublisher.setRemoveUsersWhenCertRevoked(false);
                                }
                                value = request.getParameter(CHECKBOX_LDAP_SET_USERPASSWORD);
                                if(value != null) {
                                    ldappublisher.setUserPassword(value.equals(CHECKBOX_VALUE));
                                } else {
                                    ldappublisher.setUserPassword(false);
                                }
                                
                                String[] values = request.getParameterValues(SELECT_LDAPUSEFIELDINLDAPDN);
                                if(values != null){
                                    ArrayList<Integer> usefields = new ArrayList<>();
                                    for(int i=0;i< values.length;i++){
                                        usefields.add(Integer.valueOf(values[i]));
                                    }

                                    ldappublisher.setUseFieldInLdapDN(usefields);
                                }
                            }


                            if (publisherdata instanceof LdapSearchPublisher) {
                              LdapSearchPublisher ldapsearchpublisher = (LdapSearchPublisher) publisherdata;

                              value = request.getParameter(TEXTFIELD_LDAPSEARCHBASEDN);
                              if (value != null) {
                                value = value.trim();
                                ldapsearchpublisher.setSearchBaseDN(value);
                              }
                              value = request.getParameter(TEXTFIELD_LDAPSEARCHFILTER);
                              if (value != null) {
                                value = value.trim();
                                ldapsearchpublisher.setSearchFilter(value);
                              }
                            }


                            if(publisherdata instanceof ActiveDirectoryPublisher){
                                ActiveDirectoryPublisher adpublisher = (ActiveDirectoryPublisher) publisherdata;

                                value = request.getParameter(SELECT_ADSAMACCOUNTNAME);
                                if(value != null){
                                    value = value.trim();
                                    adpublisher.setSAMAccountName(Integer.parseInt(value));
                                }

                                value = request.getParameter(TEXTFIELD_ADUSERDESCRIPTION);
                                if(value != null){
                                    value = value.trim();
                                    adpublisher.setUserDescription(value);
                                }

                                value = request.getParameter(CHECKBOX_ADUSEPASSWORD);
                                if(value != null) {
                                    adpublisher.setUseUserPassword(value.equals(CHECKBOX_VALUE));
                                }
                                else {
                                    adpublisher.setUseUserPassword(false);
                                }
                                value = request.getParameter(SELECT_ADUSERACCOUNTCONTROL);
                                if(value != null) {
                                    value = value.trim();
                                    adpublisher.setUserAccountControl(Integer.parseInt(value));
                                }
                            }

                            if (publisherdata instanceof MultiGroupPublisher) {
                                MultiGroupPublisher multiGroupPublisher = (MultiGroupPublisher) this.publisherdata;
                                String groups = request.getParameter(TEXTAREA_GROUPS);
                                HashMap<String, Integer> publisherNameToIdMap = ejbcawebbean.getEjb().getPublisherSession().getPublisherNameToIdMap();
                                List<TreeSet<Integer>> multiPublisherGroups = convertMultiPublishersStringToData(publisherNameToIdMap, groups);
                                multiGroupPublisher.setPublisherGroups(multiPublisherGroups);
                            }

                            if(request.getParameter(BUTTON_SAVE) != null){
                                handler.changePublisher(publisher,publisherdata);
                                includefile=PAGE_PUBLISHERS;
                            }
                            if(request.getParameter(BUTTON_TESTCONNECTION)!= null){
                                setConnectionmessage(true);
                                handler.changePublisher(publisher,publisherdata);
                                try{
                                    handler.testConnection(publisher);
                                    setConnectionsuccessful(true);
                                }catch(PublisherConnectionException pce){
                                    setConnectionerrormessage(pce.getMessage());
                                }
                                includefile=PAGE_PUBLISHER;
                            }

                        }
                        if(request.getParameter(BUTTON_CANCEL) != null){
                            // Don't save changes.
                            includefile=PAGE_PUBLISHERS;
                        }

                    }
                }
            }

            if( action.equals(ACTION_CHANGE_PUBLISHERTYPE)){
                this.publishername = request.getParameter(HIDDEN_PUBLISHERNAME);
                String value = request.getParameter(SELECT_PUBLISHERTYPE);
                if(value!=null){
                    int dashPos = value.indexOf('-');
                    if (dashPos==-1) {
                        int profiletype = Integer.parseInt(value);
                        switch(profiletype){
                        case PublisherConst.TYPE_CUSTOMPUBLISHERCONTAINER :
                            publisherdata = new CustomPublisherContainer();
                            break;
                        case PublisherConst.TYPE_LDAPPUBLISHER :
                            publisherdata =  new LdapPublisher();
                            break;
                        case PublisherConst.TYPE_LDAPSEARCHPUBLISHER:
                            publisherdata = new LdapSearchPublisher();
                            break;
                        case PublisherConst.TYPE_ADPUBLISHER :
                            publisherdata =  new ActiveDirectoryPublisher();
                            break;
                        case PublisherConst.TYPE_MULTIGROUPPUBLISHER :
                            publisherdata =  new MultiGroupPublisher();
                            break;
                        }
                    } else {
                        publisherdata = new CustomPublisherContainer();
                        final String customClassName = value.substring(dashPos+1);
                        if (getCustomClasses().contains(customClassName)) {
                            ((CustomPublisherContainer)publisherdata).setClassPath(customClassName);
                        }
                    }
                }

                includefile=PAGE_PUBLISHER;
            }
        }

        return includefile;
    }
    
    private static final int[] AVAILABLEPUBLISHER_TYPES = new int[] {
        PublisherConst.TYPE_LDAPPUBLISHER, PublisherConst.TYPE_LDAPSEARCHPUBLISHER, PublisherConst.TYPE_ADPUBLISHER,
        PublisherConst.TYPE_CUSTOMPUBLISHERCONTAINER, PublisherConst.TYPE_MULTIGROUPPUBLISHER
    };
    private static final String[] AVAILABLEPUBLISHER_TYPETEXTS = new String[] {
        "LDAPPUBLISHER", "LDAPSEARCHPUBLISHER", "ACTIVEDIRECTORYPUBLISHER",
        "CUSTOMPUBLISHER", "MULTIGROUPPUBLISHER"
    };
    
    public String getPublisherName() {
        return publishername;
    }

    public int getPublisherId(){
        return publisherId;
    }
    
    public String getPublisherName(String className) {
        final String klassSimpleName = className.substring(className.lastIndexOf('.')+1);
        // Present the publisher with a nice name if a language key is present
        String text = ejbcawebbean.getText(klassSimpleName.toUpperCase());
        if (text.equals(klassSimpleName.toUpperCase())) {
            // Present the publisher with the class name when no language key is present
            text = klassSimpleName + " ("+ejbcawebbean.getText(AVAILABLEPUBLISHER_TYPETEXTS[3])+")";
        }
        return text;
    }
    
    public String getCurrentPublisherName() {
        if (publisherdata instanceof CustomPublisherContainer) {
            ICustomPublisher iCustomPublisher = ((CustomPublisherContainer) publisherdata).getCustomPublisher();
            if(iCustomPublisher != null) {
                return getPublisherName(iCustomPublisher.getClass().getName());
            } 
        }
        return getPublisherName(publisherdata.getClass().getName());
    }
    
    /** @return the available publishers as list that can be used by JSF h:datatable in the future. */
    public List<SelectItem> getSelectablePublishers() {
        final List<SelectItem> ret = new ArrayList<>();
        // List all built in publisher types and all the dynamic ones
        for (int i=0; i<AVAILABLEPUBLISHER_TYPES.length; i++) {
            final int type = AVAILABLEPUBLISHER_TYPES[i];
            if (type==PublisherConst.TYPE_CUSTOMPUBLISHERCONTAINER) {
                for (final String klass : getCustomClasses()) {
                    ret.add(new SelectItem(Integer.valueOf(type).toString()+"-"+klass, getPublisherName(klass)));
                }
            } else {
                // Add built in publisher types
                ret.add(new SelectItem(Integer.valueOf(type).toString(), ejbcawebbean.getText(AVAILABLEPUBLISHER_TYPETEXTS[i])));
            }
        }
        // Allow selection of any class path
        if (WebConfiguration.isManualClassPathsEnabled()) {
            ret.add(new SelectItem(Integer.valueOf(PublisherConst.TYPE_CUSTOMPUBLISHERCONTAINER).toString(), ejbcawebbean.getText(AVAILABLEPUBLISHER_TYPETEXTS[3])));
        }
        // If an publisher was configured before the plugin mechanism we still want to show it
        boolean customNoLongerAvailable = true;
        final String selectedPublisherValue = getSelectedPublisherValue();
        for (final SelectItem current : ret) {
            if (current.getValue().equals(selectedPublisherValue)) {
                customNoLongerAvailable = false;
                break;
            }
        }
        if (customNoLongerAvailable) {
            ret.add(new SelectItem(selectedPublisherValue, selectedPublisherValue.split("-")[1]));
        }
        // Sort by label
        Collections.sort(ret, new Comparator<SelectItem>() {
            @Override
            public int compare(final SelectItem selectItem0, final SelectItem selectItem1) {
                return String.valueOf(selectItem0.getLabel()).compareTo(String.valueOf(selectItem1.getLabel()));
            }
        });
        return ret;
    }
    
    public String getSelectedPublisherValue() {
        if (getPublisherType()==PublisherConst.TYPE_CUSTOMPUBLISHERCONTAINER) {
            final CustomPublisherContainer custompublisher = (CustomPublisherContainer) publisherdata;
            final String currentClass = custompublisher.getClassPath();
            if (currentClass==null || currentClass.isEmpty()) {
                return Integer.valueOf(PublisherConst.TYPE_CUSTOMPUBLISHERCONTAINER).toString();
            } else {
                return Integer.valueOf(PublisherConst.TYPE_CUSTOMPUBLISHERCONTAINER).toString() + "-" + currentClass;
            }
        }
        return Integer.valueOf(getPublisherType()).toString();
    }
    
    @SuppressWarnings("deprecation")
    public int getPublisherType(){
        int retval = PublisherConst.TYPE_CUSTOMPUBLISHERCONTAINER;
        if(publisherdata instanceof CustomPublisherContainer) {
            retval = PublisherConst.TYPE_CUSTOMPUBLISHERCONTAINER;
        }
        if(publisherdata instanceof LdapPublisher) {
            retval = PublisherConst.TYPE_LDAPPUBLISHER;
        }
        if (publisherdata instanceof LdapSearchPublisher) {
            retval = PublisherConst.TYPE_LDAPSEARCHPUBLISHER;
        }
        // Legacy VA publisher doesn't exist in community edition, so check the qualified class name instead. 
        if (publisherdata.getClass().getName().equals("org.ejbca.core.model.ca.publisher.ValidationAuthorityPublisher")) {
            retval = PublisherConst.TYPE_VAPUBLISHER;
        }
        if(publisherdata instanceof ActiveDirectoryPublisher) {
            retval = PublisherConst.TYPE_ADPUBLISHER;
        }
        if (publisherdata instanceof MultiGroupPublisher) {
            retval = PublisherConst.TYPE_MULTIGROUPPUBLISHER;
        }
        return retval;
    }

    public boolean hasEditRights() {
        return ejbcawebbean.isAuthorizedNoLogSilent(AccessRulesConstants.REGULAR_EDITPUBLISHER);
    }
    
    /**
     * 
     * @return true if the publisher type is inherently read-only
     */
    public boolean isReadOnly() {
        if(!hasEditRights()) {
            return true;
        } else if (publisherdata instanceof CustomPublisherContainer) {
            ICustomPublisher pub = ((CustomPublisherContainer) publisherdata).getCustomPublisher();
            // Can be null if custom publisher has not been set up yet, then it has to be editable
            return pub == null ? false : pub.isReadOnly();
        } else {
            return false;
        }
    }
    
    /**
     * 
     * @return true if the publisher is deprecated and shouldn't be editable.
     */
    public boolean isDeprecated() {
       if(publisherdata.getClass().getName().equals(LegacyValidationAuthorityPublisher.OLD_VA_PUBLISHER_QUALIFIED_NAME)) {
           return true;
       } else {
           return false;
       }
    }
    
    public int getPublisherQueueLength() {
    	return getPublisherQueueLength(publishername);
    }
    public int[] getPublisherQueueLength(int[] intervalLower, int[] intervalUpper) {
    	return getPublisherQueueLength(publishername, intervalLower, intervalUpper);
    }
    
    public int getPublisherQueueLength(String publishername) {
    	return cabean.getPublisherQueueLength(cabean.getPublisherDataHandler().getPublisherId(publishername));
    }
    public int[] getPublisherQueueLength(String publishername, int[] intervalLower, int[] intervalUpper) {
    	return cabean.getPublisherQueueLength(cabean.getPublisherDataHandler().getPublisherId(publishername), intervalLower, intervalUpper);
    }
    
    public List<String> getCustomClasses() {        
        final List<String> classes = new ArrayList<>();
        final ServiceLoader<ICustomPublisher> svcloader = ServiceLoader.load(ICustomPublisher.class);
        final boolean enabled = ((GlobalConfiguration) ejbcawebbean.getEjb().getGlobalConfigurationSession().getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID)).getEnableExternalScripts();
        String name = null;
        for (ICustomPublisher implInstance : svcloader) {
            if (!implInstance.isReadOnly()) {
                name = implInstance.getClass().getName();
                if (enabled || !GeneralPurposeCustomPublisher.class.getName().equals(name)) {
                    classes.add(name);
                }
            }
        }
        return classes;
    }
    public boolean isPublisherexists() {
        return publisherexists;
    }
    public void setPublisherexists(boolean publisherexists) {
        this.publisherexists = publisherexists;
    }
    public boolean isPublisherdeletefailed() {
        return publisherdeletefailed;
    }
    public void setPublisherdeletefailed(boolean publisherdeletefailed) {
        this.publisherdeletefailed = publisherdeletefailed;
    }
    public boolean getConnectionmessage() {
        return connectionmessage;
    }
    public void setConnectionmessage(boolean connectionmessage) {
        this.connectionmessage = connectionmessage;
    }
    public boolean isConnectionsuccessful() {
        return connectionsuccessful;
    }
    public void setConnectionsuccessful(boolean connectionsuccessful) {
        this.connectionsuccessful = connectionsuccessful;
    }
    public String getConnectionerrormessage() {
        return connectionerrormessage;
    }
    public void setConnectionerrormessage(String connectionerrormessage) {
        this.connectionerrormessage = connectionerrormessage;
    }

    public BasePublisher getPublisherdata() {
        return publisherdata;
    }
    public void setPublisherdata(BasePublisher publisherdata) {
        this.publisherdata = publisherdata;
    }
    
    /** 
     * @return password placeholder instead of real password in order to not send clear text password to browser, or empty string in case there is no ldap password (i.e. new publisher).
     */
    public String getPasswordPlaceholder() {
       if (this.publisherdata != null) {
           final String str = (String)this.publisherdata.getRawData().get(LdapPublisher.LOGINPASSWORD);
           if (StringUtils.isNotEmpty(str)) {
               return EditPublisherJSPHelper.PASSWORD_LDAPLOGINPASSWORDPLACEHOLDER;
           }
       }
       return "";
    }

    List<TreeSet<Integer>> convertMultiPublishersStringToData(final Map<String, Integer> publisherNameToIdMap, final String textareaData) throws PublisherDoesntExistsException, PublisherExistsException {
        TreeSet<Integer> selectedPublishers = new TreeSet();
        List<String> listOfPublisherNames = Arrays.asList(textareaData.split("\n"));
        ArrayList<TreeSet<Integer>> data = new ArrayList<>();
        TreeSet<Integer> tree = new TreeSet<>();
        for (String publisherName : listOfPublisherNames) {
            publisherName = publisherName.trim();
            if (StringUtils.isEmpty(publisherName)) {
                if (!tree.isEmpty()) {
                    data.add(tree);
                    tree = new TreeSet<>();
                }
            } else {
                Integer publisherId = publisherNameToIdMap.get(publisherName);
                if (publisherId != null) {
                    if (!selectedPublishers.contains(publisherId)) {
                        tree.add(publisherId);
                        selectedPublishers.add(publisherId);
                    } else {
                        throw new PublisherExistsException("Publisher selected at least twice " + publisherName);
                    }
                } else {
                    throw new PublisherDoesntExistsException("Could not find publisher *" + publisherName + "*");
                }
            }
        }
        if (!tree.isEmpty()) {
            data.add(tree);
        }
        return data;
    }

    String convertMultiPublishersDataToString(final Map<Integer,String> publisherIdToNameMap, final List<TreeSet<Integer>> data){
        StringBuffer result = new StringBuffer();
        String prefix = "";
        for (TreeSet<Integer> tree : data) {
            for (Integer publisherId : tree) {
                result.append(prefix);
                result.append(publisherIdToNameMap.get(publisherId));
                prefix = "\n";
            }
            result.append("\n");
        }
        result.setLength(Math.max(result.length() - 1, 0));
        return result.toString();
    }

    public List<String> getPublisherListAvailable() {
        final List<String> ret = new ArrayList<>();
        final Collection<Integer> authorizedPublisherIds = ejbcawebbean.getEjb().getCaAdminSession().getAuthorizedPublisherIds(ejbcawebbean.getAdminObject());
        authorizedPublisherIds.remove(this.publisherId);
        final Map<Integer, String> publisherIdToNameMap = ejbcawebbean.getEjb().getPublisherSession().getPublisherIdToNameMap();
        for (final Integer publisherId : authorizedPublisherIds) {
            ret.add(publisherIdToNameMap.get(publisherId));
        }
        Collections.sort(ret);
        return ret;
    }

    public String getMultiPublishersDataAsString(){
        MultiGroupPublisher multiGroupPublisher = (MultiGroupPublisher) this.publisherdata;
        final List<TreeSet<Integer>> publisherGroups = multiGroupPublisher.getPublisherGroups();
        final Map<Integer, String> publisherIdToNameMap = ejbcawebbean.getEjb().getPublisherSession().getPublisherIdToNameMap();
        return convertMultiPublishersDataToString(publisherIdToNameMap, publisherGroups);
    }
}
