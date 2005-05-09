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

package se.anatom.ejbca.webdist.cainterface;

import java.util.ArrayList;

import javax.servlet.http.HttpServletRequest;

import se.anatom.ejbca.authorization.AuthorizationDeniedException;
import se.anatom.ejbca.authorization.AvailableAccessRules;
import se.anatom.ejbca.ca.exception.PublisherConnectionException;
import se.anatom.ejbca.ca.exception.PublisherExistsException;
import se.anatom.ejbca.ca.publisher.ActiveDirectoryPublisher;
import se.anatom.ejbca.ca.publisher.BasePublisher;
import se.anatom.ejbca.ca.publisher.CustomPublisherContainer;
import se.anatom.ejbca.ca.publisher.LdapPublisher;
import se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean;

/**
 * Contains help methods used to parse a publisher jsp page requests.
 *
 * @author  Philip Vendil
 * @version $Id: EditPublisherJSPHelper.java,v 1.9 2005-05-09 15:34:29 anatom Exp $
 */
public class EditPublisherJSPHelper implements java.io.Serializable {
    
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
    
    public static final String HIDDEN_PUBLISHERTYPE      = "hiddenpublishertype";
    public static final String SELECT_PUBLISHERTYPE      = "selectpublishertype";
    
    public static final String SELECT_APPLICABLECAS      = "selectapplicablecas";
    public static final String TEXTAREA_DESCRIPTION      = "textareadescription";
    
    public static final String TEXTFIELD_CUSTOMCLASSPATH = "textfieldcustomclasspath";
    public static final String TEXTAREA_CUSTOMPROPERTIES = "textareacustomproperties";
    
    public static final String TEXTFIELD_LDAPHOSTNAME          = "textfieldldaphostname";
    public static final String TEXTFIELD_LDAPPORT              = "textfieldldapport";
    public static final String TEXTFIELD_LDAPBASEDN            = "textfieldldapbasedn";
    public static final String TEXTFIELD_LDAPLOGINDN           = "textfieldldaplogindn";
    public static final String TEXTFIELD_LDAPUSEROBJECTCLASS   = "textfieldldapuserobjectclass";
    public static final String TEXTFIELD_LDAPCAOBJECTCLASS     = "textfieldldapcaobjectclass";
    public static final String TEXTFIELD_LDAPUSERCERTATTRIBUTE = "textfieldldapusercertattribute";
    public static final String TEXTFIELD_LDAPCACERTATTRIBUTE   = "textfieldldapcacertattribute";
    public static final String TEXTFIELD_LDAPCRLATTRIBUTE      = "textfieldldapcrlattribute";
    public static final String TEXTFIELD_LDAPARLATTRIBUTE      = "textfieldldaparlattribute";
    public static final String PASSWORD_LDAPLOGINPASSWORD      = "textfieldldaploginpassword";
    public static final String PASSWORD_LDAPCONFIRMLOGINPWD    = "textfieldldaploginconfirmpwd";        
    public static final String CHECKBOX_LDAPUSESSL             = "checkboxldapusessl";
    public static final String CHECKBOX_LDAPCREATENONEXISTING  = "checkboxldapcreatenonexisting";
    public static final String CHECKBOX_LDAPMODIFYEXISTING     = "checkboxldapmodifyexisting";    
    public static final String SELECT_LDAPUSEFIELDINLDAPDN     = "selectldapusefieldsinldapdn";
    
    public static final String CHECKBOX_ADUSEPASSWORD          = "checkboxadusepassword";    
    public static final String SELECT_ADUSERACCOUNTCONTROL     = "selectaduseraccountcontrol";
    public static final String SELECT_ADSAMACCOUNTNAME         = "selectsamaccountname";
    public static final String TEXTFIELD_ADUSERDESCRIPTION     = "textfieldaduserdescription";
    
    public static final String PAGE_PUBLISHER                  = "publisherpage.jspf";
    public static final String PAGE_PUBLISHERS                 = "publisherspage.jspf";
    
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
            initialized = true;
            issuperadministrator = false;
            try{
                issuperadministrator = ejbcawebbean.isAuthorizedNoLog(AvailableAccessRules.ROLE_SUPERADMINISTRATOR);
            }catch(AuthorizationDeniedException ade){}
        }
    }
    
    public String parseRequest(HttpServletRequest request) throws AuthorizationDeniedException{
        String includefile = PAGE_PUBLISHERS; 
        String publisher = null;
        PublisherDataHandler handler  = cabean.getPublisherDataHandler();
        String action = null;
        
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
                            publisherdeletefailed = handler.removePublisher(publisher);          
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
                                publisherexists=true;
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
                                publisherexists=true;
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
                
                if(publisher != null){
                    if(!publisher.trim().equals("")){
                        if(request.getParameter(BUTTON_SAVE) != null ||
                                request.getParameter(BUTTON_TESTCONNECTION) != null){
                            
                            if(publisherdata == null){               
                                String tokentype = request.getParameter(HIDDEN_PUBLISHERTYPE);
                                if(tokentype.equals(TYPE_CUSTOM))
                                    publisherdata = new CustomPublisherContainer();
                                if(tokentype.equals(TYPE_LDAP))
                                    publisherdata = new LdapPublisher();
                                if(tokentype.equals(TYPE_AD))
                                    publisherdata = new ActiveDirectoryPublisher();
                            }
                            // Save changes.
                            
                            // General settings   
                            String value = request.getParameter(TEXTAREA_DESCRIPTION);
                            if(value != null){                              
                                value = value.trim();
                                publisherdata.setDescription(value); 
                            }
                            
                            
                            if(publisherdata instanceof CustomPublisherContainer){
                                value = request.getParameter(TEXTFIELD_CUSTOMCLASSPATH);
                                if(value != null){                              
                                    value = value.trim();
                                    ((CustomPublisherContainer) publisherdata).setClassPath(value); 
                                }
                                value = request.getParameter(TEXTAREA_CUSTOMPROPERTIES);
                                if(value != null){                              
                                    value = value.trim();
                                    ((CustomPublisherContainer) publisherdata).setPropertyData(value); 
                                }				   
                            }
                            
                            if(publisherdata instanceof LdapPublisher){
                                LdapPublisher ldappublisher = (LdapPublisher) publisherdata;
                                
                                value = request.getParameter(TEXTFIELD_LDAPHOSTNAME);
                                if(value != null){                              
                                    value = value.trim();
                                    ldappublisher.setHostname(value); 
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
                                    ldappublisher.setLoginPassword(value); 
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
                                value = request.getParameter(TEXTFIELD_LDAPARLATTRIBUTE);
                                if(value != null){                              
                                    value = value.trim();
                                    ldappublisher.setARLAttribute(value); 
                                }
                                value = request.getParameter(CHECKBOX_LDAPUSESSL);
                                if(value != null)                              
                                    ldappublisher.setUseSSL(value.equals(CHECKBOX_VALUE));
                                else
                                    ldappublisher.setUseSSL(false);
                                
                                value = request.getParameter(CHECKBOX_LDAPCREATENONEXISTING);
                                if(value != null)                              
                                    ldappublisher.setCreateNonExisingUsers(value.equals(CHECKBOX_VALUE));
                                else
                                    ldappublisher.setCreateNonExisingUsers(false);
                                
                                value = request.getParameter(CHECKBOX_LDAPMODIFYEXISTING);
                                if(value != null)                              
                                    ldappublisher.setModifyExistingUsers(value.equals(CHECKBOX_VALUE));
                                else
                                    ldappublisher.setModifyExistingUsers(false);
                                
                                
                                String[] values = request.getParameterValues(SELECT_LDAPUSEFIELDINLDAPDN);
                                if(values != null){
                                    ArrayList usefields = new ArrayList();
                                    for(int i=0;i< values.length;i++){
                                        usefields.add(new Integer(values[i]));	
                                    }
                                    
                                    ldappublisher.setUseFieldInLdapDN(usefields); 
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
                                if(value != null)                              
                                    adpublisher.setUseUserPassword(value.equals(CHECKBOX_VALUE));
                                else
                                    adpublisher.setUseUserPassword(false);
                                
                                value = request.getParameter(SELECT_ADUSERACCOUNTCONTROL);
                                if(value != null){                              
                                    value = value.trim();
                                    adpublisher.setUserAccountControl(Integer.parseInt(value)); 
                                }                                                          
                            }
                            
                            
                            if(request.getParameter(BUTTON_SAVE) != null){
                                handler.changePublisher(publisher,publisherdata);					
                                includefile=PAGE_PUBLISHERS;
                            }
                            if(request.getParameter(BUTTON_TESTCONNECTION)!= null){
                                connectionmessage = true;				 
                                handler.changePublisher(publisher,publisherdata);
                                try{
                                    handler.testConnection(publisher);
                                    connectionsuccessful = true;
                                }catch(PublisherConnectionException pce){
                                    connectionerrormessage = pce.getMessage();	
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
                    int profiletype = Integer.parseInt(value);
                    switch(profiletype){          
                    case CustomPublisherContainer.TYPE_CUSTOMPUBLISHERCONTAINER :
                        publisherdata = new CustomPublisherContainer();
                        break;
                    case LdapPublisher.TYPE_LDAPPUBLISHER :
                        publisherdata =  new LdapPublisher();				      
                        break;  		
                    case ActiveDirectoryPublisher.TYPE_ADPUBLISHER :
                        publisherdata =  new ActiveDirectoryPublisher();				      
                        break;  		
                    }   
                }
                
                includefile=PAGE_PUBLISHER;
            }						
        }    
        
        return includefile;	
    }
    
    public int getPublisherType(){    	
        int retval = CustomPublisherContainer.TYPE_CUSTOMPUBLISHERCONTAINER;
        
        if(publisherdata instanceof CustomPublisherContainer)
            retval = CustomPublisherContainer.TYPE_CUSTOMPUBLISHERCONTAINER;	
        
        if(publisherdata instanceof LdapPublisher)
            retval = LdapPublisher.TYPE_LDAPPUBLISHER;	
        
        if(publisherdata instanceof ActiveDirectoryPublisher)
            retval = ActiveDirectoryPublisher.TYPE_ADPUBLISHER;	  
        
        return retval;    	
    }
    
    
    // Private fields.
    private CAInterfaceBean cabean;
    private boolean initialized=false;
    public boolean  publisherexists       = false;
    public boolean  publisherdeletefailed = false;
    public boolean  connectionmessage = false;
    public boolean  connectionsuccessful = false;
    public String   connectionerrormessage = "";
    public boolean  issuperadministrator = false;    
    public BasePublisher publisherdata = null;
    public String publishername = null;
    
    
}
