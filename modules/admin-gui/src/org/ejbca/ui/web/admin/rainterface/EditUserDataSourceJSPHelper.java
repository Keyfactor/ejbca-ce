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

package org.ejbca.ui.web.admin.rainterface;

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeMap;

import javax.servlet.http.HttpServletRequest;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.util.DNFieldExtractor;
import org.ejbca.core.ejb.ra.userdatasource.UserDataSourceSession;
import org.ejbca.core.model.ra.userdatasource.BaseUserDataSource;
import org.ejbca.core.model.ra.userdatasource.CustomUserDataSourceContainer;
import org.ejbca.core.model.ra.userdatasource.UserDataSourceConnectionException;
import org.ejbca.core.model.ra.userdatasource.UserDataSourceExistsException;
import org.ejbca.core.model.ra.userdatasource.UserDataSourceVO;
import org.ejbca.ui.web.RequestHelper;
import org.ejbca.ui.web.admin.configuration.EjbcaWebBean;


/**
 * Contains help methods used to parse a edit user data source jsp page requests.
 *
 * @author  Philip Vendil
 * @version $Id$
 */
public class EditUserDataSourceJSPHelper implements java.io.Serializable {

    /**
     * Determines if a de-serialized file is compatible with this class.
     *
     * Maintainers must change this value if and only if the new version
     * of this class is not compatible with old versions. See Sun docs
     * for <a href=http://java.sun.com/products/jdk/1.1/docs/guide
     * /serialization/spec/version.doc.html> details. </a>
     *
     */
	private static final long serialVersionUID = 436830207093078432L;
	
    public static final String ACTION                                  = "action";
    public static final String ACTION_EDIT_USERDATASOURCES             = "edituserdatasources";
    public static final String ACTION_EDIT_USERDATASOURCE              = "edituserdatasource";

    public static final String ACTION_CHANGE_USERDATASOURCETYPE        = "changeuserdatasourcetype";


    public static final String CHECKBOX_VALUE                          = BaseUserDataSource.TRUE;

//  Used in userdatasources.jsp
    public static final String BUTTON_EDIT_USERDATASOURCE              = "buttonedituserdatasource";
    public static final String BUTTON_DELETE_USERDATASOURCE            = "buttondeleteuserdatasource";
    public static final String BUTTON_ADD_USERDATASOURCE               = "buttonadduserdatasource";
    public static final String BUTTON_RENAME_USERDATASOURCE            = "buttonrenameuserdatasource";
    public static final String BUTTON_CLONE_USERDATASOURCE             = "buttoncloneuserdatasource";

    public static final String SELECT_USERDATASOURCE                   = "selectuserdatasource";
    public static final String TEXTFIELD_USERDATASOURCENAME            = "textfielduserdatasourcename";
    public static final String HIDDEN_USERDATASOURCENAME               = "hiddenuserdatasourcename";

//  Buttons used in userdatasource.jsp
    public static final String BUTTON_TESTCONNECTION    = "buttontestconnection";
    public static final String BUTTON_SAVE              = "buttonsave";
    public static final String BUTTON_CANCEL            = "buttoncancel";

    public static final String TYPE_CUSTOM              = "typecustom";

    public static final String HIDDEN_USERDATASOURCETYPE      = "hiddenuserdatasourcetype";
    public static final String SELECT_USERDATASOURCETYPE      = "selectuserdatasourcetype";

    public static final String SELECT_APPLICABLECAS           = "selectapplicablecas";
    public static final String SELECT_MODIFYABLEFIELDS        = "selectmodifyablefields";
    public static final String TEXTAREA_DESCRIPTION           = "textareadescription";

    public static final String TEXTFIELD_CUSTOMCLASSPATH = "textfieldcustomclasspath";
    public static final String TEXTAREA_CUSTOMPROPERTIES = "textareacustomproperties";

    public static final String PAGE_USERDATASOURCE                  = "userdatasourcepage.jspf";
    public static final String PAGE_USERDATASOURCES                 = "userdatasourcespage.jspf";

    public boolean  userdatasourceexists       = false;
    public boolean  userdatasourcedeletefailed = false;
    public boolean  connectionmessage = false;
    public boolean  connectionsuccessful = false;
    public String   connectionerrormessage = "";
    public boolean  issuperadministrator = false;
    public BaseUserDataSource userdatasourcedata = null;
    public String userdatasourcename = null;
    
    private boolean initialized=false;
    private TreeMap<String, Integer> modifyableFieldTexts = null;
    private UserDataSourceSession userdatasourcesession = null;
    private AuthenticationToken admin = null;
    private EjbcaWebBean ejbcawebbean = null;



    /** Creates new LogInterfaceBean */
    public EditUserDataSourceJSPHelper(){
    }
    // Public methods.
    /**
     * Method that initialized the bean.
     *
     * @param request is a reference to the http request.
     */
    public void initialize(HttpServletRequest request, EjbcaWebBean ejbcawebbean,
            RAInterfaceBean rabean) throws  Exception{

        if(!initialized){
            initialized = true;
            userdatasourcesession = rabean.getUserDataSourceSession();
            issuperadministrator = false;
            admin = ejbcawebbean.getAdminObject();
            this.ejbcawebbean = ejbcawebbean;
            try{
                issuperadministrator = ejbcawebbean.isAuthorizedNoLog(StandardRules.ROLE_ROOT.resource());
            }catch(AuthorizationDeniedException ade){}
        }
    }

    public String parseRequest(HttpServletRequest request) throws AuthorizationDeniedException{
        String includefile = PAGE_USERDATASOURCES;
        String userdatasource = null;        
        String action = null;

        try {
            RequestHelper.setDefaultCharacterEncoding(request);
        } catch (UnsupportedEncodingException e1) {
            // itgnore
        }
        action = request.getParameter(ACTION);
        if( action != null){
            if( action.equals(ACTION_EDIT_USERDATASOURCES)){
                if( request.getParameter(BUTTON_EDIT_USERDATASOURCE) != null){
                    userdatasource = request.getParameter(SELECT_USERDATASOURCE);
                    if(userdatasource != null){
                        if(!userdatasource.trim().equals("")){
                            includefile=PAGE_USERDATASOURCE;
                            this.userdatasourcename = userdatasource;
                            this.userdatasourcedata = userdatasourcesession.getUserDataSource(admin,userdatasourcename);
                        }
                        else{
                            userdatasource= null;
                        }
                    }
                    if(userdatasource == null){
                        includefile=PAGE_USERDATASOURCES;
                    }
                }
                if( request.getParameter(BUTTON_DELETE_USERDATASOURCE) != null) {
                    userdatasource = request.getParameter(SELECT_USERDATASOURCE);
                    if(userdatasource != null){
                        if(!userdatasource.trim().equals("")){
                            userdatasourcedeletefailed = !userdatasourcesession.removeUserDataSource(admin,userdatasource);
                            ejbcawebbean.getInformationMemory().userDataSourceEdited();
                        }
                    }
                    includefile=PAGE_USERDATASOURCES;
                }
                if( request.getParameter(BUTTON_RENAME_USERDATASOURCE) != null){
                    // Rename selected userdatasource and display profilespage.
                    String newuserdatasourcename = request.getParameter(TEXTFIELD_USERDATASOURCENAME);
                    String olduserdatasourcename = request.getParameter(SELECT_USERDATASOURCE);
                    if(olduserdatasourcename != null && newuserdatasourcename != null){
                        if(!newuserdatasourcename.trim().equals("") && !olduserdatasourcename.trim().equals("")){
                            try{
                            	userdatasourcesession.renameUserDataSource(admin,olduserdatasourcename.trim(),newuserdatasourcename.trim());
                            	ejbcawebbean.getInformationMemory().userDataSourceEdited();
                            }catch( UserDataSourceExistsException e){
                                userdatasourceexists=true;
                            }
                        }
                    }
                    includefile=PAGE_USERDATASOURCES;
                }
                if( request.getParameter(BUTTON_ADD_USERDATASOURCE) != null){
                    userdatasource = request.getParameter(TEXTFIELD_USERDATASOURCENAME);
                    if(userdatasource != null){
                        if(!userdatasource.trim().equals("")){
                            try{
                            	userdatasourcesession.addUserDataSource(admin,userdatasource.trim(), new CustomUserDataSourceContainer());
                            	ejbcawebbean.getInformationMemory().userDataSourceEdited();
                            }catch( UserDataSourceExistsException e){
                                userdatasourceexists=true;
                            }
                        }
                    }
                    includefile=PAGE_USERDATASOURCES;
                }
                if( request.getParameter(BUTTON_CLONE_USERDATASOURCE) != null){
                    String newuserdatasourcename = request.getParameter(TEXTFIELD_USERDATASOURCENAME);
                    String olduserdatasourcename = request.getParameter(SELECT_USERDATASOURCE);
                    if(olduserdatasourcename != null && newuserdatasourcename != null){
                    	if(!newuserdatasourcename.trim().equals("") && !olduserdatasourcename.trim().equals("")){
                    		try{
                    			userdatasourcesession.cloneUserDataSource(admin,olduserdatasourcename.trim(),newuserdatasourcename.trim());
                    			ejbcawebbean.getInformationMemory().userDataSourceEdited();
                    		}catch( UserDataSourceExistsException e){
                    			userdatasourceexists=true;
                    		}
                    	}
                    }
                    includefile=PAGE_USERDATASOURCES;
                }
            }
            if( action.equals(ACTION_EDIT_USERDATASOURCE)){
                // Display edit access rules page.
                userdatasource = request.getParameter(HIDDEN_USERDATASOURCENAME);
                this.userdatasourcename = userdatasource;
                if(userdatasource != null){
                    if(!userdatasource.trim().equals("")){
                        if(request.getParameter(BUTTON_SAVE) != null ||
                                request.getParameter(BUTTON_TESTCONNECTION) != null){

                            if(userdatasourcedata == null){
                                int tokentype = Integer.parseInt(request.getParameter(HIDDEN_USERDATASOURCETYPE));
                                if(tokentype == CustomUserDataSourceContainer.TYPE_CUSTOMUSERDATASOURCECONTAINER) {
                                    userdatasourcedata = new CustomUserDataSourceContainer();
                                }
                            }
                            // Save changes.

                            // General settings
                            String value = request.getParameter(TEXTAREA_DESCRIPTION);
                            if(value != null){
                                value = value.trim();
                                userdatasourcedata.setDescription(value);
                            }
                            
                            String[] values = request.getParameterValues(SELECT_MODIFYABLEFIELDS);
                            if(values != null){
                                Set<Integer> modifyablefields = new HashSet<Integer>();
                                for(int i=0;i< values.length;i++){
                                	modifyablefields.add(Integer.valueOf(values[i]));
                                }

                                userdatasourcedata.setModifiableFields(modifyablefields);
                            }else{
                            	userdatasourcedata.setModifiableFields(new HashSet<Integer>());
                            }

                            values = request.getParameterValues(SELECT_APPLICABLECAS);
                            if(values != null){
                                List<Integer> useCAs = new ArrayList<Integer>();
                                for(int i=0;i< values.length;i++){
                                	Integer caid = Integer.valueOf(values[i]);
                                	if(caid.intValue() == BaseUserDataSource.ANYCA){
                                		useCAs = new ArrayList<Integer>();
                                		useCAs.add(caid);
                                		break;
                                	}
                                	useCAs.add(Integer.valueOf(values[i]));
                                }

                                userdatasourcedata.setApplicableCAs(useCAs);
                            }else{
                            	userdatasourcedata.setApplicableCAs(new ArrayList<Integer>());
                            }
                            
                           


                            if(userdatasourcedata instanceof CustomUserDataSourceContainer){
                                value = request.getParameter(TEXTFIELD_CUSTOMCLASSPATH);
                                if(value != null){
                                    value = value.trim();
                                    ((CustomUserDataSourceContainer) userdatasourcedata).setClassPath(value);
                                }
                                value = request.getParameter(TEXTAREA_CUSTOMPROPERTIES);
                                if(value != null){
                                    value = value.trim();
                                    ((CustomUserDataSourceContainer) userdatasourcedata).setPropertyData(value);
                                }
                            }

                            if(request.getParameter(BUTTON_SAVE) != null){
                                userdatasourcesession.changeUserDataSource(admin,userdatasource,userdatasourcedata);
                                ejbcawebbean.getInformationMemory().userDataSourceEdited();
                                includefile=PAGE_USERDATASOURCES;
                            }
                            if(request.getParameter(BUTTON_TESTCONNECTION)!= null){
                                connectionmessage = true;
                                userdatasourcesession.changeUserDataSource(admin, userdatasource,userdatasourcedata);
                                try{
                                	int userdatasourceid = userdatasourcesession.getUserDataSourceId(admin,userdatasource);
                                	userdatasourcesession.testConnection(admin,userdatasourceid);
                                    connectionsuccessful = true;
                                }catch(UserDataSourceConnectionException pce){
                                    connectionerrormessage = pce.getMessage();
                                }
                                includefile=PAGE_USERDATASOURCE;
                            }

                        }
                        if(request.getParameter(BUTTON_CANCEL) != null){
                            // Don't save changes.
                            includefile=PAGE_USERDATASOURCES;
                        }

                    }
                }
            }

            if( action.equals(ACTION_CHANGE_USERDATASOURCETYPE)){
                this.userdatasourcename = request.getParameter(HIDDEN_USERDATASOURCENAME);
                String value = request.getParameter(SELECT_USERDATASOURCETYPE);
                if(value!=null){
                    int profiletype = Integer.parseInt(value);
                    switch(profiletype){
                    case CustomUserDataSourceContainer.TYPE_CUSTOMUSERDATASOURCECONTAINER :
                        userdatasourcedata = new CustomUserDataSourceContainer();
                        break;                    
                    }
                }

                includefile=PAGE_USERDATASOURCE;
            }
        }

        return includefile;
    }

    public int getUserDataSourceType(){
        int retval = CustomUserDataSourceContainer.TYPE_CUSTOMUSERDATASOURCECONTAINER;

        if(userdatasourcedata instanceof CustomUserDataSourceContainer) {
            retval = CustomUserDataSourceContainer.TYPE_CUSTOMUSERDATASOURCECONTAINER;
        }

        return retval;
    }

    
    public TreeMap<String, Integer> getAuthorizedUserDataSourceNames(){
    	TreeMap<String, Integer> retval = new TreeMap<String, Integer>();
    	
    	Collection<Integer> authorizedsources = userdatasourcesession.getAuthorizedUserDataSourceIds(admin,false);
        for(Integer id : authorizedsources) {
    		retval.put(userdatasourcesession.getUserDataSourceName(admin,id.intValue()),id);
    	}  	
    	
    	return retval;
    }
    
    public TreeMap<String, Integer> getModifyableFieldTexts(){
    	if(modifyableFieldTexts ==null){
    		modifyableFieldTexts = new TreeMap<String, Integer>();
    		
    		String subjectdntext = ejbcawebbean.getText("CERT_SUBJECTDN");
    		String subjectaltnametext = ejbcawebbean.getText("EXT_ABBR_SUBJECTALTNAME");
    		String subjectdirattrtext = ejbcawebbean.getText("EXT_ABBR_SUBJECTDIRATTRS");
    		
    		modifyableFieldTexts.put(subjectdntext + " : " +  ejbcawebbean.getText("DN_PKIX_UID"),Integer.valueOf(DNFieldExtractor.UID));  
    		modifyableFieldTexts.put(subjectdntext + " : " +  ejbcawebbean.getText("DN_PKIX_COMMONNAME"),Integer.valueOf(DNFieldExtractor.CN));  
    		modifyableFieldTexts.put(subjectdntext + " : " +  ejbcawebbean.getText("DN_PKIX_SERIALNUMBER"), Integer.valueOf(DNFieldExtractor.SN)); 
    		modifyableFieldTexts.put(subjectdntext + " : " +  ejbcawebbean.getText("DN_PKIX_GIVENNAME"),Integer.valueOf(DNFieldExtractor.GIVENNAME)); 
    		modifyableFieldTexts.put(subjectdntext + " : " +  ejbcawebbean.getText("DN_PKIX_INITIALS"), Integer.valueOf(DNFieldExtractor.INITIALS)); 
    		modifyableFieldTexts.put(subjectdntext + " : " +  ejbcawebbean.getText("DN_PKIX_SURNAME"), Integer.valueOf(DNFieldExtractor.SURNAME)); 
    		modifyableFieldTexts.put(subjectdntext + " : " +  ejbcawebbean.getText("DN_PKIX_TITLE"), Integer.valueOf(DNFieldExtractor.T));
    		modifyableFieldTexts.put(subjectdntext + " : " +  ejbcawebbean.getText("DN_PKIX_ORGANIZATIONALUNIT"), Integer.valueOf(DNFieldExtractor.OU));
    		modifyableFieldTexts.put(subjectdntext + " : " +  ejbcawebbean.getText("DN_PKIX_ORGANIZATION"), Integer.valueOf(DNFieldExtractor.O));
    		modifyableFieldTexts.put(subjectdntext + " : " +  ejbcawebbean.getText("DN_PKIX_LOCALITY"), Integer.valueOf(DNFieldExtractor.L));
    		modifyableFieldTexts.put(subjectdntext + " : " +  ejbcawebbean.getText("DN_PKIX_STATEORPROVINCE"), Integer.valueOf(DNFieldExtractor.ST));
    		modifyableFieldTexts.put(subjectdntext + " : " +  ejbcawebbean.getText("DN_PKIX_DOMAINCOMPONENT"), Integer.valueOf(DNFieldExtractor.DC));
    		modifyableFieldTexts.put(subjectdntext + " : " +  ejbcawebbean.getText("DN_PKIX_COUNTRY"), Integer.valueOf(DNFieldExtractor.C));
    		modifyableFieldTexts.put(subjectdntext + " : " +  ejbcawebbean.getText("DN_PKIX_UNSTRUCTUREDADDRESS"), Integer.valueOf(DNFieldExtractor.UNSTRUCTUREDADDRESS));
    		modifyableFieldTexts.put(subjectdntext + " : " +  ejbcawebbean.getText("DN_PKIX_UNSTRUCTUREDNAME"), Integer.valueOf(DNFieldExtractor.UNSTRUCTUREDNAME));
    		    		
    		modifyableFieldTexts.put(subjectaltnametext + " : " +  ejbcawebbean.getText("ALT_PKIX_DNSNAME"), Integer.valueOf(DNFieldExtractor.DNSNAME));
    		modifyableFieldTexts.put(subjectaltnametext + " : " +  ejbcawebbean.getText("ALT_PKIX_IPADDRESS"), Integer.valueOf(DNFieldExtractor.IPADDRESS));
    		modifyableFieldTexts.put(subjectaltnametext + " : " +  ejbcawebbean.getText("ALT_PKIX_DIRECTORYNAME"), Integer.valueOf(DNFieldExtractor.DIRECTORYNAME));
    		modifyableFieldTexts.put(subjectaltnametext + " : " +  ejbcawebbean.getText("ALT_PKIX_UNIFORMRESOURCEID"), Integer.valueOf(DNFieldExtractor.URI));
    		modifyableFieldTexts.put(subjectaltnametext + " : " +  ejbcawebbean.getText("ALT_MS_UPN"), Integer.valueOf(DNFieldExtractor.UPN));
    		modifyableFieldTexts.put(subjectaltnametext + " : " +  ejbcawebbean.getText("ALT_MS_GUID"), Integer.valueOf(DNFieldExtractor.GUID));
    		modifyableFieldTexts.put(subjectaltnametext + " : " +  ejbcawebbean.getText("ALT_KERBEROS_KPN"), Integer.valueOf(DNFieldExtractor.KRB5PRINCIPAL));
    		modifyableFieldTexts.put(subjectaltnametext + " : " +  ejbcawebbean.getText("ALT_PKIX_PERMANENTIDENTIFIER"), Integer.valueOf(DNFieldExtractor.PERMANTIDENTIFIER));
    	    
    		modifyableFieldTexts.put(subjectdirattrtext + " : " +  ejbcawebbean.getText("SDA_DATEOFBIRTH"), Integer.valueOf(DNFieldExtractor.DATEOFBIRTH));
    		modifyableFieldTexts.put(subjectdirattrtext + " : " +  ejbcawebbean.getText("SDA_PLACEOFBIRTH"),Integer.valueOf( DNFieldExtractor.PLACEOFBIRTH));
    		modifyableFieldTexts.put(subjectdirattrtext + " : " +  ejbcawebbean.getText("SDA_GENDER"),Integer.valueOf( DNFieldExtractor.GENDER));
    		modifyableFieldTexts.put(subjectdirattrtext + " : " +  ejbcawebbean.getText("SDA_COUNTRYOFCITIZENSHIP"),Integer.valueOf( DNFieldExtractor.COUNTRYOFCITIZENSHIP));
    		modifyableFieldTexts.put(subjectdirattrtext + " : " +  ejbcawebbean.getText("SDA_COUNTRYOFRESIDENCE"),Integer.valueOf( DNFieldExtractor.COUNTRYOFRESIDENCE));


    		modifyableFieldTexts.put(ejbcawebbean.getText("USERNAME"), Integer.valueOf(UserDataSourceVO.ISMODIFYABLE_USERNAME));
    		modifyableFieldTexts.put(ejbcawebbean.getText("PASSWORD"), Integer.valueOf(UserDataSourceVO.ISMODIFYABLE_PASSWORD));
    		modifyableFieldTexts.put(ejbcawebbean.getText("CA"), Integer.valueOf(UserDataSourceVO.ISMODIFYABLE_CAID));
    		modifyableFieldTexts.put(ejbcawebbean.getText("EMAIL"), Integer.valueOf(UserDataSourceVO.ISMODIFYABLE_EMAILDATA));
    		modifyableFieldTexts.put(ejbcawebbean.getText("PASSWORD"), Integer.valueOf(UserDataSourceVO.ISMODIFYABLE_TYPE));
    		modifyableFieldTexts.put(ejbcawebbean.getText("ENDENTITYPROFILE"), Integer.valueOf(UserDataSourceVO.ISMODIFYABLE_ENDENTITYPROFILE));
    		modifyableFieldTexts.put(ejbcawebbean.getText("CERTIFICATEPROFILE"), Integer.valueOf(UserDataSourceVO.ISMODIFYABLE_CERTIFICATEPROFILE));
    		modifyableFieldTexts.put(ejbcawebbean.getText("TOKEN"), Integer.valueOf(UserDataSourceVO.ISMODIFYABLE_TOKENTYPE));    		
    		modifyableFieldTexts.put(ejbcawebbean.getText("HARDTOKENISSUER"), Integer.valueOf(UserDataSourceVO.ISMODIFYABLE_HARDTOKENISSUER));    		
    	    		
    		
    	}
    	return modifyableFieldTexts;
    }

}
