<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ page pageEncoding="ISO-8859-1"%>
<% response.setContentType("text/html; charset="+org.ejbca.config.WebConfiguration.getWebContentEncoding()); %>
<%@page errorPage="/errorpage.jsp"  import="org.ejbca.ui.web.admin.configuration.EjbcaWebBean,org.ejbca.config.GlobalConfiguration, 
    org.ejbca.ui.web.RequestHelper,org.ejbca.core.model.ra.raadmin.AdminPreference,org.cesecore.certificates.certificatetransparency.CertificateTransparencyFactory,org.cesecore.certificates.certificatetransparency.CTLogInfo,org.ejbca.ui.web.HttpUpload,org.ejbca.ui.web.ParameterException, org.ejbca.ui.web.ParameterMap, org.cesecore.keys.util.KeyTools,
                org.ejbca.ui.web.admin.configuration.WebLanguages, org.ejbca.core.model.authorization.AccessRulesConstants, org.ejbca.core.model.InternalEjbcaResources, 
                java.util.Set, java.util.Arrays, java.util.Map, org.cesecore.authorization.control.StandardRules "%>

<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />

<%! // Declarations 

  static final String ACTION                                 = "action";
  static final String ACTION_NEXT_DEFAULT_PREFERENCES        = "actionnextdefaultpreferences";
  static final String ACTION_SAVE                            = "actionsave";
  static final String ACTION_CANCEL                          = "actioncancel";


  static final String BUTTON_NEXT                            = "buttonnext"; 
  static final String BUTTON_PREVIOUS                        = "buttonprevious"; 
  static final String BUTTON_SAVE                            = "buttonsave";
  static final String BUTTON_CANCEL                          = "buttoncancel";
  static final String BUTTON_NODES_ADD						 = "buttonnodesadd";
  static final String BUTTON_NODES_REMOVE					 = "buttonnodesremove";
  static final String BUTTON_CLEAR_ALL_CACHES				 = "buttonclearallcaches";

// Textfields used in webconfiguration.jsp
  static final String TEXTFIELD_TITLE                        = "textfieldtitle";
  static final String TEXTFIELD_HEADBANNER                   = "textfieldheadbanner";
  static final String TEXTFIELD_FOOTBANNER                   = "textfieldfootbanner";

  static final String TEXTFIELD_APPROVALADMINEMAILADDRESS    = "textfieldapprovaladminemailaddress";
  static final String TEXTFIELD_APPROVALNOTIFICATIONFROMADDR = "textfieldapprovalnoificationfromaddr";  
  
  static final String TEXTFIELD_AUTOENROLL_ADSERVER          = "textfieldautoenrolladserver";
  static final String TEXTFIELD_AUTOENROLL_ADPORT            = "textfieldautoenrolladport";
  static final String TEXTFIELD_AUTOENROLL_BASEDN_USER       = "textfieldautoenrollbasednuser";
  static final String TEXTFIELD_AUTOENROLL_CONNECTIONDN      = "textfieldautoenrollconnectiondn";
  static final String TEXTFIELD_AUTOENROLL_CONNECTIONPWD     = "textfieldautoenrollconnectionpwd";
  
  static final String TEXTFIELD_NODES_ADD					 = "textfieldnodesadd";
  static final String LIST_NODES							 = "listnodes";

  static final String CHECKBOX_ENABLEEEPROFILELIMITATIONS    = "checkboxendentityprofilelimitations"; 
  static final String CHECKBOX_ENABLEAUTHENTICATEDUSERSONLY  = "checkboxauthenticatedusersonly"; 
  static final String CHECKBOX_ENABLEKEYRECOVERY             = "checkboxenablekeyrecovery";
  static final String CHECKBOX_ISSUEHARDWARETOKENS           = "checkboxissuehardwaretokens";
  static final String CHECKBOX_APPROVALUSEEMAILNOTIFICATIONS = "checkboxapprovaluseemailnotifications";
  static final String CHECKBOX_AUTOENROLL_SSLCONNECTION      = "checkboxautoenrollsslconnection";
  static final String CHECKBOX_AUTOENROLL_USE                = "checkboxautoenrolluse";
  static final String CHECKBOX_ENABLECOMMANDLINEINTERFACE	 = "checkboxenablecommandlineinterface";
  static final String CHECKBOX_ENABLECLIDEFAULTUSER			 = "checkboxenableclidefaultuser";
  static final String CHECKBOX_CLEARCACHES_EXCLUDE_CRYPTOTOKEN  = "checkboxclearcachesexcludecryptotokencache";
  
  static final String TEXTFIELD_CTLOG_URL                    = "textfieldctlogurl";
  static final String FILE_CTLOG_PUBLICKEY                   = "filectlogpublickey";
  static final String TEXTFIELD_CTLOG_TIMEOUT                = "textfieldctlogtimeout";
  static final String CHECKBOX_CTLOG_REMOVE                  = "checkboxctlogremove";
  static final String BUTTON_CTLOG_UPDATE                    = "buttonctlogupdate";
  

// Lists used in defaultuserprefereces.jsp
  static final String LIST_PREFEREDLANGUAGE                  = "listpreferedlanguage";
  static final String LIST_SECONDARYLANGUAGE                 = "listsecondarylanguage";
  static final String LIST_THEME                             = "listtheme";
  static final String LIST_ENTIESPERPAGE                     = "listentriesperpage";

  static final String LIST_VIEWPUKREQUIREDAPPROVALS          = "viewpukrequiredapprovals";  
  static final String LIST_HARDTOKENENCRYPTCA                = "hardtokenencryptca";  
  static final String LIST_AUTOENROLL_CA                     = "listautoenrollcaname";
  

  static final String CHECKBOX_VALUE             = "true";
%> 
<% 
  // Initialize environment.
  final String THIS_FILENAME                          =  "configuration.jsp";

  GlobalConfiguration gc = ejbcawebbean.initialize(request, AccessRulesConstants.ROLE_ADMINISTRATOR, StandardRules.REGULAR_EDITSYSTEMCONFIGURATION.resource()); 
  AdminPreference dup = ejbcawebbean.getDefaultAdminPreference();

  String forwardurl = "/" + gc.getMainFilename(); 

  RequestHelper.setDefaultCharacterEncoding(request);
  HttpUpload upload = new HttpUpload(request, new String[] { FILE_CTLOG_PUBLICKEY }, 128*1024);
  ParameterMap params = upload.getParameterMap();
  Map<String,byte[]> files = upload.getFileMap();

  // Determine action 
  if (params.contains(BUTTON_CANCEL)) {
       // Cancel current values and go back to old ones.
       ejbcawebbean.reloadGlobalConfiguration ();
%> 
 <jsp:forward page="<%= forwardurl %>"/>
<%  }	%>


<%
     if (params.contains(BUTTON_SAVE)) {
        // Save global configuration.

        String[] languages = ejbcawebbean.getAvailableLanguages();
        if (params.contains(LIST_PREFEREDLANGUAGE)) {
          String preferedlanguage = params.getParameter(LIST_PREFEREDLANGUAGE); 
          dup.setPreferedLanguage(languages, preferedlanguage.trim());
        }
        if (params.contains(LIST_SECONDARYLANGUAGE)) {
          String secondarylanguage = params.getParameter(LIST_SECONDARYLANGUAGE); 
          dup.setSecondaryLanguage(languages, secondarylanguage.trim());
        }
        if (params.contains(LIST_THEME)) {
          String theme = params.getParameter(LIST_THEME); 
          dup.setTheme(theme.trim());
        }
        if (params.contains(LIST_ENTIESPERPAGE)) {
          String entriesperpage = params.getParameter(LIST_ENTIESPERPAGE); 
          dup.setEntriesPerPage(Integer.parseInt(entriesperpage.trim()));
        }

       // Change global configuration and proceed with default user preferences.
       if (params.contains(TEXTFIELD_TITLE)) {
         String title = params.getParameter(TEXTFIELD_TITLE); 
         gc.setEjbcaTitle(title);
       }
       if (params.contains(TEXTFIELD_HEADBANNER)) {
         String headbanner = params.getParameter(TEXTFIELD_HEADBANNER); 
         gc.setHeadBanner(headbanner);
       }
       if (params.contains(TEXTFIELD_FOOTBANNER)) {
         String footbanner = params.getParameter(TEXTFIELD_FOOTBANNER); 
         gc.setFootBanner(footbanner);
       }

       // Set boolean values from checkboxes where default is false
       gc.setEnableEndEntityProfileLimitations(CHECKBOX_VALUE.equals(params.getParameter(CHECKBOX_ENABLEEEPROFILELIMITATIONS)));
       gc.setEnableAuthenticatedUsersOnly(CHECKBOX_VALUE.equals(params.getParameter(CHECKBOX_ENABLEAUTHENTICATEDUSERSONLY)));
       gc.setEnableKeyRecovery(CHECKBOX_VALUE.equals(params.getParameter(CHECKBOX_ENABLEKEYRECOVERY)));
       gc.setIssueHardwareTokens(CHECKBOX_VALUE.equals(params.getParameter(CHECKBOX_ISSUEHARDWARETOKENS)));
       gc.setEnableCommandLineInterface(CHECKBOX_VALUE.equals(params.getParameter(CHECKBOX_ENABLECOMMANDLINEINTERFACE)));
       gc.setEnableCommandLineInterfaceDefaultUser(CHECKBOX_VALUE.equals(params.getParameter(CHECKBOX_ENABLECLIDEFAULTUSER)));

       if (params.contains(CHECKBOX_APPROVALUSEEMAILNOTIFICATIONS) && params.getParameter(CHECKBOX_APPROVALUSEEMAILNOTIFICATIONS).equals(CHECKBOX_VALUE)){
    	   gc.setUseApprovalNotifications(true);
    	   if (params.contains(TEXTFIELD_APPROVALADMINEMAILADDRESS)) {
    		   gc.setApprovalAdminEmailAddress(params.getParameter(TEXTFIELD_APPROVALADMINEMAILADDRESS).trim());  
    	   }
    	   if (params.contains(TEXTFIELD_APPROVALNOTIFICATIONFROMADDR)) {
    		  gc.setApprovalNotificationFromAddress(params.getParameter(TEXTFIELD_APPROVALNOTIFICATIONFROMADDR)); 
    	   }
       }else{
         gc.setUseApprovalNotifications(false);
         gc.setApprovalAdminEmailAddress("");
  	     gc.setApprovalNotificationFromAddress(""); 
       }
       
       if (params.contains(LIST_VIEWPUKREQUIREDAPPROVALS)) {
    	   gc.setNumberOfApprovalsToViewPUK(Integer.parseInt(params.getParameter(LIST_VIEWPUKREQUIREDAPPROVALS)));    	   
       }else{
    	   gc.setNumberOfApprovalsToViewPUK(0);
       }
       
       if (params.contains(LIST_HARDTOKENENCRYPTCA)) {
    	   gc.setHardTokenEncryptCA(Integer.parseInt(params.getParameter(LIST_HARDTOKENENCRYPTCA)));    	   
       }else{
    	   gc.setHardTokenEncryptCA(0);
       }
       // Parse Auto Enrollment fields
       if (params.contains(CHECKBOX_AUTOENROLL_USE)) {
		   gc.setAutoEnrollUse(params.getParameter(CHECKBOX_AUTOENROLL_USE).equals(CHECKBOX_VALUE));
		   if (params.contains(LIST_AUTOENROLL_CA)) {
	    	   gc.setAutoEnrollCA(Integer.parseInt(params.getParameter(LIST_AUTOENROLL_CA)));
	       }else{
	    	   gc.setAutoEnrollCA(GlobalConfiguration.AUTOENROLL_DEFAULT_CA);
	       }
	       if (params.contains(CHECKBOX_AUTOENROLL_SSLCONNECTION)) {
	         gc.setAutoEnrollSSLConnection(params.getParameter(CHECKBOX_AUTOENROLL_SSLCONNECTION).equals(CHECKBOX_VALUE));
	       } else {
	         gc.setAutoEnrollSSLConnection(false);
	       }
	       if (params.contains(TEXTFIELD_AUTOENROLL_ADSERVER)) {
	         gc.setAutoEnrollADServer(params.getParameter(TEXTFIELD_AUTOENROLL_ADSERVER));
	       }
	       if (params.contains(TEXTFIELD_AUTOENROLL_ADPORT)) {
	         gc.setAutoEnrollADPort(Integer.parseInt(params.getParameter(TEXTFIELD_AUTOENROLL_ADPORT)));
	       }
	       if (params.contains(TEXTFIELD_AUTOENROLL_CONNECTIONDN)) {
	         gc.setAutoEnrollConnectionDN(params.getParameter(TEXTFIELD_AUTOENROLL_CONNECTIONDN));
	       }
	       if (params.contains(TEXTFIELD_AUTOENROLL_CONNECTIONPWD)) {
	         String str = params.getParameter(TEXTFIELD_AUTOENROLL_CONNECTIONPWD);
	         if ( (str != null) && (str.length() > 0) ) {
	           gc.setAutoEnrollConnectionPwd(str);
	         }
	       }
	       if (params.contains(TEXTFIELD_AUTOENROLL_BASEDN_USER)) {
	         gc.setAutoEnrollBaseDNUser(params.getParameter(TEXTFIELD_AUTOENROLL_BASEDN_USER));
	       }
       } else {
           gc.setAutoEnrollUse(false);
       }

        ejbcawebbean.saveGlobalConfiguration();
        ejbcawebbean.saveDefaultAdminPreference(dup);
     } else if (params.contains(BUTTON_NODES_ADD)) {
     	final String newNode = params.getParameter(TEXTFIELD_NODES_ADD);
     	if (newNode != null && newNode.length() > 0) {
     		final Set/*String*/ nodes = gc.getNodesInCluster();
     		nodes.add(newNode);
     		gc.setNodesInCluster(nodes);
     		ejbcawebbean.saveGlobalConfiguration();
     	}
     
     } else if (params.contains(BUTTON_NODES_REMOVE)) {
     	final String[] removeNodes = params.getParameterValues(LIST_NODES);
     	if (removeNodes != null && removeNodes.length > 0) {
     		final Set/*String*/ nodes = gc.getNodesInCluster();
     		nodes.removeAll(Arrays.asList(removeNodes));
     		gc.setNodesInCluster(nodes);
     		ejbcawebbean.saveGlobalConfiguration();
     	}
     } else if (params.contains(BUTTON_CTLOG_UPDATE)) {
        // Check for logs to update. The parameters names end with the log id
        for (CTLogInfo log : gc.getCTLogs().values()) {
            String timeoutParam = params.getParameter(TEXTFIELD_CTLOG_TIMEOUT + log.getLogId());
            if (timeoutParam != null) {
                log.setTimeout(Integer.valueOf(timeoutParam));
            }
        }
        
        // Check for logs to remove
        final String[] removeList = params.getParameterValues(CHECKBOX_CTLOG_REMOVE);
        if (removeList != null) {
            for (String remove : removeList) {
                gc.removeCTLog(Integer.valueOf(remove));
            }
        }
        
        // Check for log to add
        String url = params.getParameter(TEXTFIELD_CTLOG_URL);
        final byte[] file = files.get(FILE_CTLOG_PUBLICKEY);
        if (file != null && !url.isEmpty()) {
            byte[] asn1bytes = KeyTools.getBytesFromPublicKeyFile(file);
            if (!url.endsWith("/")) {
                url = url+"/";
            }
            final CTLogInfo loginfo = new CTLogInfo(url, asn1bytes);
            if (loginfo.getLogPublicKey() == null) {
                throw new ParameterException(ejbcawebbean.getText("CTLOGINVALIDPUBLICKEY"));
            }
            loginfo.setTimeout(Integer.valueOf(params.getParameter(TEXTFIELD_CTLOG_TIMEOUT)));
            gc.addCTLog(loginfo);
        } else if (file != null || !url.isEmpty()) {
            throw new ParameterException(ejbcawebbean.getText("CTLOGNOTFILLEDIN"));
        }
        
        ejbcawebbean.saveGlobalConfiguration();
     } else if (params.contains(BUTTON_CLEAR_ALL_CACHES)) {
    	 boolean exclude_ctokens = CHECKBOX_VALUE.equals(params.getParameter(CHECKBOX_CLEARCACHES_EXCLUDE_CRYPTOTOKEN));
    	 ejbcawebbean.clearClusterCache(exclude_ctokens);
     }

     if (!params.contains(BUTTON_SAVE) &&
         !params.contains(BUTTON_NEXT) &&
         !params.contains(BUTTON_CANCEL) &&
         !params.contains(BUTTON_PREVIOUS)) {
 
      // get current global configuration.
        ejbcawebbean.reloadGlobalConfiguration();
     }
      %>

       <%@ include file="webconfiguration.jspf" %>
       <%@ include file="defaultuserpreferences.jspf" %>
