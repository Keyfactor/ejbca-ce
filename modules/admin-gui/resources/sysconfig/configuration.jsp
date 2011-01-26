<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ page pageEncoding="ISO-8859-1"%>
<% response.setContentType("text/html; charset="+org.ejbca.config.WebConfiguration.getWebContentEncoding()); %>
<%@page errorPage="/errorpage.jsp"  import="org.ejbca.ui.web.admin.configuration.EjbcaWebBean,org.ejbca.core.model.ra.raadmin.GlobalConfiguration, 
    org.ejbca.ui.web.RequestHelper,org.ejbca.core.model.ra.raadmin.AdminPreference, org.ejbca.ui.web.admin.configuration.GlobalConfigurationDataHandler,
                org.ejbca.ui.web.admin.configuration.WebLanguages, org.ejbca.core.model.authorization.AccessRulesConstants, org.ejbca.core.model.InternalResources, 
                java.util.Set, java.util.Arrays "%>

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

  GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, AccessRulesConstants.REGULAR_EDITSYSTEMCONFIGURATION); 
  GlobalConfiguration gc = globalconfiguration;
  AdminPreference dup = ejbcawebbean.getDefaultAdminPreference();

  String forwardurl = "/" + globalconfiguration .getMainFilename(); 

  RequestHelper.setDefaultCharacterEncoding(request);

  // Determine action 
  if( request.getParameter(BUTTON_CANCEL) != null){
       // Cancel current values and go back to old ones.
       ejbcawebbean.reloadGlobalConfiguration ();
%> 
 <jsp:forward page="<%= forwardurl %>"/>
<%  }	%>


<%
     if( request.getParameter(BUTTON_SAVE) != null){
        // Save global configuration.

        String[] languages = ejbcawebbean.getAvailableLanguages();
        if(request.getParameter(LIST_PREFEREDLANGUAGE) != null){
          String preferedlanguage = request.getParameter(LIST_PREFEREDLANGUAGE); 
          dup.setPreferedLanguage(languages, preferedlanguage.trim());
        }
        if(request.getParameter(LIST_SECONDARYLANGUAGE) != null){
          String secondarylanguage = request.getParameter(LIST_SECONDARYLANGUAGE); 
          dup.setSecondaryLanguage(languages, secondarylanguage.trim());
        }
        if(request.getParameter(LIST_THEME) != null){
          String theme = request.getParameter(LIST_THEME); 
          dup.setTheme(theme.trim());
        }
        if(request.getParameter(LIST_ENTIESPERPAGE) != null){
          String entriesperpage = request.getParameter(LIST_ENTIESPERPAGE); 
          dup.setEntriesPerPage(Integer.parseInt(entriesperpage.trim()));
        }

       // Change global configuration and proceed with default user preferences.
      //GlobalConfiguration gc = ejbcawebbean.getGlobalConfiguration();
       if(request.getParameter(TEXTFIELD_TITLE) != null){
         String title = request.getParameter(TEXTFIELD_TITLE); 
         gc.setEjbcaTitle(title);
       }
       if(request.getParameter(TEXTFIELD_HEADBANNER) != null){
         String headbanner = request.getParameter(TEXTFIELD_HEADBANNER); 
         gc.setHeadBanner(headbanner);
       }
       if(request.getParameter(TEXTFIELD_FOOTBANNER) != null){
         String footbanner = request.getParameter(TEXTFIELD_FOOTBANNER); 
         gc.setFootBanner(footbanner);
       }
       if(request.getParameter(CHECKBOX_ENABLEEEPROFILELIMITATIONS) != null){
         gc.setEnableEndEntityProfileLimitations(request.getParameter(CHECKBOX_ENABLEEEPROFILELIMITATIONS).equals(CHECKBOX_VALUE));
       }
       else{
         gc.setEnableEndEntityProfileLimitations(false);
       }
       if(request.getParameter(CHECKBOX_ENABLEAUTHENTICATEDUSERSONLY) != null){
         gc.setEnableAuthenticatedUsersOnly(request.getParameter(CHECKBOX_ENABLEAUTHENTICATEDUSERSONLY).equals(CHECKBOX_VALUE));
       }
       else{
         gc.setEnableAuthenticatedUsersOnly(false);
       }
       if(request.getParameter(CHECKBOX_ENABLEKEYRECOVERY) != null){
         gc.setEnableKeyRecovery(request.getParameter(CHECKBOX_ENABLEKEYRECOVERY).equals(CHECKBOX_VALUE));
       }
       else{
         gc.setEnableKeyRecovery(false);
       }
       if(request.getParameter(CHECKBOX_ISSUEHARDWARETOKENS) != null){
         gc.setIssueHardwareTokens(request.getParameter(CHECKBOX_ISSUEHARDWARETOKENS).equals(CHECKBOX_VALUE));
       }
       else{
         gc.setIssueHardwareTokens(false);
       }

       if(request.getParameter(CHECKBOX_APPROVALUSEEMAILNOTIFICATIONS) != null && request.getParameter(CHECKBOX_APPROVALUSEEMAILNOTIFICATIONS).equals(CHECKBOX_VALUE)){
    	   gc.setUseApprovalNotifications(true);
    	   if(request.getParameter(TEXTFIELD_APPROVALADMINEMAILADDRESS) != null){
    		   gc.setApprovalAdminEmailAddress(request.getParameter(TEXTFIELD_APPROVALADMINEMAILADDRESS).trim());  
    	   }
    	   if(request.getParameter(TEXTFIELD_APPROVALNOTIFICATIONFROMADDR) != null){
    		  gc.setApprovalNotificationFromAddress(request.getParameter(TEXTFIELD_APPROVALNOTIFICATIONFROMADDR)); 
    	   }
       }else{
         gc.setUseApprovalNotifications(false);
         gc.setApprovalAdminEmailAddress("");
  	     gc.setApprovalNotificationFromAddress(""); 
       }
       
       if(request.getParameter(LIST_VIEWPUKREQUIREDAPPROVALS) != null ){
    	   gc.setNumberOfApprovalsToViewPUK(Integer.parseInt(request.getParameter(LIST_VIEWPUKREQUIREDAPPROVALS)));    	   
       }else{
    	   gc.setNumberOfApprovalsToViewPUK(0);
       }
       
       if(request.getParameter(LIST_HARDTOKENENCRYPTCA) != null ){
    	   gc.setHardTokenEncryptCA(Integer.parseInt(request.getParameter(LIST_HARDTOKENENCRYPTCA)));    	   
       }else{
    	   gc.setHardTokenEncryptCA(0);
       }
       // Parse Auto Enrollment fields
       if(request.getParameter(CHECKBOX_AUTOENROLL_USE) != null){
		   gc.setAutoEnrollUse(request.getParameter(CHECKBOX_AUTOENROLL_USE).equals(CHECKBOX_VALUE));
		   if(request.getParameter(LIST_AUTOENROLL_CA) != null ){
	    	   gc.setAutoEnrollCA(Integer.parseInt(request.getParameter(LIST_AUTOENROLL_CA)));
	       }else{
	    	   gc.setAutoEnrollCA(GlobalConfiguration.AUTOENROLL_DEFAULT_CA);
	       }
	       if(request.getParameter(CHECKBOX_AUTOENROLL_SSLCONNECTION) != null){
	         gc.setAutoEnrollSSLConnection(request.getParameter(CHECKBOX_AUTOENROLL_SSLCONNECTION).equals(CHECKBOX_VALUE));
	       } else {
	         gc.setAutoEnrollSSLConnection(false);
	       }
	       if(request.getParameter(TEXTFIELD_AUTOENROLL_ADSERVER) != null){
	         gc.setAutoEnrollADServer(request.getParameter(TEXTFIELD_AUTOENROLL_ADSERVER));
	       }
	       if(request.getParameter(TEXTFIELD_AUTOENROLL_ADPORT) != null){
	         gc.setAutoEnrollADPort(Integer.parseInt(request.getParameter(TEXTFIELD_AUTOENROLL_ADPORT)));
	       }
	       if(request.getParameter(TEXTFIELD_AUTOENROLL_CONNECTIONDN) != null){
	         gc.setAutoEnrollConnectionDN(request.getParameter(TEXTFIELD_AUTOENROLL_CONNECTIONDN));
	       }
	       if(request.getParameter(TEXTFIELD_AUTOENROLL_CONNECTIONPWD) != null){
	         gc.setAutoEnrollConnectionPwd(request.getParameter(TEXTFIELD_AUTOENROLL_CONNECTIONPWD));
	       }
	       if(request.getParameter(TEXTFIELD_AUTOENROLL_BASEDN_USER) != null){
	         gc.setAutoEnrollBaseDNUser(request.getParameter(TEXTFIELD_AUTOENROLL_BASEDN_USER));
	       }
       } else {
           gc.setAutoEnrollUse(false);
       }

        ejbcawebbean.saveGlobalConfiguration();
        ejbcawebbean.saveDefaultAdminPreference(dup);
     } else if (request.getParameter(BUTTON_NODES_ADD) != null) {
     	final String newNode = request.getParameter(TEXTFIELD_NODES_ADD);
     	if (newNode != null && newNode.length() > 0) {
     		final Set/*String*/ nodes = gc.getNodesInCluster();
     		nodes.add(newNode);
     		gc.setNodesInCluster(nodes);
     		ejbcawebbean.saveGlobalConfiguration();
     	}
     
     } else if (request.getParameter(BUTTON_NODES_REMOVE) != null) {
     	final String[] removeNodes = request.getParameterValues(LIST_NODES);
     	if (removeNodes != null && removeNodes.length > 0) {
     		final Set/*String*/ nodes = gc.getNodesInCluster();
     		nodes.removeAll(Arrays.asList(removeNodes));
     		gc.setNodesInCluster(nodes);
     		ejbcawebbean.saveGlobalConfiguration();
     	}
     } else if (request.getParameter(BUTTON_CLEAR_ALL_CACHES) != null) {
    	 ejbcawebbean.clearClusterCache();
     }

     if(request.getParameter(BUTTON_SAVE) == null &&
        request.getParameter(BUTTON_NEXT) == null &&
        request.getParameter(BUTTON_CANCEL) == null &&
        request.getParameter(BUTTON_PREVIOUS) == null){
 
      // get current global configuration.
        ejbcawebbean.reloadGlobalConfiguration();
     }
      %>

       <%@ include file="webconfiguration.jspf" %>
       <%@ include file="defaultuserpreferences.jspf" %>
