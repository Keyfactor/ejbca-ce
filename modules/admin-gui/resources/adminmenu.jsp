<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ page pageEncoding="ISO-8859-1"%>
<% response.setContentType("text/html; charset="+org.ejbca.config.WebConfiguration.getWebContentEncoding()); %>
<%@page errorPage="errorpage.jsp" import="
org.cesecore.authorization.AuthorizationDeniedException,
org.cesecore.authorization.control.AuditLogRules,
org.cesecore.authorization.control.CryptoTokenRules,
org.cesecore.authorization.control.StandardRules,
org.ejbca.config.GlobalConfiguration,
org.ejbca.core.model.authorization.AccessRulesConstants,
org.cesecore.keybind.InternalKeyBindingRules
"%>
<html>
<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />
<jsp:setProperty name="ejbcawebbean" property="*" /> 
<%
 	// A jsp page that generates the menu after the users access rights 
    // Initialize environment.
    GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, AccessRulesConstants.ROLE_ADMINISTRATOR); 
   
    final String THIS_FILENAME            =   globalconfiguration.getMenuFilename();

    final String MAIN_LINK                =   ejbcawebbean.getBaseUrl() + globalconfiguration.getAdminWebPath() +globalconfiguration.getMainFilename();

    final String APPROVAL_LINK            =   ejbcawebbean.getBaseUrl() + globalconfiguration.getAdminWebPath() + "approval/approveactionlist.jsf";
    
    final String EDITCA_LINK              =  ejbcawebbean.getBaseUrl() + globalconfiguration.getCaPath() 
                                                    + "/editcas/editcas.jsp";
    final String EDITPUBLISHERS_LINK      =  ejbcawebbean.getBaseUrl() + globalconfiguration.getCaPath() 
                                                    + "/editpublishers/editpublishers.jsp";

    final String CRYPTOTOKENS_LINK        =  ejbcawebbean.getBaseUrl() + globalconfiguration.getAdminWebPath() + "cryptotoken/cryptotokens.jsf";

    final String CA_LINK                  =  ejbcawebbean.getBaseUrl() + globalconfiguration.getCaPath() 
                                                    + "/cafunctions.jsp";
    
    final String CA_ACTIVATION_LINK		=  ejbcawebbean.getBaseUrl() + globalconfiguration.getCaPath() 
    												+ "/caactivation.jsf";
    
    final String CA_CERTIFICATEPROFILELINK  = ejbcawebbean.getBaseUrl() + globalconfiguration.getCaPath() 
                                                    + "/editcertificateprofiles/editcertificateprofiles.jsf";  
    final String RA_EDITUSERDATASOURCESLINK =  ejbcawebbean.getBaseUrl() + globalconfiguration.getRaPath()+"/edituserdatasources/edituserdatasources.jsp";
    final String RA_EDITPROFILESLINK      =  ejbcawebbean.getBaseUrl() + globalconfiguration.getRaPath()+"/editendentityprofiles/editendentityprofiles.jsp";
    final String RA_ADDENDENTITYLINK      =  ejbcawebbean.getBaseUrl() + globalconfiguration.getRaPath()+"/addendentity.jsp";
    final String RA_LISTENDENTITIESLINK   =  ejbcawebbean.getBaseUrl() + globalconfiguration.getRaPath()+"/listendentities.jsp";
    final String HT_EDITHARDTOKENISSUERS_LINK  =  ejbcawebbean.getBaseUrl() + globalconfiguration.getHardTokenPath() 
                                                    + "/edithardtokenissuers.jsp";
    final String HT_EDITHARDTOKENPROFILES_LINK  =  ejbcawebbean.getBaseUrl() + globalconfiguration.getHardTokenPath() 
                                                    + "/edithardtokenprofiles/edithardtokenprofiles.jsp";
    final String AUDIT_LINK                 =  ejbcawebbean.getBaseUrl() + globalconfiguration.getAdminWebPath() + "audit/search.jsf";
    final String LOG_CONFIGURATION_LINK   =  ejbcawebbean.getBaseUrl() + globalconfiguration.getLogPath() 
                                                    + "/logconfiguration/logconfiguration.jsp";
    final String CONFIGURATION_LINK       =  ejbcawebbean.getBaseUrl() + globalconfiguration.getConfigPath() 
                                                    + "/configuration.jsp";
    final String CMPCONFIGURATION_LINK    =  ejbcawebbean.getBaseUrl() + globalconfiguration.getConfigPath()
           											+ "/cmpconfiguration.jsp";
    
    final String INTERNALKEYBINDING_LINK  = ejbcawebbean.getBaseUrl() + globalconfiguration.getAdminWebPath() + "keybind/keybindings.jsf";
    final String SERVICES_LINK            = ejbcawebbean.getBaseUrl() + globalconfiguration.getAdminWebPath() + "services/listservices.jsf";
    final String PEERCONNECTOR_LINK       = ejbcawebbean.getBaseUrl() + globalconfiguration.getAdminWebPath() + "peerconnector/peerconnectors.jsf";
    
    final String ADMINISTRATORPRIV_LINK   =  ejbcawebbean.getBaseUrl() + globalconfiguration.getAuthorizationPath() 
                                                    + "/administratorprivileges.jsf";
    
    final String SCEPCONFIGURATION_LINK   =  ejbcawebbean.getBaseUrl() + globalconfiguration.getConfigPath() 
            										+ "/scepconfiguration.jsf";
    
	final String PUBLICWEB_LINK          = ejbcawebbean.getBaseUrl();
    
    final String MYPREFERENCES_LINK     =  ejbcawebbean.getBaseUrl() + globalconfiguration.getAdminWebPath() + "mypreferences.jsp";
    final String HELP_LINK                =  ejbcawebbean.getBaseUrl() + globalconfiguration.getAdminWebPath() + globalconfiguration.getHelpPath() 
                                                    + "/index_help.html";

    final String LOGOUT_LINK                =  ejbcawebbean.getBaseUrl() + globalconfiguration.getAdminWebPath() + "logout";


    final String MAIN_RESOURCE                          = AccessRulesConstants.ROLE_ADMINISTRATOR;
    final String CRYPTOTOKEN_RESOURCE                   = CryptoTokenRules.BASE.resource();
    final String CABASICFUNCTIONS_RESOURCE              = "/ca_functionality/basic_functions";
    final String ACTIVATECA_RESOURCE                    = "/ca_functionality/basic_functions/activate_ca";
    final String EDITCAS_RESOURCE                       = "/ca_functionality";
    final String EDITPUBLISHERS_RESOURCE                = "/ca_functionality";
    final String EDITCERTIFICATEPROFILES_RESOURCE       = "/ca_functionality/edit_certificate_profiles";
    final String RAEDITUSERDATASOURCES_RESOURCE         = AccessRulesConstants.REGULAR_EDITUSERDATASOURCES;
    final String RAEDITENDENTITYPROFILES_RESOURCE       = "/ra_functionality/edit_end_entity_profiles";
    final String RAADDENDENTITY_RESOURCE                = "/ra_functionality/create_end_entity";
    final String RALISTEDITENDENTITY_RESOURCE           = "/ra_functionality/view_end_entity";
    final String HTEDITHARDTOKENISSUERS_RESOURCE        = "/hardtoken_functionality/edit_hardtoken_issuers";
    final String HTEDITHARDTOKENPROFILES_RESOURCE       = "/hardtoken_functionality/edit_hardtoken_profiles";
    final String LOGVIEW_RESOURCE                       = AuditLogRules.VIEW.resource(); 
    final String SYSTEMCONFIGURATION_RESOURCE           = AccessRulesConstants.REGULAR_EDITSYSTEMCONFIGURATION;
    final String ADMINPRIVILEGES_RESOURCE               = "/system_functionality/edit_administrator_privileges";
    final String INTERNALKEYBINDING_RESOURCE            = InternalKeyBindingRules.BASE.resource();
    final String SERVICES_RESOURCE                      = StandardRules.ROLE_ROOT.resource();
    final String PEERCONNECTOR_RESOURCE_VIEW            = AccessRulesConstants.REGULAR_PEERCONNECTOR_VIEW;
 %>
<%  
  boolean caheaderprinted     =false;
  boolean reportsheaderprinted =false;
  boolean raheaderprinted     =false;
  boolean htheaderprinted     =false;
  boolean logheaderprinted    =false;
  boolean systemheaderprinted =false;
  boolean configheaderprinted = false;

%>
<head>
  <title><c:out value="<%= globalconfiguration.getEjbcaTitle() %>" /></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>" />
  <link rel="stylesheet" type="text/css" href="<%= ejbcawebbean.getCssFile() %>" />
  <!--[if IE]><link rel="stylesheet" type="text/css" href="<%= ejbcawebbean.getIeFixesCssFile() %>" /><![endif]-->
  <script type="text/javascript" src="<%= globalconfiguration.getAdminWebPath() %>ejbcajslib.js"></script>
</head>

<body id="menu">

	<div id="navigation">
	<ul>

<% // If authorized to use the main page then display related links.
   try{
     if(ejbcawebbean.isAuthorizedNoLog(MAIN_RESOURCE)){ %>
		<li id="cat0"><a href="<%=MAIN_LINK %>" target="<%=GlobalConfiguration.MAINFRAME %>"><%=ejbcawebbean.getText("NAV_HOME") %></a>
		</li>
<%    }
   }catch(AuthorizationDeniedException e){} 
%>
<%
   // --------------------------------------------------------------------------
   // CA FUNCTIONS
 %>
 <%
   try{
     if(ejbcawebbean.isAuthorizedNoLog(ACTIVATECA_RESOURCE)){ 
        if(!caheaderprinted){
          out.write("<li id=\"cat1\" class=\"section\"><strong>" + ejbcawebbean.getText("NAV_CAFUNCTIONS")+"</strong><ul>"); 
           caheaderprinted=true;
        } %>
				<li><a href="<%= CA_ACTIVATION_LINK %>" target="<%=GlobalConfiguration.MAINFRAME %>"><%=ejbcawebbean.getText("NAV_CAACTIVATION") %></a></li>
<%    }
   }catch(AuthorizationDeniedException e){} 
%>
<% 
   try{
     if(ejbcawebbean.isAuthorizedNoLog(CABASICFUNCTIONS_RESOURCE)){ 
         if(!caheaderprinted){
             out.write("<li id=\"cat1\" class=\"section\"><strong>" + ejbcawebbean.getText("NAV_CAFUNCTIONS")+"</strong><ul>"); 
              caheaderprinted=true;
           } %>
				<li><a href="<%= CA_LINK %>" target="<%=GlobalConfiguration.MAINFRAME %>"><%=ejbcawebbean.getText("NAV_CASTRUCTUREANDCRL") %></a></li>
<%    }
   }catch(AuthorizationDeniedException e){} 
%>
<%
   try{
     if(ejbcawebbean.isAuthorizedNoLog(EDITCERTIFICATEPROFILES_RESOURCE)){ 
        if(!caheaderprinted){
          out.write("<li id=\"cat1\" class=\"section\"><strong>" + ejbcawebbean.getText("NAV_CAFUNCTIONS")+"</strong><ul>"); 
           caheaderprinted=true;
        } %>
				<li><a href="<%= CA_CERTIFICATEPROFILELINK %>" target="<%=GlobalConfiguration.MAINFRAME %>"><%=ejbcawebbean.getText("NAV_CERTIFICATEPROFILES") %></a></li>
<%    }
   }catch(AuthorizationDeniedException e){} 
%>
<%
   try{
     if(ejbcawebbean.isAuthorizedNoLog(EDITCAS_RESOURCE)){ 
        if(!caheaderprinted){
          out.write("<li id=\"cat1\" class=\"section\"><strong>" + ejbcawebbean.getText("NAV_CAFUNCTIONS")+"</strong><ul>"); 
           caheaderprinted=true;
        } %>
				<li><a href="<%= EDITCA_LINK %>" target="<%=GlobalConfiguration.MAINFRAME %>"><%=ejbcawebbean.getText("NAV_CAS") %></a></li>     
<%    }
   }catch(AuthorizationDeniedException e){} 
%>
<% 
   // If authorized to use the ca then display related links.
   try{
     if(ejbcawebbean.isAuthorizedNoLog(CRYPTOTOKEN_RESOURCE)){ 
        if(!caheaderprinted){
          out.write("<li id=\"cat1\" class=\"section\"><strong>" + ejbcawebbean.getText("NAV_CAFUNCTIONS")+"</strong><ul>"); 
           caheaderprinted=true;
        } %>
				<li><a href="<%= CRYPTOTOKENS_LINK %>" target="<%=GlobalConfiguration.MAINFRAME %>"><%=ejbcawebbean.getText("NAV_CRYPTOTOKENS") %></a></li>
<%    }
   }catch(AuthorizationDeniedException e){} 
%>
<%
   try{
     if(ejbcawebbean.isAuthorizedNoLog(EDITPUBLISHERS_RESOURCE)){ 
        if(!caheaderprinted){
          out.write("<li id=\"cat1\" class=\"section\"><strong>" + ejbcawebbean.getText("NAV_CAFUNCTIONS")+"</strong><ul>"); 
           caheaderprinted=true;
        } %>
				<li><a href="<%= EDITPUBLISHERS_LINK %>" target="<%=GlobalConfiguration.MAINFRAME %>"><%=ejbcawebbean.getText("NAV_PUBLISHERS") %></a></li>
<%    }
   }catch(AuthorizationDeniedException e){} 
%>

<%
   if(caheaderprinted){
     out.write("</ul></li>"); 
   }
%>

<%
   // --------------------------------------------------------------------------
   // RA FUNCTIONS
%>
<%
    // If authorized to use the ra then display related links. 
    try{
      if(ejbcawebbean.isAuthorizedNoLog(RAADDENDENTITY_RESOURCE)){ 
         if(!raheaderprinted){
           out.write("<li id=\"cat2\" class=\"section\"><strong>" + ejbcawebbean.getText("NAV_RAFUNCTIONS")+"</strong><ul>"); 
           raheaderprinted=true;
         }  %>
				<li><a href="<%= RA_ADDENDENTITYLINK %>" target="<%=GlobalConfiguration.MAINFRAME %>"><%=ejbcawebbean.getText("NAV_ADDENDENTITY") %></a></li>
<%   }
   }catch(AuthorizationDeniedException e){}
%>
<%
    // If authorized to edit the ra profiles then display related links.
    try{
      if(ejbcawebbean.isAuthorizedNoLog(RAEDITENDENTITYPROFILES_RESOURCE)){            
         if(!raheaderprinted){
           out.write("<li id=\"cat2\" class=\"section\"><strong>" + ejbcawebbean.getText("NAV_RAFUNCTIONS")+"</strong><ul>"); 
           raheaderprinted=true;
         }  %>
				<li><a href="<%= RA_EDITPROFILESLINK %>" target="<%=GlobalConfiguration.MAINFRAME %>"><%=ejbcawebbean.getText("NAV_ENDENTITYPROFILES") %></a></li>
<%   }
   }catch(AuthorizationDeniedException e){}
%>
<%
    // If authorized to use the ra then display related links. 
    try{
      if(ejbcawebbean.isAuthorizedNoLog(RALISTEDITENDENTITY_RESOURCE)){ 
            if(!raheaderprinted){
              out.write("<li id=\"cat2\" class=\"section\"><strong>" + ejbcawebbean.getText("NAV_RAFUNCTIONS")+"</strong><ul>"); 
              raheaderprinted=true;
            }  %>
				<li><a href="<%= RA_LISTENDENTITIESLINK %>" target="<%=GlobalConfiguration.MAINFRAME %>"><%=ejbcawebbean.getText("NAV_SEARCHENDENTITIES") %></a></li>
<%   }
   }catch(AuthorizationDeniedException e){}
%>

<%
   // If authorized to edit the ra user data sources then display related links.
   try{
     if(ejbcawebbean.isAuthorizedNoLog(RAEDITUSERDATASOURCES_RESOURCE)){ 
         if(!raheaderprinted){
             out.write("<li id=\"cat2\" class=\"section\"><strong>" + ejbcawebbean.getText("NAV_RAFUNCTIONS")+ "</strong><ul>");
			 raheaderprinted=true;
			 } %> 
				<li><a href="<%= RA_EDITUSERDATASOURCESLINK %>" target="<%=GlobalConfiguration.MAINFRAME %>"><%=ejbcawebbean.getText("NAV_USERDATASOURCES") %></a></li>
<%   }
  }catch(AuthorizationDeniedException e){}   
%>
<%
   if(raheaderprinted){
     out.write("</ul></li>"); 
   }
%>
<%
   // --------------------------------------------------------------------------
   // HARD TOKEN FUNCTIONS
%>
<%
   if(globalconfiguration.getIssueHardwareTokens()){
       %>  
<%
     // If authorized to edit the hard token issuers then display related links.
     try{
       if(ejbcawebbean.isAuthorizedNoLog(HTEDITHARDTOKENISSUERS_RESOURCE)){ 
           if(!htheaderprinted){
             htheaderprinted=true;%> 
		<li id="cat3" class="section"><strong><%=ejbcawebbean.getText("NAV_HARDTOKENFUNCTIONS") %></strong>
			<ul>
           <% } %>
				<li><a href="<%= HT_EDITHARDTOKENISSUERS_LINK %>" target="<%=GlobalConfiguration.MAINFRAME %>"><%=ejbcawebbean.getText("NAV_HARDTOKENISSUERS") %></a></li>
<%     }
      }catch(AuthorizationDeniedException e){}
%>
    <%
     // If authorized to edit the hard token profiles then display related links.
     try{
       if(ejbcawebbean.isAuthorizedNoLog(HTEDITHARDTOKENPROFILES_RESOURCE)){ 
           if(!htheaderprinted){
               htheaderprinted=true;%> 
		<li id="cat3" class="section"><strong><%=ejbcawebbean.getText("NAV_HARDTOKENFUNCTIONS") %></strong>
			<ul>
           <% } %>
				<li><a href="<%= HT_EDITHARDTOKENPROFILES_LINK %>" target="<%=GlobalConfiguration.MAINFRAME %>"><%=ejbcawebbean.getText("NAV_HARDTOKENPROFILES") %></a></li>
<%     }
      }catch(AuthorizationDeniedException e){}
%>
<%
	if(htheaderprinted){
        out.write("</ul></li>"); 
      }
%>
<%
    }

   

   // --------------------------------------------------------------------------
   // SUPERVISION FUNCTIONS

   // If authorized to approve data show related links
   		boolean approveendentity = false;
		boolean approvecaaction = false;
		try{
			approveendentity = ejbcawebbean.isAuthorizedNoLog(AccessRulesConstants.REGULAR_APPROVEENDENTITY);
		}catch(AuthorizationDeniedException e){}
		try{
			approvecaaction = ejbcawebbean.isAuthorizedNoLog(AccessRulesConstants.REGULAR_APPROVECAACTION);
		}catch(AuthorizationDeniedException e){}
		if(approveendentity || approvecaaction){
			logheaderprinted = true;%>
		<li id="cat4" class="section"><strong><%=ejbcawebbean.getText("NAV_SUPERVISIONFUNCTIONS") %></strong>
			<ul>
				<li><a href="<%= APPROVAL_LINK %>" target="<%=GlobalConfiguration.MAINFRAME %>"><%=ejbcawebbean.getText("NAV_APPROVEACTIONS") %></a></li>
<%      }
   
    // If authorized to view log then display related links.
    try{
      if(ejbcawebbean.isAuthorizedNoLog(LOGVIEW_RESOURCE)){
            if(!logheaderprinted){
              out.write("<li id=\"cat4\" class=\"section\"><strong>" + ejbcawebbean.getText("NAV_SUPERVISIONFUNCTIONS")+"</strong><ul>"); 
              logheaderprinted=true;
            }  %>
				<li><a href="<%= AUDIT_LINK %>" target="<%=GlobalConfiguration.MAINFRAME %>"><%=ejbcawebbean.getText("NAV_AUDIT") %></a></li>
<%    }
   }catch(AuthorizationDeniedException e){} 

   if(logheaderprinted){
     out.write("</ul></li>"); 
   }
%>


<%
   // --------------------------------------------------------------------------
   // SYSTEM FUNCTIONS
%>

<%
   // If authorized to edit authorizations then display related links.
   try{
     if(ejbcawebbean.isAuthorizedNoLog(ADMINPRIVILEGES_RESOURCE)){
       if(!systemheaderprinted){
         out.write("<li id=\"cat7\" class=\"section\"><strong>" + ejbcawebbean.getText("NAV_SYSTEMFUNCTIONS")+"</strong><ul>"); 
         systemheaderprinted=true;
         }  %>
				<li><a href="<%= ADMINISTRATORPRIV_LINK %>" target="<%=GlobalConfiguration.MAINFRAME %>"><%=ejbcawebbean.getText("NAV_ROLES") %></a></li>
<%   }
  }catch(AuthorizationDeniedException e){}
%>


<%   
   // If authorized to edit Internal Key Bindings then display related links.
   try{
     if(ejbcawebbean.isAuthorizedNoLog(INTERNALKEYBINDING_RESOURCE)){
       if(!systemheaderprinted){
         out.write("<li id=\"cat7\" class=\"section\"><strong>" + ejbcawebbean.getText("NAV_SYSTEMFUNCTIONS")+"</strong><ul>"); 
         systemheaderprinted=true;
         }  %>
				<li><a href="<%= INTERNALKEYBINDING_LINK %>" target="<%=GlobalConfiguration.MAINFRAME %>"><%=ejbcawebbean.getText("NAV_KEYBINDINGS") %></a></li>
<%   }
  }catch(AuthorizationDeniedException e){}
%>

<%
   // If authorized to edit peerconnectors then display related links.
   try{
     if(ejbcawebbean.isPeerConnectorPresent() && ejbcawebbean.isAuthorizedNoLog(PEERCONNECTOR_RESOURCE_VIEW)){
       if(!systemheaderprinted){
         out.write("<li id=\"cat7\" class=\"section\"><strong>" + ejbcawebbean.getText("NAV_SYSTEMFUNCTIONS")+"</strong><ul>"); 
         systemheaderprinted=true;
         }  %>
				<li><a href="<%= PEERCONNECTOR_LINK %>" target="<%=GlobalConfiguration.MAINFRAME %>"><%=ejbcawebbean.getText("NAV_PEERCONNECTOR") %></a></li>
<%   }
  }catch(AuthorizationDeniedException e){} 
%>

<%
   // If authorized to edit services then display related links.
   try{
     if(ejbcawebbean.isAuthorizedNoLog(SERVICES_RESOURCE)){
       if(!systemheaderprinted){
         out.write("<li id=\"cat7\" class=\"section\"><strong>" + ejbcawebbean.getText("NAV_SYSTEMFUNCTIONS")+"</strong><ul>"); 
         systemheaderprinted=true;
         }  %>
				<li><a href="<%= SERVICES_LINK %>" target="<%=GlobalConfiguration.MAINFRAME %>"><%=ejbcawebbean.getText("NAV_SERVICES") %></a></li>
<%   }
  }catch(AuthorizationDeniedException e){} 
%>


<%
   if(systemheaderprinted){
     out.write("</ul></li>"); 
   }
%>


<%
   // --------------------------------------------------------------------------
   // SYSTEM CONFIGURATION
%>

<%
    // If authorized to edit CMP Configuration then display related links.
    try{
      if(ejbcawebbean.isAuthorizedNoLog(SYSTEMCONFIGURATION_RESOURCE)){ 
          if(!configheaderprinted){      
        out.write("<li id=\"cat5\" class=\"section\"><strong>" + ejbcawebbean.getText("NAV_SYSTEMCONFIGURATION")+"</strong><ul>");
        configheaderprinted = true;
          } %>
				<li><a href="<%= CMPCONFIGURATION_LINK %>" target="<%=GlobalConfiguration.MAINFRAME %>"><%=ejbcawebbean.getText("NAV_CMPCONFIGURATION") %></a></li>
<%   }
   }catch(AuthorizationDeniedException e){}
%>

<%
   // If authorized to edit SCEP configuration then display related links.
   try{
     if(ejbcawebbean.isAuthorizedNoLog(SYSTEMCONFIGURATION_RESOURCE)){
       if(!configheaderprinted){
         out.write("<li id=\"cat5\" class=\"section\"><strong>" + ejbcawebbean.getText("NAV_SYSTEMCONFIGURATION")+"</strong><ul>"); 
         configheaderprinted=true;
         }  %>
				<li><a href="<%= SCEPCONFIGURATION_LINK %>" target="<%=GlobalConfiguration.MAINFRAME %>"><%=ejbcawebbean.getText("NAV_SCEPCONFIGURATION") %></a></li>
<%   }
  }catch(AuthorizationDeniedException e){}
%>

<%
    // If authorized to configure Ejbca then display related links.
    try{
      if(ejbcawebbean.isAuthorizedNoLog(SYSTEMCONFIGURATION_RESOURCE)){ 
          if(!configheaderprinted){      
        out.write("<li id=\"cat5\" class=\"section\"><strong>" + ejbcawebbean.getText("NAV_SYSTEMCONFIGURATION")+"</strong><ul>");
        configheaderprinted = true;
          } %>
				<li><a href="<%= CONFIGURATION_LINK %>" target="<%=GlobalConfiguration.MAINFRAME %>"><%=ejbcawebbean.getText("NAV_SYSTEMCONFIGURATION") %></a></li>
<%   }
   }catch(AuthorizationDeniedException e){}
%>

<%
if(configheaderprinted){
     out.write("</ul></li>"); 
   }
%>


<%
   // --------------------------------------------------------------------------
   // END OF MENU
%>

<%
    // If authorized to edit user preferences then display related links.
    try{
      if(ejbcawebbean.isAuthorizedNoLog(MAIN_RESOURCE)){ %>
				<li id="cat8"><a href="<%= MYPREFERENCES_LINK %>" target="<%=GlobalConfiguration.MAINFRAME %>"><%=ejbcawebbean.getText("NAV_MYPREFERENCES") %></a></li>
<%   }
   }catch(AuthorizationDeniedException e){}
%>

		<li id="cat9"><a href="<%= PUBLICWEB_LINK %>" target="_ejbcapublicweb"><%=ejbcawebbean.getText("PUBLICWEB") %></a>
		</li>

<% if (ejbcawebbean.isHelpEnabled()) { %>
		<li id="cat10"><a href="<%= ejbcawebbean.getHelpBaseURI() %>/index.html" target="<%= GlobalConfiguration.DOCWINDOW %>"
			title="<%= ejbcawebbean.getText("OPENHELPSECTION") %>"><%=ejbcawebbean.getText("DOCUMENTATION") %></a>
		</li>
<% } %>

		<li id="cat11"><a href="<%= LOGOUT_LINK %>" target="_top"><%=ejbcawebbean.getText("LOGOUT") %></a></li>

	</ul>
	</div><!-- id="navigation" -->

</body>
</html>
