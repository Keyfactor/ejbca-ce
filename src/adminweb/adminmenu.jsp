<%@ page pageEncoding="ISO-8859-1"%>
<%@ page contentType="text/html; charset=@page.encoding@" %>
<%@page errorPage="errorpage.jsp" import="org.ejbca.core.model.ra.raadmin.GlobalConfiguration,
                                          org.ejbca.core.model.authorization.AuthorizationDeniedException,
                                          org.ejbca.core.model.authorization.AvailableAccessRules"%>
<html>
<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />
<jsp:setProperty name="ejbcawebbean" property="*" /> 
<% 
  // A jsp page that generates the menu after the users access rights 
  // Initialize environment.
  GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request,"/administrator"); 
 
  final String THIS_FILENAME            =   globalconfiguration.getMenuFilename();

  final String MAIN_LINK                =   ejbcawebbean.getBaseUrl() + globalconfiguration.getAdminWebPath() +globalconfiguration.getMainFilename();

  final String APPROVAL_LINK            =   ejbcawebbean.getBaseUrl() + globalconfiguration.getAdminWebPath() + "approval/approveactionlist.jsf";
  
  final String EDITCA_LINK              =  ejbcawebbean.getBaseUrl() + globalconfiguration.getCaPath() 
                                                  + "/editcas/editcas.jsp";
  final String EDITPUBLISHERS_LINK      =  ejbcawebbean.getBaseUrl() + globalconfiguration.getCaPath() 
                                                  + "/editpublishers/editpublishers.jsp";

  final String CA_LINK                  =  ejbcawebbean.getBaseUrl() + globalconfiguration.getCaPath() 
                                                  + "/cafunctions.jsp";
  final String CA_CERTIFICATEPROFILELINK  = ejbcawebbean.getBaseUrl() + globalconfiguration.getCaPath() 
                                                  + "/editcertificateprofiles/editcertificateprofiles.jsp";  
  final String RA_EDITUSERDATASOURCESLINK =  ejbcawebbean.getBaseUrl() + globalconfiguration.getRaPath()+"/edituserdatasources/edituserdatasources.jsp";
  final String RA_EDITPROFILESLINK      =  ejbcawebbean.getBaseUrl() + globalconfiguration.getRaPath()+"/editendentityprofiles/editendentityprofiles.jsp";
  final String RA_ADDENDENTITYLINK      =  ejbcawebbean.getBaseUrl() + globalconfiguration.getRaPath()+"/addendentity.jsp";
  final String RA_LISTENDENTITIESLINK   =  ejbcawebbean.getBaseUrl() + globalconfiguration.getRaPath()+"/listendentities.jsp";
  final String HT_EDITHARDTOKENISSUERS_LINK  =  ejbcawebbean.getBaseUrl() + globalconfiguration.getHardTokenPath() 
                                                  + "/edithardtokenissuers.jsp";
  final String HT_EDITHARDTOKENPROFILES_LINK  =  ejbcawebbean.getBaseUrl() + globalconfiguration.getHardTokenPath() 
                                                  + "/edithardtokenprofiles/edithardtokenprofiles.jsp";
  final String LOG_LINK                 =  ejbcawebbean.getBaseUrl() + globalconfiguration.getLogPath() 
                                                  + "/viewlog.jsp";
  final String LOG_CONFIGURATION_LINK   =  ejbcawebbean.getBaseUrl() + globalconfiguration.getLogPath() 
                                                  + "/logconfiguration/logconfiguration.jsp";
  final String CONFIGURATION_LINK       =  ejbcawebbean.getBaseUrl() + globalconfiguration.getConfigPath() 
                                                  + "/configuration.jsp";
  final String ADMINISTRATORPRIV_LINK   =  ejbcawebbean.getBaseUrl() + globalconfiguration.getAuthorizationPath() 
                                                  + "/administratorprivileges.jsp";
  
  final String PUBLICWEB_LINK          = ejbcawebbean.getBaseUrl() + "index.html";
  
  final String MYPREFERENCES_LINK     =  ejbcawebbean.getBaseUrl() + globalconfiguration.getAdminWebPath() + "mypreferences.jsp";
  final String HELP_LINK                =  ejbcawebbean.getBaseUrl() + globalconfiguration.getAdminWebPath() + globalconfiguration.getHelpPath() 
                                                  + "/index_help.html";


  final String MAIN_RESOURCE                          = "/administrator";
  final String CABASICFUNCTIONS_RESOURCE              = "/ca_functionality/basic_functions";
  final String EDITCAS_RESOURCE                       = "/super_administrator";
  final String EDITPUBLISHERS_RESOURCE                = "/super_administrator";
  final String EDITCERTIFICATEPROFILES_RESOURCE       = "/ca_functionality/edit_certificate_profiles";
  final String RAEDITUSERDATASOURCES_RESOURCE         = AvailableAccessRules.REGULAR_EDITUSERDATASOURCES;
  final String RAEDITENDENTITYPROFILES_RESOURCE       = "/ra_functionality/edit_end_entity_profiles";
  final String RAADDENDENTITY_RESOURCE                = "/ra_functionality/create_end_entity";
  final String RALISTEDITENDENTITY_RESOURCE           = "/ra_functionality/view_end_entity";
  final String HTEDITHARDTOKENISSUERS_RESOURCE        = "/hardtoken_functionality/edit_hardtoken_issuers";
  final String HTEDITHARDTOKENPROFILES_RESOURCE       = "/hardtoken_functionality/edit_hardtoken_profiles";
  final String LOGVIEW_RESOURCE                       = "/log_functionality/view_log";
  final String LOGCONFIGURATION_RESOURCE              = "/log_functionality/edit_log_configuration";
  final String SYSTEMCONFIGURATION_RESOURCE           = "/super_administrator";
  final String ADMINPRIVILEGES_RESOURCE               = "/system_functionality/edit_administrator_privileges";


%>
<%  
  boolean caheaderprinted     =false;
  boolean raheaderprinted     =false;
  boolean htheaderprinted     =false;
  boolean logheaderprinted    =false;
  boolean systemheaderprinted =false;

%>
<head>
  <title><%= ""%></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>">
  <link rel=STYLESHEET href="<%= ejbcawebbean.getCssFile() %>">
  <script language=javascript src="<%= globalconfiguration.getAdminWebPath() %>ejbcajslib.js"></script>
</head>
<body id="menu">
<%  // If authorized to use the main page then display related links.
   try{
     if(ejbcawebbean.isAuthorizedNoLog(MAIN_RESOURCE)){ %>
     <br>
     <A href="<%=MAIN_LINK %>" target="<%=GlobalConfiguration.MAINFRAME %>" id="menu"><%=ejbcawebbean.getText("MAINPAGE") %></A>     
     <br>

<%    }
   }catch(AuthorizationDeniedException e){} 
   // If authorized to use the ca then display related links.
   try{
     if(ejbcawebbean.isAuthorizedNoLog(CABASICFUNCTIONS_RESOURCE)){ 
       caheaderprinted=true;%>
     <br>
     <%=ejbcawebbean.getText("CAFUNCTIONS") %>
     <br>
     &nbsp;&nbsp;<A href='<%= CA_LINK %>' target="<%=GlobalConfiguration.MAINFRAME %>" id="menu"><%=ejbcawebbean.getText("BASICFUNCTIONS") %></a>
     <br>
<%    }
   }catch(AuthorizationDeniedException e){} 
   try{
     if(ejbcawebbean.isAuthorizedNoLog(EDITCERTIFICATEPROFILES_RESOURCE)){ 
        if(!caheaderprinted){
          out.write("<br>" + ejbcawebbean.getText("CAFUNCTIONS")+"<br>"); 
           caheaderprinted=true;
        } %>
     &nbsp;&nbsp;<A href='<%= CA_CERTIFICATEPROFILELINK %>' target="<%=GlobalConfiguration.MAINFRAME %>" id="menu"><%=ejbcawebbean.getText("EDITCERTIFICATEPROFILES") %></a>
     <br>

<%    }
   }catch(AuthorizationDeniedException e){} 
   try{
     if(ejbcawebbean.isAuthorizedNoLog(EDITPUBLISHERS_RESOURCE)){ 
        if(!caheaderprinted){
          out.write("<br>" + ejbcawebbean.getText("CAFUNCTIONS")+"<br>"); 
           caheaderprinted=true;
        } %>
     &nbsp;&nbsp;<A href='<%= EDITPUBLISHERS_LINK %>' target="<%=GlobalConfiguration.MAINFRAME %>" id="menu"><%=ejbcawebbean.getText("EDITPUBLISHERS") %></a>
     <br>

<%    }
   }catch(AuthorizationDeniedException e){} 
   try{
     if(ejbcawebbean.isAuthorizedNoLog(EDITCAS_RESOURCE)){ 
        if(!caheaderprinted){
          out.write("<br>" + ejbcawebbean.getText("CAFUNCTIONS")+"<br>"); 
           caheaderprinted=true;
        } %>
     &nbsp;&nbsp;<A href='<%= EDITCA_LINK %>' target="<%=GlobalConfiguration.MAINFRAME %>" id="menu"><%=ejbcawebbean.getText("EDITCAS") %></a>
     <br>

<%    }
   }catch(AuthorizationDeniedException e){} 
   // If authorized to edit the ra user data sources then display related links.
   try{
     if(ejbcawebbean.isAuthorizedNoLog(RAEDITUSERDATASOURCES_RESOURCE)){ 
          raheaderprinted=true;%> 
          <br>  
          <%=ejbcawebbean.getText("RAFUNCTIONS")+"<br>" %>
          &nbsp;&nbsp;<A href='<%= RA_EDITUSERDATASOURCESLINK %>' target="<%=GlobalConfiguration.MAINFRAME %>" id="menu"><%=ejbcawebbean.getText("EDITUSERDATASOURCES") %></a><br>

<%   }
  }catch(AuthorizationDeniedException e){}   
    // If authorized to edit the ra profiles then display related links.
    try{
      if(ejbcawebbean.isAuthorizedNoLog(RAEDITENDENTITYPROFILES_RESOURCE)){            
            if(!raheaderprinted){
              out.write("<br>" + ejbcawebbean.getText("RAFUNCTIONS")+"<br>"); 
              raheaderprinted=true;
            }  %>
           &nbsp;&nbsp;<A href='<%= RA_EDITPROFILESLINK %>' target="<%=GlobalConfiguration.MAINFRAME %>" id="menu"><%=ejbcawebbean.getText("EDITPROFILES") %></a><br>

<%   }
   }catch(AuthorizationDeniedException e){}
    // If authorized to use the ra then display related links. 
    try{
      if(ejbcawebbean.isAuthorizedNoLog(RAADDENDENTITY_RESOURCE)){ 
            if(!raheaderprinted){
              out.write("<br>" + ejbcawebbean.getText("RAFUNCTIONS")+"<br>"); 
              raheaderprinted=true;
            }  %>
           &nbsp;&nbsp;<A href='<%= RA_ADDENDENTITYLINK %>' target="<%=GlobalConfiguration.MAINFRAME %>" id="menu"><%=ejbcawebbean.getText("ADDENDENTITY") %></a><br>
<%   }
   }catch(AuthorizationDeniedException e){}
    // If authorized to use the ra then display related links. 
    try{
      if(ejbcawebbean.isAuthorizedNoLog(RALISTEDITENDENTITY_RESOURCE)){ 
            if(!raheaderprinted){
              out.write("<br>" + ejbcawebbean.getText("RAFUNCTIONS")+"<br>"); 
              raheaderprinted=true;
            }  %>
           &nbsp;&nbsp;<A href='<%=RA_LISTENDENTITIESLINK %>' target="<%=GlobalConfiguration.MAINFRAME %>" id="menu"><%=ejbcawebbean.getText("LISTEDITENDENTITIES") %></a><br>
<%   }
   }catch(AuthorizationDeniedException e){}
   if(globalconfiguration.getIssueHardwareTokens()){
     // If authorized to edit the hard token profiles then display related links.
     try{
       if(ejbcawebbean.isAuthorizedNoLog(HTEDITHARDTOKENPROFILES_RESOURCE)){ 
           htheaderprinted=true;%> 
           <br>  
           <%=ejbcawebbean.getText("HARDTOKENFUNCTIONS")+"<br>" %>
           &nbsp;&nbsp;<A href='<%= HT_EDITHARDTOKENPROFILES_LINK %>' target="<%=GlobalConfiguration.MAINFRAME %>" id="menu"><%=ejbcawebbean.getText("EDITHARDTOKENPROFILES") %></a><br>

<%     }
      }catch(AuthorizationDeniedException e){}
    
     // If authorized to edit the hard token issuers then display related links.
     try{
       if(ejbcawebbean.isAuthorizedNoLog(HTEDITHARDTOKENISSUERS_RESOURCE)){ 
           if(!htheaderprinted){
             htheaderprinted=true;%> 
             <br>  
             <%=ejbcawebbean.getText("HARDTOKENFUNCTIONS")+"<br>" %> 
           <% } %>
           &nbsp;&nbsp;<A href='<%= HT_EDITHARDTOKENISSUERS_LINK %>' target="<%=GlobalConfiguration.MAINFRAME %>" id="menu"><%=ejbcawebbean.getText("EDITHARDTOKENISSUERS") %></a><br>

<%     }
      }catch(AuthorizationDeniedException e){}
    }
   
   // If authorized to approve data show related links
   		boolean approveendentity = false;
		boolean approvecaaction = false;
		try{
			approveendentity = ejbcawebbean.isAuthorizedNoLog(AvailableAccessRules.REGULAR_APPROVEENDENTITY);
		}catch(AuthorizationDeniedException e){}
		try{
			approvecaaction = ejbcawebbean.isAuthorizedNoLog(AvailableAccessRules.REGULAR_APPROVECAACTION);
		}catch(AuthorizationDeniedException e){}
		if(approveendentity || approvecaaction){
			logheaderprinted = true;%>
   <br><%=ejbcawebbean.getText("SUPERVISIONFUNCTIONS") %><br> 		
   &nbsp;&nbsp;<A href="<%= APPROVAL_LINK %>" target="<%=GlobalConfiguration.MAINFRAME %>" id="menu"><%=ejbcawebbean.getText("APPROVEACTIONS") %></A>   	
   <br>
<%      }
   
    // If authorized to view log then display related links.
    try{
      if(ejbcawebbean.isAuthorizedNoLog(LOGVIEW_RESOURCE)){
            if(!logheaderprinted){
              out.write("<br>" + ejbcawebbean.getText("SUPERVISIONFUNCTIONS")+"<br>"); 
              logheaderprinted=true;
            }%>
   &nbsp;&nbsp;<A href="<%= LOG_LINK %>" target="<%=GlobalConfiguration.MAINFRAME %>" id="menu"><%=ejbcawebbean.getText("VIEWLOG") %></A>
   <br>
<%    }
   }catch(AuthorizationDeniedException e){} 
   try{
    // If authorized to edit log configurationthen display related link.
     if(ejbcawebbean.isAuthorizedNoLog(LOGCONFIGURATION_RESOURCE)){ 
            if(!logheaderprinted){
              out.write("<br>" + ejbcawebbean.getText("SUPERVISIONFUNCTIONS")+"<br>"); 
              logheaderprinted=true;
            }
%>
     &nbsp;&nbsp;<A href='<%= LOG_CONFIGURATION_LINK %>' target="<%=GlobalConfiguration.MAINFRAME %>" id="menu"><%=ejbcawebbean.getText("LOGCONFIGURATION") %></a>
     <br>
<%   }
   }catch(AuthorizationDeniedException e){}
    // If authorized to configure Ejbca then display related links.
    try{
      if(ejbcawebbean.isAuthorizedNoLog(SYSTEMCONFIGURATION_RESOURCE)){ 
        systemheaderprinted = true;%>
   <br><%=ejbcawebbean.getText("SYSTEMFUNCTIONS") %><br> 
      &nbsp;&nbsp;<A href="<%= CONFIGURATION_LINK %>" target="<%=GlobalConfiguration.MAINFRAME %>" id="menu"><%=ejbcawebbean.getText("SYSTEMCONFIGURATION") %></A><br>
<%   }
   }catch(AuthorizationDeniedException e){}
    // If authorized to edit authorizations then display related links.
    try{
      if(ejbcawebbean.isAuthorizedNoLog(ADMINPRIVILEGES_RESOURCE)){
        if(!systemheaderprinted){
          out.write("<br>" + ejbcawebbean.getText("SYSTEMFUNCTIONS")+"<br>"); 
          systemheaderprinted=true;
          }
%>
     &nbsp;&nbsp;<A href="<%= ADMINISTRATORPRIV_LINK %>" target="<%=GlobalConfiguration.MAINFRAME %>" id="menu"><%=ejbcawebbean.getText("EDITADMINISTRATORPRIV") %></A><br>
<%   }
   }catch(AuthorizationDeniedException e){} %>
   
   <br>
   <br>
   <A href="<%= PUBLICWEB_LINK %>" target="<%=GlobalConfiguration.MAINFRAME %>" id="menu"><%=ejbcawebbean.getText("PUBLICWEB") %></A>
 <%   
    // If authorized to edit user preferences then display related links.
    try{
      if(ejbcawebbean.isAuthorizedNoLog(MAIN_RESOURCE)){ %>
     <br>
     <br>
     <A href="<%= MYPREFERENCES_LINK %>" target="<%=GlobalConfiguration.MAINFRAME %>" id="menu"><%=ejbcawebbean.getText("MYPREFERENCES") %></A>
     <br>
<%   }
   }catch(AuthorizationDeniedException e){
 //     throw new AuthorizationDeniedException();
 } 
    // If authorized to view help pages then display related links.
 /*  try{
     if(ejbcawebbean.isAuthorizedNoLog(MAIN_RESOURCE)){ */%>
  <!--   <br><br><br>
     <u><A onclick='displayHelpWindow("<%= ejbcawebbean.getHelpfileInfix("index_help.html") %>")' id="menu"><%=ejbcawebbean.getText("HELP") %></A></u>
-->
<% /*  }
    }catch(AuthorizationDeniedException e){} */%>



</body>
</html>
