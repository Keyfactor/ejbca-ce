<html>
<%@page contentType="text/html"%>
<%@page errorPage="errorpage.jsp" import="se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean,se.anatom.ejbca.ra.GlobalConfiguration,se.anatom.ejbca.ra.authorization.AuthorizationDeniedException"%>
<jsp:useBean id="ejbcawebbean" scope="session" class="se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean" />
<jsp:setProperty name="ejbcawebbean" property="*" /> 
<% 
  // A jsp page that generates the menu after the users access rights 
  // Initialize environment.
  GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request,"/"); 
 
  final String THIS_FILENAME            =   globalconfiguration.getMenuFilename();

  final String MAIN_LINK                =  "/" + globalconfiguration.getAdminWebPath() +globalconfiguration.getMainFilename();

  final String CA_LINK                  = "/" +globalconfiguration.getCaPath() 
                                                  + "/cafunctions.jsp";
  final String CA_CERTIFICATEPROFILELINK  = "/" +globalconfiguration.getCaPath() 
                                                  + "/editcertificateprofiles/editcertificateprofiles.jsp";  
  final String RA_EDITPROFILESLINK      = "/" +globalconfiguration.getRaPath()+"/editendentityprofiles/editendentityprofiles.jsp";
  final String RA_LISTUSERSLINK         = "/" +globalconfiguration.getRaPath()+"/listendentities.jsp";
  final String RA_ADDENDENTITYLINK      = "/" +globalconfiguration.getRaPath()+"/addendentity.jsp";
  final String RA_LISTENDENTITIESLINK   = "/" +globalconfiguration.getRaPath()+"/listendentities.jsp";
  final String HT_EDITHARDTOKENISSUERS_LINK  = "/" +globalconfiguration.getHardTokenPath() 
                                                  + "/edithardtokenissuers.jsp";
  final String LOG_LINK                 = "/" +globalconfiguration.getLogPath() 
                                                  + "/viewlog.jsp";
  final String LOG_CONFIGURATION_LINK   = "/" +globalconfiguration.getLogPath() 
                                                  + "/logconfiguration/logconfiguration.jsp";
  final String CONFIGURATION_LINK       = "/" +globalconfiguration.getConfigPath() 
                                                  + "/configuration.jsp";
  final String ADMINISTRATORPRIV_LINK   = "/" +globalconfiguration.getAuthorizationPath() 
                                                  + "/administratorprivileges.jsp";
  final String AVAILABLE_ACCESSRULES_LINK  = "/" +globalconfiguration.getAuthorizationPath() 
                                                  + "/availablerules/editavailablerules.jsp";
  final String MYPREFERENCES_LINK     = "/" +globalconfiguration.getAdminWebPath() + "mypreferences.jsp";
  final String HELP_LINK                = "/" +globalconfiguration.getAdminWebPath() + globalconfiguration.getHelpPath() 
                                                  + "/index_help.html";


  final String MAIN_RESOURCE                          = "/";
  final String CABASICFUNCTIONS_RESOURCE              = "/ca_functionallity/basic_functions";
  final String EDITCERTIFICATEPROFILES_RESOURCE       = "/ca_functionallity/edit_certificate_profiles";
  final String RAEDITENDENTITYPROFILES_RESOURCE       = "/ra_functionallity/edit_end_entity_profiles";
  final String RAADDENDENTITY_RESOURCE                = "/ra_functionallity/create_end_entity";
  final String RALISTEDITENDENTITY_RESOURCE           = "/ra_functionallity/view_end_entity";
  final String HTEDITHARDTOKENISSUERS_RESOURCE        = "/hardtoken_functionallity/edit_hardtoken_issuers";
  final String LOGVIEW_RESOURCE                       = "/log_functionallity/view_log";
  final String LOGCONFIGURATION_RESOURCE              = "/log_functionallity/edit_log_configuration";
  final String SYSTEMCONFIGURATION_RESOURCE           = "/system_functionallity/edit_system_configuration";
  final String ADMINPRIVILEGES_RESOURCE               = "/system_functionallity/edit_administrator_privileges";
  final String AVAILABLEACCESSRULES_RESOURCE          = "/system_functionallity/edit_administrator_privileges/edit_available_accessrules";

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
     <A href="<%=MAIN_LINK %>" target="<%=globalconfiguration.MAINFRAME %>" id="menu"><%=ejbcawebbean.getText("MAINPAGE") %></A>     
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
     &nbsp;&nbsp;<A href='<%= CA_LINK %>' target="<%=globalconfiguration.MAINFRAME %>" id="menu"><%=ejbcawebbean.getText("BASICFUNCTIONS") %></a>
     <br>
<%    }
   }catch(AuthorizationDeniedException e){} 
   try{
     if(ejbcawebbean.isAuthorizedNoLog(EDITCERTIFICATEPROFILES_RESOURCE)){ 
        if(!caheaderprinted){
          out.write("<br>" + ejbcawebbean.getText("CAFUNCTIONS")+"<br>"); 
           raheaderprinted=true;
        } %>
     &nbsp;&nbsp;<A href='<%= CA_CERTIFICATEPROFILELINK %>' target="<%=globalconfiguration.MAINFRAME %>" id="menu"><%=ejbcawebbean.getText("EDITCERTIFICATEPROFILES") %></a>
     <br>

<%    }
   }catch(AuthorizationDeniedException e){} 
    // If authorized to edit the ra profiles then display related links.
    try{
      if(ejbcawebbean.isAuthorizedNoLog(RAEDITENDENTITYPROFILES_RESOURCE)){ 
           raheaderprinted=true;%> 
           <br>  
           <%=ejbcawebbean.getText("RAFUNCTIONS")+"<br>" %>
           &nbsp;&nbsp;<A href='<%= RA_EDITPROFILESLINK %>' target="<%=globalconfiguration.MAINFRAME %>" id="menu"> 
           <%=ejbcawebbean.getText("EDITPROFILES") %></a><br>

<%   }
   }catch(AuthorizationDeniedException e){}
    // If authorized to use the ra then display related links. 
    try{
      if(ejbcawebbean.isAuthorizedNoLog(RAADDENDENTITY_RESOURCE)){ 
            if(!raheaderprinted){
              out.write("<br>" + ejbcawebbean.getText("RAFUNCTIONS")+"<br>"); 
              raheaderprinted=true;
            }  %>
           &nbsp;&nbsp;<A href='<%= RA_ADDENDENTITYLINK %>' target="<%=globalconfiguration.MAINFRAME %>" id="menu"> 
           <%=ejbcawebbean.getText("ADDENDENTITY") %></a><br>
<%   }
   }catch(AuthorizationDeniedException e){}
    // If authorized to use the ra then display related links. 
    try{
      if(ejbcawebbean.isAuthorizedNoLog(RALISTEDITENDENTITY_RESOURCE)){ 
            if(!raheaderprinted){
              out.write("<br>" + ejbcawebbean.getText("RAFUNCTIONS")+"<br>"); 
              raheaderprinted=true;
            }  %>
           &nbsp;&nbsp;<A href='<%=RA_LISTENDENTITIESLINK %>' target="<%=globalconfiguration.MAINFRAME %>" id="menu"> 
           <%=ejbcawebbean.getText("LISTEDITENDENTITIES") %></a><br>
<%   }
   }catch(AuthorizationDeniedException e){}
   if(globalconfiguration.getIssueHardwareTokens()){
     // If authorized to edit the hard token issuers then display related links.
     try{
       if(ejbcawebbean.isAuthorizedNoLog(HTEDITHARDTOKENISSUERS_RESOURCE)){ 
           raheaderprinted=true;%> 
           <br>  
           <%=ejbcawebbean.getText("HARDTOKENFUNCTIONS")+"<br>" %>
           &nbsp;&nbsp;<A href='<%= HT_EDITHARDTOKENISSUERS_LINK %>' target="<%=globalconfiguration.MAINFRAME %>" id="menu"> 
           <%=ejbcawebbean.getText("EDITHARDTOKENISSUERS") %></a><br>

<%     }
      }catch(AuthorizationDeniedException e){}
    }
    // If authorized to view log then display related links.
    try{
      if(ejbcawebbean.isAuthorizedNoLog(LOGVIEW_RESOURCE)){
        logheaderprinted = true;%>
   <br><%=ejbcawebbean.getText("LOGFUNCTIONS") %><br> 
   &nbsp;&nbsp;<A href="<%= LOG_LINK %>" target="<%=globalconfiguration.MAINFRAME %>" id="menu"><%=ejbcawebbean.getText("VIEWLOG") %></A>
   <br>
<%    }
   }catch(AuthorizationDeniedException e){} 
   try{
    // If authorized to edit log configurationthen display related link.
     if(ejbcawebbean.isAuthorizedNoLog(LOGCONFIGURATION_RESOURCE)){ 
            if(!logheaderprinted){
              out.write("<br>" + ejbcawebbean.getText("LOGFUNCTIONS")+"<br>"); 
              logheaderprinted=true;
            }
%>
     &nbsp;&nbsp;<A href='<%= LOG_CONFIGURATION_LINK %>' target="<%=globalconfiguration.MAINFRAME %>" id="menu"><%=ejbcawebbean.getText("LOGCONFIGURATION") %></a>
     <br>
<%   }
   }catch(AuthorizationDeniedException e){}
    // If authorized to configure Ejbca then display related links.
    try{
      if(ejbcawebbean.isAuthorizedNoLog(SYSTEMCONFIGURATION_RESOURCE)){ 
        systemheaderprinted = true;%>
   <br><%=ejbcawebbean.getText("SYSTEMFUNCTIONS") %><br> 
      &nbsp;&nbsp;<A href="<%= CONFIGURATION_LINK %>" target="<%=globalconfiguration.MAINFRAME %>" id="menu"><%=ejbcawebbean.getText("SYSTEMCONFIGURATION") %></A><br>
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
     &nbsp;&nbsp;<A href="<%= ADMINISTRATORPRIV_LINK %>" target="<%=globalconfiguration.MAINFRAME %>" id="menu"><%=ejbcawebbean.getText("EDITADMINISTRATORPRIV") %></A><br>
<%   }
   }catch(AuthorizationDeniedException e){}
    // If authorized to edit authorizations then display related links.
    try{
      if(ejbcawebbean.isAuthorizedNoLog(AVAILABLEACCESSRULES_RESOURCE)){ 
        if(!systemheaderprinted){
          out.write("<br>" + ejbcawebbean.getText("SYSTEMFUNCTIONS")+"<br>"); 
          systemheaderprinted=true;
          }%>
   &nbsp;&nbsp; <A href="<%= AVAILABLE_ACCESSRULES_LINK  %>" target="<%=globalconfiguration.MAINFRAME %>" id="menu"><%=ejbcawebbean.getText("EDITAVAILABLERULES") %></A>
<br>   
<%   }
   }catch(AuthorizationDeniedException e){}
    // If authorized to edit user preferences then display related links.
    try{
      if(ejbcawebbean.isAuthorizedNoLog(MAIN_RESOURCE)){ %>
     <br>
     <br>
     <A href="<%= MYPREFERENCES_LINK %>" target="<%=globalconfiguration.MAINFRAME %>" id="menu"><%=ejbcawebbean.getText("MYPREFERENCES") %></A>
     <br>
<%   }
   }catch(AuthorizationDeniedException e){
 //     throw new AuthorizationDeniedException();
 } 
    // If authorized to view help pages then display related links.
   try{
     if(ejbcawebbean.isAuthorizedNoLog(MAIN_RESOURCE)){ %>
     <br><br><br>
     <u><A onclick='displayHelpWindow("<%= ejbcawebbean.getHelpfileInfix("index_help.html") %>")' id="menu"><%=ejbcawebbean.getText("HELP") %></A></u>

<%   }
    }catch(AuthorizationDeniedException e){}%>



</body>
</html>
