<html>
<%@page contentType="text/html"%>
<%@page errorPage="errorpage.jsp" import="se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean,se.anatom.ejbca.webdist.webconfiguration.GlobalConfiguration,se.anatom.ejbca.webdist.ejbcaathorization.AuthorizationDeniedException"%>
<jsp:useBean id="ejbcawebbean" scope="session" class="se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean" />
<jsp:setProperty name="ejbcawebbean" property="*" /> 
<% 
  // A jsp page that generates the menu after the users access rights 



  final String THIS_FILENAME            =   GlobalConfiguration.getMenuFilename();

  final String MAIN_LINK                =  GlobalConfiguration.getRaAdminPath() + "/" +GlobalConfiguration.getMainFilename();

  final String CA_LINK                  = GlobalConfiguration.getCaPath() 
                                                  + "/cafunctions.jsp";
  final String RA_LINK                  = GlobalConfiguration.getRaPath() 
                                                  + "/adduser.jsp";
  final String RA_EDITPROFILESLINK      = GlobalConfiguration.getRaPath()+"/profiles/editprofiles.jsp";
  final String RA_LISTUSERSLINK         = GlobalConfiguration.getRaPath()+"/listusers.jsp";
  final String RA_ADDUSERLINK           = GlobalConfiguration.getRaPath()+"/adduser.jsp";
  final String RA_LISTUSERS             = GlobalConfiguration.getRaPath()+"/listusers.jsp";
  final  String LOG_LINK                = GlobalConfiguration.getLogPath() 
                                                  + "/ejbcaauthorization.jsp";
  final  String CONFIGURATION_LINK      = GlobalConfiguration.getConfigPath() 
                                                  + "/configuration.jsp";
  final String AUTHORIZATION_LINK       = GlobalConfiguration.getAuthorizationPath() 
                                                  + "/ejbcaauthorization.jsp";
  final String USERPREFERENCES_LINK     = GlobalConfiguration.getRaAdminPath() + "userpreferences.jsp";
  final String HELP_LINK                = GlobalConfiguration.getHelpPath() 
                                                  + "/index_help.html";
%>
<%  
  // Initialize environment.
  ejbcawebbean.initialize(request); 
 
  boolean raheaderprinted =false;
%>
<head>
  <title><%= ""%></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>">
  <link rel=STYLESHEET href="<%= ejbcawebbean.getCssFile() %>">
  <script language=javascript src="<%= GlobalConfiguration.getRaAdminPath() %>ejbcajslib.js"></script>
</head>
<body id="menu">
<%  // If authorized to use the main page then display related links.
   try{
     if(ejbcawebbean.isAuthorized(MAIN_LINK)){ %>
     <br>
     <A href="<%=MAIN_LINK %>" target="<%=GlobalConfiguration.MAINFRAME %>"><%=ejbcawebbean.getText("MAINPAGE") %></A>     
     <br>

<%    }
   }catch(AuthorizationDeniedException e){} 
   // If authorized to use the ca then display related links.
   try{
     if(ejbcawebbean.isAuthorized(CA_LINK)){ %>
     <br>
     <A href='<%= CA_LINK %>' target="<%=GlobalConfiguration.MAINFRAME %>"><%=ejbcawebbean.getText("CAFUNCTIONS") %></a>
     <br>

<%    }
    // Temporate
   }catch(AuthorizationDeniedException e){} 

    // If authorized to edit the ra profiles then display related links.
    try{
      if(ejbcawebbean.isAuthorized(RA_EDITPROFILESLINK)){ 
           raheaderprinted=true;%>
           <%=ejbcawebbean.getText("RAFUNCTIONS")+"<br>" %>
           &nbsp;&nbsp;<A href='<%= RA_EDITPROFILESLINK %>' target="<%=GlobalConfiguration.MAINFRAME %>"> 
           <%=ejbcawebbean.getText("EDITPROFILES") %></a><br><br>

<%   }
   }catch(AuthorizationDeniedException e){}
    // If authorized to use the ra then display related links. 
    try{
      if(ejbcawebbean.isAuthorized(RA_LINK)){ 
            if(!raheaderprinted){
              out.write(ejbcawebbean.getText("RAFUNCTIONS")+"<br>"); 
              raheaderprinted=true;
            }  %>
           &nbsp;&nbsp;<A href='<%= RA_ADDUSERLINK %>' target="<%=GlobalConfiguration.MAINFRAME %>"> 
           <%=ejbcawebbean.getText("ADDUSER") %></a><br>
           &nbsp;&nbsp;<A href='<%=RA_LISTUSERSLINK %>' target="<%=GlobalConfiguration.MAINFRAME %>"> 
           <%=ejbcawebbean.getText("LISTUSERS") %></a><br>
  
<%   }
   }catch(AuthorizationDeniedException e){}
    // If authorized to configure Ejbca then display related links.
    try{
      if(ejbcawebbean.isAuthorized(CONFIGURATION_LINK)){ %>
   <br>
   <br>
   <A href="<%= CONFIGURATION_LINK %>" target="<%=GlobalConfiguration.MAINFRAME %>"><%=ejbcawebbean.getText("SYSTEMCONFIGURATION") %></A>
   <br>
<%   }
   }catch(AuthorizationDeniedException e){}
    // If authorized to edit authorizations then display related links.
    try{
      if(ejbcawebbean.isAuthorized(AUTHORIZATION_LINK)){ %>
   
   <A href="<%= AUTHORIZATION_LINK %>" target="<%=GlobalConfiguration.MAINFRAME %>"><%=ejbcawebbean.getText("AUTHORIZATION") %></A>
   <br>
<%   }
   }catch(AuthorizationDeniedException e){}
    // If authorized to edit user preferences then display related links.
    try{
      if(ejbcawebbean.isAuthorized(USERPREFERENCES_LINK)){ %>
     <br>
     <br>
     <A href="<%= USERPREFERENCES_LINK %>" target="<%=GlobalConfiguration.MAINFRAME %>"><%=ejbcawebbean.getText("USERPREFERENCES") %></A>
     <br>
<%   }
   }catch(AuthorizationDeniedException e){
 //     throw new AuthorizationDeniedException();
 } 
    // If authorized to view help pages then display related links.
   try{
     if(ejbcawebbean.isAuthorized(HELP_LINK)){ %>
     <br><br><br>
     <u><A onclick='displayHelpWindow("<%= ejbcawebbean.getHelpfileInfix("index_help.html") %>")'><%=ejbcawebbean.getText("HELP") %></A></u>

<%   }
    }catch(AuthorizationDeniedException e){}%>



</body>
</html>
