<%@ page pageEncoding="ISO-8859-1"%>
<%@ page contentType="text/html; charset=@page.encoding@" %>
<%@page errorPage="/errorpage.jsp" import="java.util.*, org.ejbca.ui.web.admin.configuration.EjbcaWebBean,org.ejbca.core.model.ra.raadmin.GlobalConfiguration, org.ejbca.core.model.SecConst, org.ejbca.core.model.authorization.AuthorizationDeniedException,
               org.ejbca.core.model.authorization.AvailableAccessRules,
               org.ejbca.ui.web.admin.hardtokeninterface.HardTokenInterfaceBean, org.ejbca.core.model.hardtoken.profiles.*, org.ejbca.ui.web.admin.hardtokeninterface.EditHardTokenProfileJSPHelper, 
               org.ejbca.core.model.hardtoken.HardTokenProfileExistsException"%>

<html>
<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />
<jsp:useBean id="hardtokenbean" scope="session" class="org.ejbca.ui.web.admin.hardtokeninterface.HardTokenInterfaceBean" />
<jsp:useBean id="helper" scope="session" class="org.ejbca.ui.web.admin.hardtokeninterface.EditHardTokenProfileJSPHelper" />

<% 

  // Initialize environment
  String includefile = "hardtokenprofilespage.jspf"; 


  GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, AvailableAccessRules.HARDTOKEN_EDITHARDTOKENPROFILES); 
                                            hardtokenbean.initialize(request, ejbcawebbean); 
                                            helper.initialize(ejbcawebbean, hardtokenbean);
  String THIS_FILENAME            =  globalconfiguration.getHardTokenPath()  + "/edithardtokenprofiles/edithardtokenprofiles.jsp";
  

  
 

%>
 
<head>
  <title><%= globalconfiguration .getEjbcaTitle() %></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>">
  <link rel=STYLESHEET href="<%= ejbcawebbean.getCssFile() %>">
  <script language=javascript src="<%= globalconfiguration .getAdminWebPath() %>ejbcajslib.js"></script>
</head>
<body>

<%  // Determine action 

  includefile = helper.parseRequest(request);

 // Include page
  if( includefile.equals("hardtokenprofilepage.jspf")){ 
%>
   <%@ include file="hardtokenprofilepage.jspf" %>
<%}
  if( includefile.equals("hardtokenprofilespage.jspf")){ %>
   <%@ include file="hardtokenprofilespage.jspf" %> 
<%} 
  if( includefile.equals("uploadtemplate.jspf")){ %>
   <%@ include file="uploadtemplate.jspf" %> 
<%}

   // Include Footer 
   String footurl =   globalconfiguration.getFootBanner(); %>
   
  <jsp:include page="<%= footurl %>" />

</body>
</html>

