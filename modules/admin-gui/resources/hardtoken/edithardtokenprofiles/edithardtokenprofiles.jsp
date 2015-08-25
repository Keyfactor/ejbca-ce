<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ page pageEncoding="ISO-8859-1"%>
<% response.setContentType("text/html; charset="+org.ejbca.config.WebConfiguration.getWebContentEncoding()); %>
<%@page errorPage="/errorpage.jsp" import="java.util.*, org.ejbca.ui.web.admin.configuration.EjbcaWebBean,org.ejbca.config.GlobalConfiguration, org.ejbca.core.model.SecConst, org.cesecore.authorization.AuthorizationDeniedException,
               org.ejbca.core.model.authorization.AccessRulesConstants,
               org.ejbca.ui.web.admin.hardtokeninterface.HardTokenInterfaceBean, org.ejbca.core.model.hardtoken.profiles.*, org.ejbca.ui.web.admin.hardtokeninterface.EditHardTokenProfileJSPHelper, 
               org.ejbca.core.model.hardtoken.HardTokenProfileExistsException,
               org.cesecore.certificates.certificateprofile.CertificateProfileConstants"%>

<html>
<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />
<jsp:useBean id="hardtokenbean" scope="session" class="org.ejbca.ui.web.admin.hardtokeninterface.HardTokenInterfaceBean" />
<jsp:useBean id="edithardtokenprofile" scope="session" class="org.ejbca.ui.web.admin.hardtokeninterface.EditHardTokenProfileJSPHelper" />

<% 

  // Initialize environment
  String includefile = "hardtokenprofilespage.jspf"; 


  GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, AccessRulesConstants.ROLE_ADMINISTRATOR, AccessRulesConstants.HARDTOKEN_EDITHARDTOKENPROFILES); 
                                            hardtokenbean.initialize(request, ejbcawebbean); 
                                            edithardtokenprofile.initialize(ejbcawebbean, hardtokenbean);
  String THIS_FILENAME            =  globalconfiguration.getHardTokenPath()  + "/edithardtokenprofiles/edithardtokenprofiles.jsp";
  

  
 

%>
 
<head>
  <title><c:out value="<%= globalconfiguration.getEjbcaTitle() %>" /></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>" />
  <link rel="stylesheet" type="text/css" href="<c:out value='<%=ejbcawebbean.getCssFile() %>' />" />
  <script type="text/javascript" src="<%= globalconfiguration .getAdminWebPath() %>ejbcajslib.js"></script>
</head>

<body>

<%  // Determine action 

  includefile = edithardtokenprofile.parseRequest(request);

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

