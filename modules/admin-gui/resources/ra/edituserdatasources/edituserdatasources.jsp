<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ page pageEncoding="ISO-8859-1"%>
<% response.setContentType("text/html; charset="+org.ejbca.config.WebConfiguration.getWebContentEncoding()); %>
<%@page errorPage="/errorpage.jsp" import="java.util.*, org.ejbca.ui.web.admin.configuration.EjbcaWebBean,org.ejbca.config.GlobalConfiguration, org.ejbca.core.model.SecConst, 
              org.cesecore.authorization.AuthorizationDeniedException, org.ejbca.core.model.authorization.AccessRulesConstants,
               org.ejbca.ui.web.admin.rainterface.RAInterfaceBean, org.ejbca.core.model.ra.userdatasource.*, org.ejbca.ui.web.admin.rainterface.EditUserDataSourceJSPHelper, 
               org.cesecore.certificates.util.DNFieldExtractor"%>

<html>
<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />
<jsp:useBean id="rabean" scope="session" class="org.ejbca.ui.web.admin.rainterface.RAInterfaceBean" />
<jsp:useBean id="userdatasourcehelper" scope="session" class="org.ejbca.ui.web.admin.rainterface.EditUserDataSourceJSPHelper" />

<% 

  // Initialize environment
  String includefile = "userdatasourcespage.jspf"; 


  GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, AccessRulesConstants.ROLE_ADMINISTRATOR, AccessRulesConstants.REGULAR_EDITUSERDATASOURCES); 
                                            rabean.initialize(request, ejbcawebbean); 
                                            userdatasourcehelper.initialize(request,ejbcawebbean, rabean);
  String THIS_FILENAME            =  globalconfiguration.getRaPath()  + "/edituserdatasources/edituserdatasources.jsp";
  
%>
 
<head>
  <title><c:out value="<%= globalconfiguration.getEjbcaTitle() %>" /></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>" />
  <link rel="stylesheet" type="text/css" href="<c:out value='<%=ejbcawebbean.getCssFile() %>' />" />
  <script type="text/javascript" src="<%= globalconfiguration .getAdminWebPath() %>ejbcajslib.js"></script>
</head>

<body>

<%  // Determine action 

  includefile = userdatasourcehelper.parseRequest(request);

 // Include page
  if( includefile.equals("userdatasourcepage.jspf")){ 
%>
   <%@ include file="userdatasourcepage.jspf" %>
<%}
  if( includefile.equals("userdatasourcespage.jspf")){ %>
   <%@ include file="userdatasourcespage.jspf" %> 
<%} 

   // Include Footer 
   String footurl =   globalconfiguration.getFootBanner(); %>
   
  <jsp:include page="<%= footurl %>" />

</body>
</html>
