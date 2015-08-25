<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@page pageEncoding="ISO-8859-1" errorPage="errorpage.jsp"%>
<%@page import="org.ejbca.config.GlobalConfiguration"%>
<%@page import="org.ejbca.config.WebConfiguration"%>
<%@page import="org.ejbca.core.model.authorization.AccessRulesConstants"%>
<%@page import="org.ejbca.ui.web.RequestHelper"%>
<% response.setContentType("text/html; charset="+WebConfiguration.getWebContentEncoding()); %>
<html>
<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />
<jsp:setProperty name="ejbcawebbean" property="*" /> 
<%   // Initialize environment
  GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, AccessRulesConstants.ROLE_ADMINISTRATOR); 
%>
<head>
  <title><c:out value="<%= globalconfiguration.getEjbcaTitle() %>" /></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>" />
  <link rel="shortcut icon" href="<%=ejbcawebbean.getImagefileInfix("favicon.png")%>" type="image/png" />
  <link rel="stylesheet" type="text/css" href="<c:out value='<%=ejbcawebbean.getCssFile() %>' />" />
  <meta http-equiv="Content-Type" content="text/html; charset=<%= WebConfiguration.getWebContentEncoding() %>" />
</head>

<frameset rows="100,*" cols="*" frameborder="NO" border="0" framespacing="0"> 
  <frame name="<%= globalconfiguration.HEADERFRAME %>" scrolling="NO" noresize src="<%= globalconfiguration.getHeadBanner() %>" >
  <frameset cols="250,*" frameborder="NO" border="0" framespacing="0" rows="*"> 
    <frame name="<%= globalconfiguration.MENUFRAME %>" noresize scrolling="NO" src="<%= globalconfiguration.getAdminWebPath() +
                                                                                        globalconfiguration.getMenuFilename() %>">
    <frame name="<%= globalconfiguration.MAINFRAME %>" src="<%= globalconfiguration.getAdminWebPath() + globalconfiguration.getMainFilename() %>">
  </frameset>
</frameset>
<noframes>
<body>
  <h1><%= ejbcawebbean.getText("ERRORNOBROWSER") %></h1>
</body>
</noframes>
</html>
