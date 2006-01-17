<%@ page pageEncoding="ISO-8859-1"%>
<%@page errorPage="../errorpage.jsp" import="org.ejbca.core.model.ra.raadmin.GlobalConfiguration"%>
<html>
<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />
<jsp:setProperty name="ejbcawebbean" property="*" /> 
<%   // Initialize environment
  GlobalConfiguration  globalconfiguration = ejbcawebbean.initialize(request,"/administrator"); 
%>
<head>
  <title><%= globalconfiguration .getEjbcaTitle() %></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>">
  <link rel=STYLESHEET href="<%= ejbcawebbean.getCssFile() %>">
 </head>
<body>
<img src="<%= ejbcawebbean.getImagefileInfix("@ejbca@header.jpg") %>" width="800" height="100" border="0">
</body>
</html>
