<%@ page pageEncoding="ISO-8859-1"%>
<% response.setContentType("text/html; charset="+org.ejbca.config.WebConfiguration.getWebContentEncoding()); %>
<%@page errorPage="../errorpage.jsp" import="org.ejbca.core.model.ra.raadmin.GlobalConfiguration"%>
<html>
<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />
<jsp:setProperty name="ejbcawebbean" property="*" /> 
<%	// Initialize environment
	GlobalConfiguration  globalconfiguration = ejbcawebbean.initialize(request,"/administrator"); 
%>
<head>
	<title><%= globalconfiguration .getEjbcaTitle() %></title>
	<base href="<%= ejbcawebbean.getBaseUrl() %>" />
	<link rel="stylesheet" type="text/css" media="all" href="<%= ejbcawebbean.getCssFile() %>" />
</head>

<body id="header">
	<div id="banner">
		<img src="<%= ejbcawebbean.getImagefileInfix("banner_"+org.ejbca.config.InternalConfiguration.getAppNameLower()+"-admin.png") %>" alt="<%= globalconfiguration .getEjbcaTitle() %>" />
	</div>
</body>
</html>
