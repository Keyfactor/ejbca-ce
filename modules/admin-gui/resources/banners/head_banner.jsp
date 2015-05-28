<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ page pageEncoding="ISO-8859-1"%>
<% response.setContentType("text/html; charset="+org.ejbca.config.WebConfiguration.getWebContentEncoding()); %>
<%@page errorPage="../errorpage.jsp" import="org.ejbca.config.GlobalConfiguration"%>
<html>
<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />
<jsp:setProperty name="ejbcawebbean" property="*" /> 
<%	// Initialize environment
	GlobalConfiguration  globalconfiguration = ejbcawebbean.initialize(request,"/administrator"); 
%>
<head>
    <title><c:out value="<%= globalconfiguration.getEjbcaTitle() %>" /></title>
	<base href="<%= ejbcawebbean.getBaseUrl() %>" />
	<link rel="stylesheet" type="text/css" media="all" href="<%= ejbcawebbean.getCssFile() %>" />
</head>

<body id="header">
	<div id="banner">
		<a href="<%= ejbcawebbean.getBaseUrl() + globalconfiguration.getAdminWebPath() %>" target="_top"><img src="<%= ejbcawebbean.getImagefileInfix("banner_"+org.ejbca.config.InternalConfiguration.getAppNameLower()+"-admin.png") %>" alt="<c:out value="<%= globalconfiguration.getEjbcaTitle() %>" />" /></a>
		<h0>Administration</h0>
	</div>
</body>
</html>
