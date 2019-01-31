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
	<link rel="stylesheet" type="text/css" media="all" href="<c:out value='<%=ejbcawebbean.getCssFile() %>' />" />
</head>

<%
/*
    Note since EJBCA 6.12.0: A hard coded head banner is built in into the default
    template, to avoid having to include this file through an <iframe> element.
    The hard coded variant is used when the head banner is set to "head_banner.jsp".
    
    If you want to customize the head banner, please copy/rename this file
    (otherwise it won't be included) and change the setting under System
    Configuration.
    
    If a custom head banner is configured, then it will be included in a
    100px high 100% wide <iframe> at the top of each page.
*/
%>
<body id="header">
	<div id="banner">
		<a href="<%= ejbcawebbean.getBaseUrl() + globalconfiguration.getAdminWebPath() %>" target="_top"><img src="<%= ejbcawebbean.getImagefileInfix("banner_"+org.ejbca.config.InternalConfiguration.getAppNameLower()+"-admin.png") %>" alt="<c:out value="<%= org.ejbca.config.InternalConfiguration.getAppNameCapital() %>" />" /></a>
	</div>
</body>
</html>
