<%@ page pageEncoding="ISO-8859-1"%>
<%@ page contentType="text/html; charset=@page.encoding@" %>
<%@page errorPage="errorpage.jsp" import="org.ejbca.core.model.ra.raadmin.GlobalConfiguration,org.ejbca.ui.web.RequestHelper,java.net.InetAddress,java.net.UnknownHostException" %>
<html>
<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />
<jsp:setProperty name="ejbcawebbean" property="*" /> 
<%   // Initialize environment
  GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request,"/administrator"); 
%>
<head>
  <title><%= globalconfiguration.getEjbcaTitle() %></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>">
  <link rel=STYLESHEET href="<%= ejbcawebbean.getCssFile() %>">
  <meta http-equiv="Content-Type" content="text/html; charset=<%= RequestHelper.getDefaultContentEncoding() %>">
</head>
<body>
<H5><DIV align=right><i><%= ejbcawebbean.getText("VERSION") + " " + GlobalConfiguration.EJBCA_VERSION%></i>
<%	if ( ejbcawebbean.isUsingExportableCryptography() ) { %>
	<div style="color: #FF0000; font-size: 0.7em;"><%= ejbcawebbean.getText("EXPORTABLE") %></div>
<%	} %>
</div></H5> 

<H3><%= ejbcawebbean.getText("WELCOME") + " " + ejbcawebbean.getUsersCommonName() + " " + ejbcawebbean.getText("TOEJBCA")%> </H3> 
<div align=left><i><%= ejbcawebbean.getText("NODEHOSTNAME") + " : "+ejbcawebbean.getHostName()%></i></div> 

<p>&nbsp;</p>
<%@ include file="statuspages/publisherqueuestatuses.jspf" %>

<% // Include Footer 
   String footurl =   globalconfiguration.getFootBanner(); %>
   
  <jsp:include page="<%= footurl %>" />
</body>
</html>
