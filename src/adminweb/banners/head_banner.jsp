<html>
<%@page contentType="text/html"%>
<%@page errorPage="../errorpage.jsp" import="se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean,se.anatom.ejbca.ra.GlobalConfiguration"%>
<jsp:useBean id="ejbcawebbean" scope="session" class="se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean" />
<jsp:setProperty name="ejbcawebbean" property="*" /> 
<%   // Initialize environment
  GlobalConfiguration  globalconfiguration = ejbcawebbean.initialize(request,"/"); 
%>
<head>
  <title><%= globalconfiguration .getEjbcaTitle() %></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>">
  <link rel=STYLESHEET href="<%= ejbcawebbean.getCssFile() %>">
  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">
 </head>
<body>
<img src="<%= ejbcawebbean.getImagefileInfix("ejbcaheader.jpg") %>" width="800" height="100" border="0">
</body>
</html>
