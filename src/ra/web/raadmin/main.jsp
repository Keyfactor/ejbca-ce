<html>
<%@page contentType="text/html"%>
<%@page  errorPage="errorpage.jsp" import="se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean, se.anatom.ejbca.webdist.webconfiguration.GlobalConfiguration " %>
<jsp:useBean id="ejbcawebbean" scope="session" class="se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean" />
<jsp:setProperty name="ejbcawebbean" property="*" /> 
<%   // Initialize environment
   ejbcawebbean.initialize(request); 
%>
<head>
  <title><%= GlobalConfiguration.getEjbcaTitle() %></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>">
  <link rel=STYLESHEET href="<%= ejbcawebbean.getCssFile() %>">
</head>
<body>
<H3><%= ejbcawebbean.getText("WELCOME") + " " + ejbcawebbean.getUsersCommonName() + " " + ejbcawebbean.getText("TOEJBCA")%> </H3> 

<br><br>

Lite text

<% // Include Footer 
   String footurl =   GlobalConfiguration.getFootBanner(); %>
   
  <jsp:include page="<%= footurl %>" />
</body>
</html>
