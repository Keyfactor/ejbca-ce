<html>
<%@page contentType="text/html"%>
<%@page  errorPage="errorpage.jsp" import="se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean, se.anatom.ejbca.ra.GlobalConfiguration " %>
<jsp:useBean id="ejbcawebbean" scope="session" class="se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean" />
<jsp:setProperty name="ejbcawebbean" property="*" /> 
<%   // Initialize environment
   GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request); 
%>
<head>
  <title><%= globalconfiguration.getEjbcaTitle() %></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>">
  <link rel=STYLESHEET href="<%= ejbcawebbean.getCssFile() %>">
</head>
<body>
<H3><%= ejbcawebbean.getText("WELCOME") + " " + ejbcawebbean.getUsersCommonName() + " " + ejbcawebbean.getText("TOEJBCA")%> </H3> 

<br><br>
<p><%= ejbcawebbean.getText("EJBCAISAFULLY") %></p>
<p><%= ejbcawebbean.getText("WRITTENEXCLUSIVELY") %></p>


<% // Include Footer 
   String footurl =   globalconfiguration.getFootBanner(); %>
   
  <jsp:include page="<%= footurl %>" />
</body>
</html>
