<html>
<%@page contentType="text/html"%>
<%@page  errorPage="errorpage.jsp" import="se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean, se.anatom.ejbca.ra.raadmin.GlobalConfiguration " %>
<jsp:useBean id="ejbcawebbean" scope="session" class="se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean" />
<jsp:setProperty name="ejbcawebbean" property="*" /> 
<%   // Initialize environments
   GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request,"/administrator"); 
%>
<head>
  <title><%= globalconfiguration.getEjbcaTitle() %></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>">
  <link rel=STYLESHEET href="<%= ejbcawebbean.getCssFile() %>">
</head>
<body>
<H5><DIV align=right><i><%= ejbcawebbean.getText("VERSION") + " " + GlobalConfiguration.EJBCA_VERSION%></i></div></H5> 

<H3><%= ejbcawebbean.getText("WELCOME") + " " + ejbcawebbean.getUsersCommonName() + " " + ejbcawebbean.getText("TOEJBCA")%> </H3> 

<br><br>
<p><%= ejbcawebbean.getText("EJBCAISAFULLY") %></p>
<p><%= ejbcawebbean.getText("WRITTENEXCLUSIVELY") %></p>

<% // Include Footer 
   String footurl =   globalconfiguration.getFootBanner(); %>
   
  <jsp:include page="<%= footurl %>" />
</body>
</html>
