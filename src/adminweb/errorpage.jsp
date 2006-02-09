<%@ page pageEncoding="ISO-8859-1"%>
<%@ page contentType="text/html; charset=@page.encoding@" %>
<%@page isErrorPage="true" import="org.ejbca.core.model.ra.raadmin.GlobalConfiguration, org.ejbca.core.model.authorization.AuthorizationDeniedException,
                                   org.ejbca.core.model.authorization.AuthenticationFailedException"%>

<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />
<jsp:setProperty name="ejbcawebbean" property="*" /> 

<%   // Initialize environment
   GlobalConfiguration globalconfiguration = ejbcawebbean.initialize_errorpage(request);

%>
<html>
<head>
  <title><%= globalconfiguration.getEjbcaTitle() %></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>">
  <link rel=STYLESHEET href="<%= ejbcawebbean.getCssFile() %>">
</head>
<body>
<br>
<br>
<% if( exception instanceof AuthorizationDeniedException){
       // Print Authorization Denied Exception.
     out.write("<H2>" + ejbcawebbean.getText("AUTHORIZATIONDENIED") + "</H2>");
     out.write("<H4>" + ejbcawebbean.getText("CAUSE") + " : " + exception.getMessage() + "</H4>");
     exception.printStackTrace() ; // TODO Remove
   }
   else
   if( exception instanceof AuthenticationFailedException){
       // Print Authorization Denied Exception.
     out.write("<H2>" + ejbcawebbean.getText("AUTHORIZATIONDENIED") + "</H2>");
     out.write("<H4>" + ejbcawebbean.getText("CAUSE") + " : " + exception.getMessage() + "</H4>");
   }else{
       // Other exception occured, print exception and stack trace.   
     out.write("<H2>" + ejbcawebbean.getText("EXCEPTIONOCCURED") + "</H2>");
     out.write("<H4>" + exception.toString() + " : " + exception.getMessage() + "</H4>");
     exception.printStackTrace() ;
   }
%>


</body>
</html>
