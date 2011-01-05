<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ page pageEncoding="ISO-8859-1"%>
<%@ page contentType="text/html;" %>
<%@ page isErrorPage="true" import="org.ejbca.core.model.ra.raadmin.GlobalConfiguration, org.ejbca.core.model.authorization.AuthorizationDeniedException,
                                   org.ejbca.core.model.authorization.AuthenticationFailedException, org.ejbca.core.model.ca.catoken.CATokenOfflineException,
                                   org.ejbca.ui.web.ParameterError, org.ejbca.config.WebConfiguration"%>
<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />
<jsp:setProperty name="ejbcawebbean" property="*" /> 

<%  // Initialize environment
    GlobalConfiguration globalconfiguration = ejbcawebbean.initialize_errorpage(request);
%>
<html>
<head>
    <title><c:out value="<%= globalconfiguration.getEjbcaTitle() %>" /></title>
    <base href="<%= ejbcawebbean.getBaseUrl() %>">
    <link rel=STYLESHEET href="<%= ejbcawebbean.getCssFile() %>">
</head>
<body>
<br/>
<br/>
<%  if (exception instanceof AuthorizationDeniedException || exception instanceof AuthenticationFailedException) {
        // Print Authorization Denied Exception.%>
        <H2><c:out value='<%= ejbcawebbean.getText(\"AUTHORIZATIONDENIED\") %>' /></H2>
        <H4><c:out value='<%= ejbcawebbean.getText(\"CAUSE\") + \" : \" + exception.getMessage() %>' /></H4><%
        response.setStatus(HttpServletResponse.SC_OK);
    } else if (exception instanceof CATokenOfflineException) {
        // Print CATokenOfflineException. %>
        <H2><c:out value='<%= ejbcawebbean.getText(\"CATOKENISOFFLINE\") %>' /></H2>
        <H4><c:out value='<%= ejbcawebbean.getText(\"CAUSE\") + \" : \" + exception.getMessage() %>' /></H4><%
        response.setStatus(HttpServletResponse.SC_OK);
    } else if (exception instanceof ParameterError) { %>
        <h2><c:out value="${exception.localizedMessage}" /></h2><%
        response.setStatus(HttpServletResponse.SC_OK);
    } else if (exception instanceof org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile) { %>
        <H2><c:out value='<%= WebConfiguration.notification(ejbcawebbean.getText(\"EXCEPTIONOCCURED\")) %>' /></H2>
        <H4><c:out value="<%= exception.getLocalizedMessage() %>" /></H4><%
        org.apache.log4j.Logger.getLogger("errorpage.jsp").info(exception.getMessage());
        response.setStatus(HttpServletResponse.SC_OK);
    } else {
        // Other exception occurred, print exception and stack trace.%>
        <H2><c:out value='<%= WebConfiguration.notification(ejbcawebbean.getText(\"EXCEPTIONOCCURED\")) %>' /></H2>
        <H4><c:out value="<%= exception.getLocalizedMessage() %>" /></H4><%
        if ( WebConfiguration.doShowStackTraceOnErrorPage() ) {
            java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
            exception.printStackTrace(new java.io.PrintStream(baos));
            String stackTrace = new String(baos.toByteArray());%>
            <br/>
            <pre style="font-style: italic;"><c:out value="<%= stackTrace %>" /></pre><%
        }
        org.apache.log4j.Logger.getLogger("errorpage.jsp").error(exception.getMessage(), exception); // Prints in server.log
        response.setStatus(HttpServletResponse.SC_OK);
    }
%>
</body>
</html>
