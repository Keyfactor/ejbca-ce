<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ page pageEncoding="ISO-8859-1"%>
<%@ page contentType="text/html;" %>
<%@ page isErrorPage="true" import="org.ejbca.config.GlobalConfiguration, org.cesecore.authorization.AuthorizationDeniedException,
                                   org.cesecore.authentication.AuthenticationFailedException, org.cesecore.keys.token.CryptoTokenOfflineException,
                                   org.ejbca.ui.web.ParameterException, org.ejbca.config.WebConfiguration"%>
<jsp:useBean id="ejbcawebbean" scope="request" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />
<jsp:setProperty name="ejbcawebbean" property="*" /> 

<%  // Initialize environment
    GlobalConfiguration globalconfiguration = ejbcawebbean.initialize_errorpage(request);
%>
<html>
<head>
    <title><c:out value="<%= globalconfiguration.getEjbcaTitle() %>" /></title>
    <base href="<%= ejbcawebbean.getBaseUrl() %>" />
    <link rel="stylesheet" type="text/css" href="<c:out value='<%=ejbcawebbean.getCssFile() %>' />" />
    <link rel="shortcut icon" href="<%=ejbcawebbean.getImagefileInfix("favicon.png")%>" type="image/png" />
    <meta http-equiv="Content-Type" content="text/html; charset=<%= WebConfiguration.getWebContentEncoding() %>" />
</head>

<body>
<br/>
<br/>
<%  if (exception instanceof AuthorizationDeniedException || exception instanceof AuthenticationFailedException) {
        // Print Authorization Denied Exception.%>
        <H2><c:out value='<%= ejbcawebbean.getText(\"AUTHORIZATIONDENIED\") %>' /></H2>
        <H4><c:out value='<%= ejbcawebbean.getText(\"CAUSE\") + \" : \" + exception.getMessage() %>' /></H4><%
        response.setStatus(HttpServletResponse.SC_OK);
        response.addHeader("X-FRAME-OPTIONS", "DENY" );
        response.addHeader("content-security-policy", "default-src 'none'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self'; frame-src 'self'; reflected-xss block" );
        response.addHeader("x-content-security-policy", "default-src 'none'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self'; frame-src 'self'; reflected-xss block" );
    } else if (exception instanceof CryptoTokenOfflineException) {
        // Print CryptoTokenOfflineException. %>
        <H2><c:out value='<%= ejbcawebbean.getText(\"CATOKENISOFFLINE\") %>' /></H2>
        <H4><c:out value='<%= ejbcawebbean.getText(\"CAUSE\") + \" : \" + exception.getMessage() %>' /></H4><%
        response.setStatus(HttpServletResponse.SC_OK);
        response.addHeader("X-FRAME-OPTIONS", "DENY" );
        response.addHeader("content-security-policy", "default-src 'none'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self'; frame-src 'self'; reflected-xss block" );
        response.addHeader("x-content-security-policy", "default-src 'none'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self'; frame-src 'self'; reflected-xss block" );
    } else if (exception instanceof ParameterException) { %>
        <h2><c:out value="<%= exception.getLocalizedMessage() %>" /></h2><%
            response.setStatus(HttpServletResponse.SC_OK);
            } else if (exception instanceof org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException) {
        %>
        <H2><c:out value='<%= WebConfiguration.notification(ejbcawebbean.getText(\"EXCEPTIONOCCURED\")) %>' /></H2>
        <H4><c:out value="<%= exception.getLocalizedMessage() %>" /></H4><%
        org.apache.log4j.Logger.getLogger("errorpage.jsp").info(exception.getMessage());
        response.setStatus(HttpServletResponse.SC_OK);
        response.addHeader("X-FRAME-OPTIONS", "DENY" );
        response.addHeader("content-security-policy", "default-src 'none'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self'; frame-src 'self'; reflected-xss block" );
        response.addHeader("x-content-security-policy", "default-src 'none'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self'; frame-src 'self'; reflected-xss block" );
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
        response.addHeader("X-FRAME-OPTIONS", "DENY" );
        response.addHeader("content-security-policy", "default-src 'none'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self'; frame-src 'self'; reflected-xss block" );
        response.addHeader("x-content-security-policy", "default-src 'none'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self'; frame-src 'self'; reflected-xss block" );
    }
%>
</body>
</html>
