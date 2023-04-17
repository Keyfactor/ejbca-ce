<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ page pageEncoding="ISO-8859-1"%>
<%@ page contentType="text/html;" %>
<%@ page isErrorPage="true" import="org.ejbca.config.GlobalConfiguration, org.cesecore.authorization.AuthorizationDeniedException,
                                   org.cesecore.authentication.AuthenticationFailedException,com.keyfactor.util.keys.token.CryptoTokenOfflineException,
                                   org.ejbca.ui.web.ParameterException, org.ejbca.config.WebConfiguration, org.ejbca.ui.web.jsf.configuration.EjbcaWebBean"%>
<jsp:useBean id="ejbcawebbean" scope="request" type="org.ejbca.ui.web.jsf.configuration.EjbcaWebBean" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBeanImpl" />
<jsp:setProperty name="ejbcawebbean" property="*" /> 

<%  // Initialize environment
    GlobalConfiguration globalconfiguration = ejbcawebbean.initialize_errorpage(request);
%>
<html>
<head>
    <title><c:out value="<%= globalconfiguration.getEjbcaTitle() %>" /></title>
    <link rel="stylesheet" type="text/css" href="<c:out value='<%= ejbcawebbean.getBaseUrl() + ejbcawebbean.getCssFile() %>' />" />
    <link rel="shortcut icon" href="<%=ejbcawebbean.getAdminWebBaseUrl() + ejbcawebbean.getImagePath("favicon.png")%>" type="image/png" />
    <meta http-equiv="Content-Type" content="text/html; charset=<%= WebConfiguration.getWebContentEncoding() %>" />
</head>

<body>
<br/>
<br/>
<%  if (exception instanceof AuthorizationDeniedException) {
        // Print Authorization Denied Exception.%>
        <H2><c:out value='<%= ejbcawebbean.getText(\"AUTHORIZATIONDENIED\") %>' /></H2>
        <H4><c:out value='<%= ejbcawebbean.getText(\"CAUSE\") + \" : \" + exception.getMessage() %>' /></H4><%
        response.setStatus(HttpServletResponse.SC_OK);
        response.addHeader("X-FRAME-OPTIONS", "DENY" );
    } else if (exception instanceof AuthenticationFailedException) {
        // Redirect to the login page.
        response.addHeader("X-FRAME-OPTIONS", "DENY" );
        response.sendRedirect("/ejbca/adminweb/login.xhtml");;
    } else if (exception instanceof CryptoTokenOfflineException) {
        // Print CryptoTokenOfflineException. %>
        <H2><c:out value='<%= ejbcawebbean.getText(\"CATOKENISOFFLINE\") %>' /></H2>
        <H4><c:out value='<%= ejbcawebbean.getText(\"CAUSE\") + \" : \" + exception.getMessage() %>' /></H4><%
        response.setStatus(HttpServletResponse.SC_OK);
        response.addHeader("X-FRAME-OPTIONS", "DENY" );
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
    }
%>
</body>
</html>
