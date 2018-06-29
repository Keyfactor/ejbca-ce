<%
    // Version: $Id$
%>
<%@ taglib uri="http://java.sun.com/jsf/html" prefix="h" %>
<%@ taglib uri="http://java.sun.com/jsf/core" prefix="f" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ page pageEncoding="UTF-8"%>
<% response.setContentType("text/html; charset="+org.ejbca.config.WebConfiguration.getWebContentEncoding()); %>
<%@page errorPage="/errorpage.jsp" import="
org.ejbca.ui.web.admin.configuration.EjbcaWebBean,
org.ejbca.config.GlobalConfiguration,
org.ejbca.core.model.authorization.AccessRulesConstants,
org.cesecore.authorization.control.AuditLogRules,
org.cesecore.authorization.control.StandardRules
"%>

<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />
<%
    GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, AccessRulesConstants.ROLE_ADMINISTRATOR, StandardRules.SYSTEMCONFIGURATION_VIEW.resource());
%>
<html>
<f:view>
    <head>
        <title><h:outputText value="#{web.ejbcaWebBean.globalConfiguration.ejbcaTitle}"/></title>
        <base href="<%= ejbcawebbean.getBaseUrl() %>"/>
        <link rel="stylesheet" type="text/css" href="<c:out value='<%=ejbcawebbean.getCssFile() %>' />"/>
        <link rel="shortcut icon" href="<%=ejbcawebbean.getImagefileInfix("favicon.png")%>" type="image/png"/>
        <script src="<%= globalconfiguration.getAdminWebPath() %>ejbcajslib.js"></script>
    </head>
    <body>
    <jsp:include page="../adminmenu.jsp"/>
    <div class="main-wrapper">
        <div class="container">
            <h1>
                <h:outputText value="#{acmeConfigMBean.currentAlias.alias}"/>
            </h1>

        </div> <!-- Container -->

        <% // Include Footer
            String footurl = globalconfiguration.getFootBanner(); %>
        <jsp:include page="<%= footurl %>"/>
    </div> <!-- main-wrapper -->
    </body>
</f:view>
</html>