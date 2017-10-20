<%
/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

 // Version: $Id: customcertextension.jsp$
%>
<%@ taglib uri="http://java.sun.com/jsf/html" prefix="h" %>
<%@ taglib uri="http://java.sun.com/jsf/core" prefix="f" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib uri="http://myfaces.apache.org/tomahawk" prefix="t" %>
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
  <title><h:outputText value="#{web.ejbcaWebBean.globalConfiguration.ejbcaTitle}" /></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>" />
  <link rel="stylesheet" type="text/css" href="<c:out value='<%=ejbcawebbean.getCssFile() %>' />" />
  <script src="<%= globalconfiguration.getAdminWebPath() %>ejbcajslib.js"></script>
</head>
<body>
    <h1>
        <h:outputText value="#{web.text.CTLOGCONFIGURATION_EDITLOG}: #{systemConfigMBean.editedCTLogDisplayName}"/>
        <%= ejbcawebbean.getHelpReference("/adminguide.html#Certificate%20Transparency%20(Enterprise%20only)") %>
    </h1>
    <div class="message"><h:messages layout="table" errorClass="alert" infoClass="info"/></div>
    <h:form id="currentCustomCertExtensionForm" enctype="multipart/form-data">
        <h:panelGrid columns="2">
            <h:outputLink value="adminweb/sysconfig/systemconfiguration.jsf"><h:outputText value="#{web.text.BACK}"/></h:outputLink>
            <h:panelGroup id="placeholder1"/>

            <h:outputText value="#{web.text.CTLOGCONFIGURATION_URL}"/>
            <h:inputText value="#{systemConfigMBean.editedCTLogURL}" size="46"/>
            
            <h:outputText value="#{web.text.CTLOGCONFIGURATION_CURRENT_PUBLICKEY}"/>
            <h:outputText value="#{systemConfigMBean.editedCTLogPublicKeyID}" styleClass="monospace"/>
            
            <h:outputText value="#{web.text.CTLOGCONFIGURATION_REPLACE_PUBLICKEY} "/>
            <t:inputFileUpload id="editedCTLogKeyFile" value="#{systemConfigMBean.editedCTLogPublicKeyFile}" title="#{web.text.CTLOGCONFIGURATION_NEW_PUBLICKEYFILE}"/>
            
            <h:outputText value="#{web.text.CTLOGCONFIGURATION_TIMEOUT}"/>
            <h:inputText id="editedCTLogTimeout" required="true"
                                    value="#{systemConfigMBean.editedCTLogTimeout}"
                                    title="#{web.text.FORMAT_MILLISECONDS}"
                                    size="10"/>
            <h:panelGroup />
            <h:panelGrid columns="2">
                <h:selectBooleanCheckbox id="isCtLogMandatory" value="#{systemConfigMBean.isEditedCtLogMandatory}" />
                <h:outputLabel for="isCtLogMandatory" value="#{web.text.MANDATORY}" />
            </h:panelGrid>
        </h:panelGrid>
        <h:commandButton action="#{systemConfigMBean.saveEditedCTLog}" value="#{web.text.SAVE}" />
    </h:form>
    <%  // Include Footer 
    String footurl = globalconfiguration.getFootBanner(); %>
    <jsp:include page="<%= footurl %>" />
</body>
</f:view>
</html>
