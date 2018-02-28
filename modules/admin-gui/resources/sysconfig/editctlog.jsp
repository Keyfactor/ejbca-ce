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
  <link rel="shortcut icon" href="<%=ejbcawebbean.getImagefileInfix("favicon.png")%>" type="image/png" />
  <script src="<%= globalconfiguration.getAdminWebPath() %>ejbcajslib.js"></script>
</head>
<body>
<jsp:include page="../adminmenu.jsp" />
<div class="main-wrapper">
<div class="container">
    <h1>
        <h:outputText value="#{web.text.CTLOGCONFIGURATION_EDITLOG}: #{systemConfigMBean.ctLogManager.ctLogEditor.ctLogBeingEdited.url}"/>
        <%= ejbcawebbean.getHelpReference("/Certificate_Transparency.html") %>
    </h1>
    <div class="message">
        <h:messages layout="table" errorClass="alert" infoClass="info"/>
    </div>
    <h:form id="currentCustomCertExtensionForm" enctype="multipart/form-data">
        <h:panelGrid columns="2">
            <h:outputLink value="adminweb/sysconfig/systemconfiguration.jsf">
                <h:outputText value="#{web.text.BACK}"/>
            </h:outputLink>
            <h:panelGroup id="placeholder1"/>

            <h:outputText value="#{web.text.CTLOGCONFIGURATION_URL}"/>
            <h:inputText value="#{systemConfigMBean.ctLogManager.ctLogEditor.ctLogUrl}" size="46"/>
            
            <h:outputText value="#{web.text.CTLOGCONFIGURATION_CURRENT_PUBLICKEY}"/>
            <h:outputText value="#{systemConfigMBean.ctLogManager.ctLogEditor.ctLogBeingEdited.logKeyIdString}" styleClass="monospace"/>
            
            <h:outputText value="#{web.text.CTLOGCONFIGURATION_REPLACE_PUBLICKEY} "/>
            <t:inputFileUpload id="editedCTLogKeyFile" 
                value="#{systemConfigMBean.ctLogManager.ctLogEditor.publicKeyFile}" 
                title="#{web.text.CTLOGCONFIGURATION_NEW_PUBLICKEYFILE}"/>
            
            <h:outputText value="#{web.text.CTLOGCONFIGURATION_TIMEOUT}"/>
            <h:inputText id="editedCTLogTimeout" 
                required="true"
                value="#{systemConfigMBean.ctLogManager.ctLogEditor.ctLogTimeout}"
                title="#{web.text.FORMAT_MILLISECONDS}"
                size="10"/>
            <h:outputText value="#{web.text.LABEL}"/>
            <h:inputText id="editedCtLogLabel"
                required="true"
                value="#{systemConfigMBean.ctLogManager.ctLogEditor.ctLogLabel}"
                size="46"/>
        </h:panelGrid>
        
        <h3><h:outputLabel value="#{web.text.CONSTRAINTS}"/></h3>
        <div class="block">
	         <h:selectBooleanCheckbox id="enableExpirationYearAcceptanceRule"
	             styleClass="checkbox"
	             value="#{systemConfigMBean.ctLogManager.ctLogEditor.isAcceptingByExpirationYear}" /> 
	         <h:outputLabel for="enableExpirationYearAcceptanceRule" 
	             value="#{web.text.ACCEPTING_BASED_ON_YEAR_OF_EXPIRY}" />
	    </div>
	    <div class="block">
	         <h:outputText value="#{web.text.YEAR}"
	             styleClass="textLabel"/>
             <h:inputText id="expirationYearRequired"
                 value="#{systemConfigMBean.ctLogManager.ctLogEditor.expirationYearRequired}" />
	    </div>
        <h:commandButton action="#{systemConfigMBean.ctLogManager.saveCtLogBeingEdited}" value="#{web.text.SAVE}" />
    </h:form>
    </div> <!-- Container -->
    <%  // Include Footer 
    String footurl = globalconfiguration.getFootBanner(); %>
    <jsp:include page="<%= footurl %>" />
</div> <!-- main-wrapper -->
</body>
</f:view>
</html>
