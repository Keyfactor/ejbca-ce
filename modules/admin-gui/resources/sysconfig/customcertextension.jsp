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
<% GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, AccessRulesConstants.ROLE_ADMINISTRATOR, StandardRules.REGULAR_EDITSYSTEMCONFIGURATION.resource()); %>
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
	    <h:outputText value="#{web.text.CUSTOMCERTEXTENSION_NEW}" rendered="#{systemConfigMBean.currentCEId == 0}"/>
		<h:outputText value="#{web.text.CUSTOMCERTEXTENSION} #{systemConfigMBean.currentCustomExtension.displayName}" rendered="#{systemConfigMBean.currentCEId != 0}"/>
	</h1>
	<div class="message"><h:messages layout="table" errorClass="alert" infoClass="info"/></div>
	<h:form id="currentCustomCertExtensionForm">
	<h:panelGrid columns="2">
		<h:outputLink value="adminweb/sysconfig/systemconfiguration.jsf"><h:outputText value="#{web.text.CUSTOMCERTEXTENSION_NAV_BACK}"/></h:outputLink>
		<h:commandButton action="#{systemConfigMBean.toggleCurrentCustomCertExtensionEditMode}" value="#{web.text.CRYPTOTOKEN_NAV_EDIT}" rendered="#{(!systemConfigMBean.currentCustomCertExtensionEditMode) && cryptoTokenMBean.allowedToModify}"/>
		<h:panelGroup id="placeholder1" rendered="#{systemConfigMBean.currentCustomCertExtensionEditMode || !systemConfigMBean.allowedToModify}"/>
		
		<h:outputLabel for="currentCEId" value="#{web.text.CRYPTOTOKEN_ID}:"/>
		<h:panelGroup id="currentCEId">
			<h:outputText value="#{systemConfigMBean.currentCEId}" rendered="#{systemConfigMBean.currentCEId != 0}"/>
			<h:inputText value="#{systemConfigMBean.currentCustomExtension.id}" rendered="#{systemConfigMBean.currentCEId == 0}"/>
		</h:panelGroup>
		
		<h:outputLabel for="currentCEOid" value="#{web.text.OID}:"/>
		<h:panelGroup id="currentCEOid">
	    	<h:inputText  value="#{systemConfigMBean.currentCustomExtension.oid}" rendered="#{systemConfigMBean.currentCustomCertExtensionEditMode}" />
	    	<h:outputText value="#{systemConfigMBean.currentCustomExtension.oid}" rendered="#{!systemConfigMBean.currentCustomCertExtensionEditMode}"/>
		</h:panelGroup>
		
		<h:outputLabel for="currentCEDisplayName" value="#{web.text.DISPLAYNAME}:"/>
		<h:panelGroup id="currentCEDisplayName">
	    	<h:inputText  value="#{systemConfigMBean.currentCustomExtension.displayName}" rendered="#{systemConfigMBean.currentCustomCertExtensionEditMode}">
	    		<f:validator validatorId="legalCharsValidator"/>
	    	</h:inputText>
	    	<h:outputText value="#{systemConfigMBean.currentCustomExtension.displayName}" rendered="#{!systemConfigMBean.currentCustomCertExtensionEditMode}"/>
		</h:panelGroup>

		<h:outputLabel for="currentCEClassPath" value="#{web.text.CUSTOMCERTEXTENSION_CLASSPATH}:"/>
		<h:panelGroup id="currentCEClassPath">
	    	<h:inputText  value="#{systemConfigMBean.currentCustomExtension.classPath}" rendered="#{systemConfigMBean.currentCustomCertExtensionEditMode}" />
	    	<h:outputText value="#{systemConfigMBean.currentCustomExtension.classPath}" rendered="#{!systemConfigMBean.currentCustomCertExtensionEditMode}"/>
		</h:panelGroup>
		
		<h:outputLabel for="currentCECritical" value="#{web.text.CRITICAL}:"/>
		<h:selectBooleanCheckbox id="currentCECritical" value="#{systemConfigMBean.currentCustomExtension.critical}"
			disabled="#{!systemConfigMBean.currentCustomCertExtensionEditMode}"/>

		<h:outputLabel for="currentCEProperties" value="#{web.text.PROPERTIES}:"/>
		<h:panelGroup id="currentCEProperties">
	    	<h:inputText  value="#{systemConfigMBean.currentCustomExtension.properties}" rendered="#{systemConfigMBean.currentCustomCertExtensionEditMode}" />
	    	<h:outputText value="#{systemConfigMBean.currentCustomExtension.properties}" rendered="#{!systemConfigMBean.currentCustomCertExtensionEditMode}"/>
		</h:panelGroup>


		<h:panelGroup>
			<h:commandButton action="#{systemConfigMBean.cancelCurrentCustomExtension}" value="#{web.text.CRYPTOTOKEN_CANCEL}" rendered="#{systemConfigMBean.currentCustomCertExtensionEditMode && systemConfigMBean.currentCEId != 0}"/>
			<h:commandButton action="#{systemConfigMBean.saveCurrentCustomCertExtension}" value="#{web.text.CRYPTOTOKEN_SAVE}" rendered="#{systemConfigMBean.currentCustomCertExtensionEditMode}"/>
		</h:panelGroup>
	</h:panelGrid>
	</h:form>

	
	<%	// Include Footer 
	String footurl = globalconfiguration.getFootBanner(); %>
	<jsp:include page="<%= footurl %>" />
</body>
</f:view>
</html>
