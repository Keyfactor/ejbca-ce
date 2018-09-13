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
<%
    GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, AccessRulesConstants.ROLE_ADMINISTRATOR, StandardRules.CUSTOMCERTEXTENSIONCONFIGURATION_VIEW.resource());
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
<jsp:include page="../adminmenu.jsp" />

<div class="main-wrapper">
<div class="container">
	<h1>
		<h:outputText value="#{web.text.CUSTOMCERTEXTENSION}: #{customCertExtensionMBean.currentExtensionGUIInfo.displayName}"/>
		<%= ejbcawebbean.getHelpReference("/Custom_Certificate_Extensions.html") %>
	</h1>
	<div class="message"><h:messages layout="table" errorClass="alert" infoClass="info"/></div>
	<h:form id="currentCustomCertExtensionForm">
		<h:panelGrid columns="2">
			<h:outputLink value="adminweb/sysconfig/systemconfiguration.jsf"><h:outputText value="#{web.text.CUSTOMCERTEXTENSION_NAV_BACK}"/></h:outputLink>
			<h:panelGroup id="placeholder1"/>

			<h:outputLabel for="currentCEId" value="#{web.text.ID}"/>
    		<h:outputText id="currentCEId" value="#{customCertExtensionMBean.currentExtensionGUIInfo.id}" />
		
			<h:outputLabel for="currentCEOid" value="#{web.text.OID}"/>
    		<h:inputText id="currentCEOid" value="#{customCertExtensionMBean.currentExtensionGUIInfo.oid}" size="25" title="#{web.text.FORMAT_OID}"
    			disabled="#{!customCertExtensionMBean.allowedToEditCustomCertificateExtension}"/>
		
			<h:outputLabel for="currentCEDisplayName" value="#{web.text.LABEL}"/>
    		<h:inputText id="currentCEDisplayName" value="#{customCertExtensionMBean.currentExtensionGUIInfo.displayName}" size="35" title="#{web.text.FORMAT_STRING}"
    			disabled="#{!customCertExtensionMBean.allowedToEditCustomCertificateExtension}">
    			<f:validator validatorId="legalCharsValidator"/>
    		</h:inputText>

			<h:outputLabel for="currentCustomExtension" value="#{web.text.CUSTOMCERTEXTENSION_CLASS}"/>
			
			<h:selectOneMenu  id="currentCustomExtension" value="#{customCertExtensionMBean.currentExtensionGUIInfo.classPath}" title="#{web.text.FORMAT_CLASSPATH}"
				 onchange="document.getElementById('currentCustomCertExtensionForm:updateButton').click();" valueChangeListener="#{customCertExtensionMBean.updateExtension}"
				 disabled="#{!customCertExtensionMBean.allowedToEditCustomCertificateExtension}">
				<f:selectItems value="#{customCertExtensionMBean.availableCustomCertificateExtensions}"/>
			</h:selectOneMenu>
			<h:commandButton id="updateButton" action="#{customCertExtensionMBean.update}" value="#{web.text.UPDATE}" disabled="#{!customCertExtensionMBean.allowedToEditCustomCertificateExtension}"/>			
			<script>document.getElementById('currentCustomCertExtensionForm:updateButton').style.display = 'none'</script>
					
			<h:outputLabel for="currentCECritical" value="#{web.text.CRITICAL}"/>
			<h:panelGroup>
				<h:selectBooleanCheckbox id="currentCECritical" value="#{customCertExtensionMBean.currentExtensionGUIInfo.critical}"
					disabled="#{!customCertExtensionMBean.allowedToEditCustomCertificateExtension}"/>
			</h:panelGroup>
			<h:outputLabel for="currentCERequired" value="#{web.text.REQUIRED}"/>
			<h:panelGroup>
				<h:selectBooleanCheckbox id="currentCERequired" value="#{customCertExtensionMBean.currentExtensionGUIInfo.required}"
					disabled="#{!customCertExtensionMBean.allowedToEditCustomCertificateExtension}"/>
			</h:panelGroup>
		</h:panelGrid>
		<h2><h:outputText value="#{web.text.PROPERTIES}" /></h2>
		<h:dataTable value="#{customCertExtensionMBean.currentExtensionPropertiesList}" var="prop" styleClass="grid" style="border-collapse: collapse; right: auto; left: auto">
			<h:column>
   				<f:facet name="header"><h:outputText value="#{web.text.KEY}"/></f:facet>
				<h:outputText value="#{prop.label}" title="#{prop.label}"/>
			</h:column>
			<h:column>
   				<f:facet name="header"><h:outputText value="#{web.text.VALUE}"/></f:facet>
				<h:panelGroup>
					<h:inputText id="currentPropertyValue" value="#{prop.value}" size="35" rendered="#{prop.possibleValuesCount == 0}" disabled="#{!customCertExtensionMBean.allowedToEditCustomCertificateExtension}" />
					<h:selectOneMenu rendered="#{prop.possibleValuesCount > 0}" value="#{prop.value}" disabled="#{!customCertExtensionMBean.allowedToEditCustomCertificateExtension}">
						<f:selectItems value="#{prop.possibleValues}"/>
					</h:selectOneMenu>
				</h:panelGroup>			
			</h:column>			
		</h:dataTable>
	<h:commandButton action="#{customCertExtensionMBean.saveCurrentExtension}" value="#{web.text.SAVE}" rendered="#{customCertExtensionMBean.allowedToEditCustomCertificateExtension}" />
	</h:form>
	</div> <!-- Container -->
	<%	// Include Footer 
	String footurl = globalconfiguration.getFootBanner(); %>
	<jsp:include page="<%= footurl %>" />
</div> <!-- main-wrapper -->
</body>
</f:view>
</html>
