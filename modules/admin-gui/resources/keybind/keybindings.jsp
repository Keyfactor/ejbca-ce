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

 // Version: $Id$
%>
<%@ taglib uri="http://java.sun.com/jsf/html" prefix="h" %>
<%@ taglib uri="http://java.sun.com/jsf/core" prefix="f" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib uri="http://myfaces.apache.org/tomahawk" prefix="t" %>
<%@ page pageEncoding="UTF-8"%>
<% response.setContentType("text/html; charset="+org.ejbca.config.WebConfiguration.getWebContentEncoding()); %>
<%@ page errorPage="/errorpage.jsp" import="
org.ejbca.ui.web.admin.configuration.EjbcaWebBean,
org.ejbca.config.GlobalConfiguration,
org.ejbca.core.model.authorization.AccessRulesConstants,
org.cesecore.keybind.InternalKeyBindingRules
"%>
<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />
<% GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, AccessRulesConstants.ROLE_ADMINISTRATOR, InternalKeyBindingRules.VIEW.resource()); %>
<html>
<f:view>
<head>
  <title><h:outputText value="#{web.ejbcaWebBean.globalConfiguration.ejbcaTitle}" /></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>" />
  <link rel="stylesheet" type="text/css" href="<c:out value='<%=ejbcawebbean.getCssFile() %>' />" />
  <script src="<%= globalconfiguration.getAdminWebPath() %>ejbcajslib.js"></script>
</head>
<body>
	<h:outputText value="" rendered="#{internalKeyBindingMBean.pageLoadResetTrigger}"/>
	<h1>
		<h:outputText value="#{web.text.INTERNALKEYBINDINGS}"/>
		<%= ejbcawebbean.getHelpReference("/userguide.html#Managing%20Internal%20Key%20Bindings") %>
	</h1>
	<div class="message"><h:messages layout="table" errorClass="alert" infoClass="infoMessage"/></div>
	<div class="tabLinks">
		<c:forEach items="#{internalKeyBindingMBean.availableKeyBindingTypes}" var="type">
		<span>
			<h:outputLink value="adminweb/keybind/keybindings.jsf?type=#{type}"
				styleClass="tabLink#{type eq internalKeyBindingMBean.selectedInternalKeyBindingType}">
				<h:outputText value="#{web.text[type]}"/>
			</h:outputLink>
		</span>
		</c:forEach>
	</div>
	<p>
		<h:outputText rendered="#{internalKeyBindingMBean.selectedInternalKeyBindingType eq 'OcspKeyBinding'}"
			value="#{web.text.INTERNALKEYBINDING_OCSPKEYBINDING_DESCRIPTION}"/>
		<h:outputText rendered="#{internalKeyBindingMBean.selectedInternalKeyBindingType eq 'AuthenticationKeyBinding'}"
			value="#{web.text.INTERNALKEYBINDING_AUTHENTICATIONKEYBINDING_DESCRIPTION}"/>
	</p>
	<h:form id="internalkeybindings">
	<h:dataTable value="#{internalKeyBindingMBean.internalKeyBindingGuiList}" var="guiInfo"
		styleClass="grid" style="border-collapse: collapse; right: auto; left: auto">
		<h:column>
   			<f:facet name="header"><h:outputText value="#{web.text.INTERNALKEYBINDING_NAME}"/></f:facet>
			<h:outputLink
				value="adminweb/keybind/keybinding.jsf?internalKeyBindingId=#{guiInfo.internalKeyBindingId}">
				<h:outputText value="#{guiInfo.name}" title="#{web.text.INTERNALKEYBINDING_VIEWWITH} #{guiInfo.internalKeyBindingId}"/>
			</h:outputLink>
		</h:column>
		<h:column>
   			<f:facet name="header"><h:outputText value="#{web.text.INTERNALKEYBINDING_CERTIFICATEISSUER}"/></f:facet>
			<h:outputLink value="adminweb/viewcertificate.jsp" rendered="#{guiInfo.certificateBound}">
                <f:param name="certsernoparameter" value="#{guiInfo.caCertificateSerialNumber},#{guiInfo.caCertificateIssuerDn}"/>
                <f:param name="returnTo" value="#{internalKeyBindingMBean.selectedInternalKeyBindingType eq 'OcspKeyBinding' ? '2' : '3'}"/>
				<h:outputText value="#{guiInfo.certificateInternalCaName}" rendered="#{guiInfo.issuedByInternalCa}"/>
				<h:outputText value="#{guiInfo.certificateIssuerDn}" rendered="#{!guiInfo.issuedByInternalCa}"/>
			</h:outputLink>
			<h:outputText value="#{web.text.INTERNALKEYBINDING_NOT_PRESENT}" rendered="#{!guiInfo.certificateBound}"/>
		</h:column>
		<h:column>
   			<f:facet name="header"><h:outputText value="#{web.text.INTERNALKEYBINDING_CERTIFICATESERIAL}"/></f:facet>
			<h:outputLink value="adminweb/viewcertificate.jsp" rendered="#{guiInfo.certificateBound}">
                <f:param name="certsernoparameter" value="#{guiInfo.certificateSerialNumber},#{guiInfo.certificateIssuerDn}"/>
                <f:param name="returnTo" value="#{internalKeyBindingMBean.selectedInternalKeyBindingType eq 'OcspKeyBinding' ? '2' : '3'}"/>
            	<h:outputText style="font-family: monospace; text-align: right;" value="#{guiInfo.certificateSerialNumber}"/>
			</h:outputLink>
			<h:outputText value="#{web.text.INTERNALKEYBINDING_NOT_PRESENT}" rendered="#{!guiInfo.certificateBound}"/>
		</h:column>
		<h:column>
   			<f:facet name="header"><h:outputText value="#{web.text.INTERNALKEYBINDING_CRYPTOTOKEN}"/></f:facet>
			<h:outputLink value="adminweb/cryptotoken/cryptotoken.jsf?cryptoTokenId=#{guiInfo.cryptoTokenId}&ref=keybindings">
				<h:outputText value="#{guiInfo.cryptoTokenName}" title="#{web.text.CRYPTOTOKEN_VIEWWITH} #{guiInfo.cryptoTokenId}"/>
			</h:outputLink>
		</h:column>
		<h:column>
   			<f:facet name="header"><h:outputText value="#{web.text.INTERNALKEYBINDING_KEYPAIRALIAS}"/></f:facet>
			<h:outputText value="#{guiInfo.keyPairAlias}"/>
		</h:column>
		<h:column>
   			<f:facet name="header"><h:outputText value="#{web.text.INTERNALKEYBINDING_NEXTKEYPAIRALIAS}"/></f:facet>
			<h:outputText rendered="#{guiInfo.nextKeyAliasAvailable}" value="#{guiInfo.nextKeyPairAlias}"/>
		</h:column>
		<h:column>
   			<f:facet name="header"><h:outputText value="#{web.text.INTERNALKEYBINDING_STATUS}"/></f:facet>
			<h:outputText value="#{web.text[guiInfo.status]}"/>
		</h:column>
		<h:column rendered="#{!internalKeyBindingMBean.forbiddenToEdit}">
   			<f:facet name="header">
   				<h:outputText value="#{web.text.INTERNALKEYBINDING_ACTION}"/>
   			</f:facet>
			<h:commandButton rendered="#{guiInfo.status ne 'INTERNALKEYBINDING_STATUS_DISABLED'}" action="#{internalKeyBindingMBean.commandDisable}"
				value="#{web.text.INTERNALKEYBINDING_DISABLE_SHORT}" title="#{web.text.INTERNALKEYBINDING_DISABLE_FULL}" disabled="#{internalKeyBindingMBean.forbiddenToEdit}"/>
			<h:commandButton rendered="#{guiInfo.status eq 'INTERNALKEYBINDING_STATUS_DISABLED'}" action="#{internalKeyBindingMBean.commandEnable}"
				value="#{web.text.INTERNALKEYBINDING_ENABLE_SHORT}" title="#{web.text.INTERNALKEYBINDING_ENABLE_FULL}" disabled="#{internalKeyBindingMBean.forbiddenToEdit}"/>
			<h:commandButton action="#{internalKeyBindingMBean.commandDelete}"
				value="#{web.text.INTERNALKEYBINDING_DELETE_SHORT}" title="#{web.text.INTERNALKEYBINDING_DELETE_FULL}"
				onclick="return confirm('#{web.text.INTERNALKEYBINDING_CONF_DELETE}')" disabled="#{internalKeyBindingMBean.forbiddenToEdit}"/>
			<h:commandButton rendered="#{!guiInfo.nextKeyAliasAvailable and guiInfo.cryptoTokenAvailable}"
				action="#{internalKeyBindingMBean.commandGenerateNewKey}"
				value="#{web.text.INTERNALKEYBINDING_GENERATENEWKEY_SHORT}" title="#{web.text.INTERNALKEYBINDING_GENERATENEWKEY_FULL}"
				disabled="#{internalKeyBindingMBean.forbiddenToEdit}"/>
			<h:commandButton rendered="#{guiInfo.cryptoTokenAvailable}" action="#{internalKeyBindingMBean.commandGenerateRequest}"
				value="#{web.text.INTERNALKEYBINDING_GETCSR_SHORT}" title="#{web.text.INTERNALKEYBINDING_GETCSR_FULL}"
				disabled="#{internalKeyBindingMBean.forbiddenToEdit}"/>
			<h:commandButton action="#{internalKeyBindingMBean.commandReloadCertificate}"
				value="#{web.text.INTERNALKEYBINDING_RELOADCERTIFICATE_SHORT}" title="#{web.text.INTERNALKEYBINDING_RELOADCERTIFICATE_FULL}"
				disabled="#{internalKeyBindingMBean.forbiddenToEdit}"/>
			<h:commandButton rendered="#{guiInfo.issuedByInternalCa}" action="#{internalKeyBindingMBean.commandRenewCertificate}"
				value="#{web.text.INTERNALKEYBINDING_RENEWCERTIFICATE_SHORT}" title="#{web.text.INTERNALKEYBINDING_RENEWCERTIFICATE_FULL}"
				disabled="#{internalKeyBindingMBean.forbiddenToEdit}"/>
		</h:column>
	</h:dataTable>
	<br/>
	<h:outputLink
		value="adminweb/keybind/keybinding.jsf?internalKeyBindingId=0&type=#{internalKeyBindingMBean.selectedInternalKeyBindingType}" rendered="#{internalKeyBindingMBean.allowedToEdit}">
		<h:outputText value="#{web.text.INTERNALKEYBINDING_CREATENEW}"/>
	</h:outputLink>
	</h:form>
	<h:form id="uploadCertificate" enctype="multipart/form-data" rendered="#{not empty internalKeyBindingMBean.uploadTargets and internalKeyBindingMBean.allowedToEdit}">
		<h3><h:outputText value="#{web.text.INTERNALKEYBINDING_UPLOADHEADER}"/></h3>
		<h:panelGrid columns="5">
			<h:outputLabel for="certificateUploadTarget" value="#{web.text.INTERNALKEYBINDING_UPLOAD_TARGET} #{internalKeyBindingMBean.selectedInternalKeyBindingType}:"/>
			<h:selectOneMenu id="certificateUploadTarget" value="#{internalKeyBindingMBean.uploadTarget}">
				<f:selectItems value="#{internalKeyBindingMBean.uploadTargets}"/>
			</h:selectOneMenu>
			<h:outputLabel for="certificateUploadInput" value="#{web.text.INTERNALKEYBINDING_UPLOAD_CERTIFICATE}:"/>
			<t:inputFileUpload id="certificateUploadInput" value="#{internalKeyBindingMBean.uploadToTargetFile}" size="20"/>
			<h:commandButton action="#{internalKeyBindingMBean.uploadToTarget}" value="#{web.text.INTERNALKEYBINDING_UPLOAD}"/>
		</h:panelGrid>
	</h:form>
	<h:form id="defaultResponder" rendered="#{internalKeyBindingMBean.selectedInternalKeyBindingType eq 'OcspKeyBinding'}">
		<h3>
			<h:outputText value="#{web.text.INTERNALKEYBINDING_DEFAULTRESPONDER}" rendered="#{internalKeyBindingMBean.forbiddenToEdit}"/>
			<h:outputText value="#{web.text.INTERNALKEYBINDING_SET_DEFAULTRESPONDER}" rendered="#{!internalKeyBindingMBean.forbiddenToEdit}"/>			
			<%= ejbcawebbean.getHelpReference("/installation-ocsp.html#Setting%20the%20Default%20Responder") %>
		</h3>
		<h:panelGrid columns="3">
			<h:selectOneMenu id="defaultResponderTarget" value="#{internalKeyBindingMBean.defaultResponderTarget}" disabled="#{internalKeyBindingMBean.forbiddenToEdit}" >
				<f:selectItems value="#{internalKeyBindingMBean.defaultResponderTargets}"/>
			</h:selectOneMenu>
			<h:commandButton action="#{internalKeyBindingMBean.saveDefaultResponder}" rendered="#{internalKeyBindingMBean.allowedToEdit}" value="#{web.text.INTERNALKEYBINDING_SET}"/>
		</h:panelGrid>
	</h:form>
	
	<h:form id="responderId" rendered="#{internalKeyBindingMBean.selectedInternalKeyBindingType eq 'OcspKeyBinding'}">
		<h3>
			<h:outputText value="#{web.text.INTERNALKEYBINDING_DEFAULT_RESPONDERIDTYPE}" rendered="#{internalKeyBindingMBean.forbiddenToEdit}"/>
			<h:outputText value="#{web.text.INTERNALKEYBINDING_SET_DEFAULT_RESPONDERIDTYPE}" rendered="#{!internalKeyBindingMBean.forbiddenToEdit}"/>			
			<%= ejbcawebbean.getHelpReference("/installation-ocsp.html#Responder%20ID%20Type%20for%20CAs") %>
		</h3>
		<h:panelGrid columns="3">
			<h:selectOneMenu id="defaultResponderId" value="#{internalKeyBindingMBean.responderIdType}" disabled="#{internalKeyBindingMBean.forbiddenToEdit}" >
				<f:selectItems value="#{internalKeyBindingMBean.responderIdTargets}"/>
			</h:selectOneMenu>
			<h:commandButton action="#{internalKeyBindingMBean.saveResponderIdType}" rendered="#{internalKeyBindingMBean.allowedToEdit}" value="#{web.text.INTERNALKEYBINDING_SET}"/>
		</h:panelGrid>
	</h:form>
	<%	// Include Footer 
	String footurl = globalconfiguration.getFootBanner(); %>
	<jsp:include page="<%= footurl %>" />
</body>
</f:view>
</html>
