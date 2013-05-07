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
<%@ page pageEncoding="UTF-8"%>
<% response.setContentType("text/html; charset="+org.ejbca.config.WebConfiguration.getWebContentEncoding()); %>
<%@ page errorPage="/errorpage.jsp" import="
org.ejbca.ui.web.admin.configuration.EjbcaWebBean,
org.ejbca.config.GlobalConfiguration,
org.ejbca.core.model.authorization.AccessRulesConstants,
org.ejbca.core.ejb.keybind.InternalKeyBindingRules
"%>
<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />
<% GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, AccessRulesConstants.ROLE_ADMINISTRATOR, InternalKeyBindingRules.BASE.resource()); %>
<html>
<f:view>
<head>
  <title><h:outputText value="#{web.ejbcaWebBean.globalConfiguration.ejbcaTitle}" /></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>" />
  <link rel="stylesheet" type="text/css" href="<%= ejbcawebbean.getCssFile() %>" />
  <script src="<%= globalconfiguration.getAdminWebPath() %>ejbcajslib.js"></script>
  <style type="text/css">
		/* TODO: Move re-usable styles to included .css */
		.infoMessage {
			font-style: italic;
			padding: 0.5em;
			border-radius: 0.3em;
			background: #fcfcfc;
			margin-bottom: 1em;
		}
		.propertyTable {
			border: 0px;
			right: auto;
			left: auto;
		}
   </style>
</head>
<body>
	<h1>
		<h:outputText value="#{web.text.INTERNALKEYBINDING}"/>
		<%= ejbcawebbean.getHelpReference("/userguide.html#Managing%20InternalKeyBindings") %>
	</h1>
	<div class="message"><h:messages layout="table" errorClass="alert" infoClass="infoMessage"/></div>
	<div>
		<h:panelGrid columns="2">
			<h:outputLink value="adminweb/keybind/keybindings.jsf?type=#{internalKeyBindingMBean.selectedInternalKeyBindingType}">
				<h:outputText value="Back to #{web.text[internalKeyBindingMBean.selectedInternalKeyBindingType]} overview"/>
			</h:outputLink>
			<h:form rendered="#{internalKeyBindingMBean.switchToEditAllowed or internalKeyBindingMBean.switchToViewAllowed}">
				<h:commandButton rendered="#{internalKeyBindingMBean.switchToEditAllowed}" action="#{internalKeyBindingMBean.switchToEdit}"
					value="Edit" title="Switch to edit mode"/>
				<h:commandButton rendered="#{internalKeyBindingMBean.switchToViewAllowed}" action="#{internalKeyBindingMBean.switchToView}"
					value="View" title="Switch to view mode"/>
			</h:form>
		</h:panelGrid>
	</div>
	<h:form id="internalkeybinding">
	<h:panelGrid columns="3">
		<h:outputLabel for="type" value="Type:"/>
		<h:outputText id="type" value="#{internalKeyBindingMBean.selectedInternalKeyBindingType}"/>
		<h:message for="type"/>
		<h:outputLabel for="internalKeyBindingId" value="Id:"/>
		<h:panelGroup id="internalKeyBindingId">
			<h:outputText rendered="#{internalKeyBindingMBean.currentInternalKeyBindingId ne '0'}" value="#{internalKeyBindingMBean.currentInternalKeyBindingId}"/>
			<h:outputText rendered="#{internalKeyBindingMBean.currentInternalKeyBindingId eq '0'}" value="Not yet generated"/>
		</h:panelGroup>
		<h:message for="internalKeyBindingId"/>
		<h:outputLabel for="name" value="Name:"/>
		<h:panelGroup id="name">
			<h:inputText rendered="#{internalKeyBindingMBean.inEditMode}" value="#{internalKeyBindingMBean.currentName}"/>
			<h:outputText rendered="#{!internalKeyBindingMBean.inEditMode}" value="#{internalKeyBindingMBean.currentName}"/>
		</h:panelGroup>
		<h:message for="name"/>
		<h:outputLabel for="cryptoToken" value="CryptoToken:"/>
		<h:panelGroup id="cryptoToken">
			<h:panelGroup rendered="#{internalKeyBindingMBean.inEditMode and internalKeyBindingMBean.cryptoTokenActive}">
				<h:selectOneMenu value="#{internalKeyBindingMBean.currentCryptoToken}"
					onchange="document.getElementById('internalkeybinding:reloadCryptoToken').click();">
					<f:selectItems value="#{internalKeyBindingMBean.availableCryptoTokens}"/>
				</h:selectOneMenu>
				<h:commandButton id="reloadCryptoToken" value="Update next" action="#{internalKeyBindingMBean.reloadCryptoToken}"/>
				<script>document.getElementById('internalkeybinding:reloadCryptoToken').style.display = 'none';</script>
			</h:panelGroup>
			<h:outputText rendered="#{!internalKeyBindingMBean.inEditMode or !internalKeyBindingMBean.cryptoTokenActive}"
				value="#{internalKeyBindingMBean.currentCryptoTokenName}" title="#{internalKeyBindingMBean.currentCryptoToken}"/>
			<h:outputText rendered="#{internalKeyBindingMBean.inEditMode or !internalKeyBindingMBean.cryptoTokenActive}"
				value=" (Not active)"/>
		</h:panelGroup>
		<h:message for="cryptoToken"/>
		<h:outputLabel for="keyPairAlias" value="Key Pair Alias:"/>
		<h:panelGroup id="keyPairAlias">
			<h:panelGroup rendered="#{internalKeyBindingMBean.inEditMode and internalKeyBindingMBean.cryptoTokenActive and !internalKeyBindingMBean.boundToCertificate}">
			<h:selectOneMenu value="#{internalKeyBindingMBean.currentKeyPairAlias}"
				onchange="document.getElementById('internalkeybinding:reloadKeyPairAlias').click();">
				<f:selectItems value="#{internalKeyBindingMBean.availableKeyPairAliases}"/>
			</h:selectOneMenu>
			<h:commandButton id="reloadKeyPairAlias" value="Update next" action="#{internalKeyBindingMBean.reloadKeyPairAlias}"/>
			<script>document.getElementById('internalkeybinding:reloadKeyPairAlias').style.display = 'none';</script>
			</h:panelGroup>
			<h:outputText rendered="#{!internalKeyBindingMBean.inEditMode or !internalKeyBindingMBean.cryptoTokenActive || internalKeyBindingMBean.boundToCertificate}"
				value="#{internalKeyBindingMBean.currentKeyPairAlias}"/>
		</h:panelGroup>
		<h:message for="keyPairAlias"/>
		<h:outputLabel for="signatureAlgorithm" value="Signature Algorithm:"/>
		<h:panelGroup id="signatureAlgorithm">
			<h:selectOneMenu rendered="#{internalKeyBindingMBean.inEditMode and internalKeyBindingMBean.cryptoTokenActive}"
				value="#{internalKeyBindingMBean.currentSignatureAlgorithm}">
				<f:selectItems value="#{internalKeyBindingMBean.availableSignatureAlgorithms}"/>
			</h:selectOneMenu>
			<h:outputText rendered="#{!internalKeyBindingMBean.inEditMode or !internalKeyBindingMBean.cryptoTokenActive}"
				value="#{internalKeyBindingMBean.currentSignatureAlgorithm}"/>
		</h:panelGroup>
		<h:message for="signatureAlgorithm"/>
		<h:outputLabel for="nextKeyPairAlias" value="Next Key Pair Alias:"
			rendered="#{internalKeyBindingMBean.currentInternalKeyBindingId ne '0'}"/>
		<h:panelGroup id="nextKeyPairAlias" rendered="#{internalKeyBindingMBean.currentInternalKeyBindingId ne '0'}">
			<h:panelGroup rendered="#{internalKeyBindingMBean.inEditMode and internalKeyBindingMBean.cryptoTokenActive}">
			<h:selectOneMenu value="#{internalKeyBindingMBean.currentNextKeyPairAlias}">
				<f:selectItem itemValue="" itemLabel="None"/>
				<f:selectItems value="#{internalKeyBindingMBean.availableKeyPairAliases}"/>
			</h:selectOneMenu>
			</h:panelGroup>
			<h:outputText rendered="#{!internalKeyBindingMBean.inEditMode or !internalKeyBindingMBean.cryptoTokenActive}"
				value="#{internalKeyBindingMBean.currentNextKeyPairAlias}"/>
		</h:panelGroup>
		<h:message for="nextKeyPairAlias" rendered="#{internalKeyBindingMBean.currentInternalKeyBindingId ne '0'}"/>
		<h:outputLabel for="certificateId" value="Bound Certificate:"
			rendered="#{internalKeyBindingMBean.boundToCertificate}"/>
		<h:panelGroup id="certificateId" rendered="#{internalKeyBindingMBean.boundToCertificate}">
			<h:outputText value="TODO"/>
		</h:panelGroup>
		<h:message for="certificateId" rendered="#{internalKeyBindingMBean.boundToCertificate}"/>
	</h:panelGrid>
	<h3>Trusted certificates</h3>
	<h:outputText rendered="#{internalKeyBindingMBean.trustedCertificates.rowCount == 0}" value="Trusting ANY known CA certificate"/>
	<h:dataTable id="trustedCertificates" value="#{internalKeyBindingMBean.trustedCertificates}" var="trustEntry"
		rendered="#{internalKeyBindingMBean.trustedCertificates.rowCount != 0 or internalKeyBindingMBean.inEditMode}">
		<h:column>
   			<f:facet name="header"><h:outputText value="#{web.text.INTERNALKEYBINDING_CA}"/></f:facet>
			<h:outputText value="#{internalKeyBindingMBean.trustedCertificatesCaName}" title="#{trustEntry.key}"/>
			<f:facet name="footer">
				<h:selectOneMenu rendered="#{internalKeyBindingMBean.inEditMode}"
					value="#{internalKeyBindingMBean.currentCertificateAuthority}">
					<f:selectItems value="#{internalKeyBindingMBean.availableCertificateAuthorities}"/>
				</h:selectOneMenu>
			</f:facet>
		</h:column>
		<h:column>
   			<f:facet name="header"><h:outputText value="#{web.text.INTERNALKEYBINDING_SERIALNUMER}"/></f:facet>
			<h:outputText rendered="#{!empty trustEntry.value}" value="#{internalKeyBindingMBean.trustedCertificatesSerialNumberHex}"/>
			<h:outputText rendered="#{empty trustEntry.value}" value="ANY"/>
			<f:facet name="footer">
				<h:inputText id="certificateSerialNumber" rendered="#{internalKeyBindingMBean.inEditMode}" required="false"
					value="#{internalKeyBindingMBean.currentCertificateSerialNumber}"
					title="Leave empty for 'ANY' Certificate Serial Number">
					<f:validator validatorId="hexSerialNumberValidator"/>
   				</h:inputText>
				<h:message for="certificateSerialNumber" rendered="#{internalKeyBindingMBean.inEditMode}"/>
			</f:facet>
		</h:column>
		<h:column>
   			<f:facet name="header"><h:outputText value="#{web.text.INTERNALKEYBINDING_ACTION}"/></f:facet>
			<h:commandButton value="Remove" action="#{internalKeyBindingMBean.removeTrust}"/>
			<f:facet name="footer">
				<h:commandButton  rendered="#{internalKeyBindingMBean.inEditMode}" action="#{internalKeyBindingMBean.addTrust}"
					value="Add"/>
			</f:facet>
		</h:column>
	</h:dataTable>
	<h3>Properties (todo: make localizable and not look like a table)</h3>
	<h:dataTable value="#{internalKeyBindingMBean.internalKeyBindingPropertyList}" var="property" styleClass="propertyTable">
		<h:column>
			<h:outputText value="#{internalKeyBindingMBean.propertyNameTranslated}:"/>
		</h:column>
		<h:column>
   			<h:panelGroup rendered="#{!property.multiValued}">
	   			<h:inputText disabled="#{!internalKeyBindingMBean.inEditMode}" rendered="#{property.type.simpleName eq 'String'}" value="#{property.value}"/>
	   			<h:inputText disabled="#{!internalKeyBindingMBean.inEditMode}" rendered="#{property.type.simpleName eq 'Integer'}" value="#{property.value}">
					<f:convertNumber integerOnly="true"/>
	   			</h:inputText>
   				<h:selectBooleanCheckbox disabled="#{!internalKeyBindingMBean.inEditMode}" rendered="#{property.type.simpleName eq 'Boolean'}" value="#{property.value}"/>
   			</h:panelGroup>
			<h:selectOneMenu disabled="#{!internalKeyBindingMBean.inEditMode}" rendered="#{property.multiValued}" value="#{property.encodedValue}">
				<f:selectItems value="#{internalKeyBindingMBean.propertyPossibleValues}"/>
			</h:selectOneMenu>
		</h:column>
	</h:dataTable>
	<h:commandButton value="Create" action="#{internalKeyBindingMBean.createNew}" rendered="#{internalKeyBindingMBean.inEditMode and internalKeyBindingMBean.creatingNew}"/>
	<h:commandButton value="Save" action="#{internalKeyBindingMBean.saveCurrent}" rendered="#{internalKeyBindingMBean.inEditMode and !internalKeyBindingMBean.creatingNew}"/>
	</h:form>
	<%	// Include Footer 
	String footurl = globalconfiguration.getFootBanner(); %>
	<jsp:include page="<%= footurl %>" />
</body>
</f:view>
</html>
