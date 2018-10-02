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
  <link rel="shortcut icon" href="<%=ejbcawebbean.getImagefileInfix("favicon.png")%>" type="image/png" />
  <script src="<%= globalconfiguration.getAdminWebPath() %>ejbcajslib.js"></script>
</head>
<body>
<jsp:include page="../adminmenu.jsp" />

<div class="main-wrapper">
<div class="container">
	<h1>
		<h:outputText value="#{web.text.INTERNALKEYBINDING}"/>
		<%= ejbcawebbean.getHelpReference("/Managing_Internal_Key_Bindings.html") %>
	</h1>
	<div class="message"><h:messages layout="table" errorClass="alert" infoClass="infoMessage"/></div>
	<div>
		<h:panelGrid columns="2" styleClass="margin-bottom">
			<h:outputLink value="adminweb/keybind/keybindings.jsf?type=#{internalKeyBindingMBean.selectedInternalKeyBindingType}">
				<h:outputText value="#{internalKeyBindingMBean.backLinkTranslatedText}"/>
			</h:outputLink>
			<h:form rendered="#{internalKeyBindingMBean.switchToEditAllowed or internalKeyBindingMBean.switchToViewAllowed}">
				<h:commandButton rendered="#{internalKeyBindingMBean.switchToEditAllowed}" action="#{internalKeyBindingMBean.switchToEdit}"
					value="#{web.text.EDIT}" title="#{web.text.SWITCHTOEDITMODE}"/>
				<h:commandButton rendered="#{internalKeyBindingMBean.switchToViewAllowed}" action="#{internalKeyBindingMBean.switchToView}"
					value="#{web.text.VIEW}" title="#{web.text.SWITCHTOVIEWMODE}"/>
			</h:form>
		</h:panelGrid>
	</div>
	<h:form id="internalkeybinding">
	<h:panelGrid columns="3">
		<h:outputLabel for="type" value="#{web.text.INTERNALKEYBINDING_FIELD_TYPE}"/>
		<h:outputText id="type" value="#{internalKeyBindingMBean.selectedInternalKeyBindingType}"/>
		<h:message for="type"/>
		<h:outputLabel for="internalKeyBindingId" value="#{web.text.INTERNALKEYBINDING_FIELD_ID}"/>
		<h:panelGroup id="internalKeyBindingId">
			<h:outputText rendered="#{internalKeyBindingMBean.currentInternalKeyBindingId ne '0'}" value="#{internalKeyBindingMBean.currentInternalKeyBindingId}"/>
			<h:outputText rendered="#{internalKeyBindingMBean.currentInternalKeyBindingId eq '0'}" value="#{web.text.INTERNALKEYBINDING_NOTYETGENERATED}"/>
		</h:panelGroup>
		<h:message for="internalKeyBindingId"/>
		<h:outputLabel for="name" value="#{web.text.INTERNALKEYBINDING_FIELD_NAME}"/>
		<h:panelGroup id="name">
			<h:inputText rendered="#{internalKeyBindingMBean.inEditMode}" value="#{internalKeyBindingMBean.currentName}" size="40" maxlength="255" title="#{web.text.FORMAT_ID_STR}" />
			<h:outputText rendered="#{!internalKeyBindingMBean.inEditMode}" value="#{internalKeyBindingMBean.currentName}"/>
		</h:panelGroup>
		<h:message for="name"/>
		<h:outputLabel for="cryptoToken" value="#{web.text.INTERNALKEYBINDING_FIELD_CRYPTOTOKEN}"/>
		<h:panelGroup id="cryptoToken">
			<h:panelGroup rendered="#{internalKeyBindingMBean.inEditMode and internalKeyBindingMBean.cryptoTokenActive}">
				<h:selectOneMenu value="#{internalKeyBindingMBean.currentCryptoToken}"
					onchange="document.getElementById('internalkeybinding:reloadCryptoToken').click();">
					<f:selectItems value="#{internalKeyBindingMBean.availableCryptoTokens}"/>
				</h:selectOneMenu>
				<h:commandButton id="reloadCryptoToken" value="#{web.text.INTERNALKEYBINDING_CRYPTOTOKEN_UPDATENEXT}" action="#{internalKeyBindingMBean.reloadCryptoToken}"/>
				<script>document.getElementById('internalkeybinding:reloadCryptoToken').style.display = 'none';</script>
			</h:panelGroup>
			<h:outputText rendered="#{internalKeyBindingMBean.inEditMode and !internalKeyBindingMBean.cryptoTokenActive and internalKeyBindingMBean.currentCryptoTokenName != null}"
				value=" #{web.text.INTERNALKEYBINDING_CRYPTOTOKEN_NOTACTIVE}"/>
			<h:outputText rendered="#{!internalKeyBindingMBean.inEditMode or !internalKeyBindingMBean.cryptoTokenActive}"
				value="#{internalKeyBindingMBean.currentCryptoTokenName != null ? internalKeyBindingMBean.currentCryptoTokenName : web.text.INTERNALKEYBINDING_CRYPTOTOKEN_MISSING}" title="#{internalKeyBindingMBean.currentCryptoToken}"/>
		</h:panelGroup>
		<h:message for="cryptoToken"/>
		<h:outputLabel for="keyPairAlias" value="#{web.text.INTERNALKEYBINDING_FIELD_KEYPAIRALIAS}"/>
		<h:panelGroup id="keyPairAlias">
			<h:panelGroup rendered="#{internalKeyBindingMBean.inEditMode and internalKeyBindingMBean.cryptoTokenActive and !internalKeyBindingMBean.boundToCertificate}">
			<h:selectOneMenu value="#{internalKeyBindingMBean.currentKeyPairAlias}"
				onchange="document.getElementById('internalkeybinding:reloadKeyPairAlias').click();">
				<f:selectItems value="#{internalKeyBindingMBean.availableKeyPairAliases}"/>
			</h:selectOneMenu>
			<h:commandButton id="reloadKeyPairAlias" value="#{web.text.INTERNALKEYBINDING_KEYPAIRALIAS_UPDATE}" action="#{internalKeyBindingMBean.reloadKeyPairAlias}"/>
			<script>document.getElementById('internalkeybinding:reloadKeyPairAlias').style.display = 'none';</script>
			</h:panelGroup>
			<h:outputText rendered="#{!internalKeyBindingMBean.inEditMode or !internalKeyBindingMBean.cryptoTokenActive || internalKeyBindingMBean.boundToCertificate}"
				value="#{internalKeyBindingMBean.currentKeyPairAlias}"/>
		</h:panelGroup>
		<h:message for="keyPairAlias"/>
		<h:outputLabel for="signatureAlgorithm" value="#{web.text.INTERNALKEYBINDING_FIELD_SIGALG}"/>
		<h:panelGroup id="signatureAlgorithm">
			<h:selectOneMenu rendered="#{internalKeyBindingMBean.inEditMode and internalKeyBindingMBean.cryptoTokenActive}"
				value="#{internalKeyBindingMBean.currentSignatureAlgorithm}">
				<f:selectItems value="#{internalKeyBindingMBean.availableSignatureAlgorithms}"/>
			</h:selectOneMenu>
			<h:panelGroup rendered="#{!internalKeyBindingMBean.inEditMode or !internalKeyBindingMBean.cryptoTokenActive}">
				<h:outputText rendered="#{internalKeyBindingMBean.currentSignatureAlgorithm != null}"
					value="#{internalKeyBindingMBean.currentSignatureAlgorithm}"/>
				<h:outputText rendered="#{internalKeyBindingMBean.currentSignatureAlgorithm == null}"
					value="#{web.text.INTERNALKEYBINDING_FIELD_NOTSPECIFIED} (error)"/>
			</h:panelGroup>
		</h:panelGroup>
		<h:message for="signatureAlgorithm"/>
		<h:outputLabel for="nextKeyPairAlias" value="#{web.text.INTERNALKEYBINDING_FIELD_NEXTKEYPAIRALIAS}"
			rendered="#{internalKeyBindingMBean.currentInternalKeyBindingId ne '0'}"/>
		<h:panelGroup id="nextKeyPairAlias" rendered="#{internalKeyBindingMBean.currentInternalKeyBindingId ne '0'}">
			<h:panelGroup rendered="#{internalKeyBindingMBean.inEditMode and internalKeyBindingMBean.cryptoTokenActive}">
			<h:selectOneMenu value="#{internalKeyBindingMBean.currentNextKeyPairAlias}">
				<f:selectItem itemValue="" itemLabel="#{web.text.INTERNALKEYBINDING_FIELD_NONE}"/>
				<f:selectItems value="#{internalKeyBindingMBean.availableKeyPairAliases}"/>
			</h:selectOneMenu>
			</h:panelGroup>
			<h:panelGroup rendered="#{!internalKeyBindingMBean.inEditMode or !internalKeyBindingMBean.cryptoTokenActive}">
				<h:outputText rendered="#{internalKeyBindingMBean.currentNextKeyPairAlias != null}"
					value="#{internalKeyBindingMBean.currentNextKeyPairAlias}"/>
				<h:outputText rendered="#{internalKeyBindingMBean.currentNextKeyPairAlias == null}"
					value="#{web.text.INTERNALKEYBINDING_FIELD_NOTSPECIFIED}"/>
			</h:panelGroup>
		</h:panelGroup>
		<h:message for="nextKeyPairAlias" rendered="#{internalKeyBindingMBean.currentInternalKeyBindingId ne '0'}"/>
		<h:outputLabel for="certificateId" value="#{web.text.INTERNALKEYBINDING_FIELD_BOUNDCERT}"
			rendered="#{internalKeyBindingMBean.boundToCertificate}"/>
		<h:panelGroup id="certificateId" rendered="#{internalKeyBindingMBean.boundToCertificate}">
			<h:outputLink target="_blank" value="adminweb/viewcertificate.jsp?certsernoparameter=#{internalKeyBindingMBean.boundCaCertificateSerialNumber},#{internalKeyBindingMBean.boundCaCertificateIssuerDn}&ref=keybindings">
				<h:outputText value="#{internalKeyBindingMBean.boundCertificateInternalCaName}" rendered="#{internalKeyBindingMBean.boundCertificateInternalCaName != null}"/>
				<h:outputText value="#{internalKeyBindingMBean.boundCertificateIssuerDn}" rendered="#{internalKeyBindingMBean.boundCertificateInternalCaName == null}"/>
			</h:outputLink>
			<h:outputText value="  "/>
			<h:outputLink target="_blank" value="adminweb/viewcertificate.jsp?certsernoparameter=#{internalKeyBindingMBean.boundCertificateSerialNumber},#{internalKeyBindingMBean.boundCertificateIssuerDn}&ref=keybindings">
				<h:outputText style="font-family: monospace; text-align: right;" value="#{internalKeyBindingMBean.boundCertificateSerialNumber}"/>
			</h:outputLink>
		</h:panelGroup>
		<h:message for="certificateId" rendered="#{internalKeyBindingMBean.boundToCertificate}"/>
	</h:panelGrid>
	<h3><h:outputText value="#{web.text.INTERNALKEYBINDING_TRUSTEDCERTIFICATES}"/></h3>
	<h:outputText rendered="#{internalKeyBindingMBean.trustedCertificates.rowCount == 0}" value="#{web.text.INTERNALKEYBINDING_TRUSTINGANY}"/>
	<h:dataTable id="trustedCertificates" value="#{internalKeyBindingMBean.trustedCertificates}" var="trustEntry"
		rendered="#{internalKeyBindingMBean.trustedCertificates.rowCount != 0 or internalKeyBindingMBean.inEditMode}">
		<h:column>
   			<f:facet name="header"><h:outputText value="#{web.text.INTERNALKEYBINDING_CA}"/></f:facet>
			<h:outputText value="#{internalKeyBindingMBean.trustedCertificatesCaName}" title="#{trustEntry.caId}"/>
			<f:facet name="footer">
				<h:selectOneMenu rendered="#{internalKeyBindingMBean.inEditMode}"
					value="#{internalKeyBindingMBean.currentCertificateAuthority}">
					<f:selectItems value="#{internalKeyBindingMBean.availableCertificateAuthorities}"/>
				</h:selectOneMenu>
			</f:facet>
		</h:column>
		<h:column>
   			<f:facet name="header"><h:outputText value="#{web.text.INTERNALKEYBINDING_SERIALNUMER}"/></f:facet>
			<h:outputText rendered="#{!empty trustEntry.certificateSerialNumberDecimal}" value="#{internalKeyBindingMBean.trustedCertificatesSerialNumberHex}"/>
			<h:outputText rendered="#{empty trustEntry.certificateSerialNumberDecimal}" value="ANY"/>
			<f:facet name="footer">
				<h:inputText id="certificateSerialNumber" rendered="#{internalKeyBindingMBean.inEditMode}" required="false"
					value="#{internalKeyBindingMBean.currentCertificateSerialNumber}"
					size="26" maxlength="255"
					title="#{web.text.INTERNALKEYBINDING_EMPTYFORANY}">
					<f:validator validatorId="optionalHexSerialNumberValidator"/>
   				</h:inputText>
				<h:message for="certificateSerialNumber" rendered="#{internalKeyBindingMBean.inEditMode}"/>
			</f:facet>
		</h:column>
		<h:column>
   			<f:facet name="header"><h:outputText value="#{web.text.INTERNALKEYBINDING_TRUSTENTRY_DESCRIPTION}"/></f:facet>
   			<h:outputText value="#{trustEntry.trustEntryDescription}"/>
   			<f:facet name="footer">
				<h:inputText id="trustEntryDescription" rendered="#{internalKeyBindingMBean.inEditMode}" required="false"
					value="#{internalKeyBindingMBean.currentTrustEntryDescription}"
					size="18" maxlength="255"
					title="#{web.text.INTERNALKEYBINDING_TRUSTENTRY_TITLE}">
   				</h:inputText>
				<h:message for="trustEntryDescription" rendered="#{internalKeyBindingMBean.inEditMode}"/>
			</f:facet>
		</h:column>
		<h:column>
   			<f:facet name="header"><h:outputText value="#{web.text.INTERNALKEYBINDING_ACTIONS}"/></f:facet>
			<h:commandButton value="#{web.text.REMOVE}" action="#{internalKeyBindingMBean.removeTrust}" rendered="#{internalKeyBindingMBean.inEditMode}"/>
			<f:facet name="footer">
				<h:commandButton  rendered="#{internalKeyBindingMBean.inEditMode}" action="#{internalKeyBindingMBean.addTrust}"
					value="#{web.text.ADD}"/>
			</f:facet>
		</h:column>
	</h:dataTable>
	
	<h3><h:outputText value="#{web.text.INTERNALKEYBINDING_PROPERTIES}"/></h3>
	<h:dataTable value="#{internalKeyBindingMBean.internalKeyBindingPropertyList}" var="property" styleClass="propertyTable">
		<h:column>
			<h:outputText value="#{internalKeyBindingMBean.propertyNameTranslated}"/>
		</h:column>
		<h:column>
   			<h:panelGroup rendered="#{!property.multiValued}">
	   			<h:inputText disabled="#{!internalKeyBindingMBean.inEditMode}" rendered="#{property.type.simpleName eq 'String'}" value="#{property.value}"/>
	   			<h:inputText disabled="#{!internalKeyBindingMBean.inEditMode}" rendered="#{property.type.simpleName eq 'Long'}" value="#{property.value}">
                   <f:converter converterId="javax.faces.Long"/>
	   			</h:inputText>
   				<h:selectBooleanCheckbox disabled="#{!internalKeyBindingMBean.inEditMode}" rendered="#{property.type.simpleName eq 'Boolean'}" value="#{property.value}"/>
   			</h:panelGroup>
			<h:selectOneMenu disabled="#{!internalKeyBindingMBean.inEditMode}" rendered="#{property.multiValued}" value="#{property.encodedValue}">
				<f:selectItems value="#{internalKeyBindingMBean.propertyPossibleValues}"/>
			</h:selectOneMenu>
		</h:column>
	</h:dataTable>
	<h:panelGroup rendered="#{internalKeyBindingMBean.internalKeyBindingPropertyList.rowCount == 0}">
	    <div><h:outputText value="#{web.text.INTERNALKEYBINDING_NOPROPERTIES}"/></div>
    </h:panelGroup>
    
   	<h3><h:outputText value="#{web.text.INTERNALKEYBINDING_OCSPKEYBINDING_OCSPEXTENSIONHEADER}" rendered="#{internalKeyBindingMBean.ocspKeyBinding}"/></h3>
	<h:dataTable id="ocspExtensions" value="#{internalKeyBindingMBean.ocspExtensions}" rendered="#{internalKeyBindingMBean.ocspKeyBinding}" var="extensionEntry">
		<h:column>
   			<f:facet name="header"><h:outputText value="#{web.text.INTERNALKEYBINDING_OCSPKEYBINDING_OCSPEXTENSION_NAME}"/></f:facet>
			<h:outputText value="#{internalKeyBindingMBean.ocspExtensionDisplayName}"/>
			<f:facet name="footer">
				<h:selectOneMenu rendered="#{internalKeyBindingMBean.inEditMode}"
					value="#{internalKeyBindingMBean.currentOcspExtension}">
					<f:selectItems value="#{internalKeyBindingMBean.availableOcspExtensions}"/>
				</h:selectOneMenu>
			</f:facet>
		</h:column>
		<h:column>
   			<f:facet name="header"><h:outputText value="#{web.text.INTERNALKEYBINDING_OCSPKEYBINDING_OCSPEXTENSION_OID}"/></f:facet>
			<h:outputText value="#{internalKeyBindingMBean.ocspExtensionOid}"/>
		</h:column>
		<h:column>
   			<f:facet name="header"><h:outputText value="#{web.text.INTERNALKEYBINDING_ACTIONS}"/></f:facet>
			<h:commandButton value="#{web.text.REMOVE}" action="#{internalKeyBindingMBean.removeOcspExtension}" rendered="#{internalKeyBindingMBean.inEditMode}"/>
			<f:facet name="footer">
				<h:commandButton  rendered="#{internalKeyBindingMBean.inEditMode}" action="#{internalKeyBindingMBean.addOcspExtension}"
					value="#{web.text.ADD}"/>
			</f:facet>
		</h:column>
	</h:dataTable>
    
	<h:commandButton value="#{web.text.CREATE}" action="#{internalKeyBindingMBean.createNew}" rendered="#{internalKeyBindingMBean.inEditMode and internalKeyBindingMBean.creatingNew}"/>
	<h:commandButton value="#{web.text.SAVE}" action="#{internalKeyBindingMBean.saveCurrent}" rendered="#{internalKeyBindingMBean.inEditMode and !internalKeyBindingMBean.creatingNew}"/>
	</h:form>
	
	</div> <!-- container -->
	
	<%	// Include Footer 
	String footurl = globalconfiguration.getFootBanner(); %>
	<jsp:include page="<%= footurl %>" />
</div> <!-- main-wrapper -->
</body>
</f:view>
</html>