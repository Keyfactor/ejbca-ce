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
<%@ page pageEncoding="UTF-8"%>
<% response.setContentType("text/html; charset="+org.ejbca.config.WebConfiguration.getWebContentEncoding()); %>
<%@page errorPage="/errorpage.jsp" import="
org.ejbca.ui.web.admin.configuration.EjbcaWebBean,
org.ejbca.config.GlobalConfiguration,
org.ejbca.core.model.authorization.AccessRulesConstants,
org.cesecore.authorization.control.AuditLogRules,
org.cesecore.authorization.control.CryptoTokenRules
"%>

<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />
<% GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, AccessRulesConstants.ROLE_ADMINISTRATOR, CryptoTokenRules.BASE.resource()); %>
<html>
<f:view>
<head>
  <title><h:outputText value="#{web.ejbcaWebBean.globalConfiguration.ejbcaTitle}" /></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>" />
  <link rel="stylesheet" type="text/css" href="<%= ejbcawebbean.getCssFile() %>" />
  <script src="<%= globalconfiguration.getAdminWebPath() %>ejbcajslib.js"></script>
</head>
<body>
	<h1>
	    <h:outputText value="#{web.text.CRYPTOTOKEN_NEW}" rendered="#{cryptoTokenMBean.currentCryptoTokenId == 0}"/>
		<h:outputText value="#{web.text.CRYPTOTOKEN} #{cryptoTokenMBean.currentCryptoToken.name}" rendered="#{cryptoTokenMBean.currentCryptoTokenId != 0}"/>
	</h1>
	<div class="message"><h:messages layout="table" errorClass="alert" infoClass="info"/></div>
	<h:form id="currentCryptoTokenForm">
	<h:panelGrid columns="2">
		<h:panelGroup>
			<h:outputLink rendered="#{cryptoTokenMBean.paramRef eq 'default'}" value="adminweb/cryptotoken/cryptotokens.jsf"><h:outputText value="#{web.text.CRYPTOTOKEN_NAV_BACK}"/></h:outputLink>
			<h:outputLink rendered="#{cryptoTokenMBean.paramRef eq 'caactivation'}" value="adminweb/ca/caactivation.jsf"><h:outputText value="#{web.text.CRYPTOTOKEN_NAV_BACK_ACT}"/></h:outputLink>
		</h:panelGroup>
		<h:commandButton action="#{cryptoTokenMBean.toggleCurrentCryptoTokenEditMode}" value="#{web.text.CRYPTOTOKEN_NAV_EDIT}" rendered="#{!cryptoTokenMBean.currentCryptoTokenEditMode && cryptoTokenMBean.allowedToModify}"/>
		<h:panelGroup id="placeholder1" rendered="#{cryptoTokenMBean.currentCryptoTokenEditMode || !cryptoTokenMBean.allowedToModify}"/>
		<h:outputLabel for="currentCryptoTokenId" value="Id:" rendered="#{cryptoTokenMBean.currentCryptoTokenId != 0}"/>
		<h:outputText id="currentCryptoTokenId" value="#{cryptoTokenMBean.currentCryptoTokenId}" rendered="#{cryptoTokenMBean.currentCryptoTokenId != 0}"/>
		<h:outputLabel for="currentCryptoTokenName" value="#{web.text.CRYPTOTOKEN_NAME}:"/>
		<h:panelGroup id="currentCryptoTokenName">
	    	<h:inputText  value="#{cryptoTokenMBean.currentCryptoToken.name}" rendered="#{cryptoTokenMBean.currentCryptoTokenEditMode}">
	    		<f:validator validatorId="legalCharsValidator"/>
	    	</h:inputText>
	    	<h:outputText value="#{cryptoTokenMBean.currentCryptoToken.name}" rendered="#{!cryptoTokenMBean.currentCryptoTokenEditMode}"/>
		</h:panelGroup>
		<h:outputLabel for="currentCryptoTokenType" value="#{web.text.CRYPTOTOKEN_TYPE}:"/>
		<h:panelGroup id="currentCryptoTokenType">
			<h:panelGroup rendered="#{cryptoTokenMBean.currentCryptoTokenId == 0}">
			<h:selectOneMenu id="selectOneMenuType" value="#{cryptoTokenMBean.currentCryptoToken.type}"
				onchange="document.getElementById('currentCryptoTokenForm:selectCryptoTokenType').click();">
				<f:selectItems value="#{cryptoTokenMBean.availableCryptoTokenTypes}"/>
			</h:selectOneMenu>
			<h:commandButton id="selectCryptoTokenType" action="#{cryptoTokenMBean.selectCryptoTokenType}" value="Update"/>
			<script>document.getElementById('currentCryptoTokenForm:selectCryptoTokenType').style.display = 'none';</script>
			</h:panelGroup>
	    	<h:outputText value="#{cryptoTokenMBean.currentCryptoToken.type}"
	    		rendered="#{cryptoTokenMBean.currentCryptoTokenId != 0}"/>
		</h:panelGroup>
		<h:outputLabel for="currentCryptoTokenReferenced" value="#{web.text.CRYPTOTOKEN_REFDHEAD}:" rendered="#{cryptoTokenMBean.currentCryptoTokenId!=0}"/>
		<h:selectBooleanCheckbox id="currentCryptoTokenReferenced" value="#{cryptoTokenMBean.currentCryptoToken.referenced}" disabled="true" rendered="#{cryptoTokenMBean.currentCryptoTokenId!=0}"/>
		<h:outputLabel for="currentCryptoTokenActive" value="#{web.text.CRYPTOTOKEN_ACTIVE}:" rendered="#{cryptoTokenMBean.currentCryptoTokenId!=0}"/>
		<h:selectBooleanCheckbox id="currentCryptoTokenActive" value="#{cryptoTokenMBean.currentCryptoToken.active}" disabled="true" rendered="#{cryptoTokenMBean.currentCryptoTokenId!=0}"/>
		<h:outputLabel for="currentCryptoTokenSecret1" value="#{web.text.CRYPTOTOKEN_PIN}:" rendered="#{cryptoTokenMBean.currentCryptoTokenEditMode}"/>
    	<h:inputSecret id="currentCryptoTokenSecret1" value="#{cryptoTokenMBean.currentCryptoToken.secret1}" rendered="#{cryptoTokenMBean.currentCryptoTokenEditMode}"/>
		<h:outputLabel for="currentCryptoTokenSecret2" value="#{web.text.CRYPTOTOKEN_PIN_REPEAT}:" rendered="#{cryptoTokenMBean.currentCryptoTokenEditMode}"/>
    	<h:inputSecret id="currentCryptoTokenSecret2" value="#{cryptoTokenMBean.currentCryptoToken.secret2}" rendered="#{cryptoTokenMBean.currentCryptoTokenEditMode}"/>
		<h:outputLabel for="currentCryptoTokenAutoActivate" value="#{web.text.CRYPTOTOKEN_AUTO}:"/>
		<h:selectBooleanCheckbox id="currentCryptoTokenAutoActivate" value="#{cryptoTokenMBean.currentCryptoToken.autoActivate}"
			disabled="#{!cryptoTokenMBean.currentCryptoTokenEditMode}"/>
		<h:panelGroup id="currentCryptoTokenAllowExportPrivateKeyPanelGroup" rendered="#{cryptoTokenMBean.currentCryptoToken.showSoftCryptoToken}">
			<h:outputLabel id="currentCryptoTokenAllowExportPrivateKeyLabel" for="currentCryptoTokenAllowExportPrivateKey"
				value="#{web.text.CRYPTOTOKEN_ALLOWEXPORT} "/>
			<%= ejbcawebbean.getHelpReference("/userguide.html#New%20Crypto%20Tokens") + ":" %>
		</h:panelGroup>
		<h:selectBooleanCheckbox id="currentCryptoTokenAllowExportPrivateKey" rendered="#{cryptoTokenMBean.currentCryptoToken.showSoftCryptoToken}"
			value="#{cryptoTokenMBean.currentCryptoToken.allowExportPrivateKey}" disabled="#{!cryptoTokenMBean.currentCryptoTokenEditMode}"/>
		<h:outputLabel id="currentCryptoTokenP11LibraryLabel" for="currentCryptoTokenP11Library" rendered="#{cryptoTokenMBean.currentCryptoToken.showP11CryptoToken}"
			value="#{web.text.CRYPTOTOKEN_TYPE_P11} #{web.text.CRYPTOTOKEN_LIBRARY}:"/>
		<h:panelGroup id="currentCryptoTokenP11Library" rendered="#{cryptoTokenMBean.currentCryptoToken.showP11CryptoToken}">
			<h:selectOneMenu value="#{cryptoTokenMBean.currentCryptoToken.p11Library}" rendered="#{cryptoTokenMBean.currentCryptoTokenEditMode}">
				<f:selectItems value="#{cryptoTokenMBean.availableCryptoTokenP11Libraries}"/>
			</h:selectOneMenu>
			<h:outputText value="#{cryptoTokenMBean.currentCryptoToken.p11LibraryAlias}" rendered="#{!cryptoTokenMBean.currentCryptoTokenEditMode}"/>
		</h:panelGroup>
		<h:outputLabel id="currentCryptoTokenP11SlotLabelTypeLabel" for="currentCryptoTokenP11SlotLabelType" rendered="#{cryptoTokenMBean.currentCryptoToken.showP11CryptoToken}"
			value="#{web.text.CRYPTOTOKEN_TYPE_P11} #{web.text.CRYPTOTOKEN_LABEL_TYPE}:"/>
		<h:panelGroup id="currentCryptoTokenP11SlotLabelType" rendered="#{cryptoTokenMBean.currentCryptoToken.showP11CryptoToken}">
			<h:panelGroup rendered="#{cryptoTokenMBean.currentCryptoTokenEditMode}">
			<h:selectOneMenu value="#{cryptoTokenMBean.currentCryptoToken.p11SlotLabelType}"
				onchange="document.getElementById('currentCryptoTokenForm:selectCryptoTokenP11SlotLabelTypeLabel').click();">
				<f:selectItems value="#{cryptoTokenMBean.availableCryptoTokenP11SlotLabelTypes}"/>
			</h:selectOneMenu>
			<h:commandButton id="selectCryptoTokenP11SlotLabelTypeLabel" action="#{cryptoTokenMBean.selectCryptoTokenLabelType}" value="Update"/>
			<script>document.getElementById('currentCryptoTokenForm:selectCryptoTokenP11SlotLabelTypeLabel').style.display = 'none';</script>
			</h:panelGroup>
			<h:outputText value="#{cryptoTokenMBean.currentCryptoToken.p11SlotLabelTypeText}" rendered="#{!cryptoTokenMBean.currentCryptoTokenEditMode}"/>
		</h:panelGroup>

		<h:outputLabel id="currentCryptoTokenP11SlotLabel" for="currentCryptoTokenP11Slot" rendered="#{cryptoTokenMBean.currentCryptoToken.showP11CryptoToken}"
			value="#{web.text.CRYPTOTOKEN_TYPE_P11} #{web.text.CRYPTOTOKEN_SLOT}:"/>
		<h:panelGroup id="currentCryptoTokenP11Slot" rendered="#{cryptoTokenMBean.currentCryptoToken.showP11CryptoToken}">
			<h:panelGroup rendered="#{cryptoTokenMBean.currentCryptoTokenEditMode}">
				<h:selectOneMenu value="#{cryptoTokenMBean.currentCryptoToken.p11Slot}" rendered="#{cryptoTokenMBean.currentCryptoToken.slotOfTokenLabelType}">
					<f:selectItems value="#{cryptoTokenMBean.availableCryptoTokenP11SlotTokenLabels}"/>
				</h:selectOneMenu>
			    <h:inputText value="#{cryptoTokenMBean.currentCryptoToken.p11Slot}" rendered="#{!cryptoTokenMBean.currentCryptoToken.slotOfTokenLabelType}"/>
			</h:panelGroup>
			<h:outputText value="#{cryptoTokenMBean.currentCryptoToken.p11Slot}" rendered="#{!cryptoTokenMBean.currentCryptoTokenEditMode}"/>
		</h:panelGroup>

		<h:outputLabel id="currentCryptoTokenP11AttributeFileLabel" for="currentCryptoTokenP11AttributeFile" rendered="#{cryptoTokenMBean.currentCryptoToken.showP11CryptoToken}"
			value="#{web.text.CRYPTOTOKEN_TYPE_P11} #{web.text.CRYPTOTOKEN_ATTRFILE}:"/>
		<h:panelGroup id="currentCryptoTokenP11AttributeFile" rendered="#{cryptoTokenMBean.currentCryptoToken.showP11CryptoToken}">
			<h:selectOneMenu value="#{cryptoTokenMBean.currentCryptoToken.p11AttributeFile}" rendered="#{cryptoTokenMBean.currentCryptoTokenEditMode}">
				<f:selectItems value="#{cryptoTokenMBean.availableCryptoTokenP11AttributeFiles}"/>
			</h:selectOneMenu>
			<h:outputText value="#{cryptoTokenMBean.currentCryptoToken.p11AttributeFileAlias}" rendered="#{!cryptoTokenMBean.currentCryptoTokenEditMode}"/>
		</h:panelGroup>
		<h:panelGroup/>
		<h:panelGroup>
			<h:commandButton action="#{cryptoTokenMBean.cancelCurrentCryptoToken}" value="#{web.text.CRYPTOTOKEN_CANCEL}" rendered="#{cryptoTokenMBean.currentCryptoTokenEditMode && cryptoTokenMBean.currentCryptoTokenId != 0}"/>
			<h:commandButton action="#{cryptoTokenMBean.saveCurrentCryptoToken}" value="#{web.text.CRYPTOTOKEN_SAVE}" rendered="#{cryptoTokenMBean.currentCryptoTokenEditMode}"/>
		</h:panelGroup>
	</h:panelGrid>
	</h:form>

	<h:outputText value="#{web.text.CRYPTOTOKEN_KPM_NA}" rendered="#{!cryptoTokenMBean.currentCryptoToken.active && cryptoTokenMBean.currentCryptoTokenId!=0}"/>
	<h:form rendered="#{cryptoTokenMBean.currentCryptoToken.active}">
	<h:dataTable value="#{cryptoTokenMBean.keyPairGuiList}" var="keyPairGuiInfo" rendered="#{!cryptoTokenMBean.keyPairGuiListEmpty}"
		styleClass="grid" style="border-collapse: collapse; right: auto; left: auto">
		<h:column>
			<h:selectBooleanCheckbox value="#{keyPairGuiInfo.selected}"/>
		</h:column>
		<h:column>
   			<f:facet name="header"><h:outputText value="#{web.text.CRYPTOTOKEN_KPM_ALIAS}"/></f:facet>
			<h:outputText value="#{keyPairGuiInfo.alias}"/>
		</h:column>
		<h:column>
   			<f:facet name="header"><h:outputText value="#{web.text.CRYPTOTOKEN_KPM_ALGO}"/></f:facet>
			<h:outputText value="#{keyPairGuiInfo.keyAlgorithm}"/>
		</h:column>
		<h:column>
   			<f:facet name="header"><h:outputText value="#{web.text.CRYPTOTOKEN_KPM_SPEC}"/></f:facet>
			<h:outputText value="#{keyPairGuiInfo.keySpecification}"/>
		</h:column>
		<h:column>
   			<f:facet name="header"><h:outputText value="#{web.text.CRYPTOTOKEN_KPM_SKID}"/></f:facet>
			<h:outputText style="font-family: monospace;" value="#{keyPairGuiInfo.subjectKeyID}" rendered="#{!keyPairGuiInfo.placeholder}"/>
			<h:outputText value="#{web.text.CRYPTOTOKEN_KPM_NOTGENERATED}" rendered="#{keyPairGuiInfo.placeholder}"/>
		</h:column>
		<h:column>
   			<f:facet name="header"><h:outputText value="#{web.text.CRYPTOTOKEN_KPM_ACTION}"/></f:facet>
			<h:commandButton value="#{web.text.CRYPTOTOKEN_KPM_TEST}" action="#{cryptoTokenMBean.testKeyPair}" rendered="#{cryptoTokenMBean.allowedToKeyTest}" disabled="#{keyPairGuiInfo.placeholder}"/>
			<h:commandButton value="#{web.text.CRYPTOTOKEN_KPM_REMOVE}" action="#{cryptoTokenMBean.removeKeyPair}" rendered="#{cryptoTokenMBean.allowedToKeyRemoval}"
				onclick="return confirm('#{web.text.CRYPTOTOKEN_KPM_CONF_REM}')"/>
            <h:commandButton value="#{web.text.CRYPTOTOKEN_KPM_GENFROMTEMPLATE}" action="#{cryptoTokenMBean.generateFromTemplate}" rendered="#{keyPairGuiInfo.placeholder && cryptoTokenMBean.allowedToKeyGeneration}"/>
			<h:outputLink value="adminweb/cryptoTokenDownloads?cryptoTokenId=#{cryptoTokenMBean.currentCryptoTokenId}&alias=#{keyPairGuiInfo.alias}" rendered="#{!keyPairGuiInfo.placeholder}">
				<h:outputText value="#{web.text.CRYPTOTOKEN_KPM_DOWNPUB}"/>
			</h:outputLink>
		</h:column>
	</h:dataTable>
	<h:panelGroup rendered="#{cryptoTokenMBean.keyPairGuiListFailed}">
	    <div class="message"><table><tr><td class="alert"><h:outputText value="#{cryptoTokenMBean.keyPairGuiListError}"/></td></tr></table></div>
    </h:panelGroup>
	<h:outputText value="#{web.text.CRYPTOTOKEN_KPM_NOPAIRS}" rendered="#{cryptoTokenMBean.keyPairGuiListEmpty && !cryptoTokenMBean.keyPairGuiListFailed}"/>
	<h:panelGrid columns="3">
		<h:panelGroup rendered="#{!cryptoTokenMBean.keyPairGuiListEmpty && cryptoTokenMBean.allowedToKeyRemoval}"/>
		<h:panelGroup rendered="#{!cryptoTokenMBean.keyPairGuiListEmpty && cryptoTokenMBean.allowedToKeyRemoval}"/>
	    <h:commandButton value="#{web.text.CRYPTOTOKEN_KPM_REMOVESEL}" action="#{cryptoTokenMBean.removeSelectedKeyPairs}"
	    	rendered="#{!cryptoTokenMBean.keyPairGuiListEmpty && cryptoTokenMBean.allowedToKeyRemoval}" onclick="return confirm('#{web.text.CRYPTOTOKEN_KPM_CONF_REMS}')"/>
		<h:inputText value="#{cryptoTokenMBean.newKeyPairAlias}" rendered="#{cryptoTokenMBean.allowedToKeyGeneration}">
			<f:validator validatorId="legalCharsValidator"/>
		</h:inputText>
		<h:selectOneMenu value="#{cryptoTokenMBean.newKeyPairSpec}" rendered="#{cryptoTokenMBean.allowedToKeyGeneration}">
			<f:selectItems value="#{cryptoTokenMBean.availbleKeySpecs}"/>
		</h:selectOneMenu>
	    <h:commandButton value="#{web.text.CRYPTOTOKEN_KPM_GENNEW}" action="#{cryptoTokenMBean.generateNewKeyPair}"/>
	</h:panelGrid>
	</h:form>
	<%	// Include Footer 
	String footurl = globalconfiguration.getFootBanner(); %>
	<jsp:include page="<%= footurl %>" />
</body>
</f:view>
</html>
