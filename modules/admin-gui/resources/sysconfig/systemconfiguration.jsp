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
org.cesecore.authorization.control.StandardRules
"%>
<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />
<% GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, AccessRulesConstants.ROLE_ADMINISTRATOR, StandardRules.REGULAR_EDITSYSTEMCONFIGURATION.resource()); %>
<html>
<f:view>
<head>
  <title><h:outputText value="#{web.ejbcaWebBean.globalConfiguration.ejbcaTitle}" /></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>" />
  <link rel="stylesheet" type="text/css" href="<%= ejbcawebbean.getCssFile() %>" />
  <script src="<%= globalconfiguration.getAdminWebPath() %>ejbcajslib.js"></script>
  <style type="text/css">
  	input[type='checkbox'].checkBoxOverlay {
  		-moz-user-focus: ignore;
  	}
  	input[type='submit'].checkBoxOverlay {
  		vertical-align: text-bottom;
  		${web.legacyInternetExplorer ? '' : 'position:relative; z-index: 1; left: -20px;'}
  		${web.legacyInternetExplorer ? 'color: #000;' : 'color: transparent; background-color: transparent; border: 0px;'}
  		width: 20px;
  		height: 20px;
  		font-size: 8px;
  		padding: 0px;
  		margin: 0px;
  		
  	}
  	label.checkBoxOverlay {
  		${web.legacyInternetExplorer ? '' : 'position:relative; z-index: 0; left: -20px;'}
  	}
  	label.subItem {
  		padding-left: 10px;
  	}
  </style>
</head>
<body>
	<h1>
		<h:outputText value="#{web.text.SYSTEMCONFIGURATION}"/>
	</h1>
	<div class="message"><h:messages layout="table" errorClass="alert" infoClass="infoMessage"/></div>

	<h:form id="systemconfiguration" enctype="multipart/form-data">
		<h:panelGrid columns="3">
			<h:outputLabel for="title" value="#{web.text.EJBCATITLE}"/>
			<h:inputText id="title" value="#{systemConfigMBean.currentConfig.title}"/>
			<h:message for="title"/>
		
			<h:outputLabel for="headbanner" value="#{web.text.HEADBANNER}"/>
			<h:inputText id="headbanner" value="#{systemConfigMBean.currentConfig.headBanner}"/>
			<h:message for="headbanner"/>
		
			<h:outputLabel for="footbanner" value="#{web.text.FOOTBANNER}"/>
			<h:inputText id="footbanner" value="#{systemConfigMBean.currentConfig.footBanner}"/>
			<h:message for="footbanner"/>
		
			<h:outputLabel for="enableeeplimit" value="#{web.text.ENABLEENDENTITYPROFILELIM}"/>
			<h:selectBooleanCheckbox id="enableeeplimit" value="#{systemConfigMBean.currentConfig.enableEndEntityProfileLimitations}"/>
			<h:message for="enableeeplimit" />
		
			<h:panelGroup>
				<h:outputLabel for="enablekeyrecovery" value="#{web.text.ENABLEKEYRECOVERY}"/>
				<%= ejbcawebbean.getHelpReference("/adminguide.html#Key%20Recovery") %>
			</h:panelGroup>
			<h:selectBooleanCheckbox id="enablekeyrecovery" value="#{systemConfigMBean.currentConfig.enableKeyRecovery}"/>
			<h:message for="enablekeyrecovery" />
		
			<h:outputLabel for="issuehwtokens" value="#{web.text.ISSUEHARDWARETOKENS}"/>
			<h:selectBooleanCheckbox id="issuehwtokens" value="#{systemConfigMBean.currentConfig.issueHardwareToken}"/>
			<h:message for="issuehwtokens" />

			<h:outputLabel for="htdEncryptCa" value="#{web.text.HARDTOKENENCRYPTCA}"/>
			<h:panelGroup id="htdEncryptCa">
				<h:selectOneMenu value="#{systemConfigMBean.currentConfig.hardTokenDataEncryptCA}">
					<f:selectItems value="#{systemConfigMBean.availableCAsAndNoEncryptionOption}"/>
				</h:selectOneMenu>
			</h:panelGroup>
			<h:message for="htdEncryptCa"/>
			
			<h:panelGroup>
				<h:outputLabel for="clearAllCaches" value="#{web.text.CLEARALLCACHES}"/>
				<%= ejbcawebbean.getHelpReference("/adminguide.html#Clear%20All%20Caches") %>
			</h:panelGroup>
			<h:panelGroup id="clearAllCaches">
				<h:selectBooleanCheckbox id="excludetokens" value="#{systemConfigMBean.excludeActiveCryptoTokensFromClearCaches}"/>
				<h:outputText value="#{web.text.CLEARALLCACHES_EXCLUDE_CRYPTOTOKEN_CACHE}" />
			</h:panelGroup>
			<h:commandButton value="#{web.text.CLEARALLCACHES}" action="#{systemConfigMBean.clearAllCaches}" />
		</h:panelGrid>
		
    	<h3><h:outputText value="Approval Notifications"/></h3>
    	<h:panelGrid columns="3">
			<h:outputLabel for="useApprovalNotifications" value="#{web.text.USEAPPROVALNOTIFICATIONS}"/>
			<h:panelGroup id="useApprovalNotifications">
				<h:selectBooleanCheckbox styleClass="checkBoxOverlay" value="#{systemConfigMBean.currentConfig.useApprovalNotifications}" />
				<h:commandButton id="toggleUseApprovalNotifications" styleClass="checkBoxOverlay" action="#{systemConfigMBean.toggleUseApprovalNotification}"
					value="#{systemConfigMBean.currentConfig.useApprovalNotifications?web.text.BOOL_TRUE:web.text.BOOL_FALSE}"/>
			</h:panelGroup>
			<h:message for="useApprovalNotifications" />
		
			<h:outputLabel for="emailToApprovalAdmin" value="#{web.text.EMAILADDRESSTOAPPROVING}"/>
			<h:inputText id="emailToApprovalAdmin" disabled="#{!systemConfigMBean.currentConfig.useApprovalNotifications}" value="#{systemConfigMBean.currentConfig.approvalAdminEmail}"/>
			<h:message for="emailToApprovalAdmin"/>
		
			<h:outputLabel for="approvalNoteFromAddress" value="#{web.text.APPROVALNOTIFICATIONFROM}"/>
			<h:inputText id="approvalNoteFromAddress" disabled="#{!systemConfigMBean.currentConfig.useApprovalNotifications}" value="#{systemConfigMBean.currentConfig.approvalNoteFromAddress}"/>
			<h:message for="approvalNoteFromAddress"/>
		</h:panelGrid>
	
    	<h3>
    		<h:outputText value="AutoEnrollment"/>
    		<%= ejbcawebbean.getExternalHelpReference("http://www.ejbca.org/guides.html#Setting%20up%20Autoenrollment%20for%20Windows%20clients%20with%20EJBCA") %>
    	</h3>
    	<h:panelGrid columns="3">
			<h:outputLabel for="useAutoEnrollment" value="#{web.text.AUTOENROLLUSE}"/>
			<h:panelGroup id="useAutoEnrollment">
				<h:selectBooleanCheckbox styleClass="checkBoxOverlay" value="#{systemConfigMBean.currentConfig.useAutoEnrollment}" />
				<h:commandButton id="toggleUseAutoEnrollment" styleClass="checkBoxOverlay" action="#{systemConfigMBean.toggleUseAutoEnrollment}"
					value="#{systemConfigMBean.currentConfig.useAutoEnrollment?web.text.BOOL_TRUE:web.text.BOOL_FALSE}"/>
			</h:panelGroup>
			<h:message for="useAutoEnrollment" />
		
			<h:outputLabel for="autoEnrollCA" value="#{web.text.AUTOENROLLCA}"/>
			<h:panelGroup id="autoEnrollCA">
				<h:selectOneMenu disabled="#{!systemConfigMBean.currentConfig.useAutoEnrollment}" value="#{systemConfigMBean.currentConfig.autoEnrollmentCA}">
					<f:selectItems value="#{systemConfigMBean.availableCAs}"/>
				</h:selectOneMenu>
			</h:panelGroup>
			<h:message for="autoEnrollCA"/>
		
			<h:outputLabel for="useSSLconnection" value="#{web.text.AUTOENROLLSSLCONNECTION}"/>
			<h:selectBooleanCheckbox id="useSSLconnection" disabled="#{!systemConfigMBean.currentConfig.useAutoEnrollment}" value="#{systemConfigMBean.currentConfig.autoEnrollUseSSLConnection}"/>
			<h:message for="useSSLconnection" />
		
			<h:outputLabel for="dcserver" value="#{web.text.AUTOENROLLADSERVER}"/>
			<h:inputText id="dcserver" disabled="#{!systemConfigMBean.currentConfig.useAutoEnrollment}" value="#{systemConfigMBean.currentConfig.autoEnrollAdServer}"/>
			<h:message for="dcserver"/>
		
			<h:outputLabel for="dcport" value="#{web.text.AUTOENROLLADPORT}"/>
			<h:inputText id="dcport" disabled="#{!systemConfigMBean.currentConfig.useAutoEnrollment}" value="#{systemConfigMBean.currentConfig.autoEnrollAdServerPort}"/>
			<h:message for="dcport"/>
		
			<h:outputLabel for="dcdn" value="#{web.text.AUTOENROLLCONNECTIONDN}"/>
			<h:inputText id="dcdn" disabled="#{!systemConfigMBean.currentConfig.useAutoEnrollment}" value="#{systemConfigMBean.currentConfig.autoEnrollConnectionDN}"/>
			<h:message for="dcdn"/>
		
			<h:outputLabel for="dcpwd" value="#{web.text.AUTOENROLLCONNECTIONPWD}"/>
			<h:inputText id="dcpwd" disabled="#{!systemConfigMBean.currentConfig.useAutoEnrollment}" value="#{systemConfigMBean.currentConfig.autoEnrollConnectionPassword}"/>
			<h:message for="dcpwd"/>
		
			<h:outputLabel for="dcBaseUserDN" value="#{web.text.AUTOENROLLBASEDNUSER}"/>
			<h:inputText id="dcBaseUserDN" disabled="#{!systemConfigMBean.currentConfig.useAutoEnrollment}" value="#{systemConfigMBean.currentConfig.autoEnrollUserBaseDN}"/>
			<h:message for="dcBaseUserDN"/>
		</h:panelGrid>
	
		<h3><h:outputText value="#{web.text.COMMANDLINEINTERFACE}"/></h3>
    	<h:panelGrid columns="3">
    		<h:panelGroup>
				<h:outputLabel for="enableCommandLine" value="#{web.text.ENABLECLIACCESS}"/>
				<%= ejbcawebbean.getHelpReference("/adminguide.html#Disabling%20the%20Command%20Line%20Interface") %>
			</h:panelGroup>
			<h:selectBooleanCheckbox id="enableCommandLine" value="#{systemConfigMBean.currentConfig.enableCommandLine}"/>
			<h:message for="enableCommandLine" />
		
			<h:panelGroup>
				<h:outputLabel for="enableCommandLineDefUser" value="#{web.text.ENABLECLIDEFAULTUSER}"/>
				<%= ejbcawebbean.getHelpReference("/adminguide.html#Local%20CLI%20Authentication") %>
			</h:panelGroup>
			<h:selectBooleanCheckbox id="enableCommandLineDefUser" value="#{systemConfigMBean.currentConfig.enableCommandLineDefaultUser}"/>
			<h:message for="enableCommandLineDefUser" />
		</h:panelGrid>
		
		<h3><h:outputText value="#{web.text.DEFAULTADMINPREFERENCES}"/></h3>
    	<h:panelGrid columns="3">
			<h:outputLabel for="preferedLanguage" value="#{web.text.PREFEREDLANGUAGE}"/>
			<h:panelGroup id="preferedLanguage">
				<h:selectOneMenu value="#{systemConfigMBean.currentConfig.preferedLanguage}">
					<f:selectItems value="#{systemConfigMBean.availableLanguages}"/>
				</h:selectOneMenu>
			</h:panelGroup>
			<h:message for="preferedLanguage" />
		
			<h:outputLabel for="secondaryLanguage" value="#{web.text.SECONDARYLANGUAGE}"/>
			<h:panelGroup id="secondaryLanguage">
				<h:selectOneMenu value="#{systemConfigMBean.currentConfig.secondaryLanguage}">
					<f:selectItems value="#{systemConfigMBean.availableLanguages}"/>
				</h:selectOneMenu>
			</h:panelGroup>
			<h:message for="secondaryLanguage" />
		
			<h:outputLabel for="theme" value="#{web.text.THEME}"/>
			<h:inputText id="theme" value="#{systemConfigMBean.currentConfig.theme}"/>
			<h:message for="theme"/>
		
			<h:outputLabel for="entriesPerPage" value="#{web.text.NUMBEROFRECORDSPERPAGE}"/>
			<h:panelGroup id="entriesPerPage">
				<h:selectOneMenu value="#{systemConfigMBean.currentConfig.entriesPerPage}">
					<f:selectItems value="#{systemConfigMBean.possibleEntriesPerPage}"/>
				</h:selectOneMenu>
			</h:panelGroup>
			<h:message for="entriesPerPage" />
		</h:panelGrid>
	
		<h3><h:outputText value="#{web.text.NODESINCLUSTER}"/></h3>
		<h:outputText value="#{web.text.NODESINCLUSTER_HELP}"/>
		<h:dataTable id="nodes" value="#{systemConfigMBean.nodesInCluster}" var="nodeEntry">
			<h:column>
   				<f:facet name="header"><h:outputText value="Node Name"/></f:facet>
				<h:outputText value="#{nodeEntry}"/>
				<f:facet name="footer">
					<h:inputText id="nodename" required="false" value="#{systemConfigMBean.currentNode}" />
				</f:facet>
			</h:column>
			<h:column>
   				<f:facet name="header"><h:outputText value="#{web.text.ACTION}"/></f:facet>
				<h:commandButton value="#{web.text.REMOVE}" action="#{systemConfigMBean.removeNode}" />
				<f:facet name="footer">
					<h:commandButton value="#{web.text.ADD}" action="#{systemConfigMBean.addNode}"/>
				</f:facet>
			</h:column>
		</h:dataTable>

		<h3>
			<h:outputText value="#{web.text.CTLOGCONFIGURATION}"/>
			<%= ejbcawebbean.getHelpReference("/adminguide.html#Certificate%20Transparency%20(Enterprise%20only)") %>
		</h3>
		<h:outputText value="#{web.text.CTLOGCONFIGURATION_HELP}"/>
		<h:dataTable id="ctlogs" value="#{systemConfigMBean.ctLogs}" var="ctlog" >
			<h:column>
   				<f:facet name="header"><h:outputText value="#{web.text.CTLOGCONFIGURATION_URL}"/></f:facet>
				<h:outputText value="#{systemConfigMBean.ctLogUrl}" title="#{ctlog.url}"/>
				<f:facet name="footer">
					<h:inputText id="currentURL" value="#{systemConfigMBean.currentCTLogURL}" />
				</f:facet>
			</h:column>
			<h:column>
   				<f:facet name="header"><h:outputText value="#{web.text.CTLOGCONFIGURATION_PUBLICKEY}"/></f:facet>
				<h:outputText value="#{systemConfigMBean.ctLogPublicKeyID}"/>
				<f:facet name="footer">
					<t:inputFileUpload id="currentCTLogKeyFile" value="#{systemConfigMBean.currentCTLogPublicKeyFile}" 
							title="#{web.text.CTLOGCONFIGURATION_PUBLICKEYFILE}" />
				</f:facet>
			</h:column>
			<h:column>
   				<f:facet name="header"><h:outputText value="#{web.text.CTLOGCONFIGURATION_TIMEOUT}"/></f:facet>
				<h:outputText value="#{systemConfigMBean.ctLogTimeout}"/>
				<f:facet name="footer">
					<h:inputText id="currentTimeout" required="false"
						value="#{systemConfigMBean.currentCTLogTimeout}"
						title="#{web.text.CTLOGCONFIGURATION_TIMEOUT}">
   					</h:inputText>
					<h:message for="currentTimeout" />
				</f:facet>
			</h:column>
			<h:column>
   				<f:facet name="header"><h:outputText value="#{web.text.ACTION}"/></f:facet>
				<h:commandButton value="#{web.text.REMOVE}" action="#{systemConfigMBean.removeCTLog}" />
				<f:facet name="footer">
					<h:commandButton  value="#{web.text.ADD}" action="#{systemConfigMBean.addCTLog}" />
				</f:facet>
			</h:column>
		</h:dataTable>
		
	
		<h:commandButton value="#{web.text.SAVE}" action="#{systemConfigMBean.saveCurrentConfig}" />
		<h:commandButton value="#{web.text.CANCEL}" action="#{systemConfigMBean.flushCache}" />
	</h:form>
	<%	// Include Footer 
	String footurl = globalconfiguration.getFootBanner(); %>
	<jsp:include page="<%= footurl %>" />
</body>
</f:view>
</html>
