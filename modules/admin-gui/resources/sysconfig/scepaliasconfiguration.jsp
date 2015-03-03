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
</head>
<body>
	<h1>
		<h:outputText value="#{scepConfigMBean.currentAlias.alias}" rendered="true"/>
	</h1>
	<div class="message"><h:messages layout="table" errorClass="alert"/></div>
	<h:form id="currentAliasForm">
	<h:panelGrid columns="2">
		<h:panelGroup>
			<h:outputLink rendered="true" value="adminweb/sysconfig/scepconfiguration.jsf"><h:outputText value="#{web.text.SCEP_ALIAS_NAV_BACK}              "/></h:outputLink>
			<h:commandButton action="#{scepConfigMBean.toggleCurrentAliasEditMode}" value="#{web.text.CRYPTOTOKEN_NAV_EDIT}" rendered="#{!scepConfigMBean.currentAliasEditMode}"/>
		</h:panelGroup>
		
		<h:panelGroup id="placeholder1" rendered="true"/>
		
		<h:outputLabel for="currentAlias" value="#{web.text.SCEP_ALIAS}:"/>
		<h:panelGroup id="currentAlias">
	    	<h:outputText value="#{scepConfigMBean.currentAlias.alias}" rendered="true"/>
		</h:panelGroup>
 
		<h:outputLabel for="currentMode" value="#{web.text.SCEP_OPERATIONAL_MODE}"/>
		<h:panelGroup id="currentMode">
			<h:panelGroup rendered="#{scepConfigMBean.currentAliasEditMode}">
				<h:selectOneMenu id="selectOneMenuMode" value="#{scepConfigMBean.currentAlias.mode}"
						onchange="document.getElementById('currentAliasForm:selectAliasMode').click();">
					<f:selectItems value="#{scepConfigMBean.availableModes}"/>
				</h:selectOneMenu>
				<h:commandButton id="selectAliasMode" action="#{scepConfigMBean.selectUpdate}" value="#{scepConfigMBean.currentAlias.mode}"/>
				<script>document.getElementById('currentAliasForm:selectAliasMode').style.display = 'none';</script>
			</h:panelGroup>
			<h:outputText value="#{scepConfigMBean.currentAlias.mode}" rendered="#{!scepConfigMBean.currentAliasEditMode}"/>
		</h:panelGroup>

		<h:outputLabel for="includeca" value="#{web.text.SCEP_INCLUDE_CA}" rendered="true"/>
		<h:selectBooleanCheckbox id="includeca" value="#{scepConfigMBean.currentAlias.includeCA}" disabled="#{!scepConfigMBean.currentAliasEditMode}" rendered="true"/>

		<h:outputLabel for="eep" value="#{web.text.SCEP_RA_ENDENTITY_PROFILE}" rendered="#{scepConfigMBean.currentAlias.mode == \"RA\"}"/>
		<h:panelGroup id="eep"  rendered="#{scepConfigMBean.currentAlias.mode == \"RA\"}">
			<h:panelGroup rendered="#{scepConfigMBean.currentAliasEditMode}">
				<h:selectOneMenu id="selectOneMenuEEP" value="#{scepConfigMBean.currentAlias.raEEProfile}"
						onchange="document.getElementById('currentAliasForm:selectEEP').click();">
					<f:selectItems value="#{scepConfigMBean.authorizedEEProfileNames}"/>
				</h:selectOneMenu>
				<h:commandButton id="selectEEP" action="#{scepConfigMBean.selectUpdate}" value="#{scepConfigMBean.currentAlias.raEEProfile}"/>
				<script>document.getElementById('currentAliasForm:selectEEP').style.display = 'none';</script>
			</h:panelGroup>
			<h:outputText value="#{scepConfigMBean.currentAlias.raEEProfile}" rendered="#{!scepConfigMBean.currentAliasEditMode}"/>
		</h:panelGroup>

		<h:outputLabel for="cp" value="#{web.text.SCEP_RA_CERT_PROFILE}" rendered="#{scepConfigMBean.currentAlias.mode == \"RA\"}"/>
		<h:panelGroup id="cp" rendered="#{scepConfigMBean.currentAlias.mode == \"RA\"}">
			<h:panelGroup rendered="#{scepConfigMBean.currentAliasEditMode}">
				<h:selectOneMenu id="selectOneMenuCP" value="#{scepConfigMBean.currentAlias.raCertProfile}"
						onchange="document.getElementById('currentAliasForm:selectCP').click();">
					<f:selectItems value="#{scepConfigMBean.availableCertProfilesOfEEProfile}"/>
				</h:selectOneMenu>
				<h:commandButton id="selectCP" action="#{scepConfigMBean.selectUpdate}" value="#{scepConfigMBean.currentAlias.raCertProfile}"/>
				<script>document.getElementById('currentAliasForm:selectCP').style.display = 'none';</script>
			</h:panelGroup>
			<h:outputText value="#{scepConfigMBean.currentAlias.raCertProfile}" rendered="#{!scepConfigMBean.currentAliasEditMode}"/>
		</h:panelGroup>

		<h:outputLabel for="raca" value="#{web.text.SCEP_RA_CA}" rendered="#{scepConfigMBean.currentAlias.mode == \"RA\"}"/>
		<h:panelGroup id="raca" rendered="#{scepConfigMBean.currentAlias.mode == \"RA\"}">
			<h:panelGroup rendered="#{scepConfigMBean.currentAliasEditMode}">
				<h:selectOneMenu id="selectOneMenuRACA" value="#{scepConfigMBean.currentAlias.raDefaultCA}"
						onchange="document.getElementById('currentAliasForm:selectRACA').click();">
					<f:selectItems value="#{scepConfigMBean.availableCAsOfEEProfile}"/>
				</h:selectOneMenu>
				<h:commandButton id="selectRACA" action="#{scepConfigMBean.selectUpdate}" value="#{scepConfigMBean.currentAlias.raDefaultCA}"/>
				<script>document.getElementById('currentAliasForm:selectRACA').style.display = 'none';</script>
			</h:panelGroup>
			<h:outputText value="#{scepConfigMBean.currentAlias.raDefaultCA}" rendered="#{!scepConfigMBean.currentAliasEditMode}"/>
		</h:panelGroup>

		<h:outputLabel for="rapwd" value="#{web.text.SCEP_RA_AUTH_PASSWORD}" rendered="#{scepConfigMBean.currentAlias.mode == \"RA\"}"/>
		<h:panelGroup id="rapwd" rendered="#{scepConfigMBean.currentAlias.mode == \"RA\"}">
	    	<h:inputText  value="#{scepConfigMBean.currentAlias.raAuthPassword}" rendered="#{scepConfigMBean.currentAliasEditMode}">
	    		<f:validator validatorId="legalCharsValidator"/>
	    	</h:inputText>
	    	<h:outputText value="#{scepConfigMBean.currentAlias.raAuthPassword}" rendered="#{!scepConfigMBean.currentAliasEditMode}"/>
		</h:panelGroup>

		<h:outputLabel for="rascheme" value="#{web.text.SCEP_RA_NAME_GEN_SCHEME}" rendered="#{scepConfigMBean.currentAlias.mode == \"RA\"}"/>
		<h:panelGroup id="rascheme" rendered="#{scepConfigMBean.currentAlias.mode == \"RA\"}">
			<h:panelGroup rendered="#{scepConfigMBean.currentAliasEditMode}">
				<h:selectOneMenu id="selectOneMenuRAScheme" value="#{scepConfigMBean.currentAlias.raNameGenScheme}"
						onchange="document.getElementById('currentAliasForm:selectRAScheme').click();">
					<f:selectItems value="#{scepConfigMBean.availableSchemes}"/>
				</h:selectOneMenu>
				<h:commandButton id="selectRAScheme" action="#{scepConfigMBean.selectUpdate}" value="#{scepConfigMBean.currentAlias.raNameGenScheme}"/>
				<script>document.getElementById('currentAliasForm:selectRAScheme').style.display = 'none';</script>
			</h:panelGroup>
			<h:outputText value="#{scepConfigMBean.currentAlias.raNameGenScheme}" rendered="#{!scepConfigMBean.currentAliasEditMode}"/>
		</h:panelGroup>

		<h:outputLabel for="raparam" value="#{web.text.SCEP_RA_NAME_GEN_PARAMS}" rendered="#{scepConfigMBean.currentAlias.mode == \"RA\"}"/>
		<h:panelGroup id="raparam"  rendered="#{scepConfigMBean.currentAlias.mode == \"RA\"}">
			<h:panelGroup rendered="#{scepConfigMBean.currentAlias.raNameGenScheme==\"DN\"}">
				<h:panelGroup rendered="#{scepConfigMBean.currentAliasEditMode}">
					<h:selectOneMenu id="selectOneMenuRAParam" value="#{scepConfigMBean.currentAlias.raNameGenParams}"
							onchange="document.getElementById('currentAliasForm:selectRAParam').click();">
						<f:selectItems value="#{scepConfigMBean.dnParts}"/>
					</h:selectOneMenu>
					<h:commandButton id="selectRAParam" action="#{scepConfigMBean.selectUpdate}" value="#{scepConfigMBean.currentAlias.raNameGenParams}"/>
					<script>document.getElementById('currentAliasForm:selectRAParam').style.display = 'none';</script>
				</h:panelGroup>
				<h:outputText value="#{scepConfigMBean.currentAlias.raNameGenParams}" rendered="#{!scepConfigMBean.currentAliasEditMode}"/>
			</h:panelGroup>
	    		
	    	<h:panelGroup rendered="#{scepConfigMBean.currentAlias.raNameGenScheme==\"FIXED\"}">
	    		<h:inputText  value="#{scepConfigMBean.currentAlias.raNameGenParams}" rendered="#{scepConfigMBean.currentAliasEditMode}">
	    			<f:validator validatorId="legalCharsValidator"/>
	    		</h:inputText>
	    		<h:outputText value="#{scepConfigMBean.currentAlias.raNameGenParams}" rendered="#{!scepConfigMBean.currentAliasEditMode}"/>
			</h:panelGroup>	
		</h:panelGroup>

		<h:outputLabel for="raprefix" value="#{web.text.SCEP_RA_NAME_GEN_PREFIX}" rendered="#{scepConfigMBean.currentAlias.mode == \"RA\"}"/>
		<h:panelGroup id="raprefix" rendered="#{scepConfigMBean.currentAlias.mode == \"RA\"}">
	    	<h:inputText  value="#{scepConfigMBean.currentAlias.raNameGenPrefix}" rendered="#{scepConfigMBean.currentAliasEditMode}">
	    		<f:validator validatorId="legalCharsValidator"/>
	    	</h:inputText>
	    	<h:outputText value="#{scepConfigMBean.currentAlias.raNameGenPrefix}" rendered="#{!scepConfigMBean.currentAliasEditMode}"/>
		</h:panelGroup>

		<h:outputLabel for="rapostfix" value="#{web.text.SCEP_RA_NAME_GEN_POSTFIX}" rendered="#{scepConfigMBean.currentAlias.mode == \"RA\"}"/>
		<h:panelGroup id="rapostfix" rendered="#{scepConfigMBean.currentAlias.mode == \"RA\"}">
	    	<h:inputText  value="#{scepConfigMBean.currentAlias.raNameGenPostfix}" rendered="#{scepConfigMBean.currentAliasEditMode}">
	    		<f:validator validatorId="legalCharsValidator"/>
	    	</h:inputText>
	    	<h:outputText value="#{scepConfigMBean.currentAlias.raNameGenPostfix}" rendered="#{!scepConfigMBean.currentAliasEditMode}"/>
		</h:panelGroup>


		<h:panelGroup/>
		<h:panelGroup>
			<h:commandButton action="#{scepConfigMBean.cancelCurrentAlias}" value="#{web.text.CANCEL}" rendered="#{scepConfigMBean.currentAliasEditMode}"/>
			<h:commandButton action="#{scepConfigMBean.saveCurrentAlias}" value="#{web.text.SAVE}" rendered="#{scepConfigMBean.currentAliasEditMode}"/>
		</h:panelGroup>
	</h:panelGrid>
	</h:form>


	<%	// Include Footer 
	String footurl = globalconfiguration.getFootBanner(); %>
	<jsp:include page="<%= footurl %>" />
</body>
</f:view>
</html>
