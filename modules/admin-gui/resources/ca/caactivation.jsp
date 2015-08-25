<%@page import="org.cesecore.authorization.control.StandardRules"%>
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
<%@ page pageEncoding="ISO-8859-1"%>
<% response.setContentType("text/html; charset="+org.ejbca.config.WebConfiguration.getWebContentEncoding()); %>
<%@page errorPage="/errorpage.jsp" import="
org.ejbca.config.GlobalConfiguration,
org.ejbca.ui.web.RequestHelper,
org.ejbca.ui.web.admin.configuration.EjbcaJSFHelper,
org.ejbca.core.model.authorization.AccessRulesConstants
"%>
<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />
<jsp:setProperty name="ejbcawebbean" property="*" /> 
<%  // Initialize environment
	GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, AccessRulesConstants.ROLE_ADMINISTRATOR, StandardRules.CAVIEW.resource()); 
	EjbcaJSFHelper.getBean().setEjbcaWebBean(ejbcawebbean);
%>
<html>
<head>
  <title><c:out value="<%= globalconfiguration.getEjbcaTitle() %>" /></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>" />
  <link rel="stylesheet" type="text/css" href="<c:out value='<%=ejbcawebbean.getCssFile() %>' />" />
  <meta http-equiv="Content-Type" content="text/html; charset=<%= org.ejbca.config.WebConfiguration.getWebContentEncoding() %>" />
</head>

<f:view>
<body>
	<h1><h:outputText value="#{web.text.ACTIVATECAS}"/></h1>
	<div class="message"><h:messages layout="table" errorClass="alert"/></div>
	<h:form>
	<h:dataTable value="#{cAActivationMBean.authorizedTokensAndCas}" var="tokenAndCa" styleClass="actCas" footerClass="actCasFooter" headerClass="actCasHeader">
		<h:column>
   			<f:facet name="header"><h:panelGroup><h:outputText value="#{web.text.CRYPTOTOKEN}"/><br/><h:outputText value="#{web.text.ACTIVATECAS_NAME}"/></h:panelGroup></f:facet>
			<h:outputLink rendered="#{tokenAndCa.first && tokenAndCa.cryptoToken.existing}" value="adminweb/cryptotoken/cryptotoken.jsf?cryptoTokenId=#{tokenAndCa.cryptoToken.cryptoTokenId}&ref=caactivation">
				<h:outputText value="#{tokenAndCa.cryptoToken.cryptoTokenName}"/>
			</h:outputLink>
			<h:outputText rendered="#{!tokenAndCa.first}" value="#{tokenAndCa.cryptoToken.cryptoTokenName}"/>
			<h:outputText rendered="#{!tokenAndCa.cryptoToken.existing}" style="font-style: italic;" value="#{web.text.ACTIVATECAS_NA}"/>
		</h:column>
		<h:column>
   			<f:facet name="header"><h:panelGroup><h:outputText value="#{web.text.CRYPTOTOKEN}"/><br/><h:outputText value="#{web.text.ACTIVATECAS_STATE}*"/></h:panelGroup></f:facet>
			<h:panelGroup rendered="#{tokenAndCa.first}">
				<h:graphicImage rendered="#{tokenAndCa.cryptoToken.cryptoTokenActive}" url="adminweb/images/status-ca-active.png" height="12" width="12" style="border-width:0"/>
				<h:graphicImage rendered="#{!tokenAndCa.cryptoToken.cryptoTokenActive}" url="adminweb/images/status-ca-offline.png" height="12" width="12" style="border-width:0"/>
				<h:outputText value=" #{web.text.ACTIVE}" rendered="#{tokenAndCa.cryptoToken.cryptoTokenActive}"/>
				<h:outputText value=" #{web.text.OFFLINE}" rendered="#{!tokenAndCa.cryptoToken.cryptoTokenActive}"/>
			</h:panelGroup>
			<h:outputText rendered="#{!tokenAndCa.first}" escape="false" value=" &#12291;"/>
		</h:column>
		<h:column>
   			<f:facet name="header"><h:panelGroup><h:outputText value="#{web.text.CRYPTOTOKEN}"/><br/><h:outputText value="#{web.text.ACTIVATECAS_ACTION}"/></h:panelGroup></f:facet>
			<h:panelGroup rendered="#{tokenAndCa.first}">
				<h:selectBooleanCheckbox value="#{tokenAndCa.cryptoToken.cryptoTokenNewState}" disabled="#{tokenAndCa.cryptoToken.stateChangeDisabled}"/>
				<h:outputText value=" #{web.text.ACTIVATECAS_KEEPACT}" rendered="#{tokenAndCa.cryptoToken.cryptoTokenActive}"/>
				<h:outputText value=" #{web.text.ACTIVATE}" rendered="#{!tokenAndCa.cryptoToken.cryptoTokenActive}"/>
			</h:panelGroup>
			<h:outputText rendered="#{!tokenAndCa.first}" escape="false" value=" &#12291;"/>
		</h:column>
		<h:column>
   			<f:facet name="header"><h:panelGroup><h:outputText value="#{web.text.CA}"/><br/><h:outputText value="#{web.text.ACTIVATECAS_NAME}"/></h:panelGroup></f:facet>
   			<h:outputText value="#{tokenAndCa.ca.name}"/>
   		</h:column>
		<h:column>
   			<f:facet name="header"><h:panelGroup><h:outputText value="#{web.text.CA}"/><br/><h:outputText value="#{web.text.ACTIVATECAS_SSTATE}"/></h:panelGroup></f:facet>
			<h:graphicImage rendered="#{tokenAndCa.ca.active}" url="adminweb/images/status-ca-active.png" height="12" width="12" style="border-width:0"/>
			<h:graphicImage rendered="#{!tokenAndCa.ca.active}" url="adminweb/images/status-ca-offline.png" height="12" width="12" style="border-width:0"/>
			<h:outputText value="#{web.text.ACTIVE}" rendered="#{tokenAndCa.ca.active}"/>
			<h:outputText value="#{web.text.EXPIRED}" rendered="#{tokenAndCa.ca.expired}"/>
			<h:outputText value="#{web.text.REVOKED}" rendered="#{tokenAndCa.ca.revoked}"/>
			<h:outputText value="#{web.text.OFFLINE}" rendered="#{!tokenAndCa.ca.active && !tokenAndCa.ca.expired && !tokenAndCa.ca.revoked}"/>
		</h:column>
		<h:column>
   			<f:facet name="header"><h:panelGroup><h:outputText value="#{web.text.CA}"/><br/><h:outputText value="#{web.text.ACTIVATECAS_SACTION}"/></h:panelGroup></f:facet>
			<h:selectBooleanCheckbox value="#{tokenAndCa.ca.newState}" disabled="#{tokenAndCa.ca.unableToChangeState or tokenAndCa.cryptoToken.stateChangeDisabled}"/>
			<h:outputText value=" #{web.text.ACTIVATECAS_KEEPACT}" rendered="#{tokenAndCa.ca.active}"/>
			<h:outputText value=" #{web.text.ACTIVATE}" rendered="#{!tokenAndCa.ca.active}"/>
		</h:column>
		<h:column>
   			<f:facet name="header"><h:panelGroup><h:outputText value="#{web.text.CA}"/><br/><h:outputText value="#{web.text.ACTIVATECAS_MONITORED}"/></h:panelGroup></f:facet>
			<h:selectBooleanCheckbox value="#{tokenAndCa.ca.monitoredNewState}" disabled="#{!tokenAndCa.cryptoToken.existing or not cAActivationMBean.authorizedToBasicFunctions}"/>
			<h:outputText value="#{web.text.ACTIVATECAS_HCHECK}"/>
		</h:column>
		<f:facet name="footer">
			<h:outputText value="* #{web.text.ACTIVATECAS_FOOTNOTE} (#{web.ejbcaWebBean.hostName})."/>
		</f:facet>
	</h:dataTable>
	<h:panelGrid columns="3">
		<h:outputLabel rendered="#{cAActivationMBean.activationCodeShown}" for="authCode" value="#{web.text.ACTIVATECAS_ACTCODE}:"/>
		<h:inputSecret rendered="#{cAActivationMBean.activationCodeShown}" id="authCode" value="#{cAActivationMBean.authenticationCode}"/>
		<h:commandButton action="#{cAActivationMBean.applyChanges}" value="#{web.text.APPLY}" disabled="#{not cAActivationMBean.authorizedToBasicFunctions }" />
	</h:panelGrid>
	</h:form>
 
	<%/* Include footer */%>
	<jsp:include page="<%= globalconfiguration.getFootBanner() %>" />
</body>
</f:view>
</html>
