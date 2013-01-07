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
	GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, AccessRulesConstants.ROLE_ADMINISTRATOR, AccessRulesConstants.REGULAR_ACTIVATECA); 
	EjbcaJSFHelper.getBean().setEjbcaWebBean(ejbcawebbean);
%>
<html>
<head>
  <title><c:out value="<%= globalconfiguration.getEjbcaTitle() %>" /></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>" />
  <link rel="stylesheet" type="text/css" href="<%= ejbcawebbean.getCssFile() %>" />
  <meta http-equiv="Content-Type" content="text/html; charset=<%= org.ejbca.config.WebConfiguration.getWebContentEncoding() %>" />
</head>

<f:view>
<body>
	<h1><h:outputText value="#{web.text.ACTIVATECAS}"/></h1>
	<div class="message"><h:messages layout="table" errorClass="alert"/></div>
	<h:form>
	<h:dataTable value="#{cAActivationMBean.authorizedTokensAndCas}" var="tokenAndCa" styleClass="actTokenAndCas">
		<h:column>
			<h:panelGroup>
				<h:outputLink value="adminweb/cryptotoken/cryptotoken.jsf?cryptoTokenId=#{tokenAndCa.cryptoTokenId}">
					<h2><h:outputText value="#{tokenAndCa.cryptoTokenName}"/></h2>
				</h:outputLink>
				<h:graphicImage rendered="#{tokenAndCa.cryptoTokenActive}" url="adminweb/images/status-ca-active.png" height="12" width="12" style="border-width:0"/>
				<h:graphicImage rendered="#{!tokenAndCa.cryptoTokenActive}" url="adminweb/images/status-ca-offline.png" height="12" width="12" style="border-width:0"/>
				<h:outputText value=" CryptoToken is #{web.text.ACTIVE} on #{web.ejbcaWebBean.hostName}" rendered="#{tokenAndCa.cryptoTokenActive}"/>
				<h:outputText value=" CryptoToken is #{web.text.OFFLINE} on #{web.ejbcaWebBean.hostName}" rendered="#{!tokenAndCa.cryptoTokenActive}"/>
				<h:selectBooleanCheckbox value="#{tokenAndCa.cryptoTokenNewState}" disabled="#{tokenAndCa.stateChangeDisabled}"/>
				<h:outputText value=" Keep #{web.text.ACTIVE}" rendered="#{tokenAndCa.cryptoTokenActive}"/>
				<h:outputText value=" #{web.text.ACTIVATE}" rendered="#{!tokenAndCa.cryptoTokenActive}"/>
			</h:panelGroup>
			<h:dataTable value="#{tokenAndCa.cas}" var="ca" styleClass="actCas" headerClass="actCasHeader">
				<h:column>
	    			<f:facet name="header"><h:outputText value="#{web.text.CA}"/></f:facet>
	    			<h:outputText value="#{ca.name}"/>
	    		</h:column>
				<h:column>
					<f:facet name="header"><h:outputText value="CA Service state"/></f:facet>
					<h:graphicImage rendered="#{ca.active}" url="adminweb/images/status-ca-active.png" height="12" width="12" style="border-width:0"/>
					<h:graphicImage rendered="#{!ca.active}" url="adminweb/images/status-ca-offline.png" height="12" width="12" style="border-width:0"/>
					<h:outputText value="#{web.text.ACTIVE}" rendered="#{ca.active}"/>
					<h:outputText value="#{web.text.EXPIRED}" rendered="#{ca.expired}"/>
					<h:outputText value="#{web.text.REVOKED}" rendered="#{ca.revoked}"/>
					<h:outputText value="#{web.text.OFFLINE}" rendered="#{!ca.active && !ca.expired && !ca.revoked}"/>
				</h:column>
				<h:column>
					<f:facet name="header"><h:outputText value="Action"/></f:facet>
					<h:selectBooleanCheckbox value="#{ca.newState}" disabled="#{ca.unableToChangeState}"/>
					<h:outputText value="Keep #{web.text.ACTIVE}" rendered="#{ca.active}"/>
					<h:outputText value="#{web.text.ACTIVATE}" rendered="#{!ca.active}"/>
				</h:column>
				<h:column>
					<f:facet name="header"><h:outputText value="Monitor"/></f:facet>
					<h:selectBooleanCheckbox value="#{ca.monitoredNewState}"/>
					<h:outputText value="Monitored from HealthCheck"/>
				</h:column>
			</h:dataTable>
		</h:column>
	</h:dataTable>
	<h:panelGrid columns="3">
		<h:outputLabel rendered="#{cAActivationMBean.activationCodeShown}" for="authCode" value="CryptoToken activation code:"/>
		<h:inputSecret rendered="#{cAActivationMBean.activationCodeShown}" id="authCode" value="#{cAActivationMBean.authenticationCode}"/>
		<h:commandButton action="#{cAActivationMBean.applyChanges}" value="#{web.text.APPLY}"/>
	</h:panelGrid>
	</h:form>

	<%/* Include footer */%>
	<jsp:include page="<%= globalconfiguration.getFootBanner() %>" />
</body>
</f:view>
</html>
