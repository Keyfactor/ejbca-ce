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
<%@ page errorPage="/errorpage.jsp" import="
org.ejbca.ui.web.admin.configuration.EjbcaWebBean,
org.ejbca.config.GlobalConfiguration,
org.ejbca.core.model.authorization.AccessRulesConstants,
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
     <style type="text/css">
		/* TODO: Move re-usable styles to included .css */
		.expandOnClick { width: 25em;  height: 1em;  display: block; overflow: hidden; white-space: nowrap; }
		.expandOnClick:after { content: "..."; }
		.expandOnClick:focus { width: 100%; display: inline; overflow: auto; color:#000000; white-space: pre-wrap; cursor: pointer; }
		.expandOnClick:focus:after { content: ""; }
   </style>

   
</head>
<body>
	<h1>
		<h:outputText value="#{web.text.CRYPTOTOKENS}"/>
		<%= ejbcawebbean.getHelpReference("/userguide.html#Managing%20CryptoTokens") %>
	</h1>
	<div class="message"><h:messages layout="table" errorClass="alert"/></div>
	<h:form>
	<h:dataTable value="#{cryptoTokenMBean.cryptoTokenGuiList}" var="cryptoTokenGuiInfo"
		styleClass="grid" style="border-collapse: collapse; right: auto; left: auto">
		<h:column rendered="false">
			<h:selectBooleanCheckbox value="#{cryptoTokenGuiInfo.selected}"/>
		</h:column>
		<h:column>
   			<f:facet name="header"><h:outputText value="#{web.text.CRYPTOTOKEN_NAME}"/></f:facet>
			<h:outputLink value="adminweb/cryptotoken/cryptotoken.jsf?cryptoTokenId=#{cryptoTokenGuiInfo.cryptoTokenId}">
				<h:outputText value="#{cryptoTokenGuiInfo.tokenName}" title="#{web.text.CRYPTOTOKEN_VIEWWITH} #{cryptoTokenGuiInfo.cryptoTokenId}"/>
			</h:outputLink>
		</h:column>
		<h:column>
   			<f:facet name="header"><h:outputText value="#{web.text.CRYPTOTOKEN_TYPE}"/></f:facet>
			<h:outputText value="#{cryptoTokenGuiInfo.tokenType}"/>
		</h:column>
		<h:column>
   			<f:facet name="header"><h:outputText value="#{web.text.CRYPTOTOKEN_LIBRARY}"/></f:facet>
			<h:outputText value="#{cryptoTokenGuiInfo.p11LibraryAlias}"/>
		</h:column>
		<h:column>
   			<f:facet name="header"><h:outputText value="#{web.text.CRYPTOTOKEN_SLOT}"/></f:facet>
			<h:outputText value="#{cryptoTokenGuiInfo.p11Slot}"/>
		</h:column>
		<h:column>
   			<f:facet name="header"><h:outputText value="#{web.text.CRYPTOTOKEN_ACTIVE}"/></f:facet>
			<h:graphicImage height="16" width="16" url="#{cryptoTokenGuiInfo.statusImg}" style="border-width:0"/>
		</h:column>
		<h:column>
   			<f:facet name="header">
			<h:panelGroup>
   				<h:outputText value="#{web.text.CRYPTOTOKEN_ACTION}"/>
   				<%= ejbcawebbean.getHelpReference("/userguide.html#Activation%20and%20deactivation") %>
			</h:panelGroup>
   			</f:facet>
			<h:panelGroup rendered="#{!cryptoTokenGuiInfo.active && cryptoTokenGuiInfo.allowedActivation}">
				<h:inputSecret size="16" title="#{web.text.CRYPTOTOKEN_PIN}" value="#{cryptoTokenGuiInfo.authenticationCode}"/>
				<h:commandButton value="#{web.text.CRYPTOTOKEN_ACTIVATE}" action="#{cryptoTokenMBean.activateCryptoToken}"/>
			</h:panelGroup>
			<h:panelGroup rendered="#{cryptoTokenGuiInfo.active && cryptoTokenGuiInfo.allowedDeactivation}">
				<h:commandButton value="#{web.text.CRYPTOTOKEN_DEACTIVATE}" action="#{cryptoTokenMBean.deactivateCryptoToken}" rendered="#{!cryptoTokenGuiInfo.autoActivation}"/>
				<h:commandButton value="#{web.text.CRYPTOTOKEN_REACTIVATE}" action="#{cryptoTokenMBean.deactivateCryptoToken}" rendered="#{cryptoTokenGuiInfo.autoActivation}"/>
			</h:panelGroup>
			<h:commandButton value="#{web.text.CRYPTOTOKEN_DELETE}" action="#{cryptoTokenMBean.deleteCryptoToken}" rendered="#{!cryptoTokenGuiInfo.active && cryptoTokenMBean.allowedToDelete}"/>
		</h:column>
	</h:dataTable>
	<br/>
	<h:outputLink value="adminweb/cryptotoken/cryptotoken.jsf?cryptoTokenId=0" rendered="#{cryptoTokenMBean.allowedToModify}">
		<h:outputText value="#{web.text.CRYPTOTOKEN_CREATENEW}"/>
	</h:outputLink>

	</h:form>
	<%	// Include Footer 
	String footurl = globalconfiguration.getFootBanner(); %>
	<jsp:include page="<%= footurl %>" />
</body>
</f:view>
</html>