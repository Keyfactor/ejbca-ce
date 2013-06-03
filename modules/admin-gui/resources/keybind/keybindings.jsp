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
		div.tabLinks {
			width: inherit;
			margin-top: 5px;
			padding-left: 2px;
			border-bottom: 1px solid #aaa;
		}
		a.tabLinkfalse {
			/*
			font-family: "Lucida Sans Unicode", "Lucida Grande", Sans-Serif;
			font-variant: small-caps;
		    text-decoration: none;
			*/
			font-size: 16px;
			font-weight: bold;
		    text-align: left;
		    padding: 2px 7px 2px 7px;
		    margin-bottom: 2px;
			color: #669;
			background: #fbfbfb;
			border-left: 1px solid #aaa;
			border-top: 1px solid #aaa;
			border-right: 1px solid #aaa;
			border-bottom: 1px solid #aaa;
			border-top-left-radius: 5px;
			border-top-right-radius: 5px;
		}
		a.tabLinktrue {
			/*
			font-family: "Lucida Sans Unicode", "Lucida Grande", Sans-Serif;
			font-variant: small-caps;
		    text-decoration: none;
			*/
			font-size: 16px;
			font-weight: bold;
		    text-align: left;
		    padding: 2px 7px 2px 7px;
		    margin-bottom: 2px;
			color: #009;
			background: #fff;
			border-left: 1px solid #aaa;
			border-top: 1px solid #aaa;
			border-right: 1px solid #aaa;
			border-bottom: 1px solid #fff;
			border-top-left-radius: 3px;
			border-top-right-radius: 3px;
		}
		a.tabLinkfalse:hover, a.tabLinktrue:hover{
			color: #009;
			background: #eee;
		}
		.infoMessage {
			font-style: italic;
			padding: 0.5em;
			border-radius: 0.3em;
			background: #fcfcfc;
			margin-bottom: 1em;
		}
   </style>
</head>
<body>
	<h1>
		<h:outputText value="#{web.text.INTERNALKEYBINDINGS}"/>
		<%= ejbcawebbean.getHelpReference("/userguide.html#Managing%20InternalKeyBindings") %>
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
	<br/>
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
			<h:outputLink value="adminweb/viewcertificate.jsp?caid=#{guiInfo.certificateInternalCaId}&ref=keybindings"
				rendered="#{guiInfo.certificateBound}">
				<h:outputText value="#{guiInfo.certificateInternalCaName}" rendered="#{guiInfo.issuedByInternalCa}"/>
				<h:outputText value="#{guiInfo.certificateIssuerDn}" rendered="#{!guiInfo.issuedByInternalCa}"/>
			</h:outputLink>
			<h:outputText value="#{web.text.INTERNALKEYBINDING_NOT_PRESENT}" rendered="#{!guiInfo.certificateBound}"/>
		</h:column>
		<h:column>
   			<f:facet name="header"><h:outputText value="#{web.text.INTERNALKEYBINDING_CERTIFICATESERIAL}"/></f:facet>
			<h:outputLink value="adminweb/viewcertificate.jsp?certsernoparameter=#{guiInfo.certificateSerialNumber},#{guiInfo.certificateIssuerDn}&ref=keybindings" rendered="#{guiInfo.certificateBound}">
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
		<h:column>
   			<f:facet name="header">
   				<h:outputText value="#{web.text.INTERNALKEYBINDING_ACTION}"/>
   			</f:facet>
			<h:commandButton rendered="#{guiInfo.status eq 'ACTIVE'}" action="#{internalKeyBindingMBean.commandDisable}"
				value="#{web.text.INTERNALKEYBINDING_DISABLE_SHORT}" title="#{web.text.INTERNALKEYBINDING_DISABLE_FULL}"/>
			<h:commandButton rendered="#{guiInfo.status eq 'DISABLED'}" action="#{internalKeyBindingMBean.commandEnable}"
				value="#{web.text.INTERNALKEYBINDING_ENABLE_SHORT}" title="#{web.text.INTERNALKEYBINDING_ENABLE_FULL}"/>
			<h:commandButton action="#{internalKeyBindingMBean.commandDelete}"
				value="#{web.text.INTERNALKEYBINDING_DELETE_SHORT}" title="#{web.text.INTERNALKEYBINDING_DELETE_FULL}"
				onclick="return confirm('#{web.text.INTERNALKEYBINDING_CONF_DELETE}')"/>
			<h:commandButton rendered="#{!guiInfo.nextKeyAliasAvailable and guiInfo.cryptoTokenAvailable}"
				action="#{internalKeyBindingMBean.commandGenerateNewKey}"
				value="#{web.text.INTERNALKEYBINDING_GENERATENEWKEY_SHORT}" title="#{web.text.INTERNALKEYBINDING_GENERATENEWKEY_FULL}"/>
			<h:commandButton rendered="#{guiInfo.cryptoTokenAvailable}" action="#{internalKeyBindingMBean.commandGenerateRequest}"
				value="#{web.text.INTERNALKEYBINDING_GETCSR_SHORT}" title="#{web.text.INTERNALKEYBINDING_GETCSR_FULL}"/>
			<h:commandButton action="#{internalKeyBindingMBean.commandReloadCertificate}"
				value="#{web.text.INTERNALKEYBINDING_RELOADCERTIFICATE_SHORT}" title="#{web.text.INTERNALKEYBINDING_RELOADCERTIFICATE_FULL}"/>
			<h:commandButton rendered="#{guiInfo.issuedByInternalCa}" action="#{internalKeyBindingMBean.commandRenewCertificate}"
				value="#{web.text.INTERNALKEYBINDING_RENEWCERTIFICATE_SHORT}" title="#{web.text.INTERNALKEYBINDING_RENEWCERTIFICATE_FULL}"/>
		</h:column>
	</h:dataTable>
	<br/>
	<h:outputLink
		value="adminweb/keybind/keybinding.jsf?internalKeyBindingId=0&type=#{internalKeyBindingMBean.selectedInternalKeyBindingType}">
		<h:outputText value="#{web.text.INTERNALKEYBINDING_CREATENEW}"/>
	</h:outputLink>
	</h:form>
	<h:form id="uploadCertificate">
		TODO: Upload new certificate for a selected IntenalKeyBinding
	</h:form>
	<%	// Include Footer 
	String footurl = globalconfiguration.getFootBanner(); %>
	<jsp:include page="<%= footurl %>" />
</body>
</f:view>
</html>
