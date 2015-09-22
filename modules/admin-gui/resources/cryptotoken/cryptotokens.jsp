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
org.cesecore.authorization.control.CryptoTokenRules
"%>
<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />
<% GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, AccessRulesConstants.ROLE_ADMINISTRATOR, CryptoTokenRules.VIEW.resource()); %>
<html>
<f:view>
<head>
  <title><h:outputText value="#{web.ejbcaWebBean.globalConfiguration.ejbcaTitle}" /></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>" />
  <link rel="stylesheet" type="text/css" href="<c:out value='<%=ejbcawebbean.getCssFile() %>' />"/>
  <script src="<%= globalconfiguration.getAdminWebPath() %>ejbcajslib.js"></script>
  <script>
	/** Prevent form submission if enter is pressed in form and instead clicks on the button right of the inputText instead..) */
	function preventSubmitOnEnter(o, e) {
		if (typeof e == 'undefined' && window.event) {
			e = window.event;
		}
		if (e.keyCode == 13) {
			e.returnValue = false;
			o.nextSibling.click();
		}
	}
  </script>
   
</head>
<body>
	<h:outputText value="" rendered="#{cryptoTokenMBean.pageLoadResetTrigger}"/>
	<h1>
		<h:outputText value="#{web.text.MANAGECRYPTOTOKENS}"/>
		<%= ejbcawebbean.getHelpReference("/userguide.html#Managing%20Crypto%20Tokens") %>
	</h1>
	<div class="message"><h:messages layout="table" errorClass="alert"/></div>
	<h:form id="cryptotokens">
	<h:dataTable value="#{cryptoTokenMBean.cryptoTokenGuiList}" var="cryptoTokenGuiInfo" styleClass="grid" columnClasses=",gridCenter,,,,gridCenter,gridCenter,gridCenter,">
		<h:column rendered="false">
			<h:selectBooleanCheckbox value="#{cryptoTokenGuiInfo.selected}"/>
		</h:column>
		<h:column>
   			<f:facet name="header"><h:outputText value="#{web.text.CRYPTOTOKEN_NAME}"/></f:facet>
			<h:outputLink value="adminweb/cryptotoken/cryptotoken.jsf?cryptoTokenId=#{cryptoTokenGuiInfo.cryptoTokenId}&ref=default">
				<h:outputText value="#{cryptoTokenGuiInfo.tokenName}" title="#{web.text.CRYPTOTOKEN_VIEWWITH} #{cryptoTokenGuiInfo.cryptoTokenId}"/>
			</h:outputLink>
		</h:column>
		<h:column>
   			<f:facet name="header"><h:outputText value="#{web.text.CRYPTOTOKEN_TYPE}"/></f:facet>
			<h:outputText value="#{web.text.CRYPTOTOKEN_TYPE_P11}" rendered="#{cryptoTokenGuiInfo.p11SlotType}"/>
			<h:outputText value="#{web.text.CRYPTOTOKEN_TYPE_SOFT}" rendered="#{!cryptoTokenGuiInfo.p11SlotType}"/>
		</h:column>
		<h:column>
   			<f:facet name="header"><h:outputText value="#{web.text.CRYPTOTOKEN_LIBRARY}"/></f:facet>
			<h:outputText value="#{cryptoTokenGuiInfo.p11LibraryAlias}"/>
		</h:column>
        <h:column>
            <f:facet name="header"><h:outputText value="#{web.text.CRYPTOTOKEN_LABEL_TYPE}"/></f:facet>
            <h:outputText value="#{cryptoTokenGuiInfo.p11SlotLabelTypeText}"/>
        </h:column>
		<h:column>
   			<f:facet name="header"><h:outputText value="#{web.text.CRYPTOTOKEN_SLOT}"/></f:facet>
			<h:outputText value="#{cryptoTokenGuiInfo.p11Slot}"/>
		</h:column>
		<h:column>
   			<f:facet name="header"><h:outputText value="#{web.text.CRYPTOTOKEN_ACTIVE}"/></f:facet>
			<h:graphicImage height="16" width="16" url="#{cryptoTokenGuiInfo.statusImg}" styleClass="statusIcon"/>
		</h:column>
		<h:column>
   			<f:facet name="header"><h:outputText value="#{web.text.CRYPTOTOKEN_AUTO}"/></f:facet>
			<h:graphicImage height="16" width="16" url="#{cryptoTokenGuiInfo.autoActivationYesImg}" styleClass="statusIcon" rendered="#{cryptoTokenGuiInfo.autoActivation}"/>
		</h:column>
		<h:column>
   			<f:facet name="header"><h:outputText value="#{web.text.CRYPTOTOKEN_REFDHEAD}"/></f:facet>
			<h:outputText value="#{web.text.CRYPTOTOKEN_UNUSED}" rendered="#{!cryptoTokenGuiInfo.referenced}"/>
			<h:outputText value="#{web.text.CRYPTOTOKEN_REFD}" rendered="#{cryptoTokenGuiInfo.referenced}"/>
		</h:column>
		<h:column>
   			<f:facet name="header">
			<h:panelGroup>
   				<h:outputText value="#{web.text.CRYPTOTOKEN_ACTION}"/>
   				<%= ejbcawebbean.getHelpReference("/userguide.html#Activation%20and%20deactivation") %>
			</h:panelGroup>
   			</f:facet>
			<h:panelGroup rendered="#{!cryptoTokenGuiInfo.active && cryptoTokenGuiInfo.allowedActivation}">
				<h:inputSecret size="16" title="#{web.text.CRYPTOTOKEN_PIN}" value="#{cryptoTokenGuiInfo.authenticationCode}" onkeypress="preventSubmitOnEnter(this,event)"/>
				<h:commandButton value="#{web.text.CRYPTOTOKEN_ACTIVATE}" action="#{cryptoTokenMBean.activateCryptoToken}"/>
			</h:panelGroup>
			<h:panelGroup rendered="#{cryptoTokenGuiInfo.active && cryptoTokenGuiInfo.allowedDeactivation}">
				<h:commandButton value="#{web.text.CRYPTOTOKEN_DEACTIVATE}" action="#{cryptoTokenMBean.deactivateCryptoToken}" rendered="#{!cryptoTokenGuiInfo.autoActivation}"/>
				<h:commandButton value="#{web.text.CRYPTOTOKEN_REACTIVATE}" action="#{cryptoTokenMBean.deactivateCryptoToken}" rendered="#{cryptoTokenGuiInfo.autoActivation}"/>
			</h:panelGroup>
			<h:commandButton value="#{web.text.CRYPTOTOKEN_DELETE}" action="#{cryptoTokenMBean.deleteCryptoToken}"
				rendered="#{cryptoTokenMBean.allowedToDelete}" onclick="return confirm('#{web.text.CRYPTOTOKEN_CONF_DELETE}')"/>
		</h:column>
	</h:dataTable>
	<br/>
	<h:outputLink value="adminweb/cryptotoken/cryptotoken.jsf?cryptoTokenId=0&ref=cryptotokens" rendered="#{cryptoTokenMBean.allowedToModify}">
		<h:outputText value="#{web.text.CRYPTOTOKEN_CREATENEW}"/>
	</h:outputLink>

	</h:form>
	<%	// Include Footer 
	String footurl = globalconfiguration.getFootBanner(); %>
	<jsp:include page="<%= footurl %>" />
</body>
</f:view>
</html>