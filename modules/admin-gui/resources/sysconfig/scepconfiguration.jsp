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
	<h1>
		<h:outputText value="#{web.text.SCEP_MANAGEALIASES}"/>
		<%= ejbcawebbean.getHelpReference("/adminguide.html#Scep") %>
	</h1>
	<div class="message"><h:messages layout="table" errorClass="alert"/></div>
	<h3><h:outputText value="#{web.text.SCEP_LISTOFALIASES}" /></h3>
	<h:form id="aliases">
	
		<h:inputHidden id="newAlias" value="#{scepConfigMBean.newAlias}">
			<f:validator validatorId="legalCharsValidator" />
		</h:inputHidden>	
	
		<h:inputHidden id="currentAliasStr" value="#{scepConfigMBean.currentAliasStr}">
			<f:validator validatorId="legalCharsValidator" />
		</h:inputHidden>
	
		<h:dataTable value="#{scepConfigMBean.aliasGuiList}" var="alias" styleClass="grid">

			<h:column headerClass="listColumn1">
   				<f:facet name="header">
   					<h:outputText value="#{web.text.SCEP_ALIAS}"/>
   				</f:facet>
   				
				<h:outputLink value="adminweb/sysconfig/scepaliasconfiguration.jsf?alias=#{alias.alias}">
					<h:outputText value="#{alias.alias}" title="#{alias.alias}"/>
				</h:outputLink>
			</h:column>
		
			<h:column>
   				<f:facet name="header"><h:outputText value="#{web.text.SCEP_MODE}"/></f:facet>
				<h:outputText value="#{alias.mode}" title="#{alias.mode}"/>
			</h:column>
		
			<h:column>
				<f:facet name="header"><h:outputText value="#{web.text.SCEP_ACTION}"/></f:facet>
				<h:commandLink action="#{scepConfigMBean.renameAlias}"
					onclick="return getInputToField('aliases:newAlias','#{web.text.SCEP_ENTERNEWALIAS}', '#{web.text.ONLYCHARACTERS}') && getInsertIntoField('aliases:currentAliasStr','#{alias.alias}', '#{web.text.ONLYCHARACTERS}');"
					styleClass="commandLink" title="#{web.text.SCEP_RENAME_ALIAS}">
					<h:outputText value="#{web.text.RENAME}"/>
				</h:commandLink>
				<h:commandLink action="#{scepConfigMBean.deleteAlias}" onclick="return confirm('#{web.text.AREYOUSURE}') && getInsertIntoField('aliases:currentAliasStr','#{alias.alias}', '#{web.text.ONLYCHARACTERS}');"
					styleClass="commandLink" title="#{web.text.SCEP_DELETE_ALIAS}">
					<h:outputText value="#{web.text.DELETE}"/>
				</h:commandLink>
			</h:column>

		</h:dataTable>
		<br/>
		<h:commandLink action="#{scepConfigMBean.addAlias}" styleClass="commandLink" title="#{web.text.SCEP_ADD_ALIAS}"
			onclick="return getInputToField('aliases:newAlias','#{web.text.SCEP_ENTERNEWALIAS}', '#{web.text.ONLYCHARACTERS}');" >
			<h:outputText value="#{web.text.ADD}"/>
		</h:commandLink>
 
	</h:form>
	<%	// Include Footer 
	String footurl = globalconfiguration.getFootBanner(); %>
	<jsp:include page="<%= footurl %>" />
</body>
</f:view>
</html>