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
 
 // Original version by Philip Vendil.
 
%>
<%@ taglib uri="http://java.sun.com/jsf/html" prefix="h" %>
<%@ taglib uri="http://java.sun.com/jsf/core" prefix="f" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<% response.setContentType("text/html; charset="+org.ejbca.config.WebConfiguration.getWebContentEncoding()); %>
<%@page pageEncoding="ISO-8859-1" errorPage="/errorpage.jsp"%>
<%@page import="org.cesecore.authorization.control.StandardRules"%>
<%@page import="org.ejbca.config.GlobalConfiguration"%>
<%@page import="org.ejbca.core.model.authorization.AccessRulesConstants"%>
<%@page import="org.ejbca.ui.web.admin.configuration.EjbcaWebBean"%>

<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />
 
<% 
  GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, AccessRulesConstants.ROLE_ADMINISTRATOR, StandardRules.VIEWROLES.resource()); 
%>
 
<html>
<f:view>
<head>
  <title><h:outputText value="#{web.ejbcaWebBean.globalConfiguration.ejbcaTitle}" /></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>" />
  <link rel="stylesheet" type="text/css" href="<c:out value='<%=ejbcawebbean.getCssFile() %>' />" />
  <script language="javascript" src="<%= globalconfiguration.getAdminWebPath() %>ejbcajslib.js"></script>
</head>

<body>
 
 <div align="center">

	<h2>
		<h:outputText value="#{web.text.EDITACCESSRULES}" rendered="#{rolesManagedBean.authorizedToEdit}"/> 
		<h:outputText value="#{web.text.VIEWACCESSRULES}" rendered="#{!rolesManagedBean.authorizedToEdit}" />
	</h2>
	<h3><h:outputText value="#{web.text.ADMINROLE} : #{rolesManagedBean.currentRole}" /></h3>

	<h:outputText value="#{web.text.AUTHORIZATIONDENIED}" rendered="#{!rolesManagedBean.authorizedToRole}"/>
</div>	

	<h:panelGroup rendered="#{rolesManagedBean.authorizedToRole}">
 
	<h:messages layout="table" errorClass="alert"/>
 
	<h:panelGrid styleClass="edit-top" width="100%" columns="1" rowClasses="Row0,Row1" style="text-align: right;">
		<h:outputLink value="#{web.ejbcaWebBean.globalConfiguration.authorizationPath}/administratorprivileges.jsf"
			title="#{web.text.BACKTOROLES}">
			<h:outputText value="#{web.text.BACKTOROLES}"/>
		</h:outputLink>
		<h:outputLink value="#{web.ejbcaWebBean.globalConfiguration.authorizationPath}/editadminentities.jsf?currentRole=#{rolesManagedBean.currentRole}"
			title="#{web.text.EDITADMINS}" rendered="#{not empty rolesManagedBean.currentRole}">
			<h:outputText value="#{web.text.EDITADMINS}" rendered="#{rolesManagedBean.authorizedToEdit}"/>
			<h:outputText value="#{web.text.VIEWADMINS}" rendered="#{!rolesManagedBean.authorizedToEdit}"/>
		</h:outputLink>
		<h:outputLink value="#{web.ejbcaWebBean.globalConfiguration.authorizationPath}/editbasicaccessrules.jsf?currentRole=#{rolesManagedBean.currentRole}"
			rendered="#{not empty rolesManagedBean.currentRole && !rolesManagedBean.basicRuleSet.forceAdvanced}"
			title="#{web.text.BASICMODE}">
			<h:outputText value="#{web.text.BASICMODE}"/>
		</h:outputLink>
	</h:panelGrid>
	
	<h:form id="accessRulesForm" rendered="#{not empty rolesManagedBean.currentRole}">
	<h:inputHidden id="currentRole" value="#{rolesManagedBean.currentRole}" />
	<h:dataTable value="#{rolesManagedBean.accessRulesCollections}" var="accessRuleCollection"
		headerClass="listHeader" style="width: 100%;">
		<h:column>
		<h:dataTable value="#{accessRuleCollection.collection}" var="accessRule" rendered="#{not empty accessRuleCollection.collection}"
			headerClass="listHeader" rowClasses="Row0,Row1" columnClasses="rulesColumn1,rulesColumn2,rulesColumn2" style="width: 100%">
			<f:facet name="header">
				<h:outputText value="#{web.text[accessRuleCollection.name]}"/>
			</f:facet>
			<h:column>
				<f:facet name="header">
					<h:outputText value="#{web.text.RESOURCE}" />
				</f:facet>
				<h:outputText value="#{rolesManagedBean.parsedAccessRule}"/>
			</h:column>
			<h:column>
				<f:facet name="header">
					<h:outputText value="#{web.text.RULE}" />
				</f:facet>
				<h:selectOneMenu id="selectrole" value="#{accessRule.state}" disabled="#{!rolesManagedBean.authorizedToEdit ||  !rolesManagedBean.hasAccessToRule(rolesManagedBean.parsedAccessRule, accessRule.recursive)}">
					<f:selectItems value="#{rolesManagedBean.accessRuleStates}" />
				</h:selectOneMenu> 
			</h:column>
			<h:column>
				<f:facet name="header">
					<h:outputText value="#{web.text.RECURSIVE}" />
				</f:facet>
				<h:selectBooleanCheckbox value="#{accessRule.recursive}" disabled="#{!rolesManagedBean.authorizedToEdit}"/>
			</h:column>
		</h:dataTable>
		</h:column>
	</h:dataTable>
	
	<h:panelGrid styleClass="edit-bottom" width="100%" columns="1" style="text-align: center;">
		<h:panelGroup>
			<h:commandButton action="#{rolesManagedBean.saveAdvancedAccessRules}" value="#{web.text.SAVE}" rendered="#{rolesManagedBean.authorizedToEdit}"/>
			<f:verbatim>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</f:verbatim>
			<h:commandButton action="#{rolesManagedBean.restoreAdvancedAccessRules}" value="#{web.text.RESTORE}" rendered="#{rolesManagedBean.authorizedToEdit}"/>
		</h:panelGroup>
	</h:panelGrid>
	
	</h:form>
	
	</h:panelGroup>
	
<%	// Include Footer 
	String footurl = globalconfiguration.getFootBanner(); %>
	<jsp:include page="<%= footurl %>" />

</body>
</f:view>
</html>
