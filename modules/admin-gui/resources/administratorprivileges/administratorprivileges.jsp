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
	GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, AccessRulesConstants.ROLE_ADMINISTRATOR, StandardRules.EDITROLES.resource()); 
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

<h1><h:outputText value="#{web.text.MANAGEROLES}" /><%= ejbcawebbean.getHelpReference("/userguide.html#Administrator%20Roles") %></h1>

<div>
	<p><h:messages layout="table" errorClass="alert"/></p>

	<h:form id="groupList">
	<h:inputHidden id="newGroupName" value="#{rolesManagedBean.newRoleName}">
		 <f:validator validatorId="legalCharsValidator" />
	</h:inputHidden>
	<h:inputHidden id="currentRole" value="#{rolesManagedBean.currentRole}">
		 <f:validator validatorId="legalCharsValidator" />
	</h:inputHidden>
	<h:dataTable value="#{rolesManagedBean.roles}" var="role"
		headerClass="listHeader" rowClasses="Row0,Row1">
		<f:facet name="header">
			<h:outputText value="#{web.text.LISTOFROLES}" />
		</f:facet>
		<h:column>
			<h:outputText value="#{role.roleName}"/>
		</h:column>
		<h:column>
			<h:outputLink value="#{web.ejbcaWebBean.globalConfiguration.authorizationPath}/editadminentities.jsf?currentRole=#{role.roleName}"
				styleClass="commandLink" title="#{web.text.EDITADMINS}">
				<h:outputText value="#{web.text.ADMINS}"/>
			</h:outputLink>
			<h:outputLink value="#{web.ejbcaWebBean.globalConfiguration.authorizationPath}/editbasicaccessrules.jsf?currentRole=#{role.roleName}"
				styleClass="commandLink" title="#{web.text.EDITACCESSRULES}" rendered="#{!rolesManagedBean.basicRuleSetForEach.forceAdvanced}">
				<h:outputText value="#{web.text.ACCESSRULES}"/>
			</h:outputLink>
			<h:outputLink value="#{web.ejbcaWebBean.globalConfiguration.authorizationPath}/editadvancedaccessrules.jsf?currentRole=#{role.roleName}"
				styleClass="commandLink" title="#{web.text.EDITACCESSRULES}" rendered="#{rolesManagedBean.basicRuleSetForEach.forceAdvanced}">
				<h:outputText value="#{web.text.ACCESSRULES}"/>
			</h:outputLink>
		</h:column>
		<h:column>
			<h:commandLink action="#{rolesManagedBean.renameRole}"
				onclick="return getInputToField('groupList:newGroupName','#{web.text.ENTERNEWNAME}', '#{web.text.ONLYCHARACTERS}') && getInsertIntoField('groupList:currentRole','#{role.roleName}', '#{web.text.ONLYCHARACTERS}');"
				styleClass="commandLink" title="#{web.text.RENAMEROLE}">
				<h:outputText value="#{web.text.RENAME}"/>
			</h:commandLink>
			<h:commandLink action="#{rolesManagedBean.deleteRole}" onclick="return confirm('#{web.text.AREYOUSURE}') && getInsertIntoField('groupList:currentRole','#{role.roleName}', '#{web.text.ONLYCHARACTERS}');"
				styleClass="commandLink" title="#{web.text.DELETEROLE}">
				<h:outputText value="#{web.text.DELETE}"/>
			</h:commandLink>
		</h:column>
	</h:dataTable>
	<p>
	<h:commandLink action="#{rolesManagedBean.addRole}" styleClass="commandLink" title="#{web.text.ADDROLE}"
		onclick="return getInputToField('groupList:newGroupName','#{web.text.ENTERNEWNAME}', '#{web.text.ONLYCHARACTERS}');" >
		<h:outputText value="#{web.text.ADD}"/>
	</h:commandLink>
	</p>
	</h:form >
</div>

<%	// Include Footer 
	String footurl = globalconfiguration.getFootBanner(); %>
	<jsp:include page="<%= footurl %>" />

</body>
</f:view>
</html>
