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
<%@ page pageEncoding="ISO-8859-1"%>
<% response.setContentType("text/html; charset="+org.ejbca.config.WebConfiguration.getWebContentEncoding()); %>
<%@page errorPage="/errorpage.jsp" import="org.ejbca.ui.web.admin.configuration.EjbcaWebBean,org.ejbca.config.GlobalConfiguration" %>

<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />

<%
	GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, "/system_functionality/edit_administrator_privileges"); 
%>

<html>
<f:view>
<head>
  <title><h:outputText value="#{web.ejbcaWebBean.globalConfiguration.ejbcaTitle}" /></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>" />
  <link rel="stylesheet" type="text/css" href="<%= ejbcawebbean.getCssFile() %>" />
  <script language="javascript" src="<%= globalconfiguration.getAdminWebPath() %>ejbcajslib.js"></script>
</head>

<body>

<h1><h:outputText value="#{web.text.ADMINPRIVILEGES}" /></h1>

<div>
	<p><h:messages layout="table" errorClass="alert"/></p>

	<h:form id="groupList">
	<h:inputHidden id="newGroupName" value="#{adminGroupsManagedBean.newRoleName}">
		 <f:validator validatorId="legalCharsValidator" />
	</h:inputHidden>
	<h:inputHidden id="currentAdminGroup" value="#{adminGroupsManagedBean.currentAdminGroup}">
		 <f:validator validatorId="legalCharsValidator" />
	</h:inputHidden>
	<h:dataTable value="#{adminGroupsManagedBean.adminGroups}" var="adminGroup"
		headerClass="listHeader" rowClasses="listRow1,listRow2">
		<f:facet name="header">
			<h:outputText value="#{web.text.CURRENTADMINGROUPS}" />
		</f:facet>
		<h:column>
			<h:outputText value="#{adminGroup.roleName}"/>
		</h:column>
		<h:column>
			<h:outputLink value="#{web.ejbcaWebBean.globalConfiguration.authorizationPath}/editadminentities.jsf?currentAdminGroup=#{adminGroup.roleName}"
				styleClass="commandLink" title="#{web.text.EDITADMINS}">
				<h:outputText value="#{web.text.ADMINS}"/>
			</h:outputLink>
			<h:outputLink value="#{web.ejbcaWebBean.globalConfiguration.authorizationPath}/editbasicaccessrules.jsf?currentAdminGroup=#{adminGroup.roleName}"
				styleClass="commandLink" title="#{web.text.EDITACCESSRULES}" rendered="#{!adminGroupsManagedBean.basicRuleSetForEach.forceAdvanced}">
				<h:outputText value="#{web.text.ACCESSRULES}"/>
			</h:outputLink>
			<h:outputLink value="#{web.ejbcaWebBean.globalConfiguration.authorizationPath}/editadvancedaccessrules.jsf?currentAdminGroup=#{adminGroup.roleName}"
				styleClass="commandLink" title="#{web.text.EDITACCESSRULES}" rendered="#{adminGroupsManagedBean.basicRuleSetForEach.forceAdvanced}">
				<h:outputText value="#{web.text.ACCESSRULES}"/>
			</h:outputLink>
		</h:column>
		<h:column>
			<h:commandLink action="#{adminGroupsManagedBean.renameRole}"
				onclick="return getInputToField('groupList:newGroupName','#{web.text.ENTERNEWNAME}', '#{web.text.ONLYCHARACTERS}') && getInsertIntoField('groupList:currentAdminGroup','#{adminGroup.roleName}', '#{web.text.ONLYCHARACTERS}');"
				styleClass="commandLink" title="#{web.text.RENAMEADMINGROUP}">
				<h:outputText value="#{web.text.RENAME}"/>
			</h:commandLink>
			<h:commandLink action="#{adminGroupsManagedBean.deleteGroup}" onclick="return confirm('#{web.text.AREYOUSURE}') && getInsertIntoField('groupList:currentAdminGroup','#{adminGroup.roleName}', '#{web.text.ONLYCHARACTERS}');"
				styleClass="commandLink" title="#{web.text.DELETEGROUP}">
				<h:outputText value="#{web.text.DELETE}"/>
			</h:commandLink>
		</h:column>
	</h:dataTable>
	<p>
	<h:commandLink action="#{adminGroupsManagedBean.addGroup}" styleClass="commandLink" title="#{web.text.ADDADMINGROUP}"
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
