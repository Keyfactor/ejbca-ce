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
<%@page errorPage="/errorpage.jsp" import="org.ejbca.ui.web.admin.configuration.EjbcaWebBean,org.ejbca.core.model.ra.raadmin.GlobalConfiguration"%>

<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />

<%
	GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, "/system_functionality/edit_administrator_privileges"); 
%>

<html>
<f:view>
<head>
  <title><h:outputText value="#{web.ejbcaWebBean.globalConfiguration.ejbcaTitle}" /></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>">
  <link rel="stylesheet" type="text/css" href="<%= ejbcawebbean.getCssFile() %>">
  <script language="javascript" src="<%= globalconfiguration.getAdminWebPath() %>ejbcajslib.js"></script>
</head>
<body>

<div align="center">
	<p><H2><h:outputText value="#{web.text.ADMINSINGROUP} #{adminGroupsManagedBean.currentAdminGroup}"
  			rendered="#{not empty adminGroupsManagedBean.currentAdminGroup}"/></H2></p>
	<h:outputText value="#{web.text.AUTHORIZATIONDENIED}" rendered="#{empty adminGroupsManagedBean.currentAdminGroup && !adminGroupsManagedBean.authorizedToGroup}"/>
	<h:panelGroup rendered="#{not empty adminGroupsManagedBean.currentAdminGroup && adminGroupsManagedBean.authorizedToGroup}">
 
	<div align="right">
	<h:panelGrid columns="1" style="text-align: right;">
		<h:outputLink value="#{web.ejbcaWebBean.globalConfiguration.authorizationPath}/administratorprivileges.jsf"
			title="#{web.text.BACKTOADMINGROUPS}">
			<h:outputText value="#{web.text.BACKTOADMINGROUPS}"/>
		</h:outputLink>
		<h:outputLink value="#{web.ejbcaWebBean.globalConfiguration.authorizationPath}/editbasicaccessrules.jsf?currentAdminGroup=#{adminGroupsManagedBean.currentAdminGroup}"
			title="#{web.text.EDITACCESSRULES}" rendered="#{not empty adminGroupsManagedBean.currentAdminGroup && not adminGroupsManagedBean.basicRuleSet.forceAdvanced}">
			<h:outputText value="#{web.text.EDITACCESSRULES}"/>
		</h:outputLink>
		<h:outputLink value="#{web.ejbcaWebBean.globalConfiguration.authorizationPath}/editadvancedaccessrules.jsf?currentAdminGroup=#{adminGroupsManagedBean.currentAdminGroup}"
			title="#{web.text.EDITACCESSRULES}" rendered="#{not empty adminGroupsManagedBean.currentAdminGroup && adminGroupsManagedBean.basicRuleSet.forceAdvanced}">
			<h:outputText value="#{web.text.EDITACCESSRULES}"/>
		</h:outputLink>
	</h:panelGrid>
	</div>
  
	<div align="center">
	<h:messages layout="table" errorClass="alert"/>

	<h:form id="adminListForm" rendered="#{not empty adminGroupsManagedBean.currentAdminGroup}">
	<h:inputHidden id="currentAdminGroup" value="#{adminGroupsManagedBean.currentAdminGroup}" />
	<h:dataTable value="#{adminGroupsManagedBean.admins}" var="admin" style="width: 100%;"
		headerClass="listHeader" rowClasses="listRow1,listRow2" columnClasses="caColumn,withColumn,typeColumn,valueColumn,commandColumn">
		<h:column>
			<f:facet name="header">
				<h:panelGroup>
					<h:outputText value="#{web.text.CA}" /><br />
					<h:selectOneMenu id="caId" value="#{adminGroupsManagedBean.matchCaId}">
						<f:selectItems value="#{adminGroupsManagedBean.availableCaIds}" />
					</h:selectOneMenu>
					<br /><h:outputText value="&nbsp;" escape="false"/>
				</h:panelGroup>
			</f:facet>
			<h:outputText value="#{adminGroupsManagedBean.issuingCA}"/>
		</h:column>
		<h:column>
			<f:facet name="header">
				<h:panelGroup>
					<h:outputText value="#{web.text.MATCHWITH}" /><br />
					<h:selectOneMenu id="matchWith" value="#{adminGroupsManagedBean.matchWith}">
						<f:selectItems value="#{adminGroupsManagedBean.matchWithTexts}" />
					</h:selectOneMenu> 
					<br /><h:outputText value="&nbsp;" escape="false"/>
				</h:panelGroup>
			</f:facet>
			<h:outputText value="#{adminGroupsManagedBean.adminsMatchWith}"/>
		</h:column>
		<h:column>
			<f:facet name="header">
				<h:panelGroup>
					<h:outputText value="#{web.text.MATCHTYPE}" /><br />
					<h:selectOneMenu id="matchType" value="#{adminGroupsManagedBean.matchType}">
						<f:selectItems value="#{adminGroupsManagedBean.matchTypeTexts}" />
					</h:selectOneMenu> 
					<br /><h:outputText value="&nbsp;" escape="false"/>
				</h:panelGroup>
			</f:facet>
			<h:outputText value="#{adminGroupsManagedBean.adminsMatchType}"/>
		</h:column>
		<h:column>
			<f:facet name="header">
				<h:panelGroup>
					<h:outputText value="#{web.text.MATCHVALUE}" /><br />
					<h:inputText id="matchValue" value="#{adminGroupsManagedBean.matchValue}">
						<f:validator validatorId="legalCharsValidator" />
						<f:validator validatorId="hexSerialNumberValidator" />
					</h:inputText>
					<br /><h:outputText value="&nbsp;" escape="false"/>
				</h:panelGroup>
			</f:facet>
			<h:outputText value="#{admin.matchValue}" rendered="#{adminGroupsManagedBean.adminEntityConstants.WITH_SERIALNUMBER ne admin.matchWith}"/>
			<h:outputLink
				value="#{web.ejbcaWebBean.baseUrl}#{web.ejbcaWebBean.globalConfiguration.raPath}/listendentities.jsp?action=listusers&buttonisrevoked=value&textfieldserialnumber=#{admin.matchValue}"
				rendered="#{adminGroupsManagedBean.adminEntityConstants.WITH_SERIALNUMBER eq admin.matchWith}">
				<h:outputText value="#{admin.matchValue}"/>
			</h:outputLink>
		</h:column>
		<h:column>
			<f:facet name="header">
				<h:panelGroup>
					<br />
					<h:commandButton action="#{adminGroupsManagedBean.addAdmin}" value="#{web.text.ADD}"
						styleClass="commandButton"/>
					<br /><h:outputText value="&nbsp;" escape="false"/>
				</h:panelGroup>
			</f:facet>
			<h:commandLink action="#{adminGroupsManagedBean.deleteAdmin}" title="#{web.text.DELETE}"
				styleClass="commandLink" onclick="return confirm('#{web.text.AREYOUSURE}');" >
				<h:outputText value="#{web.text.DELETE}"/>
			</h:commandLink>
		</h:column>
	</h:dataTable>
	</h:form >
	<h:outputText value="#{web.text.NOADMINSDEFINED}" rendered="#{empty adminGroupsManagedBean.admins}"/>
	</div>
	</h:panelGroup>
</div>
 
<%	// Include Footer 
	String footurl = globalconfiguration.getFootBanner(); %>
	<jsp:include page="<%= footurl %>" />
 
</body>
</f:view>
</html>
