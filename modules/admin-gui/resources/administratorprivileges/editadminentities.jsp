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
		<h:outputText value="#{web.text.EDITADMINS}" rendered="#{rolesManagedBean.authorizedToEdit}"/>
		<h:outputText value="#{web.text.VIEWADMINS}" rendered="#{!rolesManagedBean.authorizedToEdit}"/>
	</h2>
	<h3><h:outputText value="#{web.text.ADMINROLE} : #{rolesManagedBean.currentRole}"
  			rendered="#{not empty rolesManagedBean.currentRole}"/></h3>

	<h:outputText value="#{web.text.AUTHORIZATIONDENIED}" rendered="#{empty rolesManagedBean.currentRole && !rolesManagedBean.authorizedToRole}"/>
</div>


	<h:panelGroup rendered="#{not empty rolesManagedBean.currentRole && rolesManagedBean.authorizedToRole}">
 
	<h:panelGrid styleClass="edit-top" width="100%" columns="1" rowClasses="Row0,Row1" style="text-align: right;">
		<h:outputLink value="#{web.ejbcaWebBean.globalConfiguration.authorizationPath}/administratorprivileges.jsf"
			title="#{web.text.BACKTOROLES}">
			<h:outputText value="#{web.text.BACKTOROLES}"/>
		</h:outputLink>
		<h:outputLink value="#{web.ejbcaWebBean.globalConfiguration.authorizationPath}/editbasicaccessrules.jsf?currentRole=#{rolesManagedBean.currentRole}"
			title="#{web.text.EDITACCESSRULES}" rendered="#{not empty rolesManagedBean.currentRole && not rolesManagedBean.basicRuleSet.forceAdvanced}">
			<h:outputText value="#{web.text.EDITACCESSRULES}" rendered="#{rolesManagedBean.authorizedToEdit}"/>
			<h:outputText value="#{web.text.VIEWACCESSRULES}" rendered="#{!rolesManagedBean.authorizedToEdit}"/>
		</h:outputLink>
		<h:outputLink value="#{web.ejbcaWebBean.globalConfiguration.authorizationPath}/editadvancedaccessrules.jsf?currentRole=#{rolesManagedBean.currentRole}"
			title="#{web.text.EDITACCESSRULES}" rendered="#{not empty rolesManagedBean.currentRole && rolesManagedBean.basicRuleSet.forceAdvanced}">
			<h:outputText value="#{web.text.EDITACCESSRULES}" rendered="#{rolesManagedBean.authorizedToEdit}"/>
			<h:outputText value="#{web.text.VIEWACCESSRULES}" rendered="#{!rolesManagedBean.authorizedToEdit}"/>			
		</h:outputLink>
	</h:panelGrid>
  
	<div align="center">
	<h:messages layout="table" errorClass="alert"/>

	<h:form id="adminListForm" rendered="#{not empty rolesManagedBean.currentRole}" prependId="false">
	<h:inputHidden id="currentRole" value="#{rolesManagedBean.currentRole}" />
	<h:dataTable value="#{rolesManagedBean.admins}" var="admin" style="width: 100%;" id="adminsTable" 
		headerClass="listHeader" rowClasses="Row0,Row1" columnClasses="caColumn,typeColumn,withColumn,typeColumn,valueColumn,commandColumn">
		<h:column>
			<f:facet name="header" >
				<h:panelGroup >
					<h:outputText value="#{web.text.CA}" /><br />
					<h:selectOneMenu id="caId" value="#{rolesManagedBean.matchCaId}" rendered="#{rolesManagedBean.authorizedToEdit}">
						<f:selectItems value="#{rolesManagedBean.availableCaIds}" />
					</h:selectOneMenu>
					<h:outputText value="<br/>&nbsp;" escape="false" rendered="#{!rolesManagedBean.authorizedToEdit}"/>
				</h:panelGroup>
			</f:facet>
			<h:outputText value="#{rolesManagedBean.issuingCA}"/>
		</h:column>
		<h:column>
			<f:facet name="header">
				<h:panelGroup> 
					<h:outputText value="#{web.text.MATCHWITH}" /><br />
					<h:selectOneMenu id="matchWith" binding="#{rolesManagedBean.matchWithMenu}" rendered="#{rolesManagedBean.authorizedToEdit}">
						<f:selectItems value="#{rolesManagedBean.matchWithItems}" />
					</h:selectOneMenu> 
					<h:outputText value="<br/>&nbsp;" escape="false" rendered="#{rolesManagedBean.authorizedToEdit}"/>
				</h:panelGroup>
			</f:facet>
			<h:outputText value="#{rolesManagedBean.adminsMatchWith}"/>
		</h:column>
		<h:column>
			<f:facet name="header">
				<h:panelGroup>
					<h:outputText value="#{web.text.MATCHTYPE}" /><br />
					<h:selectOneMenu id="matchType" value="#{rolesManagedBean.matchType}"rendered="#{rolesManagedBean.authorizedToEdit}">
						<f:selectItems value="#{rolesManagedBean.matchTypeTexts}" />
					</h:selectOneMenu> 
					<h:outputText value="<br/>&nbsp;" escape="false" rendered="#{rolesManagedBean.authorizedToEdit}"/>
				</h:panelGroup>
			</f:facet>
			<h:outputText value="#{rolesManagedBean.adminsMatchType}"/>
		</h:column>
		<h:column>
			<f:facet name="header">
				<h:panelGroup>
					<h:outputText value="#{web.text.MATCHVALUE}" /><br />
					<h:inputText id="matchValue" value="#{rolesManagedBean.matchValue}" rendered="#{rolesManagedBean.authorizedToEdit}">
						<f:validator validatorId="legalCharsValidator" />
						<f:validator validatorId="hexSerialNumberValidator" />
					</h:inputText>
					<h:outputText value="<br/>&nbsp;" escape="false" rendered="#{rolesManagedBean.authorizedToEdit}"/>
				</h:panelGroup>
			</f:facet>
		    <h:outputText value="#{admin.matchValue}" rendered="#{rolesManagedBean.accessMatchValuesAsMap['CertificateAuthenticationToken:WITH_SERIALNUMBER'] ne admin.matchWith}"/> 
			<h:outputLink
				value="#{web.ejbcaWebBean.baseUrl}#{web.ejbcaWebBean.globalConfiguration.raPath}/listendentities.jsp?action=listusers&buttonisrevoked=value&textfieldserialnumber=#{admin.matchValue}"
				rendered="#{rolesManagedBean.accessMatchValuesAsMap['CertificateAuthenticationToken:WITH_SERIALNUMBER'] eq admin.matchWith}">
				<h:outputText value="#{admin.matchValue}"/>
			</h:outputLink>
		</h:column>
		<h:column>
			<f:facet name="header">
				<h:panelGroup rendered="#{rolesManagedBean.authorizedToEdit}">
					<br />
					<h:commandButton action="#{rolesManagedBean.addAdmin}" value="#{web.text.ADD}"
						styleClass="commandButton"/>
					<br /><h:outputText value="&nbsp;" escape="false"/>
				</h:panelGroup>
			</f:facet>
			<h:commandLink action="#{rolesManagedBean.deleteAdmin}" title="#{web.text.DELETE}"
				styleClass="commandLink" onclick="return confirm('#{web.text.AREYOUSURE}');" immediate="true" rendered="#{rolesManagedBean.authorizedToEdit}">
				<h:outputText value="#{web.text.DELETE}" rendered="#{rolesManagedBean.authorizedToEdit}"/>
				<f:param name="primaryKey" value="#{admin.primaryKey}"/>
			</h:commandLink>
		</h:column>
	</h:dataTable>
	</h:form >

	<h:outputText value="#{web.text.NOADMINSDEFINED}" rendered="#{empty rolesManagedBean.admins}"/>
	</div>
	</h:panelGroup>
 
<%	// Include Footer 
	String footurl = globalconfiguration.getFootBanner(); %>
	<jsp:include page="<%= footurl %>" />
 
</body>
</f:view>
</html>
