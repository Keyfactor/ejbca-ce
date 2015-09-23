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

 // Version: $Id: customcertextension.jsp$
%>
<%@ taglib uri="http://java.sun.com/jsf/html" prefix="h" %>
<%@ taglib uri="http://java.sun.com/jsf/core" prefix="f" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ page pageEncoding="UTF-8"%>
<% response.setContentType("text/html; charset="+org.ejbca.config.WebConfiguration.getWebContentEncoding()); %>
<%@page errorPage="/errorpage.jsp" import="
org.ejbca.ui.web.admin.configuration.EjbcaWebBean,
org.ejbca.config.GlobalConfiguration,
org.ejbca.core.model.authorization.AccessRulesConstants,
org.cesecore.authorization.control.AuditLogRules,
org.cesecore.authorization.control.StandardRules
"%>

<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />
<% GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, AccessRulesConstants.ROLE_ADMINISTRATOR, StandardRules.REGULAR_EDITSYSTEMCONFIGURATION.resource()); %>
<html>
<f:view>
<head>
  <title><h:outputText value="#{web.ejbcaWebBean.globalConfiguration.ejbcaTitle}" /></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>" />
  <link rel="stylesheet" type="text/css" href="<c:out value='<%=ejbcawebbean.getCssFile() %>' />" />
  <script src="<%= globalconfiguration.getAdminWebPath() %>ejbcajslib.js"></script>
</head>
<body>
	<h1>
	    <h:outputText value="#{web.text.CUSTOMCERTEXTENSION_NEW}" rendered="#{customCertExtensionMBean.currentExtensionId == 0}"/>
		<h:outputText value="#{web.text.CUSTOMCERTEXTENSION} : #{customCertExtensionMBean.currentExtensionGUIInfo.displayName}" rendered="#{customCertExtensionMBean.currentExtensionId != 0}"/>
	</h1>
	<div class="message"><h:messages layout="table" errorClass="alert" infoClass="info"/></div>
	<h:form id="currentCustomCertExtensionForm">
		<h:panelGrid columns="2">
			<h:outputLink value="adminweb/sysconfig/systemconfiguration.jsf"><h:outputText value="#{web.text.CUSTOMCERTEXTENSION_NAV_BACK}"/></h:outputLink>
			<h:panelGroup id="placeholder1"/>
		
			<h:outputLabel for="currentCEId" value="#{web.text.IDENTIFIER}"/>
			<h:outputText id="currentCEId" value="#{customCertExtensionMBean.currentExtensionGUIInfo.id}"/>
		
			<h:outputLabel for="currentCEOid" value="#{web.text.OID}"/>
    		<h:inputText id="currentCEOid" value="#{customCertExtensionMBean.currentExtensionGUIInfo.oid}" size="25" title="#{web.text.FORMAT_OID}"/>
		
			<h:outputLabel for="currentCEDisplayName" value="#{web.text.LABEL}"/>
    		<h:inputText id="currentCEDisplayName" value="#{customCertExtensionMBean.currentExtensionGUIInfo.displayName}" size="35" title="#{web.text.FORMAT_STRING}">
    			<f:validator validatorId="legalCharsValidator"/>
    		</h:inputText>

			<h:outputLabel for="currentCEClassPath" value="#{web.text.CUSTOMCERTEXTENSION_CLASSPATH}"/>
	   		<h:inputText id="currentCEClassPath" value="#{customCertExtensionMBean.currentExtensionGUIInfo.classPath}" size="70" title="#{web.text.FORMAT_CLASSPATH}"/>
		
			<h:outputLabel for="currentCECritical" value="#{web.text.CRITICAL}"/>
			<h:panelGroup>
				<h:selectBooleanCheckbox id="currentCECritical" value="#{customCertExtensionMBean.currentExtensionGUIInfo.critical}"/>
				<h:outputLabel for="currentCECritical" value="#{web.text.CRITICAL}" />
			</h:panelGroup>

			<h:commandButton action="#{customCertExtensionMBean.saveCurrentExtension}" value="#{web.text.SAVE}" />
		</h:panelGrid>
	</h:form>

	<h2><h:outputText value="#{web.text.PROPERTIES}" /></h2>
	<h:form id="propertiesform" enctype="multipart/form-data" >
		<h:dataTable value="#{customCertExtensionMBean.currentExtensionPropertiesList}" var="prop"
					styleClass="grid" style="border-collapse: collapse; right: auto; left: auto">
			<h:column>
   				<f:facet name="header"><h:outputText value="#{web.text.KEY}"/></f:facet>
				<h:outputText value="#{prop.key}" title="#{prop.key}"/>
				<f:facet name="footer">
					<h:inputText id="currentPropertyKey" value="#{customCertExtensionMBean.currentPropertyKey}" size="25"/>
				</f:facet>
			</h:column>
			<h:column>
   				<f:facet name="header"><h:outputText value="#{web.text.VALUE}"/></f:facet>
				<h:outputText value="#{prop.value}"/>
				<f:facet name="footer">
					<h:inputText id="currentPropertyValue" value="#{customCertExtensionMBean.currentPropertyValue}" size="35">
   					</h:inputText>
				</f:facet>
			</h:column>
			<h:column>
   				<f:facet name="header">
   					<h:outputText value="#{web.text.ACTION}"/>
   				</f:facet>
				<h:commandButton action="#{customCertExtensionMBean.removeExtensionProperty}"	value="#{web.text.REMOVE}" title="#{web.text.REMOVE}"/>
				<f:facet name="footer">
					<h:commandButton  value="#{web.text.ADD}" action="#{customCertExtensionMBean.addExtensionProperty}" />
				</f:facet>
			</h:column>
		</h:dataTable>
	</h:form>


	<%	// Include Footer 
	String footurl = globalconfiguration.getFootBanner(); %>
	<jsp:include page="<%= footurl %>" />
</body>
</f:view>
</html>
