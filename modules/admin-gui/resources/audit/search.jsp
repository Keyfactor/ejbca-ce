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
<%@ page pageEncoding="ISO-8859-1"%>
<% response.setContentType("text/html; charset="+org.ejbca.config.WebConfiguration.getWebContentEncoding()); %>
<%@page errorPage="/errorpage.jsp" import="org.ejbca.ui.web.admin.configuration.EjbcaWebBean,org.ejbca.config.GlobalConfiguration" %>

<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />
<% GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, "/log_functionality/view_log"); %>
<html>
<f:view>
<head>
  <title><h:outputText value="#{web.ejbcaWebBean.globalConfiguration.ejbcaTitle}" /></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>" />
  <link rel="stylesheet" type="text/css" href="<%= ejbcawebbean.getCssFile() %>" />
  <script language="javascript" src="<%= globalconfiguration.getAdminWebPath() %>ejbcajslib.js"></script>
</head>
<body>

<h1><h:outputText value="#{web.text.AUDITHEADER}" /></h1>

<%
	//TODO: Clean up style-mess. Fix transalation keys.
%>

<div id="home" class="app">
	<p><h:messages layout="table" errorClass="alert"/></p>

	<h:form id="search">
	<h:outputLabel for="device" value="Audit Log Device"/>
	<h:selectOneMenu id="device" value="#{auditor.device}"><f:selectItems value="#{auditor.devices}" /></h:selectOneMenu>
	<h:outputLabel for="sortColumn" value="Order by"/>
	<h:selectOneMenu id="sortColumn" value="#{auditor.sortColumn}"><f:selectItems value="#{auditor.sortColumns}" /></h:selectOneMenu>
	<h:outputLabel for="sortOrder" value="Order"/>
	<h:selectOneMenu id="sortOrder" value="#{auditor.sortOrder}"><f:selectItems value="#{auditor.sortOrders}" /></h:selectOneMenu>
	<h:outputLabel for="maxResults" value="#{web.text.ENTRIESPERPAGE}"/>
	<h:inputText id="maxResults" value="#{auditor.maxResults}"><f:convertNumber type="number"/></h:inputText>
	<h:outputLabel for="startIndex" value="Results start at index"/>
	<h:inputText id="startIndex" value="#{auditor.startIndex}"><f:convertNumber type="number"/></h:inputText>

	<p>
   	<h:dataTable value="#{auditor.conditions}" var="condition" captionStyle="text-align: left; background-color: #5B8CCD; color: #FFF;" headerClass="listHeader" styleClass="grid" rowClasses="a" rendered="#{not empty auditor.conditions}">
		<f:facet name="caption"><h:outputText value="Current conditions"/></f:facet>
		<h:column><f:facet name="header"><h:outputText value="operation"/></f:facet><h:outputText value="#{condition.operation}"></h:outputText></h:column>
		<h:column><f:facet name="header"><h:outputText value="column"/></f:facet><h:outputText value="#{condition.column}"></h:outputText></h:column>
		<h:column><f:facet name="header"><h:outputText value="condition"/></f:facet><h:outputText value="#{condition.condition}"></h:outputText></h:column>
		<h:column><f:facet name="header"><h:outputText value="value"/></f:facet><h:outputText value="#{condition.value}"></h:outputText></h:column>
	</h:dataTable>
	<h:panelGrid columns="3" rendered="#{auditor.conditionToAdd == null}">
		<h:outputLabel for="conditionColumn" value="Column for new condition"/>
		<h:selectOneMenu id="conditionColumn" value="#{auditor.conditionColumn}"><f:selectItems value="#{auditor.columns}" /></h:selectOneMenu>
		<h:commandLink action="#{auditor.newCondition}" styleClass="commandLink" title="#{web.text.CONDITIONS_NEW}"><h:outputText value="#{web.text.CONDITIONS_NEW}"/></h:commandLink>
	</h:panelGrid>
	<h:panelGrid columns="6" rendered="#{auditor.conditionToAdd != null}">
		<h:selectOneMenu value="#{auditor.conditionToAdd.operation}"><f:selectItems value="#{auditor.definedOperations}"/></h:selectOneMenu>
		<h:outputText value="#{auditor.conditionToAdd.column}"></h:outputText>
		<h:selectOneMenu value="#{auditor.conditionToAdd.condition}"><f:selectItems value="#{auditor.definedConditions}"/></h:selectOneMenu>
		<h:inputText value="#{auditor.conditionToAdd.value}" rendered="#{empty auditor.conditionToAdd.options}"></h:inputText>
		<h:selectOneMenu value="#{auditor.conditionToAdd.value}" rendered="#{not empty auditor.conditionToAdd.options}"><f:selectItems value="#{auditor.conditionToAdd.options}"/></h:selectOneMenu>
		<h:commandLink action="#{auditor.addCondition}" styleClass="commandLink" title="#{web.text.CONDITIONS_ADD}"><h:outputText value="#{web.text.CONDITIONS_ADD}"/></h:commandLink>
		<h:commandLink action="#{auditor.cancelCondition}" styleClass="commandLink" title="#{web.text.CONDITIONS_CANCEL}"><h:outputText value="#{web.text.CONDITIONS_CANCEL}"/></h:commandLink>
	</h:panelGrid>
		<h:commandLink action="#{auditor.clearConditions}" styleClass="commandLink" title="#{web.text.CONDITIONS_CLEAR}"><h:outputText value="#{web.text.CONDITIONS_CLEAR}"/></h:commandLink>
	</p>
	<br/>
	<p>
		<h:commandLink action="#{auditor.previous}" styleClass="commandLink" title="#{web.text.PREVIOUS}"><h:outputText value="#{web.text.PREVIOUS}" rendered="#{auditor.startIndex != 1}"/></h:commandLink>
		<h:commandLink action="#{auditor.reload}" styleClass="commandLink" title="#{web.text.RELOAD}"><h:outputText value="#{web.text.RELOAD}"/></h:commandLink>
		<h:commandLink action="#{auditor.next}" styleClass="commandLink" title="#{web.text.NEXT}"><h:outputText value="#{web.text.NEXT}" rendered="#{not empty auditor.results}"/></h:commandLink>
	</p>

	<h:dataTable value="#{auditor.results}" var="auditLogEntry" captionStyle="text-align: left; background-color: #5B8CCD; color: #FFF;" headerClass="listHeader" styleClass="grid" rowClasses="a" rendered="#{not empty auditor.results}">
		<f:facet name="caption"><h:outputText value="Search results"/></f:facet>
		<h:column><f:facet name="header"><h:outputText value="#{web.text.TIME}"/></f:facet><h:outputText value="#{auditLogEntry.timeStamp}"><f:convertDateTime pattern="yyyy-MM-dd HH:mm:ssZZ" /></h:outputText></h:column>
		<h:column><f:facet name="header"><h:outputText value="#{web.text.EVENT}"/></f:facet><h:outputText value="#{auditLogEntry.eventTypeValue}"/></h:column>
		<h:column><f:facet name="header"><h:outputText value="eventStatus"/></f:facet><h:outputText value="#{auditLogEntry.eventStatusValue}"/></h:column>
		<h:column><f:facet name="header"><h:outputText value="#{web.text.ADMINISTRATOR}"/></f:facet><h:outputText value="#{auditLogEntry.authToken}"/></h:column>
		<h:column><f:facet name="header"><h:outputText value="service"/></f:facet><h:outputText value="#{auditLogEntry.serviceTypeValue}"/></h:column>
		<h:column><f:facet name="header"><h:outputText value="#{web.text.MODULE}"/></f:facet><h:outputText value="#{auditLogEntry.moduleTypeValue}"/></h:column>
		<h:column><f:facet name="header"><h:outputText value="#{web.text.CA}"/></f:facet>
		    <h:outputLink value="#{web.ejbcaBaseURL}#{web.ejbcaWebBean.globalConfiguration.adminWebPath}viewcertificate.jsf?caid=#{auditLogEntry.customId}"><h:outputText value="#{auditor.caIdToName[(auditLogEntry.customId)]}"/></h:outputLink>
		</h:column>
		<h:column><f:facet name="header"><h:outputText value="#{web.text.CERTIFICATENR}"/></f:facet>
		    <h:outputLink value="#{web.ejbcaBaseURL}#{web.ejbcaWebBean.globalConfiguration.adminWebPath}viewcertificate.jsf?serno=#{auditLogEntry.searchDetail1}&caid=#{auditLogEntry.customId}"><h:outputText value="#{auditLogEntry.searchDetail1}"/></h:outputLink>
		</h:column>
		<h:column><f:facet name="header"><h:outputText value="#{web.text.USERNAME_ABBR}"/></f:facet>
		    <h:outputLink value="#{web.ejbcaBaseURL}#{web.ejbcaWebBean.globalConfiguration.adminWebPath}viewcertificate.jsf?username=#{auditLogEntry.searchDetail2}"><h:outputText value="#{auditLogEntry.searchDetail2}"/></h:outputLink>
		</h:column>
		<h:column><f:facet name="header"><h:outputText value="nodeId"/></f:facet><h:outputText value="#{auditLogEntry.nodeId}"/></h:column>
		<h:column><f:facet name="header"><h:outputText value="sequenceNumber"/></f:facet><h:outputText value="#{auditLogEntry.sequenceNumber}"/></h:column>
		<h:column><f:facet name="header"><h:outputText value="additionalDetails"/></f:facet><h:outputText value="#{auditLogEntry.mapAdditionalDetails}"><f:converter converterId="mapToStringConverter"/></h:outputText></h:column>
	</h:dataTable>
	</h:form >
</div>

<%	// Include Footer 
	String footurl = globalconfiguration.getFootBanner(); %>
	<jsp:include page="<%= footurl %>" />

</body>
</f:view>
</html>
