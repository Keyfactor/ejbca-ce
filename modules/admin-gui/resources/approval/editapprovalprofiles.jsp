<%@ taglib uri="http://java.sun.com/jsf/html" prefix="h" %>
<%@ taglib uri="http://java.sun.com/jsf/core" prefix="f" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib uri="http://myfaces.apache.org/tomahawk" prefix="t" %>
<%@ page pageEncoding="UTF-8"%>
<% response.setContentType("text/html; charset="+org.ejbca.config.WebConfiguration.getWebContentEncoding()); %>
<%@page errorPage="/errorpage.jsp" %>
<%@page import="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" %>
<%@page import="org.ejbca.config.GlobalConfiguration" %>
<%@page import="org.ejbca.core.model.authorization.AccessRulesConstants" %>
<%@page import="org.ejbca.ui.web.RequestHelper" %>
<%@page import="org.ejbca.ui.web.admin.cainterface.CAInterfaceBean" %>
<%@page import="org.cesecore.authorization.control.StandardRules" %>
<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean"/>
<jsp:useBean id="cabean" scope="session" class="org.ejbca.ui.web.admin.cainterface.CAInterfaceBean"/>
<html>
<%
  GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, AccessRulesConstants.ROLE_ADMINISTRATOR, StandardRules.APPROVALPROFILEVIEW.resource());
  cabean.initialize(ejbcawebbean);
%>
<f:view>
<head>
  <title><h:outputText value="#{web.ejbcaTitle}"/></title>
  <base href="<%=ejbcawebbean.getBaseUrl()%>"/>
  <link rel="stylesheet" type="text/css" href="<c:out value='<%=ejbcawebbean.getCssFile() %>' />"/>
  <link rel="shortcut icon" href="<%=ejbcawebbean.getImagefileInfix("favicon.png")%>" type="image/png" />
  <script type="text/javascript" src="<%=globalconfiguration.getAdminWebPath()%>ejbcajslib.js"></script>
</head>
<body>
<jsp:include page="../adminmenu.jsp" />

<div class="main-wrapper">
<div class="container">
	<h1><h:outputText value="#{web.text.MANAGEAPPROVALPROFILES}"/></h1>
	<div class="message"><h:messages layout="table" errorClass="alert" infoClass="infoMessage"/></div>
	<h:form id="editapprovalprofiles">
		<h:panelGroup rendered="#{!approvalProfilesMBean.operationInProgress}">
		<h3><h:outputText value="#{web.text.LISTOFAPPROVALPROFILES}"/></h3>
		<h:outputText value="#{approvalProfilesMBean.resetApprovalProfilesTrigger}"/>
		<h:dataTable value="#{approvalProfilesMBean.approvalProfiles}" var="approvalProfile" styleClass="grid" columnClasses="gridColumn1,gridColumn2">
			<h:column headerClass="gridColumn1">
				<f:facet name="header"><h:outputText value="#{web.text.APPROVALPROFILE_NAME}"/></f:facet>
				<h:outputText value="#{approvalProfile.name}"/>
				<f:facet name="footer">
		  			<h:inputText value="#{approvalProfilesMBean.approvalProfileName}" title="#{web.text.FORMAT_ID_STR}" size="45" maxlength="255" disabled="#{!(approvalProfilesMBean.authorizedToEdit)}"/>
				</f:facet>
			</h:column>
			<h:column headerClass="gridColumn2">
				<f:facet name="header"><h:outputText value="#{web.text.ACTIONS}"/></f:facet>
				<div class="button-group">
					<h:commandButton value="#{web.text.VIEW}" action="#{approvalProfilesMBean.actionView}"/>
					<h:commandButton value="#{web.text.EDIT}" action="#{approvalProfilesMBean.actionEdit}" rendered="#{approvalProfilesMBean.authorizedToEdit}"/>
					<h:commandButton value="#{web.text.DELETE}" action="#{approvalProfilesMBean.actionDelete}" rendered="#{approvalProfilesMBean.authorizedToEdit}"/>
					<h:commandButton value="#{web.text.RENAME}" action="#{approvalProfilesMBean.actionRename}" rendered="#{approvalProfilesMBean.authorizedToEdit}"/>
					<h:commandButton value="#{web.text.CLONE}" action="#{approvalProfilesMBean.actionAddFromTemplate}" rendered="#{approvalProfilesMBean.authorizedToEdit}"/>
				</div>
				<f:facet name="footer">
					<h:commandButton value="#{web.text.ADD}" action="#{approvalProfilesMBean.actionAdd}" disabled="#{!(approvalProfilesMBean.authorizedToEdit)}"/>
				</f:facet>
			</h:column>
		</h:dataTable>
		</h:panelGroup>
		
		
		
		<h:panelGroup rendered="#{approvalProfilesMBean.addFromTemplateInProgress}">
			<h3><h:outputText value="#{web.text.CLONE}"/></h3>
			<h:panelGrid columns="2">
				<h:outputLabel for="addFromTemplateProfileOld" value="#{web.text.APPROVALPROFILE_FROMTEMPLATE}"/>
				<h:outputText id="addFromTemplateProfileOld" value="#{approvalProfilesMBean.selectedApprovalProfileName}"/>
				<h:outputLabel for="addFromTemplateProfileNew" value="#{web.text.APPROVALPROFILE_NEWNAME}"/>
  				<h:inputText id="addFromTemplateProfileNew" value="#{approvalProfilesMBean.approvalProfileName}" title="#{web.text.FORMAT_ID_STR}" size="40" maxlength="255"/>
  				<h:panelGroup/>
				<h:panelGroup>
					<h:commandButton value="#{web.text.CLONE_CONFIRM}" action="#{approvalProfilesMBean.actionAddFromTemplateConfirm}"/>
					<h:commandButton value="#{web.text.CANCEL}" action="#{approvalProfilesMBean.actionCancel}"/>
				</h:panelGroup>
			</h:panelGrid>
		</h:panelGroup>

		<h:panelGroup rendered="#{approvalProfilesMBean.renameInProgress}">
			<h3><h:outputText value="#{web.text.RENAME}"/></h3>
			<h:panelGrid columns="2">
				<h:outputLabel for="renameProfileOld" value="#{web.text.RENAME_CURRENTNAME}"/>
				<h:outputText id="renameProfileOld" value="#{approvalProfilesMBean.selectedApprovalProfileName}"/>
				<h:outputLabel for="renameProfileNew" value="#{web.text.RENAME_NEWNAME}"/>
  				<h:inputText id="renameProfileNew" value="#{approvalProfilesMBean.approvalProfileName}" title="#{web.text.FORMAT_ID_STR}" size="40" maxlength="255"/>
  				<h:panelGroup/>
				<h:panelGroup>
					<h:commandButton value="#{web.text.RENAME_CONFIRM}" action="#{approvalProfilesMBean.actionRenameConfirm}"/>
					<h:commandButton value="#{web.text.CANCEL}" action="#{approvalProfilesMBean.actionCancel}"/>
				</h:panelGroup>
			</h:panelGrid>
		</h:panelGroup>

		<h:panelGroup rendered="#{approvalProfilesMBean.deleteInProgress}">
			<h3><h:outputText value="#{web.text.DELETE}"/></h3>
			<h:panelGrid columns="2">
				<h:outputLabel for="deleteProfileName" value="#{web.text.APPROVALPROFILE_NAME}"/>
				<h:outputText id="deleteProfileName" value="#{approvalProfilesMBean.selectedApprovalProfileName}"/>
  				<h:panelGroup/>
				<h:panelGroup>
					<h:commandButton value="#{web.text.DELETE_CONFIRM}" action="#{approvalProfilesMBean.actionDeleteConfirm}"/>
					<h:commandButton value="#{web.text.CANCEL}" action="#{approvalProfilesMBean.actionCancel}"/>
				</h:panelGroup>
			</h:panelGrid>
		</h:panelGroup>
		
		
		
	</h:form>
	</div> <!-- container -->


	<jsp:include page="<%=globalconfiguration.getFootBanner()%>"/>
</div> <!-- main-wrapper -->
</body>
</f:view>
</html>