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
  GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, AccessRulesConstants.ROLE_ADMINISTRATOR, StandardRules.CERTIFICATEPROFILEVIEW.resource());
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
<jsp:include page="../../adminmenu.jsp" />
<div class="main-wrapper">
<div class="container">
	<h1><h:outputText value="#{web.text.MANAGECERTIFICATEPROFILES}"/></h1>
	<div class="message"><h:messages layout="table" errorClass="alert" infoClass="infoMessage"/></div>
	<h:form id="editcertificateprofiles">
		<h:panelGroup rendered="#{!certProfilesBean.operationInProgress}">
		<h3><h:outputText value="#{web.text.LISTOFCERTIFICATEPROFILES}"/></h3>
		<h:outputText value="#{certProfilesBean.resetCertificateProfilesTrigger}"/>
		<h:dataTable value="#{certProfilesBean.certificateProfiles}" var="certificateProfile" styleClass="grid" columnClasses="gridColumn1,gridColumn2">
			<h:column headerClass="gridColumn1">
				<f:facet name="header"><h:outputText value="#{web.text.CERTIFICATEPROFILENAME}" title="#{certificateProfile.id}"/></f:facet>
				<h:outputText value="#{certificateProfile.name}"/>
				<h:outputText rendered="#{certificateProfile.missingCa}" value="#{web.text.MISSINGCAIDS}"/>
				<f:facet name="footer">
		  			<h:inputText value="#{certProfilesBean.certProfileName}" title="#{web.text.FORMAT_ID_STR}" size="45" maxlength="255" disabled="#{certProfilesBean.authorizedToOnlyView}"/>
				</f:facet>
			</h:column>
			<h:column headerClass="gridColumn2">
				<f:facet name="header"><h:outputText value="#{web.text.ACTIONS}"/></f:facet>
				<h:panelGroup styleClass="button-group">
				<h:commandButton value="#{web.text.VIEW}" action="#{certProfilesBean.actionView}"/>
				<h:commandButton value="#{web.text.EDIT}" action="#{certProfilesBean.actionEdit}" disabled="#{certificateProfile.fixed}" 
					rendered="#{certProfilesBean.authorizedToEdit}"/>
				<h:commandButton value="#{web.text.DELETE}" action="#{certProfilesBean.actionDelete}" disabled="#{certificateProfile.fixed}" 
					rendered="#{certProfilesBean.authorizedToEdit}"/>
				<h:commandButton value="#{web.text.RENAME}" action="#{certProfilesBean.actionRename}" disabled="#{certificateProfile.fixed}" 
					rendered="#{certProfilesBean.authorizedToEdit}"/>
				<h:commandButton value="#{web.text.CLONE}" action="#{certProfilesBean.actionAddFromTemplate}" 
					rendered="#{certProfilesBean.authorizedToEdit}"/>
				</h:panelGroup>
				<f:facet name="footer" >
					<h:commandButton value="#{web.text.ADD}" action="#{certProfilesBean.actionAdd}" disabled="#{certificateProfile.fixed or certProfilesBean.authorizedToOnlyView}"/>
				</f:facet>
			</h:column>
		</h:dataTable>
		</h:panelGroup>

		<h:panelGroup rendered="#{certProfilesBean.addFromTemplateInProgress}">
			<h3><h:outputText value="#{web.text.CLONE}"/></h3>
			<h:panelGrid columns="2">
				<h:outputLabel for="addFromTemplateProfileOld" value="#{web.text.CERTPROFILE_FROMTEMPLATE}"/>
				<h:outputText id="addFromTemplateProfileOld" value="#{certProfilesBean.selectedCertProfileName}"/>
				<h:outputLabel for="addFromTemplateProfileNew" value="#{web.text.CERTPROFILE_NEWNAME}"/>
  				<h:inputText id="addFromTemplateProfileNew" value="#{certProfilesBean.certProfileName}" title="#{web.text.FORMAT_ID_STR}" size="40" maxlength="255"/>
  				<h:panelGroup/>
				<h:panelGroup>
					<h:commandButton value="#{web.text.CLONE_CONFIRM}" action="#{certProfilesBean.actionAddFromTemplateConfirm}"/>
					<h:commandButton value="#{web.text.CANCEL}" action="#{certProfilesBean.actionCancel}"/>
				</h:panelGroup>
			</h:panelGrid>
		</h:panelGroup>

		<h:panelGroup rendered="#{certProfilesBean.renameInProgress}">
			<h3><h:outputText value="#{web.text.RENAME}"/></h3>
			<h:panelGrid columns="2">
				<h:outputLabel for="renameProfileOld" value="#{web.text.RENAME_CURRENTNAME}"/>
				<h:outputText id="renameProfileOld" value="#{certProfilesBean.selectedCertProfileName}"/>
				<h:outputLabel for="renameProfileNew" value="#{web.text.RENAME_NEWNAME}"/>
  				<h:inputText id="renameProfileNew" value="#{certProfilesBean.certProfileName}" title="#{web.text.FORMAT_ID_STR}" size="40" maxlength="255"/>
  				<h:panelGroup/>
				<h:panelGroup>
					<h:commandButton value="#{web.text.RENAME_CONFIRM}" action="#{certProfilesBean.actionRenameConfirm}"/>
					<h:commandButton value="#{web.text.CANCEL}" action="#{certProfilesBean.actionCancel}"/>
				</h:panelGroup>
			</h:panelGrid>
		</h:panelGroup>

		<h:panelGroup rendered="#{certProfilesBean.deleteInProgress}">
			<h3><h:outputText value="#{web.text.DELETE}"/></h3>
			<h:panelGrid columns="2">
				<h:outputLabel for="deleteProfileName" value="#{web.text.CERTIFICATEPROFILENAME}"/>
				<h:outputText id="deleteProfileName" value="#{certProfilesBean.selectedCertProfileName}"/>
  				<h:panelGroup/>
				<h:panelGroup>
					<h:commandButton value="#{web.text.DELETE_CONFIRM}" action="#{certProfilesBean.actionDeleteConfirm}"/>
					<h:commandButton value="#{web.text.CANCEL}" action="#{certProfilesBean.actionCancel}"/>
				</h:panelGroup>
			</h:panelGrid>
		</h:panelGroup>
	</h:form>
	<h:panelGroup rendered="#{not certProfilesBean.operationInProgress}" >
	<h3><h:outputText value="#{web.text.IMPORT}/" rendered="#{certProfilesBean.authorizedToEdit}"/><h:outputText value="#{web.text.EXPORT}"/></h3>
	<h:form id="uploadCertificate" enctype="multipart/form-data">
		<h:panelGrid columns="3" >
			<h:outputLabel for="certificateUploadInput" value="#{web.text.IMPORTPROFILESFROM}" rendered="#{certProfilesBean.authorizedToEdit}"/>
			<t:inputFileUpload id="certificateUploadInput" value="#{certProfilesBean.uploadFile}" size="20" rendered="#{certProfilesBean.authorizedToEdit}"/>
			<h:commandButton action="#{certProfilesBean.actionImportProfiles}" value="#{web.text.IMPORT}" rendered="#{certProfilesBean.authorizedToEdit}"/>
		</h:panelGrid>
		<h:panelGrid columns="1">
			<h:outputLink value="adminweb/profilesexport?profileType=cp">
				<h:outputText value="#{web.text.EXPORTROFILES}..."/>
			</h:outputLink>
		</h:panelGrid>
	</h:form>
	</h:panelGroup>
</div> <!-- container -->

	<jsp:include page="<%=globalconfiguration.getFootBanner()%>"/>
</div> <!-- main-wrapper -->
</body>
</f:view>
</html>
