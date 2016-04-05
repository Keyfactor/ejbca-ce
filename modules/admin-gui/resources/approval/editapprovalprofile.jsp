<%@ taglib uri="http://java.sun.com/jsf/html" prefix="h" %>
<%@ taglib uri="http://java.sun.com/jsf/core" prefix="f" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ page pageEncoding="UTF-8"%>
<% response.setContentType("text/html; charset="+org.ejbca.config.WebConfiguration.getWebContentEncoding()); %>
<%@page errorPage="/errorpage.jsp" %>
<%@page import="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" %>
<%@page import="org.ejbca.config.GlobalConfiguration" %>
<%@page import="org.ejbca.ui.web.RequestHelper" %>
<%@page import="org.ejbca.ui.web.admin.cainterface.CAInterfaceBean" %>
<%@page import="org.ejbca.core.model.authorization.AccessRulesConstants" %>
<%@page import="org.cesecore.authorization.control.StandardRules" %>
<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />
<jsp:useBean id="cabean" scope="session" class="org.ejbca.ui.web.admin.cainterface.CAInterfaceBean" />
<%
  GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, AccessRulesConstants.ROLE_ADMINISTRATOR, StandardRules.CERTIFICATEPROFILEVIEW.resource());
  cabean.initialize(ejbcawebbean);
  RequestHelper.setDefaultCharacterEncoding(request);
%>
<html>
<head>
  <title><c:out value="<%=globalconfiguration.getEjbcaTitle()%>" /></title>
  <base href="<%=ejbcawebbean.getBaseUrl()%>"/>
  <link rel="stylesheet" type="text/css" href="<c:out value='<%=ejbcawebbean.getCssFile() %>' />"/>
  <script type="text/javascript" src="<%=globalconfiguration.getAdminWebPath()%>ejbcajslib.js"></script>
  <style type="text/css">
  	input[type='checkbox'].checkBoxOverlay {
  		-moz-user-focus: ignore;
  	}
  	input[type='submit'].checkBoxOverlay {
  		vertical-align: text-bottom;
  		${web.legacyInternetExplorer ? '' : 'position:relative; z-index: 1; left: -20px;'}
  		${web.legacyInternetExplorer ? 'color: #000;' : 'color: transparent; background-color: transparent; border: 0px;'}
  		width: 20px;
  		height: 20px;
  		font-size: 8px;
  		padding: 0px;
  		margin: 0px;
  		
  	}
  	label.checkBoxOverlay {
  		${web.legacyInternetExplorer ? '' : 'position:relative; z-index: 0; left: -20px;'}
  	}
  	label.subItem {
  		padding-left: 10px;
  	}
  </style>
</head>
<f:view>
<body>
	<div class="message"><h:messages layout="table" errorClass="alert" infoClass="infoMessage"/></div>

<div align="center">
  <h2><h:outputText value="#{web.text.EDITCERTIFICATEPROFILE}"/><h:outputText value="#{web.text.VIEWCERTIFICATEPROFILE}" /></h2>
  <h3><h:outputText value="#{web.text.APPROVALPROFILE}: #{approvalProfileMBean.selectedApprovalProfileName}"/></h3>
</div>

<h:form id="apf">

	<h:panelGrid columns="2" styleClass="edit-top" cellspacing="3" cellpadding="3" border="0" width="100%" rowClasses="Row0,Row1" columnClasses="editColumn1,editColumn2">

		<h:panelGroup>
			&nbsp;
		</h:panelGroup>
		<h:outputLink value="#{web.ejbcaWebBean.globalConfiguration.adminWebPath}/approval/editapprovalprofiles.jsf">
			<h:outputText value="#{web.text.BACKTOAPPROVALPROFILES}"/>
		</h:outputLink>


		<h:outputLabel for="approvalProfileId" value="#{web.text.APPROVALPROFILEID}"/>
		<h:outputText id="approvalProfileId" value="#{approvalProfileMBean.selectedApprovalProfileId}"/>
		
		
		<h:outputLabel for="approvalProfileType" value="#{web.text.APPROVALPROFILETYPE}"/>
		<h:panelGroup id="approvalProfileType">
			<h:panelGroup>
				<h:selectOneMenu id="selectOneMenuApprovalType" value="#{approvalProfileMBean.currentApprovalProfileTypeName}"
						onchange="document.getElementById('apf:selectProfileType').click();" disabled="#{approvalProfilesMBean.viewOnly}">
					<f:selectItems value="#{approvalProfileMBean.approvalProfileTypesAvailable}"/>
				</h:selectOneMenu>
				<h:commandButton id="selectProfileType" action="#{approvalProfileMBean.selectUpdate}" value="#{approvalProfileMBean.currentApprovalProfileTypeName}"/>
				<script>document.getElementById('apf:selectProfileType').style.display = 'none';</script>
			</h:panelGroup>
		</h:panelGroup>
		
		
		
		
		

		<h:outputLabel for="selectApprovalActions" value="#{web.text.APPROVALACTIONS}"/>
		<h:selectManyListbox id="selectApprovalActions" value="#{approvalProfileMBean.approvalActions}" size="5" disabled="#{approvalProfilesMBean.viewOnly}">
			<f:selectItems value="#{approvalProfileMBean.approvalActionsAvailable}"/>
		</h:selectManyListbox>
		
		<h:outputLabel for="selectNrOfApprovals" value="#{web.text.NUMBEROFAPPROVALS}" rendered="#{approvalProfileMBean.nrOfApprovalsProfileType}"/>
		<h:selectOneMenu id="selectNrOfApprovals" value="#{approvalProfileMBean.numberOfApprovals}" rendered="#{approvalProfileMBean.nrOfApprovalsProfileType}" 
									disabled="#{approvalProfilesMBean.viewOnly}" >
			<f:selectItems value="#{approvalProfileMBean.numberOfApprovalsAvailable}"/>
		</h:selectOneMenu>

	</h:panelGrid>


	<h:panelGrid columns="2" styleClass="edit" cellspacing="3" cellpadding="3" border="0" width="100%" rowClasses="Row0,Row1" columnClasses="editColumn1,editColumn2">

		<%-- Buttons --%>
		<h:panelGroup>
			&nbsp;
		</h:panelGroup>
		<h:panelGroup>
			<h:commandButton value="#{web.text.SAVE}" action="#{approvalProfileMBean.save}"/>
			<h:commandButton value="#{web.text.CANCEL}" action="#{approvalProfileMBean.cancel}"/>
		</h:panelGroup>

	</h:panelGrid>
</h:form>


<%
   String footurl=globalconfiguration.getFootBanner();%>
  <jsp:include page="<%=footurl%>"/>
</body>
</f:view>
</html>
