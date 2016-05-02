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
  GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, AccessRulesConstants.ROLE_ADMINISTRATOR, StandardRules.APPROVALPROFILEVIEW.resource());
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
		
		


		<%-- Approval Profile by Number of Approvals Only --%>		
		
		<h:outputLabel for="selectNrOfApprovals" value="#{web.text.NUMBEROFAPPROVALS}" rendered="#{approvalProfileMBean.nrOfApprovalsProfileType}"/>
		<h:selectOneMenu id="selectNrOfApprovals" value="#{approvalProfileMBean.numberOfApprovals}" rendered="#{approvalProfileMBean.nrOfApprovalsProfileType}" 
									disabled="#{approvalProfilesMBean.viewOnly}" >
			<f:selectItems value="#{approvalProfileMBean.numberOfApprovalsAvailable}"/>
		</h:selectOneMenu>

	</h:panelGrid>
	
	
	
	
	<h:panelGrid columns="2" styleClass="edit-top" cellspacing="10" cellpadding="10" border="0" width="100%" rowClasses="Row0,Row1" columnClasses="editColumn1,editColumn2" 
			rendered="#{!approvalProfileMBean.nrOfApprovalsProfileType}">
	
		<h:outputLabel for="header_steps" value="Approval Steps" style="font-weight: bold;"/>
		<h:panelGroup id="header_steps"/>
	
		<h:panelGroup/>
		<h:dataTable id="steps" value="#{approvalProfileMBean.approvalStepsList}" var="step">

			<h:column>
	
				<h:panelGrid columns="2" cellspacing="20" cellpadding="20" border="0" width="100%" rowClasses="Row0,Row1">
				
					<h:outputLabel for="header_steps" value="Step #{step.stepId}" style="font-weight: bold;"/>
					<h:panelGroup id="header_steps"/>
				
					<h:outputLabel value="Authorization Object"/>
					<h:outputText value="#{step.stepAuthorizationObject}"/>
					
					<h:outputLabel value="Metadata Instruction"/>
					<h:outputText value="#{step.metadataInstruction}"/>
					
					<h:outputLabel value="Metadata Options"/>
					<h:outputText value="#{step.metadataOptions}"/>
					
					<h:outputLabel value="Metadata Options Type"/>
					<h:outputText value="#{step.metadataOptionTypeString}"/>
					
					<h:outputLabel value="Required Number of Approvals"/>
					<h:outputText value="#{step.nrOfApprovals}"/>
					
					<h:outputLabel value="Can see previous steps"/>
					<h:outputText value="#{step.canSeePreviousSteps}"/>
					
					<h:outputLabel value="Notification Email"/>
					<h:outputText value="#{step.email}"/>
			
				</h:panelGrid>
	
			</h:column>
			<h:column>
				<h:commandButton value="Delete" action="#{approvalProfileMBean.addNewStep}" disabled="#{approvalProfilesMBean.viewOnly}" />
				<h:commandButton value="Edit" action="#{approvalProfileMBean.addNewStep}" disabled="#{approvalProfilesMBean.viewOnly}" />
				<h:commandButton value="Move UP" action="#{approvalProfileMBean.addNewStep}" disabled="#{approvalProfilesMBean.viewOnly}" />
				<h:commandButton value="Move Down" action="#{approvalProfileMBean.addNewStep}" disabled="#{approvalProfilesMBean.viewOnly}" />
			</h:column>
	
	
		</h:dataTable>
		
	
	</h:panelGrid>
	
	
	
	
	<%--
	
		<h:panelGrid columns="2" styleClass="edit-top" cellspacing="3" cellpadding="3" border="0" width="100%" rowClasses="Row0,Row1" columnClasses="editColumn1,editColumn2">
			
			<h:outputLabel for="header_steps" value="Approval Steps" style="font-weight: bold;"/>
			<h:panelGroup id="header_steps"/>
			
			<h:outputLabel value="Step" styleClass="subItem" style="font-weight: bold;"/>
			<h:dataTable id="steps" value="#{approvalProfileMBean.approvalStepsList}" var="step">
				<h:column>
					<h:outputText value="Step ID: #{step.stepId}"/>
					<br/>
					<h:outputText value="Main Object: #{step.stepMainValue}"/>
					<br/>
					<h:dataTable id="metadata" value="#{step.metadataGui}" var="metadata">
						<h:column>
							<h:outputText value="Description: #{metadata.description}"/>
							<br/>
							<h:outputText value="Options Type: #{metadata.optionTypeString}"/>
						</h:column>
					</h:dataTable>
				</h:column>
			</h:dataTable>
		</h:panelGrid>
	 --%>
				
	<%--
			<h:panelGrid columns="2" styleClass="edit-top" cellspacing="3" cellpadding="3" border="0" width="100%" rowClasses="Row0,Row1" columnClasses="editColumn1,editColumn2">
				<h:outputLabel value="Step" styleClass="subItem" style="font-weight: bold;"/>
	
	<h:panelGroup binding="#{approvalProfileMBean.dynamicDataTableGroup}" />
	
		</h:panelGrid>

	 --%>
	
	
	
	<h:panelGrid columns="2" styleClass="edit-top" cellspacing="3" cellpadding="3" border="0" width="100%" rowClasses="Row0,Row1" columnClasses="editColumn1,editColumn2" 
				rendered="#{!approvalProfileMBean.nrOfApprovalsProfileType and !approvalProfilesMBean.viewOnly}">

		<h:outputLabel for="header_new_step" value="Adding a New Approval Steps" style="font-weight: bold;"/>
		<h:panelGroup id="header_new_step"/>
		
		
		
		<h:outputLabel for="addStepObject" value="Authorization Object"/>
	  	<h:selectOneMenu id="addStepAdmins" value="#{approvalProfileMBean.newStepAuthorizationObject}"  
		  								rendered="#{!approvalProfilesMBean.viewOnly}">
			<f:selectItems value="#{approvalProfileMBean.mainAuthorizationObjectOptions}"/>
		</h:selectOneMenu>
		
		
		
		
		
		<h:outputLabel for="addStepMetadata" value="Metadata" styleClass="subItem"/>
		<h:panelGroup>
			<h:inputText id="textfieldcaissueruri" value="#{approvalProfileMBean.newStepMetadataInstruction}" size="45" maxlength="255" title="#{web.text.FORMAT_URI}"/>
			<h:selectOneMenu value="#{approvalProfileMBean.newStepMetadataOptionsType}">
						<f:selectItems value="#{approvalProfileMBean.optionTypesAvailable}"/>
			</h:selectOneMenu>
			<h:inputText value="#{approvalProfileMBean.newStepMetadataOptions}" size="45" maxlength="255" title="#{web.text.FORMAT_URI}"/>
		</h:panelGroup>
		
		<%--
		<h:dataTable id="addStepMetadata" value="#{approvalProfileMBean.newMetadataList}" var="mt">
			<h:column>
				<h:outputText value="#{mt.description}"/>
				<f:facet name="footer">
					<h:inputText id="textfieldcaissueruri" value="#{approvalProfileMBean.newMetadataDescription}" size="45" maxlength="255" title="#{web.text.FORMAT_URI}"
						/>
				</f:facet>
			</h:column>
			<h:column>
				<h:outputText value="#{mt.optionTypeString}"/>
				<f:facet name="footer">
					<h:selectOneMenu value="#{approvalProfileMBean.newMetadataOptionsType}">
						<f:selectItems value="#{approvalProfileMBean.metadataTypesAvailable}"/>
					</h:selectOneMenu>
				</f:facet>
			</h:column>
			<h:column>
				<h:outputText value="#{mt.options}"/>
				<f:facet name="footer">
					<h:inputText value="#{approvalProfileMBean.newMetadataOptions}" size="45" maxlength="255" title="#{web.text.FORMAT_URI}"
						/>
				</f:facet>
			</h:column>
			<h:column>
				<h:commandButton id="buttondeletecaissueruri" value="#{web.text.DELETE}" action="#{approvalProfileMBean.deleteMetadata}"
					 />
				<f:facet name="footer">
					<h:commandButton id="buttonaddcaissueruri" value="#{web.text.ADD}" action="#{approvalProfileMBean.addMetadata}"
						/>
				</f:facet>
			</h:column>
		</h:dataTable>
		 --%>
		
		
		
		
		<h:outputLabel value="Required Number of Approvals"/>
	  	<h:selectOneMenu value="#{approvalProfileMBean.newStepNrOfApprovals}"  
		  								disabled="#{approvalProfilesMBean.viewOnly}">
			<f:selectItems value="#{approvalProfileMBean.nrOfApprovalsAvailable}"/>
		</h:selectOneMenu>
		
		
		
		<h:outputLabel value="Can See Previous Steps"/>
		<h:selectBooleanCheckbox value="#{approvalProfileMBean.newStepCanSeePreviousSteps}" disabled="#{approvalProfilesMBean.viewOnly}"/>
		
		
		<h:outputLabel value="Notification Email"/>
		<h:inputText value="#{approvalProfileMBean.newStepEmail}" title="#{web.text.FORMAT_ID_STR}" size="25" maxlength="255" 
		  								disabled="#{approvalProfilesMBean.viewOnly}"/>
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		<h:panelGroup />
		<h:panelGroup id="AddStep" rendered="true">
			<h:commandButton value="Add Step" action="#{approvalProfileMBean.addNewStep}" disabled="#{approvalProfilesMBean.viewOnly}" 
										/>
		</h:panelGroup>
		
		
	</h:panelGrid>
	
	
	
	<%--
	<h:panelGroup rendered="#{!approvalProfileMBean.nrOfApprovalsProfileType}">
		<h3><h:outputText value="#{web.text.PROPERTIES}"/></h3>
		<h:dataTable value="#{approvalProfileMBean.propertiesList}" var="property" styleClass="grid" columnClasses="gridColumn1,gridColumn2">
			<h:column headerClass="gridColumn1">
				<f:facet name="header"><h:outputText value="Property Key"/></f:facet>
				<h:outputText value="#{property.propertyKey}"/>
				<f:facet name="footer">
		  			<h:inputText value="#{approvalProfileMBean.addProperyKey}" title="#{web.text.FORMAT_ID_STR}" size="25" maxlength="255" rendered="#{!approvalProfilesMBean.viewOnly}"/>
				</f:facet>
			</h:column>
			<h:column headerClass="gridColumn2">
				<f:facet name="header"><h:outputText value="Property Value"/></f:facet>
				<h:outputText value="#{property.propertyValue}"/>
				<f:facet name="footer">
					<h:panelGroup>
		  				<h:inputText value="#{approvalProfileMBean.addProperyValue}" title="#{web.text.FORMAT_ID_STR}" size="25" maxlength="255" 
		  										rendered="#{!approvalProfilesMBean.viewOnly and !approvalProfileMBean.adminApprovalProfileType}"/>
		  				<h:selectOneMenu id="propertyValue" value="#{approvalProfileMBean.addProperyValue}"  
		  										rendered="#{!approvalProfilesMBean.viewOnly and approvalProfileMBean.adminApprovalProfileType}">
							<f:selectItems value="#{approvalProfileMBean.adminRolesAvailable}"/>
						</h:selectOneMenu>
		  			</h:panelGroup>
				</f:facet>
			</h:column>
			<h:column headerClass="gridColumn1">
				<f:facet name="header"><h:outputText value="Property Description"/></f:facet>
				<h:outputText value="#{property.propertyDescription}"/>
				<f:facet name="footer">
		  			<h:inputText value="#{approvalProfileMBean.addPropertyDescription}" title="#{web.text.FORMAT_ID_STR}" size="25" maxlength="255" rendered="#{!approvalProfilesMBean.viewOnly}"/>
				</f:facet>
			</h:column>
			<h:column headerClass="gridColumn2">
				<f:facet name="header"><h:outputText value="Property Metadata Type"/></f:facet>
				<h:outputText value="#{property.propertyMetadataTypeString}"/>
				<f:facet name="footer">
		  			<h:selectOneMenu id="propertyMetadataType" value="#{approvalProfileMBean.addPropertyMetaDataType}"  rendered="#{!approvalProfilesMBean.viewOnly}">
						<f:selectItems value="#{approvalProfileMBean.metadataTypesAvailable}"/>
					</h:selectOneMenu>
				</f:facet>
			</h:column>
			<h:column headerClass="gridColumn1">
				<f:facet name="header"><h:outputText value="Property Metadata Options"/></f:facet>
				<h:outputText value="#{property.propertyMetadataString}"/>
				<f:facet name="footer">
		  			<h:inputText value="#{approvalProfileMBean.addPropertyMetaData}" title="#{web.text.FORMAT_ID_STR}" size="25" maxlength="255"  rendered="#{!approvalProfilesMBean.viewOnly}"/>
				</f:facet>
			</h:column>
			<h:column headerClass="gridColumn2" rendered="#{!approvalProfilesMBean.viewOnly}">
				<f:facet name="header"><h:outputText value="#{web.text.ACTION}"/></f:facet>
				<h:commandButton value="#{web.text.DELETE}" action="#{approvalProfileMBean.deletePropertyAction}"/>
				<f:facet name="footer">
					<h:commandButton value="#{web.text.ADD}" action="#{approvalProfileMBean.addPropertyAction}"/>
				</f:facet>
			</h:column>
		</h:dataTable>
	</h:panelGroup>
	 --%>


	<h:panelGrid columns="2" styleClass="edit" cellspacing="3" cellpadding="3" border="0" width="100%" rowClasses="Row0,Row1" columnClasses="editColumn1,editColumn2">

		<%-- Buttons --%>
		<h:panelGroup>
			&nbsp;
		</h:panelGroup>
		<h:panelGroup>
			<h:commandButton value="#{web.text.SAVE}" action="#{approvalProfileMBean.save}" disabled="#{approvalProfilesMBean.viewOnly}"/>
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
