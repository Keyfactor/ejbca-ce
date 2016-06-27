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
	<div class="message">
		<h:messages layout="table" errorClass="alert" infoClass="infoMessage"/>
	</div>

	<div align="center">
	  <h2>
	  	<h:outputText value="#{web.text.EDITCERTIFICATEPROFILE}" rendered="#{!approvalProfilesMBean.viewOnly}"/>
	  	<h:outputText value="#{web.text.VIEWCERTIFICATEPROFILE}" rendered="#{approvalProfilesMBean.viewOnly}"/>
	  </h2>
	  <h3><h:outputText value="#{web.text.APPROVALPROFILE}: #{approvalProfileMBean.selectedApprovalProfileName}"/></h3>
	</div>
	
	<h:form id="approvalProfilesForm" >
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
				<h:selectOneMenu id="selectOneMenuApprovalType" value="#{approvalProfileMBean.currentApprovalProfileTypeName}"
						onchange="document.getElementById('approvalProfilesForm:selectProfileType').click();" disabled="#{approvalProfilesMBean.viewOnly}">
					<f:selectItems value="#{approvalProfileMBean.approvalProfileTypesAvailable}"/>
				</h:selectOneMenu>
				<h:commandButton id="selectProfileType" action="#{approvalProfileMBean.selectUpdate}" value="#{approvalProfileMBean.currentApprovalProfileTypeName}"
                    rendered="#{!approvalProfilesMBean.viewOnly}"/>
				<script>document.getElementById('approvalProfilesForm:selectProfileType').style.display = 'none';</script>
			</h:panelGroup>		
		</h:panelGrid>
		<h3><h:outputText value="#{web.text.APPROVAL_PROFILE_STEPS}"/>	</h3>
		<%--Retrieve GUI layout from the currently chosen approval profile archetype --%>
		<h:dataTable value="#{approvalProfileMBean.steps}" var="step" style="width: 100%"  rowClasses="Row0,Row1" columnClasses="editColumn1,editColumn2"
			footerClass="tableFooter">
			<h:column>			
				<h:outputText value="#{step.identifier}" />																					
				<h:dataTable value="#{step.partitionGuiObjects}" var="partition" style="width: 100%" headerClass="listHeader"  columnClasses="editColumn1,editColumn2" >						
					<h:column>
						<f:facet name="header">
							<h:outputText value="#{web.text.APPROVAL_PROFILE_STEP}: #{step.stepNumber}" 
								rendered="#{approvalProfileMBean.steps.getRowCount() > 1 || !approvalProfileMBean.stepSizeFixed}"/>							
						</f:facet>	
						<h:dataTable value="#{partition.profilePropertyList}" var="property" headerClass="subheader"
							columnClasses="editColumn1,editColumn2" style="width: 100%"
							rendered="#{not empty partition.profilePropertyList}" styleClass="subTable">							
							<h:column>
								<f:facet name="header">
									<h:outputText value="#{web.text.APPROVAL_PROFILE_PARTITION}: #{partition.partitionId}" 
										rendered="#{!approvalProfileMBean.stepSizeFixed}"/>
								</f:facet>
								<h:outputText value="#{partition.propertyNameLocalized}:"/>
							</h:column>
							<h:column>
								<f:facet name="header">
    								<h:panelGroup layout="block" style="text-align: right;">
    									<h:commandButton value="#{web.text.APPROVAL_PROFILE_DELETE_PARTITION}"
    				    					rendered="#{!approvalProfilesMBean.viewOnly && !approvalProfileMBean.stepSizeFixed}"
                                            action="#{approvalProfileMBean.deletePartition(partition.partitionId)}"/>	 
                                        <h:commandButton value="#{web.text.APPROVAL_PROFILE_PARTITION_NOTIFICATION_ADD}"
                                            rendered="#{!approvalProfilesMBean.viewOnly && !approvalProfileMBean.isNotificationEnabled(partition.partitionId)}"
                                            action="#{approvalProfileMBean.addNotification(partition.partitionId)}"/>  
                                        <h:commandButton value="#{web.text.APPROVAL_PROFILE_PARTITION_NOTIFICATION_REMOVE}"
                                            rendered="#{!approvalProfilesMBean.viewOnly && approvalProfileMBean.isNotificationEnabled(partition.partitionId)}"
                                            action="#{approvalProfileMBean.removeNotification(partition.partitionId)}"/>  
                                    </h:panelGroup>
				    			</f:facet>											
					   			<h:panelGroup rendered="#{!property.multiValued}">
						   			<h:inputText  disabled="#{approvalProfilesMBean.viewOnly}" rendered="#{property.type.simpleName eq 'String'}" 
						   				value="#{property.value}">
						   				<f:converter converterId="stringConverter"/>
						   			</h:inputText>
                                    <h:inputTextarea disabled="#{approvalProfilesMBean.viewOnly}" rendered="#{property.type.simpleName eq 'MultiLineString'}" 
                                        value="#{property.value.value}">
                                        <f:converter converterId="stringConverter"/>
                                    </h:inputTextarea>
						   			<h:inputText disabled="#{approvalProfilesMBean.viewOnly}" rendered="#{property.type.simpleName eq 'Long'}" value="#{property.value}" 
						   				style="text-align: right;" >
					                   <f:converter converterId="javax.faces.Long"/>
						   			</h:inputText>
						   			<h:inputText disabled="#{approvalProfilesMBean.viewOnly}" rendered="#{property.type.simpleName eq 'Integer'}" value="#{property.value}" 	
						   				style="text-align: right;" size="6">
					                   <f:converter converterId="javax.faces.Integer"/>
						   			</h:inputText>
					   				<h:selectBooleanCheckbox disabled="#{approvalProfilesMBean.viewOnly}" rendered="#{property.type.simpleName eq 'Boolean'}" value="#{property.value}"/>
					   			</h:panelGroup>
								<h:selectOneMenu disabled="#{approvalProfilesMBean.viewOnly}" rendered="#{property.multiValued && !property.hasMultipleValues}" value="#{property.encodedValue}">
									<f:selectItems value="#{partition.propertyPossibleValues}"/>
								</h:selectOneMenu>
								<h:selectManyListbox disabled="#{approvalProfilesMBean.viewOnly}" rendered="#{property.multiValued && property.hasMultipleValues}" value="#{property.encodedValues}">
									<f:selectItems value="#{partition.propertyPossibleValues}"/>
								</h:selectManyListbox>
							</h:column>
						</h:dataTable>	
						   				    
					</h:column>	
				</h:dataTable>
				
				<f:facet name="footer">
					<h:outputText value="#{web.text.APPROVAL_PROFILE_EXECUTION_HELP}" rendered="#{!approvalProfileMBean.stepSizeFixed}" />
				</f:facet>
				<h:panelGroup layout="block">
					<h:commandButton value="#{web.text.APPROVAL_PROFILE_ADD_PARTITION}" action="#{approvalProfileMBean.addPartition}"
                        rendered="#{!approvalProfilesMBean.viewOnly && !approvalProfileMBean.stepSizeFixed}"/>
				    <h:commandButton value="#{web.text.APPROVAL_PROFILE_DELETE_STEP}" action="#{approvalProfileMBean.deleteStep}"
				    	rendered="#{!approvalProfilesMBean.viewOnly && !approvalProfileMBean.stepSizeFixed}"/>
				</h:panelGroup>	
			</h:column>	
		</h:dataTable>
		<h:panelGroup layout="block" style="text-align: right;">
			<h:commandButton value="#{web.text.APPROVAL_PROFILE_ADD_STEP}" action="#{approvalProfileMBean.addStep}"
				rendered="#{!approvalProfilesMBean.viewOnly && !approvalProfileMBean.stepSizeFixed}"/>
		</h:panelGroup>
		<h:panelGrid columns="2" styleClass="edit" cellspacing="3" cellpadding="3" border="0" width="100%" rowClasses="Row0,Row1" columnClasses="editColumn1,editColumn2">
	
			<%-- Buttons --%>
			<h:panelGroup>
				&nbsp;
			</h:panelGroup>
			<h:panelGroup>
				<h:commandButton value="#{web.text.SAVE}" action="#{approvalProfileMBean.save}" rendered="#{!approvalProfilesMBean.viewOnly}"/>
				<h:commandButton value="#{web.text.CANCEL}" action="#{approvalProfileMBean.cancel}" immediate="true" />
			</h:panelGroup>
	
		</h:panelGrid>
	</h:form>


<%
   String footurl=globalconfiguration.getFootBanner();%>
  <jsp:include page="<%=footurl%>"/>
</body>
</f:view>
</html>
