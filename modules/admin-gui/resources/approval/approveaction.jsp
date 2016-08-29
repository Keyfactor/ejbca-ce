<%@ taglib uri="http://java.sun.com/jsf/html" prefix="h" %>
<%@ taglib uri="http://java.sun.com/jsf/core" prefix="f" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<% response.setContentType("text/html; charset="+org.ejbca.config.WebConfiguration.getWebContentEncoding()); %>
<%@page pageEncoding="ISO-8859-1" errorPage="/errorpage.jsp" import="
org.ejbca.config.GlobalConfiguration,org.ejbca.ui.web.RequestHelper,
org.ejbca.ui.web.admin.configuration.EjbcaJSFHelper,
org.ejbca.core.model.authorization.AccessRulesConstants
"%>

<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />
<jsp:setProperty name="ejbcawebbean" property="*" /> 
<%   // Initialize environment
 GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, AccessRulesConstants.ROLE_ADMINISTRATOR); 
 EjbcaJSFHelper helpbean = EjbcaJSFHelper.getBean();
 helpbean.setEjbcaWebBean(ejbcawebbean);
 helpbean.authorizedToApprovalPages();
%>
<html>
<head>
  <title><c:out value="<%= globalconfiguration.getEjbcaTitle() %>" /></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>" />
  <link rel="stylesheet" type="text/css" href="<c:out value='<%=ejbcawebbean.getCssFile() %>' />" />
  <meta http-equiv="Content-Type" content="text/html; charset=<%= org.ejbca.config.WebConfiguration.getWebContentEncoding() %>" />
</head>

<f:view>
<body onload='resize()'>

<script type="text/javascript">
<!--
function viewcert(link){
    enclink = encodeURI(link);
    win_popup = window.open(enclink, 'view_cert','height=650,width=600,scrollbars=yes,toolbar=no,resizable=1');
    win_popup.focus();
}
-->
</script>

<h2 align="center"><h:outputText value="#{web.text.APPROVEACTION}"/></h2>
<h:form id="approveActionForm">
  <h:inputHidden id="approveActionID" value="#{approvalActionRequest.uniqueId}"/>
  <f:attribute name="windowWidth" value="#{approvalActionManagedBean.windowWidth}"/>

   <h3 align="center">
     <h:outputText value="#{approvalActionManagedBean.approveRequestData.approveActionName}"/>
     <br /><h:messages  layout="table" errorClass="alert"/><br />
     <h:outputText value="#{web.text.CURRENTSTATUS}"/> <h:outputText value=" : "/> <h:outputText value="#{approvalActionManagedBean.approveRequestData.status}"/><br />     
   </h3>

   	<table border="0" cellpadding="5" width="100%">
   	   	<tr id="Row0">
   			<td><h:outputText value="#{web.text.REQUESTDATE}"/></td>
   			<td><h:outputText value="#{approvalActionManagedBean.approveRequestData.requestDate}"/></td>
   		</tr>
   	   	<tr id="Row1">
   			<td><h:outputText value="#{web.text.EXPIREDATE}"/></td>
   			<td><h:outputText value="#{approvalActionManagedBean.approveRequestData.expireDate}"/></td>
   		</tr>
   	   	<tr id="Row0">
   			<td><h:outputText value="#{web.text.REQUESTINGADMIN}"/></td>
   			<td><h:outputText value="#{approvalActionManagedBean.approveRequestData.requestAdminName}"/></td>
   		</tr>
   	   	<tr id="Row1">
   			<td><h:outputText value="#{web.text.RELATEDCA}"/></td>
   			<td><h:outputText value="#{approvalActionManagedBean.approveRequestData.caName}"/></td>
   		</tr>
   	   	<tr id="Row0">
   			<td><h:outputText value="#{web.text.RELATEDEEPROFILE}"/></td>
   			<td><h:outputText value="#{approvalActionManagedBean.approveRequestData.endEntityProfileName}"/></td>
   		</tr>
   		<tr id="Row1">
   			<td><h:outputText value="#{web.text.APPROVALPROFILE}"/></td>
   			<td><h:outputText value="#{approvalActionManagedBean.approveRequestData.approvalProfile.profileName}"/></td>
   		</tr>
   		<tr id="Row0">
   			<td><h:outputText value="#{web.text.REMAININGAPPROVALS}"/></td>
   			<td>
   				<h:outputText value="#{approvalActionManagedBean.approveRequestData.remainingApprovals}" 
   					rendered="#{approvalActionManagedBean.approveRequestData.remainingApprovals > 0}"/>
   				<h:outputText value="#{web.text.REMAINING_APPROVALS_NONE}" 
   					rendered="#{approvalActionManagedBean.approveRequestData.remainingApprovals < 0}"/>
   			</td>
   		</tr>
   	</table>
	
	<h:dataTable value="#{approvalActionManagedBean.approveRequestData.textComparisonList}" var="textCompareRow"  width="100%" 
		rendered="#{approvalActionManagedBean.approvalRequestComparable}">
		<h:column>
			<f:facet name="header">
				<h:outputText value="#{web.text.ORIGINALACTIONDATA}"/>
			</f:facet>
			<h:outputText value="#{textCompareRow.orgvalue}"   styleClass="#{textCompareRow.textComparisonColor}"/>
		</h:column>
		<h:column>
			<f:facet name="header">
				<h:outputText value="#{web.text.REQUESTEDACTIONDATA}"/>
			</f:facet>
			<h:outputText value="#{textCompareRow.newvalue}" styleClass="#{textCompareRow.textComparisonColor}"/>
		</h:column>
	</h:dataTable>
	<h:dataTable value="#{approvalActionManagedBean.approveRequestData.textComparisonList}" var="singleTextCompareRow"  width="100%" 
		rendered="#{!approvalActionManagedBean.approvalRequestComparable and !approvalActionManagedBean.approveRequestData.containingLink}"
		style="font-size: 0.7em;">
		<h:column>
			<f:facet name="header">
				<h:outputText value="#{web.text.REQUESTEDACTIONDATA}"/>
			</f:facet>
			<h:outputText value="#{singleTextCompareRow.newvalue}"/>
		</h:column>
	</h:dataTable>
	<h:dataTable value="#{approvalActionManagedBean.approveRequestData.textListExceptLinks}" var="singleTextCompareRow"  width="100%"
		rendered="#{!approvalActionManagedBean.approvalRequestComparable and approvalActionManagedBean.approveRequestData.containingLink}"
		style="font-size: 0.7em;">
		<h:column>
			<f:facet name="header">
				<h:outputText value="#{web.text.REQUESTEDACTIONDATA}"/>
			</f:facet>
			<h:outputText value="#{singleTextCompareRow.newvalue}"/>
		</h:column>
	</h:dataTable>
	<h:dataTable value="#{approvalActionManagedBean.approveRequestData.approvalDataLinks}" var="link"  width="100%"
		rendered="#{!approvalActionManagedBean.approvalRequestComparable and approvalActionManagedBean.approveRequestData.containingLink}"
		style="font-size: 0.7em;">
		<h:column>
			<h:outputText value="#{link.preDescription}"/>
			<h:outputLink value="#{link.URI}" target="Viewinfo" onclick="#{approvalView.viewApproverCertLink}">
				<h:outputText value="#{link.description}"/>
			</h:outputLink>
			<h:outputText value="#{link.postDescription}"/>
		</h:column>
	</h:dataTable>

    <h3><h:outputText value="#{web.text.APPROVEDBY}"/></h3>
    <h:outputText value="#{web.text.NONE}" rendered="#{!approvalActionManagedBean.existsApprovals}"/>
  	<h:dataTable id="approvalTable" value="#{approvalActionManagedBean.approvalViews}" var="approvalView" width="100%" rendered="#{approvalActionManagedBean.existsApprovals}"
  		style="font-size: 0.7em;">
	    <h:column>
	      <f:facet name="header">
	        <h:panelGroup>
	          <h:outputText value="#{web.text.ACTION}"/>
	        </h:panelGroup>
	      </f:facet>
	      <h:outputText value="#{approvalView.adminAction}"/>
	    </h:column>
	    <h:column>
	      <f:facet name="header">
	        <h:outputText value="#{web.text.DATE}"/>
	      </f:facet>
	      <h:outputText value="#{approvalView.approvalDate}"/>
	    </h:column>
	    <h:column>
	      <f:facet name="header">
	        <h:outputText value="#{web.text.ADMINISTRATOR}"/>
	      </f:facet>
	          <h:outputLink value="" target="Viewinfo" onclick="#{approvalView.viewApproverCertLink}">
	            <h:outputText  value="#{approvalView.approvalAdmin}"/>            
	          </h:outputLink>         
	    </h:column>
	    <h:column>
	      <f:facet name="header">
	        <h:panelGroup>
	          <h:outputText value="#{web.text.APCOMMENT}"/>
	        </h:panelGroup>
	      </f:facet>
	      <h:outputText value="#{approvalView.comment}"/>
	    </h:column>
	</h:dataTable>   
	<h:panelGroup layout="block" style="padding: 5px 10px" rendered="#{not empty approvalActionManagedBean.previousPartitions}">
		<h3><h:outputText value="#{web.text.APPROVAL_PROFILE_PARTITION_PREVIOUS }"/></h3>
		<h:outputText value="#{web.text.APPROVAL_PROFILE_PARTITION_HIDDEN }"  style="font-size: 0.7em;"/>
		<h:dataTable value="#{approvalActionManagedBean.previousPartitions}" var="partition" style="width: 100%"  rowClasses="Row0,Row1" columnClasses="editColumn1,editColumn2">
			<h:column>	
				<h:dataTable value="#{partition.profilePropertyList}" var="property" headerClass="subheader" columnClasses="editColumn1,editColumn2"
					 style="width: 100%" rendered="#{not empty partition.profilePropertyList}" styleClass="subTable">
					<h:column>								
						<h:outputText value="#{partition.propertyNameLocalized}:"/>
					</h:column>
					<h:column>										
			   			<h:panelGroup rendered="#{!property.multiValued}">
				   			<h:inputText disabled="true" rendered="#{property.type.simpleName eq 'String'}" value="#{property.value}">
				   				<f:converter converterId="stringConverter"/>
				   			</h:inputText>
				   			<h:inputTextarea disabled="true" rendered="#{property.type.simpleName eq 'MultiLineString'}" 
                                value="#{property.value.value}">
                            	<f:converter converterId="stringConverter"/>
                            </h:inputTextarea>
				   			<h:inputText disabled="true" rendered="#{property.type.simpleName eq 'Long'}" value="#{property.value}" style="text-align: right;" >
			                   <f:converter converterId="javax.faces.Long"/>
				   			</h:inputText>
				   			<h:inputText disabled="true" rendered="#{property.type.simpleName eq 'Integer'}" value="#{property.value}" style="text-align: right;" size="6">
			                   <f:converter converterId="javax.faces.Integer"/>
				   			</h:inputText>
			   				<h:selectBooleanCheckbox disabled="true" rendered="#{property.type.simpleName eq 'Boolean'}" value="#{property.value}"/>
			   			</h:panelGroup>
						<h:selectOneMenu disabled="true"  rendered="#{property.multiValued && !property.hasMultipleValues && property.type.simpleName != 'RadioButton'}" 
							value="#{property.encodedValue}">
							<f:selectItems value="#{partition.propertyPossibleValues}"/>
						</h:selectOneMenu>
						<h:selectManyListbox disabled="true" rendered="#{property.multiValued && property.hasMultipleValues && property.type.simpleName != 'RadioButton'}" 
							value="#{property.encodedValues}" >
							<f:selectItems value="#{partition.propertyPossibleValues}"/>
						</h:selectManyListbox>
						<h:selectOneRadio disabled="true"
								rendered="#{property.type.simpleName eq 'RadioButton' && property.multiValued  && !property.hasMultipleValues}" 
								value="#{property.encodedValue}" layout="pageDirection">
								<f:selectItems value="#{partition.propertyPossibleValues}" var="radioButton" itemLabel="#{radioButton.label}" />
								<f:converter converterId="radioButtonConverter"/>
							</h:selectOneRadio>
					</h:column>
				</h:dataTable>
			</h:column>
	</h:dataTable>
	</h:panelGroup>

	<h:panelGroup layout="block" rendered="#{approvalActionManagedBean.currentStepOrdinal > 0}">
		<h3><h:outputText value="#{web.text.APPROVAL_PROFILE_PARTITION_ACTION }"/></h3>
		<h:outputText style="font-size: 0.7em;" 
			value="#{web.text.APPROVAL_PROFILE_CURRENT_STEP}: #{approvalActionManagedBean.currentStepOrdinal} 
				of #{approvalActionManagedBean.approveRequestData.approvalProfile.numberOfSteps}"/>
			
		<h:dataTable value="#{approvalActionManagedBean.approvalPartitions}" var="partition" style="width: 100%"  rowClasses="Row0,Row1" columnClasses="editColumn1,editColumn2"
				footerClass="tableFooter">
				<h:column>	
					<h:dataTable value="#{partition.profilePropertyList}" var="property" headerClass="subheader" columnClasses="editColumn1,editColumn2"
						 style="width: 100%" rendered="#{not empty partition.profilePropertyList}" styleClass="subTable">
						<h:column>								
							<h:outputText value="#{partition.propertyNameLocalized}:"/>
						</h:column>
						<h:column>										
				   			<h:panelGroup rendered="#{!property.multiValued}">
					   			<h:inputText disabled="#{!approvalActionManagedBean.canApprovePartition(partition)
					   				|| approvalActionManagedBean.isPropertyReadOnly(property.name)}" 
					   				rendered="#{property.type.simpleName eq 'String'}" value="#{property.value}">
					   				<f:converter converterId="stringConverter"/>
					   			</h:inputText>
					   			<h:inputTextarea disabled="#{!approvalActionManagedBean.canApprovePartition(partition)
					   				|| approvalActionManagedBean.isPropertyReadOnly(property.name)}" 
					   				rendered="#{property.type.simpleName eq 'MultiLineString'}" 
	                                value="#{property.value.value}">
	                            	<f:converter converterId="stringConverter"/>
	                            </h:inputTextarea>
					   			<h:inputText disabled="#{!approvalActionManagedBean.canApprovePartition(partition)
					   				|| approvalActionManagedBean.isPropertyReadOnly(property.name)}" 
					   				rendered="#{property.type.simpleName eq 'Long'}" value="#{property.value}" style="text-align: right;" >
				                   <f:converter converterId="javax.faces.Long"/>
					   			</h:inputText>
					   			<h:inputText disabled="#{!approvalActionManagedBean.canApprovePartition(partition)
					   				|| approvalActionManagedBean.isPropertyReadOnly(property.name)}" 
					   				rendered="#{property.type.simpleName eq 'Integer'}" value="#{property.value}" style="text-align: right;" size="6">
				                   <f:converter converterId="javax.faces.Integer"/>
					   			</h:inputText>
				   				<h:selectBooleanCheckbox disabled="#{!approvalActionManagedBean.canApprovePartition(partition)
				   					|| approvalActionManagedBean.isPropertyReadOnly(property.name)}" 
				   					rendered="#{property.type.simpleName eq 'Boolean'}" value="#{property.value}"/>
				   			</h:panelGroup>
							<h:selectOneMenu disabled="#{!approvalActionManagedBean.canApprovePartition(partition)
								|| approvalActionManagedBean.isPropertyReadOnly(property.name)}"
							    rendered="#{property.multiValued && !property.hasMultipleValues && property.type.simpleName != 'RadioButton'}" 
								value="#{property.encodedValue}">
								<f:selectItems value="#{partition.propertyPossibleValues}"/>
							</h:selectOneMenu>
							<h:selectManyListbox disabled="#{!approvalActionManagedBean.canApprovePartition(partition)
								|| approvalActionManagedBean.isPropertyReadOnly(property.name)}"
								 rendered="#{property.multiValued && property.hasMultipleValues && property.type.simpleName != 'RadioButton'}" 
								value="#{property.encodedValues}" >
								<f:selectItems value="#{partition.propertyPossibleValues}"/>
							</h:selectManyListbox>
							<h:selectOneRadio disabled="#{!approvalActionManagedBean.canApprovePartition(partition)
								|| approvalActionManagedBean.isPropertyReadOnly(property.name)}"
								rendered="#{property.type.simpleName eq 'RadioButton' && property.multiValued  && !property.hasMultipleValues}" 
								value="#{property.encodedValue}" layout="pageDirection">
								<f:selectItems value="#{partition.propertyPossibleValues}" var="radioButton" itemLabel="#{radioButton.label}" />
								<f:converter converterId="radioButtonConverter"/>
							</h:selectOneRadio>
						</h:column>
					</h:dataTable>
					
					<h:panelGroup layout="block" style="padding: 5px 10px" rendered="#{approvalActionManagedBean.approvable}">
						<h:selectOneMenu id="selectAction" value="#{approvalActionManagedBean.actionForPartition}" 
							disabled="#{!approvalActionManagedBean.canApprovePartition(partition)}">
							<f:selectItems value="#{approvalActionManagedBean.actionsAvailable}"/>
						</h:selectOneMenu>  					
					</h:panelGroup>
					
				</h:column>
		</h:dataTable>
	</h:panelGroup>
	<h:panelGroup layout="block" style="padding: 5px 10px" rendered="#{approvalActionManagedBean.numberOfPartitionsInStep > approvalActionManagedBean.approvalPartitions.rowCount}" >
		<h:outputText style="font-size: 0.7em;" value="#{web.text.PARTITIONS_HIDDEN}" />
	</h:panelGroup>	

     <h:panelGroup layout="block" style="padding: 5px 10px">
    	<table border="0" cellpadding="1" width="100%">
			<col width="20%">
	  		<col width="80%">
			<tr>
				<td>
					<h:outputText value="#{web.text.APCOMMENT}:"/>
				</td>
				<td>
			        <h:inputTextarea id="comment" rows="2" cols="30" value="#{approvalActionManagedBean.comment}"
			        	disabled="#{!approvalActionManagedBean.approvable}"/>
	        	</td>
	        </tr>
		</table>
	 </h:panelGroup>
    <h:panelGroup style="padding: 5px 10px" layout="block">
    	<h:commandButton id="buttonSave" value="#{web.text.APPROVAL_SAVE_STATE}" actionListener="#{approvalActionManagedBean.saveState}"
    	rendered="#{approvalActionManagedBean.currentStepOrdinal > -1}" disabled="#{!approvalActionManagedBean.canApproveAnyPartitions()}"/>
    	<h:commandButton id="buttonCancel" value="#{web.text.CANCEL}" onclick="self.close()"/>
    </h:panelGroup>
 </h:form>

  <script language="javascript">
<!--
function resize(){
  window.resizeTo(<h:outputText value="#{approvalActionManagedBean.windowWidth}"/>,800);
}

-->
</script>
</body>
</f:view>
</html>

