<%@ taglib uri="http://java.sun.com/jsf/html" prefix="h" %>
<%@ taglib uri="http://java.sun.com/jsf/core" prefix="f" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<% response.setContentType("text/html; charset="+org.ejbca.config.WebConfiguration.getWebContentEncoding()); %>
<%@page pageEncoding="ISO-8859-1" errorPage="/errorpage.jsp"%>
<%@page import="org.ejbca.config.GlobalConfiguration"%>
<%@page import="org.ejbca.core.model.authorization.AccessRulesConstants"%>
<%@page import="org.ejbca.ui.web.RequestHelper"%>
<%@page import="org.ejbca.ui.web.admin.configuration.EjbcaJSFHelper"%>
<%@page import="org.ejbca.ui.web.admin.services.EditServiceManagedBean"%>
<%@page import="org.cesecore.authorization.control.StandardRules"%>
<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />
<jsp:setProperty name="ejbcawebbean" property="*" /> 
<%   // Initialize environment
 GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, AccessRulesConstants.ROLE_ADMINISTRATOR, StandardRules.ROLE_ROOT.resource()); 
 EjbcaJSFHelper helpbean = EjbcaJSFHelper.getBean();
 helpbean.setEjbcaWebBean(ejbcawebbean);

 String workerPage = EditServiceManagedBean.getBean().getServiceConfigurationView().getWorkerType().getJSFSubViewPage();
 String intervalPage = EditServiceManagedBean.getBean().getServiceConfigurationView().getIntervalType().getJSFSubViewPage();
 String actionPage = EditServiceManagedBean.getBean().getServiceConfigurationView().getActionType().getJSFSubViewPage();
%>
<html>
<head>
  <title><c:out value="<%= globalconfiguration.getEjbcaTitle() %>" /></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>" />
  <link rel="stylesheet" type="text/css" href="<%= ejbcawebbean.getCssFile() %>" />
  <meta http-equiv="Content-Type" content="text/html; charset=<%= org.ejbca.config.WebConfiguration.getWebContentEncoding() %>" />
</head>


<f:view>
<body id="service">

<h2><%= ejbcawebbean.getText("EDITSERVICE") %></h2>

<h3><%= ejbcawebbean.getText("SERVICE")+ " : " %><h:outputText value="#{editService.serviceName}" /></h3>

<h:form id="selectWorker" style="margin-bottom: 3px;">
<h:panelGrid styleClass="edit-top" width="100%" columns="2" rowClasses="Row0,Row1" columnClasses="editColumn1 label,editColumn2 field">
	<h:panelGroup>
		&nbsp;
	</h:panelGroup>
	<h:panelGroup>
	  	<h:commandLink id="backToServices" action="listservices" immediate="true" style="text-align: right;">
			<h:outputText value="#{web.text.BACKTOSERVICES}" style="text-align: right;"/>
		</h:commandLink>
	</h:panelGroup>

	<h:panelGroup>
		<h:outputText value="#{web.text.SELECTWORKER}"/><f:verbatim> </f:verbatim><h:outputText><%= ejbcawebbean.getHelpReference("/adminguide.html#Services%20Framework") %></h:outputText>
	</h:panelGroup>
	<h:panelGroup style="white-space: nowrap;">
		<h:selectOneMenu value="#{editService.serviceConfigurationView.selectedWorker}"
		                 onchange="document.getElementById('selectWorker:updateButton').click();">
			<f:selectItems value="#{editService.serviceConfigurationView.availableWorkers}"/>
		</h:selectOneMenu>
		<f:verbatim>&nbsp;&nbsp;&nbsp;</f:verbatim>
		<h:commandButton id="updateButton" action="#{editService.update}" value="#{web.text.UPDATE}"/>
		<script>document.getElementById('selectWorker:updateButton').style.display = 'none'</script>
	</h:panelGroup>
</h:panelGrid>
</h:form>
<h:form id="edit">
<h:inputHidden value="#{editService.serviceConfigurationView.selectedWorker}"/>
<% if (workerPage.equals("customworker.jsp")) { %>
     <jsp:include page="<%=workerPage %>"/>
<% } else { %>
<h:panelGrid styleClass="edit-ctnd" width="100%" columns="2" rowClasses="Row0,Row1" columnClasses="editColumn1 label,editColumn2 field">

     <jsp:include page="<%=workerPage %>"/>

</h:panelGrid>
<% } %>
  
<h:panelGrid styleClass="edit-ctnd" width="100%" columns="2" rowClasses="Row0,Row1" columnClasses="editColumn1 label,editColumn2 field">
    <h:panelGroup>
		<h:outputText value="#{web.text.SELECTINTERVAL}"/>
	</h:panelGroup>
	<h:panelGroup>
		<h:selectOneMenu value="#{editService.serviceConfigurationView.selectedInterval}" valueChangeListener="#{editService.changeInterval}" 
		                 onchange="document.getElementById('edit:updateButton').click();">
			<f:selectItems value="#{editService.serviceConfigurationView.availableIntervals}"/>
		</h:selectOneMenu>			
		<f:verbatim>&nbsp;&nbsp;&nbsp;</f:verbatim>
		<h:commandButton id="updateButton" action="#{editService.update}" value="#{web.text.UPDATE}"/>			
		<script>document.getElementById('edit:updateButton').style.display = 'none'</script>
	</h:panelGroup>
	
     <jsp:include page="<%=intervalPage %>"/>  
 
</h:panelGrid>

<h:panelGrid styleClass="edit-ctnd" width="100%" columns="2" rowClasses="Row0,Row1" columnClasses="editColumn1 label,editColumn2 field">
    <h:panelGroup>
		<h:outputText value="#{web.text.SELECTACTION}"/>
	</h:panelGroup>
	<h:panelGroup>
		<h:selectOneMenu value="#{editService.serviceConfigurationView.selectedAction}" valueChangeListener="#{editService.changeAction}"
		                 onchange="document.getElementById('edit:updateButton').click();">
			<f:selectItems value="#{editService.serviceConfigurationView.availableActions}"/>
		</h:selectOneMenu>			
	</h:panelGroup>
  
     <jsp:include page="<%=actionPage %>"/>
      
</h:panelGrid>

<h:panelGrid styleClass="edit-bottom" width="100%" columns="2" rowClasses="Row0,Row1" columnClasses="editColumn1 label,editColumn2 field">
	<h:panelGroup>
		<f:verbatim><strong></f:verbatim><h:outputText value="#{web.text.GENERALSETTINGS}"/><f:verbatim></strong></f:verbatim>						
	</h:panelGroup>
	<h:panelGroup>
		<f:verbatim>&nbsp;</f:verbatim>
	</h:panelGroup>

	<h:panelGroup>
		<f:verbatim><strong></f:verbatim><h:outputText value="#{web.text.ACTIVE}"/><f:verbatim></strong></f:verbatim>
	</h:panelGroup>
	<h:panelGroup>
		<h:selectBooleanCheckbox id="activeCheckbox" value="#{editService.serviceConfigurationView.active}"/>
		<h:outputLabel for="activeCheckbox" value="#{web.text.ACTIVE}" />
	</h:panelGroup>
	<h:panelGroup>
		<h:outputText value="#{web.text.PINTONODES}"/>
	</h:panelGroup>
	<h:panelGroup>
		<h:selectManyListbox id="pinToNodesListbox" value="#{editService.serviceConfigurationView.pinToNodes}">
			<f:selectItems value="#{editService.serviceConfigurationView.nodesInCluster}"/>
		</h:selectManyListbox>
	</h:panelGroup>
	<h:panelGroup>
		<h:outputText value="#{web.text.DESCRIPTION}"/>
	</h:panelGroup>
	<h:panelGroup>
		<h:inputTextarea id="descriptionTextArea" value="#{editService.serviceConfigurationView.description}" rows="2" cols="45"/>
	</h:panelGroup>
	
	<%-- Form buttons --%>
		
	<h:panelGroup>
		&nbsp;
	</h:panelGroup>
	<h:panelGroup>
		<f:verbatim>
<script type="text/javascript">
<!--  

function enableAll(){  
  var all=document.getElementsByTagName("*");
  
  for(var i=0; i<all.length; i++){
     all[i].disabled = false;
  }
} 

-->
</script>
  <div align="center">
    <h:messages styleClass="alert" layout="table"/>
  </div>
        </f:verbatim>
		<h:commandButton id="saveButton" action="#{editService.save}" value="#{web.text.SAVE}" onclick="enableAll()"/>		
		<f:verbatim>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</f:verbatim>
		<h:commandButton id="cancelButton" action="#{editService.cancel}" value="#{web.text.CANCEL}"/>		
	</h:panelGroup>
	
</h:panelGrid>
</h:form>

</body>
</f:view>
</html>
