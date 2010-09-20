<%@ taglib uri="http://java.sun.com/jsf/html" prefix="h" %>
<%@ taglib uri="http://java.sun.com/jsf/core" prefix="f" %>
<%@ taglib uri="http://myfaces.apache.org/tomahawk" prefix="t" %>
<%@ page pageEncoding="ISO-8859-1"%>
<% response.setContentType("text/html; charset="+org.ejbca.config.WebConfiguration.getWebContentEncoding()); %>
<%@page errorPage="/errorpage.jsp" import="org.ejbca.core.model.ra.raadmin.GlobalConfiguration,org.ejbca.ui.web.RequestHelper, org.ejbca.core.model.authorization.AccessRulesConstants,
                                           org.ejbca.ui.web.admin.configuration.EjbcaJSFHelper, org.ejbca.ui.web.admin.services.EditServiceManagedBean" %>
<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />
<jsp:setProperty name="ejbcawebbean" property="*" /> 
<%   // Initialize environment
 GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request,AccessRulesConstants.ROLE_SUPERADMINISTRATOR); 
 EjbcaJSFHelper helpbean = EjbcaJSFHelper.getBean();
 helpbean.setEjbcaWebBean(ejbcawebbean);
 helpbean.authorizedToServicesPages();
 
 String workerPage = EditServiceManagedBean.getBean().getServiceConfigurationView().getWorkerType().getJSFSubViewPage();
 String intervalPage = EditServiceManagedBean.getBean().getServiceConfigurationView().getIntervalType().getJSFSubViewPage();
 String actionPage = EditServiceManagedBean.getBean().getServiceConfigurationView().getActionType().getJSFSubViewPage();
%>
<html>
<head>
  <title><%= globalconfiguration.getEjbcaTitle() %></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>">
  <link rel=STYLESHEET href="<%= ejbcawebbean.getCssFile() %>">
  <meta http-equiv="Content-Type" content="text/html; charset=<%= org.ejbca.config.WebConfiguration.getWebContentEncoding() %>">
  <link href="/themes/default_theme.css" rel="stylesheet" type="text/css"/>
</head>


<f:view>
<body>

<div align="center"> 
  <h2><%= ejbcawebbean.getText("EDITSERVICE") %></h2>
  <h3><%= ejbcawebbean.getText("SERVICE")+ " : " %><h:outputText value="#{editService.serviceName}" /></h3>
</div>

<h:form id="edit"> 

  <div align="right">  <h:commandLink id="backToServices" action="listservices" immediate="true" style="text-align: right">
		<h:outputText value="#{web.text.BACKTOSERVICES}" style="text-align: right"/>
	</h:commandLink>
  </div>	

<h:panelGrid width="100%" columns="2" rowClasses="jsfrow2,jsfrow1" columnClasses="label,field">
	<h:panelGroup>
		<h:outputText value="#{web.text.SELECTWORKER}"/><f:verbatim> </f:verbatim><h:outputText><%= ejbcawebbean.getHelpReference("/adminguide.html#Currently%20Available%20Workers") %></h:outputText>
	</h:panelGroup>
	<h:panelGroup>
		<h:selectOneMenu value="#{editService.serviceConfigurationView.selectedWorker}" valueChangeListener="#{editService.changeWorker}"
		                 onchange="document.getElementById('edit:updateButton').click();">
			<f:selectItems value="#{editService.serviceConfigurationView.availableWorkers}"/>
		</h:selectOneMenu>
		<f:verbatim>&nbsp;&nbsp;&nbsp;</f:verbatim>
		<h:commandButton id="updateButton" action="#{editService.update}" value="Update"  />			
	</h:panelGroup>
  
     <jsp:include page="<%=workerPage %>"/>
  
  	<h:panelGroup>
		<f:verbatim>&nbsp;</f:verbatim>
	</h:panelGroup>
	<h:panelGroup>				
		<f:verbatim>&nbsp;</f:verbatim>
	</h:panelGroup>
    <h:panelGroup>
		<h:outputText value="#{web.text.SELECTINTERVAL}"/>
	</h:panelGroup>
	<h:panelGroup>
		<h:selectOneMenu value="#{editService.serviceConfigurationView.selectedInterval}" valueChangeListener="#{editService.changeInterval}" 
		                 onchange="document.getElementById('edit:updateButton').click();">
			<f:selectItems value="#{editService.serviceConfigurationView.availableIntervals}"/>
		</h:selectOneMenu>			
	</h:panelGroup>
	
     <jsp:include page="<%=intervalPage %>"/>  
 
  	<h:panelGroup>
		<f:verbatim>&nbsp;</f:verbatim>
	</h:panelGroup>
	<h:panelGroup>				
		<f:verbatim>&nbsp;</f:verbatim>
	</h:panelGroup>
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
      
  	<h:panelGroup>
		<f:verbatim>&nbsp;</f:verbatim>
	</h:panelGroup>
	<h:panelGroup>				
		<f:verbatim>&nbsp;</f:verbatim>
	</h:panelGroup>
	<h:panelGroup>
		<f:verbatim><strong></f:verbatim><h:outputText value="#{web.text.ACTIVE}"/><f:verbatim></strong></f:verbatim>
	</h:panelGroup>
	<h:panelGroup>
		<h:selectBooleanCheckbox id="activeCheckbox" value="#{editService.serviceConfigurationView.active}"/>
	</h:panelGroup>
	<h:panelGroup>
		<h:outputText value="#{web.text.DESCRIPTION}"/>
	</h:panelGroup>
	<h:panelGroup>
		<h:inputTextarea id="descriptionTextArea" value="#{editService.serviceConfigurationView.description}" rows="4" cols="45"/>
	</h:panelGroup>
	<h:panelGroup>
		
	</h:panelGroup>
	<h:panelGroup>
		<f:verbatim>
<SCRIPT language="JavaScript">
<!--  

function enableAll(){  
  var all=document.getElementsByTagName("*");
  
  for(var i=0; i<all.length; i++){
     all[i].disabled = false;
  }
} 

-->
</SCRIPT>
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

