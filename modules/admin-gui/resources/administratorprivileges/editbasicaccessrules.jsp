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
 
%>
<%@ taglib uri="http://java.sun.com/jsf/html" prefix="h" %>
<%@ taglib uri="http://java.sun.com/jsf/core" prefix="f" %>
<%@ page%>
<% response.setContentType("text/html; charset="+org.ejbca.config.WebConfiguration.getWebContentEncoding()); %>
<%@page pageEncoding="ISO-8859-1" errorPage="/errorpage.jsp"%>
<%@page import="org.cesecore.authorization.control.StandardRules"%>
<%@page import="org.ejbca.config.GlobalConfiguration"%>
<%@page import="org.ejbca.core.model.authorization.AccessRulesConstants"%>
<%@page import="org.ejbca.core.model.authorization.BasicAccessRuleSet"%>
<%@page import="org.ejbca.core.model.authorization.DefaultRoles"%>
<%@page import="org.ejbca.ui.web.admin.configuration.EjbcaWebBean"%>

<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />
 
<%
	GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, AccessRulesConstants.ROLE_ADMINISTRATOR, StandardRules.EDITROLES.resource()); 
%>
 
<html>
<f:view>
<head>
  <title><h:outputText value="#{web.ejbcaWebBean.globalConfiguration.ejbcaTitle}" /></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>" />
  <link rel="stylesheet" type="text/css" href="<%= ejbcawebbean.getCssFile() %>" />
  <script type="text/javascript" src="<%= globalconfiguration.getAdminWebPath() %>ejbcajslib.js"></script>
<script type="text/javascript">
<!--  
 
function roleupdated(){
  var selectcas = document.getElementById('basicRules:selectcas');
  var selectrole = document.getElementById('basicRules:selectrole');
  var selectendentityrules = document.getElementById('basicRules:selectendentityrules');
  var selectendentityprofiles = document.getElementById('basicRules:selectendentityprofiles');  
  var selectother = document.getElementById('basicRules:selectother');	
  var selectinternalkeybindingrules = document.getElementById('basicRules:selectinternalkeybindingrules');	 
  var currentrole = selectrole.options[selectrole.options.selectedIndex].value;  
 
  if(currentrole == '<%=DefaultRoles.CUSTOM.getName() %>'){
    selectcas.disabled = true;
    selectendentityrules.disabled = true;
    selectendentityprofiles.disabled = true;
    selectother.disabled = true;
    selectinternalkeybindingrules.disabled = true;
 
    numofcas = selectcas.length;
    for( i=numofcas-1; i >= 0; i-- ){          
         selectcas.options[i].selected=false;
    }
 
    numofendentity = selectendentityrules.length;
    for( i=numofendentity-1; i >= 0; i-- ){          
         selectendentityrules.options[i].selected=false;
    }
 
    numofprofiles = selectendentityprofiles.length;
    for( i=numofprofiles-1; i >= 0; i-- ){          
         selectendentityprofiles.options[i].selected=false;
    }
    
    numofintinternalkeybindings = selectinternalkeybindingrules.length;
    for( i=numofintinternalkeybindings-1; i >= 0; i-- ){          
    	numofintinternalkeybindings.options[i].selected=false;
    }
 
  }
  
  if(currentrole == '<%=DefaultRoles.SUPERADMINISTRATOR.getName() %>'){
    selectcas.disabled = true;
    selectendentityrules.disabled = true;
    selectendentityprofiles.disabled = true;
    selectother.disabled = true;
    selectinternalkeybindingrules.disabled = true;
 
    numofcas = selectcas.length;
    for( i=numofcas-1; i >= 0; i-- ){          
         selectcas.options[i].selected=false;
    }
 
    numofendentity = selectendentityrules.length;
    for( i=numofendentity-1; i >= 0; i-- ){          
         selectendentityrules.options[i].selected=false;
    }
 
    numofprofiles = selectendentityprofiles.length;
    for( i=numofprofiles-1; i >= 0; i-- ){          
         selectendentityprofiles.options[i].selected=false;
    }
    
    numofintinternalkeybindings = selectinternalkeybindingrules.length;
    for( i=numofintinternalkeybindings-1; i >= 0; i-- ){          
    	numofintinternalkeybindings.options[i].selected=false;
    }
 
  }
  if(currentrole == '<%= DefaultRoles.CAADMINISTRATOR.getName()%>'){
    selectcas.disabled = false;
    selectendentityrules.disabled = true;
    selectendentityprofiles.disabled = true;
    selectother.disabled = false;
    selectinternalkeybindingrules.disabled = false;
 
    numofendentity = selectendentityrules.length;
    for( i=numofendentity-1; i >= 0; i-- ){          
         selectendentityrules.options[i].selected=false;
    }
 
    numofprofiles = selectendentityprofiles.length;
    for( i=numofprofiles-1; i >= 0; i-- ){          
         selectendentityprofiles.options[i].selected=false;
    }
    numberofkeybindingrules = selectinternalkeybindingrules.length;
    for( i = numberofkeybindingrules -1; i >= 0; i--) {
    	selectinternalkeybindingrules.options[i].selected=true;
    }
    

  }
  if(currentrole == '<%= DefaultRoles.RAADMINISTRATOR.getName()%>'){
    selectcas.disabled = false;
    selectendentityrules.disabled = false;
    selectendentityprofiles.disabled = false;
    selectother.disabled = false;
    selectinternalkeybindingrules.disabled = true;
    
    numberofkeybindingrules = selectinternalkeybindingrules.length;
    for( i = numberofkeybindingrules -1; i >= 0; i--) {
    	selectinternalkeybindingrules.options[i].selected=false;
    }

  }  
  if(currentrole == '<%= DefaultRoles.SUPERVISOR.getName()%>'){
    selectcas.disabled = false;
    selectendentityrules.disabled = false;
    selectendentityprofiles.disabled = false;
    selectother.disabled = true;
    selectinternalkeybindingrules.disabled = true;
 
    numofendentity = selectendentityrules.length;
    for( i=numofendentity-1; i >= 0; i-- ){
       if(selectendentityrules.options[i].value == <%=BasicAccessRuleSet.ENDENTITY_VIEW %> ||
          selectendentityrules.options[i].value == <%=BasicAccessRuleSet.ENDENTITY_VIEWHISTORY %>)
         selectendentityrules.options[i].selected=true;
       else
         selectendentityrules.options[i].selected=false;
    }
    numofotherrules = selectother.length;
    for( i=numofotherrules-1; i >= 0; i--) {
    	if(selectother.options[i].value == <%=BasicAccessRuleSet.OTHER_ISSUEHARDTOKENS %>) {
    		selectother.options[i].selected=false;
    	}
    }
    
    numberofkeybindingrules = selectinternalkeybindingrules.length;
    for( i = numberofkeybindingrules -1; i >= 0; i--) {
    	selectinternalkeybindingrules.options[i].selected=false;
    }
  }
}
 
function checkallfields(){ 
	var selectcas = document.getElementById('basicRules:selectcas');
	var selectrole = document.getElementById('basicRules:selectrole');
	var selectendentityrules = document.getElementById('basicRules:selectendentityrules');
	var selectendentityprofiles = document.getElementById('basicRules:selectendentityprofiles');
	var selectother = document.getElementById('basicRules:selectother');
	var selectinternalkeybindingrules = document.getElementById('basicRules:selectinternalkeybindingrules');

    var illegalfields = 0;
    var illegalselection = false;
 
    selectcas.disabled = false;
    selectendentityrules.disabled = false;
    selectendentityprofiles.disabled = false;
    selectother.disabled = false;
    selectinternalkeybindingrules.disabled = false;
 
    var currentrole = selectrole.options[selectrole.options.selectedIndex].value;        
 
    if(currentrole == '<%= DefaultRoles.CUSTOM.getName()%>'){
      alert("<%= ejbcawebbean.getText("SELECTAROLE", true) %>");
      return false;
    }
 
    if(currentrole == '<%= DefaultRoles.SUPERVISOR.getName()%>'){
      var numofendentity = selectendentityrules.length;
      for( i=numofendentity-1; i >= 0; i-- ){
       if(selectendentityrules.options[i].selected){
         if(!(selectendentityrules.options[i].value==<%= BasicAccessRuleSet.ENDENTITY_VIEW%> ||
              selectendentityrules.options[i].value==<%= BasicAccessRuleSet.ENDENTITY_VIEWHISTORY%> ||
              selectendentityrules.options[i].value==<%= BasicAccessRuleSet.ENDENTITY_VIEWHARDTOKENS%>)){
            illegalselection = true;
         }
       }
      }
    }
    return illegalfields == 0;  
} 

-->
</script>
</head>


<body onload='roleupdated()'>

<div align="center">

	<h2><h:outputText value="#{web.text.EDITACCESSRULES}" /> <%= ejbcawebbean.getHelpReference("/userguide.html#Pre-defined%20Role%20Templates") %></h2>
	<h3><h:outputText value="#{web.text.ADMINROLE} : #{rolesManagedBean.currentRole}" /></h3>

	<h:outputText value="#{web.text.AUTHORIZATIONDENIED}" rendered="#{!rolesManagedBean.authorizedToRole}"/>

</div>
	
	<h:panelGroup rendered="#{rolesManagedBean.authorizedToRole}">
	<div><h:outputText styleClass="alert" value="#{web.text.ADVANCEDMODEREQUIRED}" rendered="#{rolesManagedBean.basicRuleSet.forceAdvanced}" /></div>
	<h:messages layout="table" errorClass="alert"/>
  
	<h:panelGroup rendered="#{!rolesManagedBean.basicRuleSet.forceAdvanced}">
 
 	<h:form id="basicRules">
	<h:inputHidden id="currentRole" value="#{rolesManagedBean.currentRole}" />
	<h:panelGrid styleClass="edit" width="100%" columns="2" rowClasses="Row0,Row1" columnClasses="label,field">

		<h:panelGroup>
			&nbsp;
		</h:panelGroup>
		<h:panelGroup>
			<h:outputLink value="#{web.ejbcaWebBean.globalConfiguration.authorizationPath}/administratorprivileges.jsf" title="#{web.text.BACKTOROLES}">
				<h:outputText value="#{web.text.BACKTOROLES}"/>
			</h:outputLink>
		</h:panelGroup>

		<h:panelGroup>
			&nbsp;
		</h:panelGroup>
		<h:panelGroup style="display: block; text-align: right;">
			<h:outputLink value="#{web.ejbcaWebBean.globalConfiguration.authorizationPath}/editadminentities.jsf?currentRole=#{rolesManagedBean.currentRole}"
				title="#{web.text.EDITADMINS}" rendered="#{not empty rolesManagedBean.currentRole}">
				<h:outputText value="#{web.text.EDITADMINS}"/>
			</h:outputLink>
		</h:panelGroup>

		<h:panelGroup>
			&nbsp;
		</h:panelGroup>
		<h:panelGroup style="display: block; text-align: right;">
			<h:outputLink value="#{web.ejbcaWebBean.globalConfiguration.authorizationPath}/editadvancedaccessrules.jsf?currentRole=#{rolesManagedBean.currentRole}"
				title="#{web.text.ADVANCEDMODE}" rendered="#{not empty rolesManagedBean.currentRole}">
				<h:outputText value="#{web.text.ADVANCEDMODE}"/>
			</h:outputLink>
		</h:panelGroup>

		<h:outputText value="#{web.text.ROLETEMPLATE}"/>
		<h:selectOneMenu id="selectrole" value="#{rolesManagedBean.currentRoleTemplate}" onchange='roleupdated()'>
			<f:selectItems value="#{rolesManagedBean.availableRoles}" />
		</h:selectOneMenu> 
		
		<h:outputText value="#{web.text.AUTHORIZEDCAS}"/>
		<h:selectManyListbox id="selectcas" value="#{rolesManagedBean.currentCAs}" size="8">
			<f:selectItems value="#{rolesManagedBean.availableCasAndAll}" />
		</h:selectManyListbox> 

		<h:outputText value="#{web.text.ENDENTITYRULES}"/>
		<h:selectManyListbox id="selectendentityrules" value="#{rolesManagedBean.currentEndEntityRules}" size="10">
			<f:selectItems value="#{rolesManagedBean.availableEndEntityRules}" />
		</h:selectManyListbox> 
 
		<h:outputText value="#{web.text.ENDENTITYPROFILES}"/>
		<h:selectManyListbox id="selectendentityprofiles" value="#{rolesManagedBean.currentEndEntityProfiles}" size="8">
			<f:selectItems value="#{rolesManagedBean.availableEndEntityProfiles}" />
		</h:selectManyListbox> 

		<h:outputText value="#{web.text.INTERNALKEYBINDINGRULES}"/>
		<h:selectManyListbox id="selectinternalkeybindingrules" value="#{rolesManagedBean.currentInternalKeyBindingRules}" size="6">
			<f:selectItems value="#{rolesManagedBean.availableInternalKeyBindingRules}" />
		</h:selectManyListbox> 

		<h:outputText value="#{web.text.OTHERRULES}"/>
		<h:selectManyListbox id="selectother" value="#{rolesManagedBean.currentOtherRules}" size="3">
			<f:selectItems value="#{rolesManagedBean.availableOtherRules}" />
		</h:selectManyListbox> 


		<%-- Form buttons --%>

		<h:panelGroup>
			&nbsp;
		</h:panelGroup>
		<h:panelGroup>
			<h:commandButton action="#{rolesManagedBean.saveAccessRules}" onclick="return checkallfields();" value="#{web.text.SAVE}"/>
			<h:commandButton action="cancel" value="#{web.text.RESTORE}"/>
		</h:panelGroup>
	</h:panelGrid>
	</h:form>
	</h:panelGroup>
	</h:panelGroup>

<%	// Include Footer 
	String footurl = globalconfiguration.getFootBanner(); %>
	<jsp:include page="<%= footurl %>" />

</body>
</f:view>
</html>
