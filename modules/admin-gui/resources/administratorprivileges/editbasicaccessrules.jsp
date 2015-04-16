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
/**
 * Enable and modify the boolean state of all the select-elements options.
 *
 * @param selectElement is a select multiple elemnent
 * @param the new boolean state of selectElement.disabled
 * @param the new boolean option.selected state for each contained option
 */
function selectAll(selectElement, selectDisabled, selectedValue) {
    var length = selectElement.length;
    for (var i=0; i<length; i++) {
    	selectElement.options[i].disabled = false;
    	selectElement.options[i].selected = selectedValue;
    }
    selectElement.disabled = selectDisabled;
}
/**
 * Enable and modify the set the state to selected of all the options that appear in the provided array.
 *
 * @param selectElement is a select multiple elemnent
 * @param optionValues an array of (String) option values that should be enabled and selected.
 * @param the new boolean option.disabled state for unselected option
 */
function selectSome(selectElement, optionValues, disableUnselected) {
	selectElement.disabled = false;
    var selectLength = selectElement.length;
    for (var i=0; i<selectLength; i++) {
    	var found = false;
        for (var j=0; j<optionValues.length; j++) {
        	if (selectElement.options[i].value === optionValues[j]) {
        		found = true;
        		break;
        	}
        }
        if (found) {
        	selectElement.options[i].selected = true;
        	selectElement.options[i].disabled = false;
        } else {
        	selectElement.options[i].selected = false;
        	selectElement.options[i].disabled = disableUnselected;
        }
    }
}
/**
 * Modify selectable fields according to the currently selected role.
 */
function roleupdated() {
	var selectcas = document.getElementById('basicRules:selectcas');
	var selectrole = document.getElementById('basicRules:selectrole');
	var selectendentityrules = document.getElementById('basicRules:selectendentityrules');
	var selectendentityprofiles = document.getElementById('basicRules:selectendentityprofiles');
	var selectother = document.getElementById('basicRules:selectother');
	var selectinternalkeybindingrules = document.getElementById('basicRules:selectinternalkeybindingrules');
	var currentrole = selectrole.options[selectrole.options.selectedIndex].value;
	if (currentrole === '<%=DefaultRoles.CUSTOM.getName() %>' || currentrole === '<%=DefaultRoles.SUPERADMINISTRATOR.getName() %>' ) {
		selectAll(selectcas, true, false);
		selectAll(selectendentityrules, true, false);
		selectAll(selectendentityprofiles, true, false);
		selectAll(selectinternalkeybindingrules, true, false);
		selectAll(selectother, true, false);
	} else if (currentrole === '<%= DefaultRoles.CAADMINISTRATOR.getName()%>') {
		selectAll(selectendentityrules, true, false);
		selectAll(selectendentityprofiles, true, false);
		selectAll(selectinternalkeybindingrules, false, true);
		selectSome(selectother, [ '<%=BasicAccessRuleSet.OTHER_VIEWLOG %>' ], true);
	} else if (currentrole === '<%= DefaultRoles.RAADMINISTRATOR.getName()%>') {
		selectSome(selectendentityrules, [
			'<%=BasicAccessRuleSet.ENDENTITY_VIEW %>',
			'<%=BasicAccessRuleSet.ENDENTITY_VIEWHISTORY %>',
			'<%=BasicAccessRuleSet.ENDENTITY_CREATE %>',
			'<%=BasicAccessRuleSet.ENDENTITY_EDIT %>',
			'<%=BasicAccessRuleSet.ENDENTITY_DELETE %>',
			'<%=BasicAccessRuleSet.ENDENTITY_REVOKE %>'
		], true);
		selectAll(selectinternalkeybindingrules, true, false);
		selectSome(selectother, [ '<%=BasicAccessRuleSet.OTHER_VIEWLOG %>' ], true);
	} else if(currentrole === '<%= DefaultRoles.SUPERVISOR.getName()%>') {
		selectSome(selectendentityrules, [
			'<%=BasicAccessRuleSet.ENDENTITY_VIEW %>',
			'<%=BasicAccessRuleSet.ENDENTITY_VIEWHISTORY %>',
			'<%=BasicAccessRuleSet.ENDENTITY_VIEWHARDTOKENS %>'
		], true);
		selectAll(selectinternalkeybindingrules, true, false);
		selectSome(selectother, [ '<%=BasicAccessRuleSet.OTHER_VIEWLOG %>' ], true);
	}
}

function checkallfields() {
	var selectrole = document.getElementById('basicRules:selectrole');
	var currentrole = selectrole.options[selectrole.options.selectedIndex].value;
	if (currentrole === '<%= DefaultRoles.CUSTOM.getName()%>') {
		alert("<%= ejbcawebbean.getText("SELECTANOTHERROLE", true) %>");
		return false;
	}
	return true;
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
