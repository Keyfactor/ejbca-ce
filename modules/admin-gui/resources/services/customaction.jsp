<%@ taglib uri="http://java.sun.com/jsf/html" prefix="h" %>
<%@ taglib uri="http://java.sun.com/jsf/core" prefix="f" %>
<%@page import="org.ejbca.config.WebConfiguration"%>

	<h:panelGroup>
		<f:verbatim><strong></f:verbatim><h:outputText value="#{web.text.CUSTOMACTIONSETTINGS}"/><f:verbatim></strong></f:verbatim>
	</h:panelGroup>
	<h:panelGroup>	
	     <f:verbatim>&nbsp;</f:verbatim>	
	</h:panelGroup>

	<h:panelGroup>
		<h:outputText value="#{web.text.CUSTOMACTIONCLASSPATH}"/>
	</h:panelGroup>
	<h:panelGroup>
<%
// we can't use the rendered="..." attribute because then we get duplicate IDs
if (WebConfiguration.isManualClassPathsEnabled()) {
%>
        <h:selectOneMenu id="actionClassPathSelect" value="#{editService.customActionType.autoClassPath}"
                         onchange="document.getElementById('edit:actionClassPathTextField').disabled = (this.value != &quot;&quot;); return true"
                         disabled="#{not editService.hasEditRights}">
            <f:selectItems value="#{editService.serviceConfigurationView.availableCustomActionItems}" />
            <f:selectItem itemValue="" itemLabel="#{web.text.MANUALCLASSPATH}" />
        </h:selectOneMenu>
        
        <f:verbatim><br></f:verbatim>
        <h:inputText id="actionClassPathTextField" value="#{editService.customActionType.manualClassPath}" size="45"/>
        
        <f:verbatim>
            <script type="text/javascript">
            <!--
            {
                var textCustomClass = document.getElementById('edit:actionClassPathTextField');
                var selectClass = document.getElementById('edit:actionClassPathSelect');
                textCustomClass.disabled = (selectClass.value != "");
            }
            //-->
            </script>
        </f:verbatim>
<%
} else {
%>
        <h:selectOneMenu id="actionClassPathSelect" value="#{editService.customActionType.autoClassPath} disabled="#{not editService.hasEditRights}"">
            <f:selectItem itemValue="" itemLabel="#{web.text.PLEASE_SELECT}" />
            <f:selectItems value="#{editService.serviceConfigurationView.availableCustomActionItems}" />
            <f:selectItems value="#{editService.manualCustomItems.actions}" />
        </h:selectOneMenu>
        
        <h:panelGroup rendered="#{!empty editService.manualCustomItems.actions}">
            <p><small><h:outputText value="#{web.text.OLDMANUALCLASSPATHELP}"/></small></p>
        </h:panelGroup>
<%
}
%>
	</h:panelGroup>

	<h:panelGroup>
		<h:outputText value="#{web.text.CUSTOMACTIONPROPERTIES}"/>
	</h:panelGroup>
	<h:panelGroup>
		<h:inputTextarea id="actionPropsTextArea" value="#{editService.customActionType.propertyText}" rows="8" cols="45" disabled="#{not editService.hasEditRights}"/>
	</h:panelGroup>

