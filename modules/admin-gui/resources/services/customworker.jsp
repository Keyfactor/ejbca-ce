<%@ taglib uri="http://java.sun.com/jsf/html" prefix="h" %>
<%@ taglib uri="http://java.sun.com/jsf/core" prefix="f" %>
<%@page import="org.ejbca.config.WebConfiguration"%>

<h:panelGrid styleClass="edit-ctnd" width="100%" columns="2" rowClasses="Row0,Row1" columnClasses="editColumn1 label,editColumn2 field">

	<h:panelGroup>
		<f:verbatim><strong></f:verbatim>
			<h:outputText value="#{web.text.CUSTOMWORKERSETTINGS}" rendered="#{!editService.customWorkerType.customUiRenderingSupported}"/>
			<h:outputText value="#{editService.customWorkerType.customUiTitleText}" rendered="#{editService.customWorkerType.customUiRenderingSupported}"/>
		<f:verbatim></strong></f:verbatim>
	</h:panelGroup>
	<h:panelGroup>
		<f:verbatim>&nbsp;</f:verbatim>
        <h:inputHidden id="workerClassPathSelectHidden" value="#{editService.customWorkerType.autoClassPath}" rendered="#{empty editService.manualCustomItems.workers}"/>
	</h:panelGroup>

	<h:panelGroup rendered="#{!editService.customWorkerType.customUiRenderingSupported}">
		<h:outputText value="#{web.text.CUSTOMWORKERCLASSPATH}"/>
	</h:panelGroup>
	<h:panelGroup rendered="#{!editService.customWorkerType.customUiRenderingSupported}">
<%
// we can't use the rendered="..." attribute because then we get duplicate IDs
if (WebConfiguration.isManualClassPathsEnabled()) {
%>
        <h:selectOneMenu id="workerClassPathSelect" value="#{editService.customWorkerType.autoClassPath}"
                         onchange="document.getElementById('edit:workerClassPathTextField').disabled = (this.value != &quot;&quot;); return true"
                         disabled="#{not editService.hasEditRights}">
            <f:selectItems value="#{editService.serviceConfigurationView.availableCustomWorkerItems}" />
            <f:selectItem itemValue="" itemLabel="#{web.text.MANUALCLASSPATH}" />
        </h:selectOneMenu>
        
        <f:verbatim><br></f:verbatim>
        <h:inputText id="workerClassPathTextField" value="#{editService.customWorkerType.manualClassPath}" size="45" disabled="#{not editService.hasEditRights}"/>
        
        <f:verbatim>
            <script type="text/javascript">
            <!--
            {
                var textCustomClass = document.getElementById('edit:workerClassPathTextField');
                var selectClass = document.getElementById('edit:workerClassPathSelect');
                textCustomClass.disabled = (selectClass.value != "");
            }
            //-->
            </script>
        </f:verbatim>
<%
} else {
%>
        <h:selectOneMenu id="workerClassPathSelect" value="#{editService.customWorkerType.autoClassPath}" disabled="#{not editService.hasEditRights}">
            <f:selectItem itemValue="" itemLabel="#{web.text.PLEASE_SELECT}" />
            <f:selectItems value="#{editService.serviceConfigurationView.availableCustomWorkerItems}" />
            <f:selectItems value="#{editService.manualCustomItems.workers}" />
        </h:selectOneMenu>
        <h:panelGroup rendered="#{!empty editService.manualCustomItems.workers}">
            <p><small><h:outputText value="#{web.text.OLDMANUALCLASSPATHELP}"/></small></p>
        </h:panelGroup>
<%
}
%>
    </h:panelGroup>

	<h:panelGroup  rendered="#{!editService.customWorkerType.customUiRenderingSupported}">
		<h:outputText value="#{web.text.CUSTOMWORKERPROPERTIES}"/>
	</h:panelGroup>
	<h:panelGroup rendered="#{!editService.customWorkerType.customUiRenderingSupported}">
		<h:inputTextarea id="workerPropsTextArea" value="#{editService.customWorkerType.propertyText}" rows="8" cols="45" disabled="#{not editService.hasEditRights}"/>
	</h:panelGroup>
</h:panelGrid>

	<h:panelGroup rendered="#{editService.customWorkerType.customUiRenderingSupported}">
		<h:dataTable style="margin-top: 0px; width: 100%;" styleClass="edit-ctnd" value="#{editService.customWorkerType.customUiPropertyList}" var="customUiProperty"
			columnClasses="editColumn1 label,editColumn2 field" rowClasses="Row0,Row1">
			<h:column>
				<h:outputLabel value="#{editService.customWorkerType.customUiPropertyText}"/>
			</h:column>
			<h:column>
				<h:inputText rendered="#{customUiProperty.typeText}" value="#{customUiProperty.value}" style="min-width: 240px;" disabled="#{not editService.hasEditRights}"/>
				<h:selectBooleanCheckbox rendered="#{customUiProperty.typeBoolean}" value="#{customUiProperty.booleanValue}" disabled="#{not editService.hasEditRights}"/>
				<h:selectOneMenu rendered="#{customUiProperty.typeSelectOne}" value="#{customUiProperty.value}" style="min-width: 240px;" disabled="#{not editService.hasEditRights}">
					<f:selectItems value="#{editService.customWorkerType.customUiPropertySelectItems}"/>
				</h:selectOneMenu>
				<h:selectManyListbox rendered="#{customUiProperty.typeSelectMany}" value="#{customUiProperty.multiValue}" style="min-width: 240px;" disabled="#{not editService.hasEditRights}">
					<f:selectItems value="#{editService.customWorkerType.customUiPropertySelectItems}"/>
				</h:selectManyListbox>
			</h:column>
		</h:dataTable>
	</h:panelGroup>

