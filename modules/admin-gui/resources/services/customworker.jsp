<%@ taglib uri="http://java.sun.com/jsf/html" prefix="h" %>
<%@ taglib uri="http://java.sun.com/jsf/core" prefix="f" %>

	<h:panelGroup>
		<f:verbatim><strong></f:verbatim><h:outputText value="#{web.text.CUSTOMWORKERSETTINGS}"/><f:verbatim></strong></f:verbatim>
	</h:panelGroup>
	<h:panelGroup>
		<f:verbatim>&nbsp;</f:verbatim>
	</h:panelGroup>

	<h:panelGroup>
		<h:outputText value="#{web.text.CUSTOMWORKERCLASSPATH}"/>
	</h:panelGroup>
	<h:panelGroup>
       <h:selectOneMenu id="workerClassPathSelect" value="#{editService.customWorkerType.autoClassPath}"
                         onchange="document.getElementById('edit:workerClassPathTextField').disabled = (this.value != &quot;&quot;); return true">
            <f:selectItems value="#{editService.serviceConfigurationView.availableCustomWorkerItems}" />
            <f:selectItem itemValue="" itemLabel="#{web.text.MANUALCLASSPATH}" />
        </h:selectOneMenu>
        
        <f:verbatim><br></f:verbatim>
        <h:inputText id="workerClassPathTextField" value="#{editService.customWorkerType.manualClassPath}" size="45"/>
        
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
	</h:panelGroup>

	<h:panelGroup>
		<h:outputText value="#{web.text.CUSTOMWORKERPROPERTIES}"/>
	</h:panelGroup>
	<h:panelGroup>
		<h:inputTextarea id="workerPropsTextArea" value="#{editService.customWorkerType.propertyText}" rows="8" cols="45"/>
	</h:panelGroup>

