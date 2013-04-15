<%@ taglib uri="http://java.sun.com/jsf/html" prefix="h" %>
<%@ taglib uri="http://java.sun.com/jsf/core" prefix="f" %>

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
        <h:selectOneMenu id="actionClassPathSelect" value="#{editService.customActionType.autoClassPath}"
                         onchange="document.getElementById('edit:actionClassPathTextField').disabled = (this.value != &quot;&quot;); return true">
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
	</h:panelGroup>

	<h:panelGroup>
		<h:outputText value="#{web.text.CUSTOMACTIONPROPERTIES}"/>
	</h:panelGroup>
	<h:panelGroup>
		<h:inputTextarea id="actionPropsTextArea" value="#{editService.customActionType.propertyText}" rows="8" cols="45"/>
	</h:panelGroup>

