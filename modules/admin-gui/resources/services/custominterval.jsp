<%@ taglib uri="http://java.sun.com/jsf/html" prefix="h" %>
<%@ taglib uri="http://java.sun.com/jsf/core" prefix="f" %>

	<h:panelGroup>
		<f:verbatim><strong></f:verbatim><h:outputText value="#{web.text.CUSTOMINTERVALSETTINGS}"/><f:verbatim></strong></f:verbatim>
	</h:panelGroup>
	<h:panelGroup>
		<f:verbatim>&nbsp;</f:verbatim>
	</h:panelGroup>

	<h:panelGroup>
		<h:outputText value="#{web.text.CUSTOMINTERVALCLASSPATH}"/>
	</h:panelGroup>
	<h:panelGroup>
        <h:selectOneMenu id="intervalClassPathSelect" value="#{editService.customIntervalType.autoClassPath}"
                         onchange="document.getElementById('edit:intervalClassPathTextField').disabled = (this.value != &quot;&quot;); return true">
            <f:selectItems value="#{editService.serviceConfigurationView.availableCustomIntervalItems}" />
            <f:selectItem itemValue="" itemLabel="#{web.text.MANUALCLASSPATH}" />
        </h:selectOneMenu>
        
        <f:verbatim><br></f:verbatim>
        <h:inputText id="intervalClassPathTextField" value="#{editService.customIntervalType.manualClassPath}" size="45"/>
        
        <f:verbatim>
            <script type="text/javascript">
            <!--
            {
                var textCustomClass = document.getElementById('edit:intervalClassPathTextField');
                var selectClass = document.getElementById('edit:intervalClassPathSelect');
                textCustomClass.disabled = (selectClass.value != "");
            }
            //-->
            </script>
        </f:verbatim>		
	</h:panelGroup>

	<h:panelGroup>
		<h:outputText value="#{web.text.CUSTOMINTERVALPROPERTIES}"/>
	</h:panelGroup>
	<h:panelGroup>
		<h:inputTextarea id="intervalPropsTextArea" value="#{editService.customIntervalType.propertyText}" rows="6" cols="45"/>
	</h:panelGroup>

