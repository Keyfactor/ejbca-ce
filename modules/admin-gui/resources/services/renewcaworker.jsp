<%@ taglib uri="http://java.sun.com/jsf/html" prefix="h" %>
<%@ taglib uri="http://java.sun.com/jsf/core" prefix="f" %>
<%@ taglib uri="http://myfaces.apache.org/tomahawk" prefix="t" %>


	<h:panelGroup>
		<h:outputText value="#{web.text.RENEWCASETTINGS}"/>
	</h:panelGroup>
	<h:panelGroup>
		<f:verbatim>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</f:verbatim>
	</h:panelGroup>
	<h:panelGroup>
		<h:outputText value="#{web.text.CASTOCHECK}"/>
	</h:panelGroup>
	<h:panelGroup>							
		<h:selectManyListbox id="certCheckCASelect" value="#{editService.notifyingType.selectedCANamesToCheck}" size="10">
			<f:selectItems value="#{editService.availableCAs}"/>
		</h:selectManyListbox>		
	</h:panelGroup>	
	<h:panelGroup>
		<h:outputText value="#{web.text.TIMERENEWBEFOREREXPIRE}"/>
	</h:panelGroup>
	<h:panelGroup>				
			<h:inputText id="certCheckTimeValueTextField" value="#{editService.notifyingType.timeValue}" size="6"/>
			<h:selectOneMenu id="certCheckTimeUnitSelect" value="#{editService.notifyingType.timeUnit}">
			  <f:selectItems value="#{editService.notifyingType.availableUnits}"/>
		    </h:selectOneMenu>		
	</h:panelGroup>	

	<h:panelGroup>
		<h:outputText value="#{web.text.RENEWKEYS}"/>
	</h:panelGroup>
	<h:panelGroup>				
			<h:selectBooleanCheckbox id="renewKeys" value="#{editService.renewType.renewKeys}"/>
	</h:panelGroup>	
	