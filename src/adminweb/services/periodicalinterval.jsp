<%@ taglib uri="http://java.sun.com/jsf/html" prefix="h" %>
<%@ taglib uri="http://java.sun.com/jsf/core" prefix="f" %>
<%@ taglib uri="http://myfaces.apache.org/tomahawk" prefix="t" %>


	<h:panelGroup>
		<h:outputText value="#{web.text.PERIODICALSETTINGS}"/>
	</h:panelGroup>
	<h:panelGroup>
		<f:verbatim>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</f:verbatim>
	</h:panelGroup>
	<h:panelGroup>
		<h:outputText value="#{web.text.PERIOD}"/>
	</h:panelGroup>
	<h:panelGroup>				
			<h:inputText id="periodicalValueTextField" value="#{editService.periodicalIntervalType.value}" size="6" />
			<h:selectOneMenu id="periodicalUnitSelect" value="#{editService.periodicalIntervalType.unit}">
			  <f:selectItems value="#{editService.periodicalIntervalType.availableUnits}"/>
		    </h:selectOneMenu>		
	</h:panelGroup>	



