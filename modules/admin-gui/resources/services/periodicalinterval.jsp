<%@ taglib uri="http://java.sun.com/jsf/html" prefix="h" %>
<%@ taglib uri="http://java.sun.com/jsf/core" prefix="f" %>

	<h:panelGroup>
		<f:verbatim><strong></f:verbatim><h:outputText value="#{web.text.PERIODICALSETTINGS}"/><f:verbatim></strong></f:verbatim>
	</h:panelGroup>
	<h:panelGroup>
		<f:verbatim>&nbsp;</f:verbatim>
	</h:panelGroup>

	<h:panelGroup>
		<h:outputText value="#{web.text.PERIOD}"/>
	</h:panelGroup>
	<h:panelGroup>				
		<h:inputText id="periodicalValueTextField" value="#{editService.periodicalIntervalType.value}" size="5" title="#{web.text.FORMAT_INTEGER}" disabled="#{not editService.hasEditRights}"/><f:verbatim> </f:verbatim>
		<h:selectOneMenu id="periodicalUnitSelect" value="#{editService.periodicalIntervalType.unit}" disabled="#{not editService.hasEditRights}">
		  <f:selectItems value="#{editService.periodicalIntervalType.availableUnits}"/>
	    </h:selectOneMenu>		
	</h:panelGroup>	



