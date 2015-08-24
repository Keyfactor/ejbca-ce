<%@ taglib uri="http://java.sun.com/jsf/html" prefix="h" %>
<%@ taglib uri="http://java.sun.com/jsf/core" prefix="f" %>

	<h:panelGroup>
		<f:verbatim><strong></f:verbatim><h:outputText value="#{web.text.RENEWCASETTINGS}"/><f:verbatim></strong></f:verbatim>
	</h:panelGroup>
	<h:panelGroup>
		<f:verbatim>&nbsp;</f:verbatim>
	</h:panelGroup>

	<h:panelGroup>
		<h:outputText value="#{web.text.CASTOCHECK}"/>
	</h:panelGroup>
	<h:panelGroup>
		<h:selectManyListbox id="certCheckCASelect" value="#{editService.notifyingType.selectedCANamesToCheck}" size="10" disabled="#{not editService.hasEditRights}">
			<f:selectItems value="#{editService.availableCAs}"/>
		</h:selectManyListbox>
	</h:panelGroup>

	<h:panelGroup>
		<h:outputText value="#{web.text.TIMERENEWBEFOREREXPIRE}"/>
	</h:panelGroup>
	<h:panelGroup>
		<h:inputText id="certCheckTimeValueTextField" value="#{editService.notifyingType.timeValue}" size="5" title="#{web.text.FORMAT_INTEGER}" disabled="#{not editService.hasEditRights}"/><f:verbatim> </f:verbatim>
		<h:selectOneMenu id="certCheckTimeUnitSelect" value="#{editService.notifyingType.timeUnit}" disabled="#{not editService.hasEditRights}">
		  <f:selectItems value="#{editService.notifyingType.availableUnits}"/>
	    </h:selectOneMenu>
	</h:panelGroup>

	<h:panelGroup>
		<h:outputText value="#{web.text.RENEWKEYS}"/>
	</h:panelGroup>
	<h:panelGroup>
		<h:selectBooleanCheckbox id="renewKeys" value="#{editService.renewType.renewKeys}" disabled="#{not editService.hasEditRights}"/>
		<h:outputLabel for="renewKeys" value="#{web.text.ACTIVATE}" />
	</h:panelGroup>
