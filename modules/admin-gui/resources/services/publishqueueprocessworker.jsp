<%@ taglib uri="http://java.sun.com/jsf/html" prefix="h" %>
<%@ taglib uri="http://java.sun.com/jsf/core" prefix="f" %>

	<h:panelGroup>
		<f:verbatim><strong></f:verbatim><h:outputText value="#{web.text.PUBLISHERQUEUESETTINGS}"/><f:verbatim></strong></f:verbatim>
	</h:panelGroup>
	<h:panelGroup>
		<f:verbatim>&nbsp;</f:verbatim>
	</h:panelGroup>

	<h:panelGroup>
		<h:outputText value="#{web.text.PUBLISHERSTOCHECK}"/>
	</h:panelGroup>
	<h:panelGroup>							
		<h:selectManyListbox id="checkPublisherIds" value="#{editService.publishWorkerType.selectedPublisherIdsToCheck}" size="10" disabled="#{not editService.hasEditRights}">
			<f:selectItems value="#{editService.availablePublishers}"/>
		</h:selectManyListbox>		
	</h:panelGroup>	

