<%@ taglib uri="http://java.sun.com/jsf/html" prefix="h" %>
<%@ taglib uri="http://java.sun.com/jsf/core" prefix="f" %>
<%@ taglib uri="http://myfaces.apache.org/tomahawk" prefix="t" %>


	<h:panelGroup>
		<h:outputText value="#{web.text.PUBLISHERQUEUESETTINGS}"/>
	</h:panelGroup>
	<h:panelGroup>
		<f:verbatim>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</f:verbatim>
	</h:panelGroup>
	<h:panelGroup>
		<h:outputText value="#{web.text.PUBLISHERSTOCHECK}"/>
	</h:panelGroup>
	<h:panelGroup>							
		<h:selectManyListbox id="checkPublisherIds" value="#{editService.publishWorkerType.selectedPublisherIdsToCheck}" size="10">
			<f:selectItems value="#{editService.availablePublishers}"/>
		</h:selectManyListbox>		
	</h:panelGroup>	
