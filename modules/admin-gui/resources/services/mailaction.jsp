<%@ taglib uri="http://java.sun.com/jsf/html" prefix="h" %>
<%@ taglib uri="http://java.sun.com/jsf/core" prefix="f" %>

	<h:panelGroup>
		<f:verbatim><strong></f:verbatim><h:outputText value="#{web.text.MAILACTIONSETTINGS}"/><f:verbatim></strong></f:verbatim>
	</h:panelGroup>
	<h:panelGroup>	
	     <f:verbatim>&nbsp;</f:verbatim>	
	</h:panelGroup>

	<h:panelGroup>
		<h:outputText value="#{web.text.MAILACTIONSENDERADDRESS}"/>
	</h:panelGroup>
	<h:panelGroup>
			<h:inputText id="mailActionSenderAddressTextField" value="#{editService.mailActionType.senderAddress}" size="45" title="#{web.text.FORMAT_EMAILADDRESS}"
				disabled="#{not editService.hasEditRights}"/>	
	</h:panelGroup>

	<h:panelGroup>
		<h:outputText value="#{web.text.MAILACTIONRECIEVERADDRESS}"/>
	</h:panelGroup>
	<h:panelGroup>
			<h:inputText id="mailActionRecieverAddressTextField" value="#{editService.mailActionType.recieverAddress}" size="45" title="#{web.text.FORMAT_EMAILADDRESS}"
				disabled="#{not editService.hasEditRights}"/>
	</h:panelGroup>

