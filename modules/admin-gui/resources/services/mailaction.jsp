<%@ taglib uri="http://java.sun.com/jsf/html" prefix="h" %>
<%@ taglib uri="http://java.sun.com/jsf/core" prefix="f" %>
<%@ taglib uri="http://myfaces.apache.org/tomahawk" prefix="t" %>


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
			<h:inputText id="mailActionSenderAddressTextField" value="#{editService.mailActionType.senderAddress}" size="45"/>		
	</h:panelGroup>

	<h:panelGroup>
		<h:outputText value="#{web.text.MAILACTIONRECIEVERADDRESS}"/>
	</h:panelGroup>
	<h:panelGroup>
			<h:inputText id="mailActionRecieverAddressTextField" value="#{editService.mailActionType.recieverAddress}" size="45"/>
	</h:panelGroup>

