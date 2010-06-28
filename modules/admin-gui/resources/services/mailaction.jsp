<%@ taglib uri="http://java.sun.com/jsf/html" prefix="h" %>
<%@ taglib uri="http://java.sun.com/jsf/core" prefix="f" %>
<%@ taglib uri="http://myfaces.apache.org/tomahawk" prefix="t" %>


	<h:panelGroup>
		<h:outputText value="#{web.text.MAILACTIONSETTINGS}"/>
	</h:panelGroup>
	<h:panelGroup>	
	     <f:verbatim>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</f:verbatim>	
	</h:panelGroup>
	<h:panelGroup>
		<h:outputText value="#{web.text.MAILACTIONSENDERADDRESS}"/>
	</h:panelGroup>
	<h:panelGroup>
			<h:inputText id="mailActionSenderAddressTextField" value="#{editService.mailActionType.senderAddress}" size="40"/>		
	</h:panelGroup>
	<h:panelGroup>
		<h:outputText value="#{web.text.MAILACTIONRECIEVERADDRESS}"/>
	</h:panelGroup>
	<h:panelGroup>
			<h:inputText id="mailActionRecieverAddressTextField" value="#{editService.mailActionType.recieverAddress}" size="40"/>
	</h:panelGroup>


