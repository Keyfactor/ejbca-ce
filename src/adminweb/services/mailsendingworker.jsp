<%@ taglib uri="http://java.sun.com/jsf/html" prefix="h" %>
<%@ taglib uri="http://java.sun.com/jsf/core" prefix="f" %>
<%@ taglib uri="http://myfaces.apache.org/tomahawk" prefix="t" %>


	<h:panelGroup>
		<h:outputText value="#{web.text.SENDNOTIFICATIONTOENDUSER1}"/><f:verbatim><br/></f:verbatim>
		<h:outputText value="#{web.text.SENDNOTIFICATIONTOENDUSER2}"/>
	</h:panelGroup>
	<h:panelGroup>				
			<h:selectBooleanCheckbox id="certCheckSendUserNotification" value="#{editService.notifyingType.useEndUserNotifications}"
			                         onchange="checkUseEndUserNotification()"/>
	</h:panelGroup>	
	<h:panelGroup>
		<h:outputText value="#{web.text.ENDUSERSUBJECT}"/>
	</h:panelGroup>
	<h:panelGroup>				
		<h:inputText id="certCheckEndUserSubjectTextField" value="#{editService.notifyingType.endUserSubject}" size="40" />
	</h:panelGroup>	
	<h:panelGroup>
		<h:outputText value="#{web.text.ENDUSERMESSAGE1}"/><f:verbatim><br/></f:verbatim>
		<h:outputText value="#{web.text.ENDUSERMESSAGE2}"/><f:verbatim><br/></f:verbatim>
		<h:outputText value="#{web.text.ENDUSERMESSAGE3}"/><f:verbatim><br/></f:verbatim>
	</h:panelGroup>
	<h:panelGroup>				
		<h:inputTextarea id="certCheckEndUserMessageTextArea" value="#{editService.notifyingType.endUserMessage}" rows="6" cols="40" />
	</h:panelGroup>
		<h:panelGroup>
		<h:outputText value="#{web.text.SENDNOTIFICATIONTOADMIN1}"/><f:verbatim><br/></f:verbatim>
		<h:outputText value="#{web.text.SENDNOTIFICATIONTOADMIN2}"/>
	</h:panelGroup>
	<h:panelGroup>				
			<h:selectBooleanCheckbox id="certCheckSendAdminNotification" value="#{editService.notifyingType.useAdminNotifications}"
			                         onchange="checkUseAdminNotification()"/>
	</h:panelGroup>	
	<h:panelGroup>
		<h:outputText value="#{web.text.ADMINSUBJECT}"/>
	</h:panelGroup>
	<h:panelGroup>				
		<h:inputText id="certCheckAdminSubjectTextField" value="#{editService.notifyingType.adminSubject}" size="40"/>
	</h:panelGroup>	
	<h:panelGroup>
		<h:outputText value="#{web.text.ADMINMESSAGE1}"/><f:verbatim><br/></f:verbatim>
	    <h:outputText value="#{web.text.ADMINMESSAGE2}"/><f:verbatim><br/></f:verbatim>
	    <h:outputText value="#{web.text.ADMINMESSAGE3}"/>
	</h:panelGroup>
	<h:panelGroup>				
		<h:inputTextarea id="certCheckAdminMessageTextArea" value="#{editService.notifyingType.adminMessage}" rows="6" cols="40" />
			<f:verbatim>
<SCRIPT language="JavaScript">
<!--  
checkUseAdminNotification();
checkUseEndUserNotification();
-->
</SCRIPT></f:verbatim>
	</h:panelGroup>
