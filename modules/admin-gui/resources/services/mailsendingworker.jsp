<%@ taglib uri="http://java.sun.com/jsf/html" prefix="h" %>
<%@ taglib uri="http://java.sun.com/jsf/core" prefix="f" %>

	<h:panelGroup>
		<f:verbatim><strong></f:verbatim><h:outputText value="#{web.text.SENDNOTIFICATIONTOENDUSER}"/><f:verbatim></strong></f:verbatim>
	</h:panelGroup>
	<h:panelGroup>				
		<h:selectBooleanCheckbox id="certCheckSendUserNotification" value="#{editService.notifyingType.useEndUserNotifications}"
		                         onchange="checkUseEndUserNotification()" disabled="#{not editService.hasEditRights}"/>
		<h:outputLabel for="certCheckSendUserNotification" value="#{web.text.USE}" />
		<f:verbatim>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</f:verbatim>
		<h:outputText styleClass="help" value="#{web.text.SENDNOTIFICATIONTOENDUSER_HELP}"/>
	</h:panelGroup>	

	<h:panelGroup>
		<h:outputText value="#{web.text.ENDUSERSUBJECT}"/>
	</h:panelGroup>
	<h:panelGroup>				
		<h:inputText id="certCheckEndUserSubjectTextField" value="#{editService.notifyingType.endUserSubject}" size="45" title="#{web.text.FORMAT_STRING}" 
			disabled="#{not editService.hasEditRights}"/>
	</h:panelGroup>	

	<h:panelGroup>
		<h:outputText value="#{web.text.ENDUSERMESSAGE}"/>
	</h:panelGroup>
	<h:panelGroup>				
		<h:inputTextarea id="certCheckEndUserMessageTextArea" value="#{editService.notifyingType.endUserMessage}" rows="8" cols="45"
			disabled="#{not editService.hasEditRights}" />
		<f:verbatim><p class="help"></f:verbatim>
		<h:outputText value="#{web.text.ENDUSERMESSAGE_HELP}"/>
		<f:verbatim></p></f:verbatim>
	</h:panelGroup>

	<h:panelGroup>
		<f:verbatim><strong></f:verbatim><h:outputText value="#{web.text.SENDNOTIFICATIONTOADMIN}"/><f:verbatim></strong></f:verbatim>
	</h:panelGroup>
	<h:panelGroup>				
		<h:selectBooleanCheckbox id="certCheckSendAdminNotification" value="#{editService.notifyingType.useAdminNotifications}"
		                         onchange="checkUseAdminNotification()" disabled="#{not editService.hasEditRights}"/>
		<h:outputLabel for="certCheckSendAdminNotification" value="#{web.text.USE}" />
		<f:verbatim>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</f:verbatim>
		<h:outputText styleClass="help" value="#{web.text.SENDNOTIFICATIONTOADMIN_HELP}"/>
	</h:panelGroup>	

	<h:panelGroup>
		<h:outputText value="#{web.text.ADMINSUBJECT}"/>
	</h:panelGroup>
	<h:panelGroup>
		<h:inputText id="certCheckAdminSubjectTextField" value="#{editService.notifyingType.adminSubject}" size="45" title="#{web.text.FORMAT_STRING}" 
			disabled="#{not editService.hasEditRights}"/>
	</h:panelGroup>	

	<h:panelGroup>
		<h:outputText value="#{web.text.ADMINMESSAGE}"/>
	</h:panelGroup>
	<h:panelGroup>				
		<h:inputTextarea id="certCheckAdminMessageTextArea" value="#{editService.notifyingType.adminMessage}" rows="8" cols="45" 
			disabled="#{not editService.hasEditRights}"/>
		<f:verbatim><p class="help"></f:verbatim>
	    <h:outputText value="#{web.text.ADMINMESSAGE_HELP}"/>
		<f:verbatim></p></f:verbatim>
		<f:verbatim rendered="#{editService.hasEditRights}">
<script type="text/javascript">
<!--  
checkUseAdminNotification();
checkUseEndUserNotification();
-->
</script></f:verbatim>
	</h:panelGroup>

