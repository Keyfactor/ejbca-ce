<%@ taglib uri="http://java.sun.com/jsf/html" prefix="h" %>
<%@ taglib uri="http://java.sun.com/jsf/core" prefix="f" %>
<%@ taglib uri="http://myfaces.apache.org/tomahawk" prefix="t" %>


	<h:panelGroup>
	<f:verbatim>
<SCRIPT language="JavaScript">
<!--  

function checkUseAdminNotification(){
  if(document.getElementById('edit:certCheckSendAdminNotification').checked){
    document.getElementById('edit:certCheckAdminSubjectTextField').disabled = false;
    document.getElementById('edit:certCheckAdminMessageTextArea').disabled = false;
  }
  else{
    document.getElementById('edit:certCheckAdminSubjectTextField').disabled = true;
    document.getElementById('edit:certCheckAdminMessageTextArea').disabled = true;
    document.getElementById('edit:certCheckAdminSubjectTextField').value = "";   
    document.getElementById('edit:certCheckAdminMessageTextArea').value = "";
  }

} 

function checkUseEndUserNotification(){
  if(document.getElementById('edit:certCheckSendUserNotification').checked){
    document.getElementById('edit:certCheckEndUserSubjectTextField').disabled = false;
    document.getElementById('edit:certCheckEndUserMessageTextArea').disabled = false;
  }
  else{
    document.getElementById('edit:certCheckEndUserSubjectTextField').disabled = true;
    document.getElementById('edit:certCheckEndUserMessageTextArea').disabled = true;
    document.getElementById('edit:certCheckEndUserSubjectTextField').value = "";   
    document.getElementById('edit:certCheckEndUserMessageTextArea').value = "";
  }

} 

-->
</SCRIPT></f:verbatim>
		<h:outputText value="#{web.text.CERTEXPIRATIONSETTINGS}"/>
	</h:panelGroup>
	<h:panelGroup>
		<f:verbatim>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</f:verbatim>
	</h:panelGroup>
	<h:panelGroup>
		<h:outputText value="#{web.text.CASTOCHECK}"/>
	</h:panelGroup>
	<h:panelGroup>							
			<h:selectManyListbox id="certCheckCASelect" value="#{editService.certificateExpriationType.selectedCANamesToCheck}" size="10">
			<f:selectItems value="#{editService.availableCAs}"/>
		</h:selectManyListbox>		
	</h:panelGroup>	
	<h:panelGroup>
		<h:outputText value="#{web.text.TIMEBEFOREEXPIRATION}"/>
	</h:panelGroup>
	<h:panelGroup>				
			<h:inputText id="certCheckTimeValueTextField" value="#{editService.certificateExpriationType.timeValue}" size="6"/>
			<h:selectOneMenu id="certCheckTimeUnitSelect" value="#{editService.certificateExpriationType.timeUnit}">
			  <f:selectItems value="#{editService.certificateExpriationType.availableUnits}"/>
		    </h:selectOneMenu>		
	</h:panelGroup>	
	<h:panelGroup>
		<h:outputText value="#{web.text.SENDNOTIFICATIONTOENDUSER1}"/><f:verbatim><br/></f:verbatim>
		<h:outputText value="#{web.text.SENDNOTIFICATIONTOENDUSER2}"/>
	</h:panelGroup>
	<h:panelGroup>				
			<h:selectBooleanCheckbox id="certCheckSendUserNotification" value="#{editService.certificateExpriationType.useEndUserNotifications}"
			                         onchange="checkUseEndUserNotification()"/>
	</h:panelGroup>	
	<h:panelGroup>
		<h:outputText value="#{web.text.ENDUSERSUBJECT}"/>
	</h:panelGroup>
	<h:panelGroup>				
		<h:inputText id="certCheckEndUserSubjectTextField" value="#{editService.certificateExpriationType.endUserSubject}" size="40" disabled="#{!editService.certificateExpriationType.useEndUserNotifications}"/>
	</h:panelGroup>	
	<h:panelGroup>
		<h:outputText value="#{web.text.ENDUSERMESSAGE1}"/><f:verbatim><br/></f:verbatim>
		<h:outputText value="#{web.text.ENDUSERMESSAGE2}"/><f:verbatim><br/></f:verbatim>
		<h:outputText value="#{web.text.ENDUSERMESSAGE3}"/><f:verbatim><br/></f:verbatim>
	</h:panelGroup>
	<h:panelGroup>				
		<h:inputTextarea id="certCheckEndUserMessageTextArea" value="#{editService.certificateExpriationType.endUserMessage}" rows="6" cols="40" disabled="#{!editService.certificateExpriationType.useEndUserNotifications}"/>
	</h:panelGroup>
		<h:panelGroup>
		<h:outputText value="#{web.text.SENDNOTIFICATIONTOADMIN1}"/><f:verbatim><br/></f:verbatim>
		<h:outputText value="#{web.text.SENDNOTIFICATIONTOADMIN2}"/>
	</h:panelGroup>
	<h:panelGroup>				
			<h:selectBooleanCheckbox id="certCheckSendAdminNotification" value="#{editService.certificateExpriationType.useAdminNotifications}"
			                         onchange="checkUseAdminNotification()"/>
	</h:panelGroup>	
	<h:panelGroup>
		<h:outputText value="#{web.text.ADMINSUBJECT}"/>
	</h:panelGroup>
	<h:panelGroup>				
		<h:inputText id="certCheckAdminSubjectTextField" value="#{editService.certificateExpriationType.adminSubject}" size="40" disabled="#{!editService.certificateExpriationType.useAdminNotifications}"/>
	</h:panelGroup>	
	<h:panelGroup>
		<h:outputText value="#{web.text.ADMINMESSAGE1}"/><f:verbatim><br/></f:verbatim>
	    <h:outputText value="#{web.text.ADMINMESSAGE2}"/><f:verbatim><br/></f:verbatim>
	    <h:outputText value="#{web.text.ADMINMESSAGE3}"/>
	</h:panelGroup>
	<h:panelGroup>				
		<h:inputTextarea id="certCheckAdminMessageTextArea" value="#{editService.certificateExpriationType.adminMessage}" rows="6" cols="40" disabled="#{!editService.certificateExpriationType.useAdminNotifications}"/>
	</h:panelGroup>



