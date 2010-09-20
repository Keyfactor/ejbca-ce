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
		<f:verbatim><strong></f:verbatim><h:outputText value="#{web.text.USEREXPIRATIONSETTINGS}"/><f:verbatim></strong></f:verbatim>
	</h:panelGroup>
	<h:panelGroup>
		<f:verbatim>&nbsp;</f:verbatim>
	</h:panelGroup>

	<h:panelGroup>
		<h:outputText value="#{web.text.CASTOCHECK}"/>
	</h:panelGroup>
	<h:panelGroup>							
		<h:selectManyListbox id="certCheckCASelect" value="#{editService.notifyingType.selectedCANamesToCheck}" size="10">
			<f:selectItems value="#{editService.availableCAs}"/>
		</h:selectManyListbox>		
	</h:panelGroup>	

	<h:panelGroup>
		<h:outputText value="#{web.text.TIMEUNTILUSEREXPIRE}"/>
	</h:panelGroup>
	<h:panelGroup>				
		<h:inputText id="certCheckTimeValueTextField" value="#{editService.notifyingType.timeValue}" size="5"/><f:verbatim> </f:verbatim>
		<h:selectOneMenu id="certCheckTimeUnitSelect" value="#{editService.notifyingType.timeUnit}">
		  <f:selectItems value="#{editService.notifyingType.availableUnits}"/>
	    </h:selectOneMenu>		
	</h:panelGroup>	
	
	<jsp:include page="mailsendingworker.jsp"/>

