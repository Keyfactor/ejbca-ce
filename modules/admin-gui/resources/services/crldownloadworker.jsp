<%@ taglib uri="http://java.sun.com/jsf/html" prefix="h" %>
<%@ taglib uri="http://java.sun.com/jsf/core" prefix="f" %>

	<h:panelGroup>
		<f:verbatim><strong></f:verbatim><h:outputText value="#{web.text.CRLDOWNLOADWORKERSETTINGS}"/><f:verbatim></strong></f:verbatim>
	</h:panelGroup>
	<h:panelGroup>
		<f:verbatim>&nbsp;</f:verbatim>
	</h:panelGroup>

	<h:panelGroup>
		<h:outputText value="#{web.text.CASTOCHECK}"/>
	</h:panelGroup>
	<h:panelGroup>
		<h:selectManyListbox id="crlDownloadCASelect" value="#{editService.baseWorkerType.selectedCANamesToCheck}" size="10">
			<f:selectItems value="#{editService.availableExternalX509CAsWithAnyOption}"/>
		</h:selectManyListbox>
	</h:panelGroup>	
	<h:panelGroup>
		<h:outputText value="#{web.text.CRLDOWNLOAD_IGNORENU}"/>
	</h:panelGroup>
	<h:panelGroup>
		<h:selectBooleanCheckbox id="crlDownloadIgnoreNextUpdate" value="#{editService.crlDownloadWorkerType.ignoreNextUpdate}"/>
	</h:panelGroup>	
	<h:panelGroup>
		<h:outputText value="#{web.text.CRLDOWNLOAD_MAXSIZE}"/>
	</h:panelGroup>
	<h:panelGroup>
		<h:inputText id="crlDownloadMaxSize" value="#{editService.crlDownloadWorkerType.maxDownloadSize}"/>
	</h:panelGroup>	
