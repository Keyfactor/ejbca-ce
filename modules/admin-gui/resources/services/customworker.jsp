<%@ taglib uri="http://java.sun.com/jsf/html" prefix="h" %>
<%@ taglib uri="http://java.sun.com/jsf/core" prefix="f" %>
<%@ taglib uri="http://myfaces.apache.org/tomahawk" prefix="t" %>


	<h:panelGroup>
		<f:verbatim><strong></f:verbatim><h:outputText value="#{web.text.CUSTOMWORKERSETTINGS}"/><f:verbatim></strong></f:verbatim>
	</h:panelGroup>
	<h:panelGroup>
		<f:verbatim>&nbsp;</f:verbatim>
	</h:panelGroup>

	<h:panelGroup>
		<h:outputText value="#{web.text.CUSTOMWORKERCLASSPATH}"/>
	</h:panelGroup>
	<h:panelGroup>
		<h:inputText id="workerClassPathTextField" value="#{editService.customWorkerType.classPath}" size="45"/>
	</h:panelGroup>

	<h:panelGroup>
		<h:outputText value="#{web.text.CUSTOMWORKERPROPERTIES}"/>
	</h:panelGroup>
	<h:panelGroup>
		<h:inputTextarea id="workerPropsTextArea" value="#{editService.customWorkerType.propertyText}" rows="8" cols="45"/>
	</h:panelGroup>

