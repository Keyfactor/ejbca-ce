<%@ taglib uri="http://java.sun.com/jsf/html" prefix="h" %>
<%@ taglib uri="http://java.sun.com/jsf/core" prefix="f" %>
<%@ taglib uri="http://myfaces.apache.org/tomahawk" prefix="t" %>


	<h:panelGroup>
		<f:verbatim><strong></f:verbatim><h:outputText value="#{web.text.CUSTOMINTERVALSETTINGS}"/><f:verbatim></strong></f:verbatim>
	</h:panelGroup>
	<h:panelGroup>
		<f:verbatim>&nbsp;</f:verbatim>
	</h:panelGroup>

	<h:panelGroup>
		<h:outputText value="#{web.text.CUSTOMINTERVALCLASSPATH}"/>
	</h:panelGroup>
	<h:panelGroup>
		<h:inputText id="intervalClassPathTextField" value="#{editService.customIntervalType.classPath}" size="45"/>		
	</h:panelGroup>

	<h:panelGroup>
		<h:outputText value="#{web.text.CUSTOMINTERVALPROPERTIES}"/>
	</h:panelGroup>
	<h:panelGroup>
		<h:inputTextarea id="intervalPropsTextArea" value="#{editService.customIntervalType.propertyText}" rows="6" cols="45"/>
	</h:panelGroup>

