<%@ taglib uri="http://java.sun.com/jsf/html" prefix="h" %>
<%@ taglib uri="http://java.sun.com/jsf/core" prefix="f" %>
<%@ taglib uri="http://myfaces.apache.org/tomahawk" prefix="t" %>


	<h:panelGroup>
		<h:outputText value="#{web.text.CUSTOMACTIONSETTINGS}"/>
	</h:panelGroup>
	<h:panelGroup>	
	     <f:verbatim>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</f:verbatim>	
	</h:panelGroup>
	<h:panelGroup>
		<h:outputText value="#{web.text.CUSTOMACTIONCLASSPATH}"/>
	</h:panelGroup>
	<h:panelGroup>
			<h:inputText id="actionClassPathTextField" value="#{editService.customActionType.classPath}" size="40"/>		
	</h:panelGroup>
	<h:panelGroup>
		<h:outputText value="#{web.text.CUSTOMACTIONPROPERTIES}"/>
	</h:panelGroup>
	<h:panelGroup>
		<h:inputTextarea id="actionPropsTextArea" value="#{editService.customActionType.propertyText}" rows="6" cols="40"/>
	</h:panelGroup>

