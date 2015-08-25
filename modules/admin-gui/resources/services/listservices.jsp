<%@ taglib uri="http://java.sun.com/jsf/html" prefix="h" %>
<%@ taglib uri="http://java.sun.com/jsf/core" prefix="f" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<% response.setContentType("text/html; charset="+org.ejbca.config.WebConfiguration.getWebContentEncoding()); %>
<%@page pageEncoding="ISO-8859-1" errorPage="/errorpage.jsp"%>
<%@page import="org.ejbca.config.GlobalConfiguration"%>
<%@page import="org.ejbca.core.model.authorization.AccessRulesConstants"%>
<%@page import="org.ejbca.ui.web.RequestHelper"%>
<%@page import="org.ejbca.ui.web.admin.configuration.EjbcaJSFHelper"%>
<%@page import="org.cesecore.authorization.control.StandardRules"%>
<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />
<jsp:setProperty name="ejbcawebbean" property="*" /> 
<%   // Initialize environment
 GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, AccessRulesConstants.ROLE_ADMINISTRATOR, AccessRulesConstants.SERVICES_VIEW); 
 EjbcaJSFHelper helpbean = EjbcaJSFHelper.getBean();
 helpbean.setEjbcaWebBean(ejbcawebbean);
%>
<html>
<head>
  <title><c:out value="<%= globalconfiguration.getEjbcaTitle() %>" /></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>" />
  <link rel="stylesheet" type="text/css" href="<c:out value='<%=ejbcawebbean.getCssFile() %>' />" />
  <meta http-equiv="Content-Type" content="text/html; charset=<%= org.ejbca.config.WebConfiguration.getWebContentEncoding() %>" />
</head>


<f:view>
<body>

<h1><h:outputText value="#{web.text.MANAGESERVICES}"/></h1>

	<h:form>
	<h:panelGrid styleClass="list" columns="2" columnClasses="listColumn1,listColumn2">
		<h:panelGroup>
			<h:messages styleClass="alert" layout="table" />
			<h3><h:outputText value="#{web.text.LISTOFSERVICES}"/></h3>
		</h:panelGroup>
		<h:panelGroup>
		</h:panelGroup>
	
		<h:panelGroup>
			<h:selectOneListbox id="listServices" value="#{listServicesManagedBean.selectedServiceName}" style="width: 50em" size="15">
				<f:selectItems value="#{listServicesManagedBean.availableServices}"/>
			</h:selectOneListbox>
		</h:panelGroup>
		<h:panelGroup>
		</h:panelGroup>
	
		<h:panelGroup>
	        <table width="100%" border="0" cellspacing="0" cellpadding="0">
	          <tr>
	            <td align="left">
	              <h:commandButton id="editButton" action="#{listServicesManagedBean.editService}" value="#{web.text.EDITSERVICE}" rendered="#{listServicesManagedBean.hasEditRights}" />
	              <h:commandButton id="viewButton" action="#{listServicesManagedBean.editService}" value="#{web.text.VIEWSERVICE}" rendered="#{!listServicesManagedBean.hasEditRights}"/>
	            </td>
	            <td align="center">
	              &nbsp;
	            </td>
	            <td align="right">
	              <h:commandButton id="deleteButton" action="#{listServicesManagedBean.deleteService}" value="#{web.text.DELETESERVICE}" onclick="return confirm('#{web.text.AREYOUSURE}');"
	              	rendered="#{listServicesManagedBean.hasEditRights}"/>
	            </td>
	          </tr>
	        </table> 
		</h:panelGroup>
		<h:panelGroup>
		</h:panelGroup>
	</h:panelGrid>
		
	<h:panelGrid styleClass="actions" width="100%" rendered="#{listServicesManagedBean.hasEditRights}">
		<h:panelGroup>
			<h3><h:outputText value="#{web.text.ADDSERVICE}"/></h3>
		</h:panelGroup>
		<h:panelGroup>
			<h:inputText id="newServiceName" value="#{listServicesManagedBean.newServiceName}" size="40" title="#{web.text.FORMAT_ID_STR}"/><h:outputText value=" "/>
			<h:commandButton id="addButton" action="#{listServicesManagedBean.addService}" value="#{web.text.ADD}"/>&nbsp;&nbsp;
			<h:commandButton id="renameButton" action="#{listServicesManagedBean.renameService}" value="#{web.text.RENAME}"/>&nbsp;&nbsp;&nbsp;
			<h:commandButton id="cloneButton" action="#{listServicesManagedBean.cloneService}" value="#{web.text.USESELECTEDASTEMPLATE}"/>
		</h:panelGroup>
	</h:panelGrid>
	</h:form>

	<%	// Include Footer 
	String footurl = globalconfiguration.getFootBanner(); %>
   
	<jsp:include page="<%= footurl %>" />

</body>
</f:view>
</html>
