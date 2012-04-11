<%@ taglib uri="http://java.sun.com/jsf/html" prefix="h" %>
<%@ taglib uri="http://java.sun.com/jsf/core" prefix="f" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<% response.setContentType("text/html; charset="+org.ejbca.config.WebConfiguration.getWebContentEncoding()); %>
<%@page pageEncoding="ISO-8859-1" errorPage="/errorpage.jsp"%>
<%@page import="org.ejbca.config.GlobalConfiguration"%>
<%@page import="org.ejbca.core.model.authorization.AccessRulesConstants"%>
<%@page import="org.ejbca.ui.web.RequestHelper"%>
<%@page import="org.ejbca.ui.web.admin.configuration.EjbcaJSFHelper"%>
<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />
<jsp:setProperty name="ejbcawebbean" property="*" /> 
<%   // Initialize environment
 GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, AccessRulesConstants.ROLE_ADMINISTRATOR, AccessRulesConstants.ROLE_SUPERADMINISTRATOR); 
 EjbcaJSFHelper helpbean = EjbcaJSFHelper.getBean();
 helpbean.setEjbcaWebBean(ejbcawebbean);
%>
<html>
<head>
  <title><c:out value="<%= globalconfiguration.getEjbcaTitle() %>" /></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>" />
  <link rel="stylesheet" type="text/css" href="<%= ejbcawebbean.getCssFile() %>" />
  <meta http-equiv="Content-Type" content="text/html; charset=<%= org.ejbca.config.WebConfiguration.getWebContentEncoding() %>" />
</head>


<f:view>
<body>

<h1><h:outputText value="#{web.text.EDITSERVICES}"/></h1>

<p>
	<h:messages styleClass="alert" layout="table"/>
	</p>

<h3><h:outputText value="#{web.text.CURRENTSERVICES}"/></h3>

	<h:form>
		<h:selectOneListbox id="listServices" value="#{listServicesManagedBean.selectedServiceName}" style="width: 50em" size="15">
			<f:selectItems value="#{listServicesManagedBean.availableServices}"/>
		</h:selectOneListbox>
		<p>
	    <h:commandButton id="editButton" action="#{listServicesManagedBean.editService}" value="#{web.text.EDITSERVICE}"/>
	    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
	    <h:commandButton id="deleteButton" action="#{listServicesManagedBean.deleteService}" value="#{web.text.DELETESERVICE}" onclick="return confirm('#{web.text.AREYOUSURE}');"/>
		</p>
		<h3><h:outputText value="#{web.text.ADDSERVICE}"/></h3>
		<h:inputText id="newServiceName" value="#{listServicesManagedBean.newServiceName}" size="40"/>
		<h:commandButton id="addButton" action="#{listServicesManagedBean.addService}" value="#{web.text.ADD}"/>
		<br/>
		<h:commandButton id="renameButton" action="#{listServicesManagedBean.renameService}" value="#{web.text.RENAMESELECTED}"/>&nbsp;&nbsp;&nbsp;&nbsp;
		<h:commandButton id="cloneButton" action="#{listServicesManagedBean.cloneService}" value="#{web.text.USESELECTEDASTEMPLATE}"/>
		<br/>
		<p></p>
	</h:form>

	<%	// Include Footer 
	String footurl = globalconfiguration.getFootBanner(); %>
   
	<jsp:include page="<%= footurl %>" />

</body>
</f:view>
</html>
