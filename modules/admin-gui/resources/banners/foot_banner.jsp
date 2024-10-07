<%@ page pageEncoding="ISO-8859-1"%>
<% response.setContentType("text/html; charset="+org.ejbca.config.WebConfiguration.getWebContentEncoding()); %>
<%@page errorPage="../errorpage.jsp" import="org.ejbca.config.GlobalConfiguration, org.ejbca.ui.web.jsf.configuration.EjbcaWebBean"%>
<jsp:useBean id="ejbcawebbean" scope="session" type="org.ejbca.ui.web.jsf.configuration.EjbcaWebBean" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBeanImpl" />
<jsp:setProperty name="ejbcawebbean" property="*" /> 
<%	// Initialize environment
    GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request);
%>

<div id="footer">
	<span><%=ejbcawebbean.getText("MADEBYPRIMEKEY") %></span>
</div>
