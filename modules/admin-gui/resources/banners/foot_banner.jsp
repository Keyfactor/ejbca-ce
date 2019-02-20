<%@ page pageEncoding="ISO-8859-1"%>
<% response.setContentType("text/html; charset="+org.ejbca.config.WebConfiguration.getWebContentEncoding()); %>
<%@page errorPage="../errorpage.jsp" import="org.ejbca.config.GlobalConfiguration, org.ejbca.ui.web.jsf.configuration.EjbcaWebBean"%>
<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.jsf.configuration.EjbcaWebBean" />
<jsp:setProperty name="ejbcawebbean" property="*" /> 
<%	// Initialize environment
    GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request);
%>

<div id="footer">
	<span><%=ejbcawebbean.getText("MADEBYPRIMEKEY") %></span>
</div>
