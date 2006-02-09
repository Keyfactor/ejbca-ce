<%@ page pageEncoding="ISO-8859-1"%>
<%@ page contentType="text/html; charset=@page.encoding@" %>
<%@page errorPage="../errorpage.jsp" import="org.ejbca.core.model.ra.raadmin.GlobalConfiguration"%>
<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />
<jsp:setProperty name="ejbcawebbean" property="*" /> 
<%   // Initialize environment
  GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, "/administrator"); 
%>
 <br>
 <br>
<div align="center" id="footer"><i><%=ejbcawebbean.getText("MADEBYPRIMEKEY") %></i></div>

