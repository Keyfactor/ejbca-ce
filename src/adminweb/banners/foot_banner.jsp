<%@ page pageEncoding="ISO-8859-1"%>
<%@page errorPage="../errorpage.jsp" import="se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean,se.anatom.ejbca.ra.raadmin.GlobalConfiguration"%>
<jsp:useBean id="ejbcawebbean" scope="session" class="se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean" />
<jsp:setProperty name="ejbcawebbean" property="*" /> 
<%   // Initialize environment
  GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, "/administrator"); 
%>
 <br>
 <br>
<div align="center" id="footer"><i><%=ejbcawebbean.getText("MADEBYPRIMEKEY") %></i></div>

