<%@page contentType="text/html"%>
<%@page errorPage="../errorpage.jsp" import="se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean,se.anatom.ejbca.ra.GlobalConfiguration"%>
<jsp:useBean id="ejbcawebbean" scope="session" class="se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean" />
<jsp:setProperty name="ejbcawebbean" property="*" /> 
<%   // Initialize environment
  GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request); 
%>
 <br>
 <br>
<div align="center" id="footer"><i><%=ejbcawebbean.getText("MADEBYPRIMEKEY") %></i></div>

