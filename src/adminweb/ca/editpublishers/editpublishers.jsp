<html>
<%@page contentType="text/html"%>
<%@page errorPage="/errorpage.jsp" import="java.util.*, se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean,se.anatom.ejbca.ra.raadmin.GlobalConfiguration, se.anatom.ejbca.SecConst, 
              se.anatom.ejbca.authorization.AuthorizationDeniedException, se.anatom.ejbca.authorization.AvailableAccessRules,
               se.anatom.ejbca.webdist.cainterface.CAInterfaceBean, se.anatom.ejbca.ca.publisher.*, se.anatom.ejbca.webdist.cainterface.EditPublisherJSPHelper, 
               se.anatom.ejbca.ca.exception.PublisherExistsException, se.anatom.ejbca.ra.raadmin.DNFieldExtractor"%>

<jsp:useBean id="ejbcawebbean" scope="session" class="se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean" />
<jsp:useBean id="cabean" scope="session" class="se.anatom.ejbca.webdist.cainterface.CAInterfaceBean" />
<jsp:useBean id="publisherhelper" scope="session" class="se.anatom.ejbca.webdist.cainterface.EditPublisherJSPHelper" />

<% 

  // Initialize environment
  String includefile = "publisherspage.jsp"; 


  GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, AvailableAccessRules.ROLE_SUPERADMINISTRATOR); 
                                            cabean.initialize(request, ejbcawebbean); 
                                            publisherhelper.initialize(request,ejbcawebbean, cabean);
  String THIS_FILENAME            =  globalconfiguration.getCaPath()  + "/editpublishers/editpublishers.jsp";
  
%>
 
<head>
  <title><%= globalconfiguration .getEjbcaTitle() %></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>">
  <link rel=STYLESHEET href="<%= ejbcawebbean.getCssFile() %>">
  <script language=javascript src="<%= globalconfiguration .getAdminWebPath() %>ejbcajslib.js"></script>
</head>
<body>

<%  // Determine action 

  includefile = publisherhelper.parseRequest(request);

 // Include page
  if( includefile.equals("publisherpage.jsp")){ 
%>
   <%@ include file="publisherpage.jsp" %>
<%}
  if( includefile.equals("publisherspage.jsp")){ %>
   <%@ include file="publisherspage.jsp" %> 
<%} 

   // Include Footer 
   String footurl =   globalconfiguration.getFootBanner(); %>
   
  <jsp:include page="<%= footurl %>" />

</body>
</html>
