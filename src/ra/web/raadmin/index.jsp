<html>
<%@page contentType="text/html"%>
<%@page errorPage="errorpage.jsp"  import="se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean,se.anatom.ejbca.webdist.webconfiguration.GlobalConfiguration, se.anatom.ejbca.webdist.webconfiguration.WebLanguages"%>
<jsp:useBean id="ejbcawebbean" scope="session" class="se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean" />
<jsp:setProperty name="ejbcawebbean" property="*" /> 
<%   // Initialize environment
  GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request); 
%>
<head>
  <title><%= globalconfiguration.getEjbcaTitle() %></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>">

  <link rel=STYLESHEET href="<%= ejbcawebbean.getCssFile() %>">
  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">
</head>

<frameset rows="131,*" cols="*" frameborder="NO" border="0" framespacing="0"> 
  <frame name="<%= globalconfiguration.HEADERFRAME %>" scrolling="NO" noresize src="<%= globalconfiguration.getHeadBanner() %>" >
  <frameset cols="217,*" frameborder="NO" border="0" framespacing="0" rows="*"> 
    <frame name="<%= globalconfiguration.MENUFRAME %>" noresize scrolling="NO" src="<%= globalconfiguration.getRaAdminPath() +
                                                                                        globalconfiguration.getMenuFilename() %>">
    <frame name="<%= globalconfiguration.MAINFRAME %>" src="<%= globalconfiguration.getRaAdminPath() + globalconfiguration.getMainFilename() %>">
  </frameset>
</frameset>
<noframes>
<body">
  <h1><%= ejbcawebbean.getText("ERRORNOBROWSER") %></h1>
</body>
</noframes>
</html>
