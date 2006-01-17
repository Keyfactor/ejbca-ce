<%@ page pageEncoding="ISO-8859-1"%>
<%@page  errorPage="error.jsp" import="org.ejbca.util.CertTools, java.security.cert.*" %>
<html>
<%   // Initialize environment
    X509Certificate[] certificates =   (X509Certificate[]) request.getAttribute( "javax.servlet.request.X509Certificate" );
    if(certificates == null) throw new ServletException("Client certificate required.");
    X509Certificate mycert = certificates[0];
    String subject = CertTools.getPartFromDN(mycert.getSubjectDN().toString(), "CN");
%>
<head>
  <title>Demo WEB</title>
</head>
<body>
<H3>Welcome <%= subject%></H3> 

<br><br>
<p>Blah blah</p>

</body>
</html>
