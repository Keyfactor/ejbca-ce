<html>
<%@page contentType="text/html"%>
<%@page  errorPage="errorpage.jsp" import="se.anatom.ejbca.util.CertTools, java.security.cert.*" %>
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
