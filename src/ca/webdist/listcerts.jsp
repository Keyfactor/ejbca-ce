<%@ page language="Java" import="javax.naming.*,javax.rmi.*,java.util.*,java.net.*,java.security.cert.*,java.math.BigInteger,se.anatom.ejbca.ca.store.*,se.anatom.ejbca.util.Hex"%>
<html>
<head><title>EJBCA - List certificates</title>
<link rel="stylesheet" href="../indexmall.css" type="text/css">
</head>
<body>
<div align="center"><span class="titel">Certificates for</span> <%=request.getParameter("subject")%> 
  <%
try  {
    String dn=request.getParameter("subject");
    if (dn == null) {
%>
  <p>Usage: listcerts.jsp?subject=<DN> 
  <%
    } else {
        InitialContext ctx = new InitialContext();
        ICertificateStoreSessionHome home = (ICertificateStoreSessionHome) PortableRemoteObject.narrow(
        ctx.lookup("CertificateStoreSession"), ICertificateStoreSessionHome.class );
        ICertificateStoreSessionRemote store = home.create();
        Collection certs = store.findCertificatesBySubject(dn);
        Iterator i = certs.iterator();
        while (i.hasNext()) {
            X509Certificate x509cert = (X509Certificate)i.next();
            Date notBefore = x509cert.getNotBefore();
            Date notAfter = x509cert.getNotAfter();
            String subject = x509cert.getSubjectDN().toString();
            String issuer = x509cert.getIssuerDN().toString();
            BigInteger serno = x509cert.getSerialNumber();
            String hexSerno = Hex.encode(serno.toByteArray());
            String urlEncIssuer = URLEncoder.encode(issuer);
%>
  <pre>Subject: <%=subject%>
Issuer: <%=issuer%>
NotBefore: <%=notBefore.toString()%>
NotAfter: <%=notAfter.toString()%>
Serial number: <%=hexSerno%>
</pre>
  <a href="revoked.jsp?issuer=<%=urlEncIssuer%>&serno=<%=hexSerno%>">Check if 
  certificate is revoked</a> 
  <%
        }
        if (certs.isEmpty()) {
%>
  <p>No certificates exists for '<%=dn%>'. 
  <%
        }
    }
} catch(Exception ex) {
    ex.printStackTrace();
}                                             
%>
</div>
</body>
</html>
