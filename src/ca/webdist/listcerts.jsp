<%@ page language="Java" import="javax.naming.*,javax.rmi.*,java.util.*,java.net.*,java.security.cert.*,java.math.BigInteger,se.anatom.ejbca.ca.store.*,se.anatom.ejbca.util.Hex"%>
<html>
<head><title>EJBCA - List certificates</title></head>
<body>

<h2>Certificates for <%=request.getParameter("subject")%></h2>
<hr>
<%
try  {
    String dn=request.getParameter("subject");
    if (dn == null) {
%>
Usage: listcerts.jsp?subject=<DN>
<%
    } else {
        InitialContext ctx = new InitialContext();
        ICertificateStoreSessionHome home = (ICertificateStoreSessionHome) PortableRemoteObject.narrow(
        ctx.lookup("CertificateStoreSession"), ICertificateStoreSessionHome.class );
        ICertificateStoreSessionRemote store = home.create();
        Certificate[] certs = store.findCertificatesBySubject(dn);
        for (int i=0;i<certs.length;i++) {
            Date notBefore = ((X509Certificate)certs[i]).getNotBefore();
            Date notAfter = ((X509Certificate)certs[i]).getNotAfter();
            String subject = ((X509Certificate)certs[i]).getSubjectDN().toString();
            String issuer = ((X509Certificate)certs[i]).getIssuerDN().toString();
            BigInteger serno = ((X509Certificate)certs[i]).getSerialNumber();
            String hexSerno = Hex.encode(serno.toByteArray());
            String urlEncIssuer = URLEncoder.encode(issuer);
%>            
<pre>Subject: <%=subject%>
Issuer: <%=issuer%>
NotBefore: <%=notBefore.toString()%>
NotAfter: <%=notAfter.toString()%>
Serial number: <%=hexSerno%>
</pre>
<a href="revoked.jsp?issuer=<%=urlEncIssuer%>&serno=<%=hexSerno%>">Check if certificate is revoked</a>
<hr>
<%
        }
        if (certs.length == 0) {
%>
No certificates exists for '<%=dn%>'.
<%
        }
    }
} catch(Exception ex) {
    ex.printStackTrace();
}                                             
%>

</body>
</html>
