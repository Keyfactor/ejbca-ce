<%@ page language="Java" import="javax.naming.*,javax.rmi.*,java.util.*,java.net.*,java.security.cert.*,java.math.BigInteger,se.anatom.ejbca.ca.store.*,se.anatom.ejbca.util.Hex"%>
<html>
<head><title>EJBCA - List certificates</title></head>
<body>

<h1>Certificates for <%=request.getParameter("subject")%></h1>
<hr>
<%
try  {
    String dn=request.getParameter("subject");
    if (dn == null) {
        out.println("Usage: listcerts.jsp?subject=<DN>");
    } else {
        InitialContext ctx = new InitialContext();
        ICertificateStoreSessionHome home = (ICertificateStoreSessionHome) PortableRemoteObject.narrow(
        ctx.lookup("CertificateStoreSession"), ICertificateStoreSessionHome.class );
        ICertificateStoreSession store = home.create();
        Certificate[] certs = store.findCertificatesBySubject(dn);
        for (int i=0;i<certs.length;i++) {
            Date notBefore = ((X509Certificate)certs[i]).getNotBefore();
            Date notAfter = ((X509Certificate)certs[i]).getNotAfter();
            String subject = ((X509Certificate)certs[i]).getSubjectDN().toString();
            String issuer = ((X509Certificate)certs[i]).getIssuerDN().toString();
            BigInteger serno = ((X509Certificate)certs[i]).getSerialNumber();
            out.println("<pre>Subject:"+subject);
            out.println("Issuer:"+issuer);
            out.println("NotBefore:"+notBefore.toString());
            out.println("NotAfter:"+notAfter.toString());
            out.println("Serial number:"+Hex.encode(serno.toByteArray()));
            out.println("</pre>");
            out.println("<a href=\"revoked.jsp?issuer="+URLEncoder.encode(issuer)+"&serno="+Hex.encode(serno.toByteArray())+"\">Check if certificate is revoked</a>");
            out.println("<hr>");
        }
        if (certs.length == 0) {
            out.println("No certificates exists for '"+dn+"'.");
        }
    }
} catch(Exception ex) {
    ex.printStackTrace();
}                                             
%>

</body>
</html>
