<%@ page language="Java" import="javax.naming.*,javax.rmi.*,java.util.*,java.security.cert.*,java.math.BigInteger,se.anatom.ejbca.ca.store.*,se.anatom.ejbca.ca.crl.RevokedCertInfo"%>
<html>
<head><title>EJBCA - Check revocation</title></head>
<body>

<h1>Check certificate with issuer '<%=request.getParameter("issuer")%>' and serial number '<%=request.getParameter("serno")%>'.</h1>
<hr>
<%
try  {
    String dn=request.getParameter("issuer");
    String serno=request.getParameter("serno");
    if ((dn == null) || (serno == null)) {
        out.println("Usage: revoked.jsp?issuer=<DN>&serno=<serial number>");
    } else {
        InitialContext ctx = new InitialContext();
        ICertificateStoreSessionHome home = (ICertificateStoreSessionHome) PortableRemoteObject.narrow(
        ctx.lookup("CertificateStoreSession"), ICertificateStoreSessionHome.class );
        ICertificateStoreSession store = home.create();
        RevokedCertInfo revinfo = store.isRevoked(dn, new BigInteger(serno));
        if (revinfo != null) {
            out.println("<b>REVOKED</b><br>");
            out.println("RevocationDate is '"+revinfo.getRevocationDate()+"' and reason '"+revinfo.getReason()+"'.");
        } else {
            out.println("<b>NOT REVOKED</b>");
        }
    }
} catch(Exception ex) {
    ex.printStackTrace();
}                                             
%>

</body>
</html>
