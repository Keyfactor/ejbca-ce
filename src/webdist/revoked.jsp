<%@ page language="Java" import="javax.naming.*,javax.rmi.*,java.util.*,java.security.cert.*,java.math.BigInteger,se.anatom.ejbca.ca.store.*,se.anatom.ejbca.ca.crl.RevokedCertInfo,se.anatom.ejbca.util.Hex"%>
<html>
<head><title>EJBCA - Check revocation</title></head>
<body>

<h2>Check certificate with issuer '<%=request.getParameter("issuer")%>' and serial number '<%=request.getParameter("serno")%>'.</h2>
<hr>
<%
try  {
    String dn=request.getParameter("issuer");
    String serno=request.getParameter("serno").trim();
    if ((dn == null) || (serno == null)) {
%>
Usage: revoked.jsp?issuer=<DN>&serno=<serial number>
<%
    } else {
        InitialContext ctx = new InitialContext();
        ICertificateStoreSessionHome home = (ICertificateStoreSessionHome) PortableRemoteObject.narrow(
        ctx.lookup("CertificateStoreSession"), ICertificateStoreSessionHome.class );
        ICertificateStoreSession store = home.create();
        try {
            RevokedCertInfo revinfo = store.isRevoked(dn, new BigInteger(Hex.decode(serno)));
            if (revinfo != null) {
%>
<b>REVOKED</b><br>
RevocationDate is '<%=revinfo.getRevocationDate()%>' and reason '<%=revinfo.getReason()%>'.
<%
            } else {
%>
<b>NOT REVOKED</b>
<%
            }
        } catch (Exception e) {
%>
<b>Certificate does not exist</b>
<%
        }
    }
} catch(Exception ex) {
    ex.printStackTrace();
}                                             
%>

</body>
</html>
