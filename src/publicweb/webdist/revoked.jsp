<%@ page pageEncoding="ISO-8859-1"%>
<%@ page language="Java" import="javax.naming.*,javax.rmi.*,java.util.*,java.security.cert.*,java.math.BigInteger,se.anatom.ejbca.ca.store.*,se.anatom.ejbca.ca.crl.RevokedCertInfo,org.bouncycastle.util.encoders.Hex, se.anatom.ejbca.log.Admin"%>
<html>
<head><title>EJBCA - Check revocation</title>
<link rel="stylesheet" href="indexmall.css" type="text/css">
</head>
<body>
<div align="center"><span class="titel">Check certificate with issuer</span> '<%=request.getParameter("issuer")%>' 
  <span class="titel">and serial number </span>'<%=request.getParameter("serno")%>'. 
</div>
<%
try  {
    String dn=request.getParameter("issuer");
    String serno=request.getParameter("serno");
    if (serno != null) serno=serno.trim();
    if ((dn == null) || (serno == null)) {
%>
<div align="center">Usage: revoked.jsp?issuer=<DN>&serno=<serial number> 
  <%
    } else {
        InitialContext ctx = new InitialContext();
        ICertificateStoreSessionHome home = (ICertificateStoreSessionHome) PortableRemoteObject.narrow(
        ctx.lookup("CertificateStoreSession"), ICertificateStoreSessionHome.class );
        ICertificateStoreSessionRemote store = home.create();
        RevokedCertInfo revinfo = store.isRevoked(new Admin(Admin.TYPE_PUBLIC_WEB_USER, request.getRemoteAddr()), dn, new BigInteger(Hex.decode(serno)));
        if (revinfo != null) {
            if (revinfo.getReason() != RevokedCertInfo.NOT_REVOKED) {

%>
  <b>REVOKED</b><br>
  RevocationDate is '<%=revinfo.getRevocationDate()%>' and reason '<%=revinfo.getReason()%>'. 
<%
            } else {
%>
  <b>NOT REVOKED</b> 
<%
            }
        } else {
%>
  <b>Certificate does not exist</b> 
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
