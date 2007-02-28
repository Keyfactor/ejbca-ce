<%@ page pageEncoding="ISO-8859-1"%>
<%@ page contentType="text/html; charset=@page.encoding@" %>
<%@ page language="Java" import="javax.naming.*,javax.rmi.*,java.math.BigInteger,org.ejbca.core.ejb.ca.store.*,org.ejbca.core.model.ca.crl.RevokedCertInfo,org.bouncycastle.util.encoders.Hex, org.ejbca.core.model.log.Admin,org.ejbca.ui.web.RequestHelper"%>
<%@ include file="header.jsp" %>
<%
  RequestHelper.setDefaultCharacterEncoding(request);
%>
<h1>Check certificate with issuer '<%=request.getParameter("issuer")%>' 
  and serial number '<%=request.getParameter("serno")%>'</h1> 

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
<%@ include file="footer.inc" %>
