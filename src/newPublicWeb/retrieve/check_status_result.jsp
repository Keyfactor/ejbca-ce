<%@ page pageEncoding="ISO-8859-1"%>
<%@ page contentType="text/html; charset=@page.encoding@" %>
<%@ page language="Java" import="javax.naming.*,javax.rmi.*,java.math.BigInteger,org.ejbca.core.ejb.ca.store.*,org.ejbca.core.model.ca.crl.RevokedCertInfo,org.bouncycastle.util.encoders.Hex, org.ejbca.core.model.log.Admin,org.ejbca.ui.web.RequestHelper"%>
<%@ include file="header.jsp" %>
<%
    RequestHelper.setDefaultCharacterEncoding(request);
%>
<h1>Certificate Status</h1>
<%
try  {
    String dn=request.getParameter("issuer");
    String serno=request.getParameter("serno");
    if (serno != null) serno=serno.trim();
    if ((dn == null) || (serno == null)) {
%>
		<div align="center">Usage: check_status_result.jsp?issuer=<DN>&serno=<serial number> 
<%
    } else {
        InitialContext ctx = new InitialContext();
        ICertificateStoreSessionHome home = (ICertificateStoreSessionHome) PortableRemoteObject.narrow(
        ctx.lookup("CertificateStoreSession"), ICertificateStoreSessionHome.class );
        ICertificateStoreSessionRemote store = home.create();
        RevokedCertInfo revinfo = store.isRevoked(new Admin(Admin.TYPE_PUBLIC_WEB_USER, 
        								request.getRemoteAddr()), dn, new BigInteger(Hex.decode(serno)));
        if (revinfo != null) {
%>
        	<p>Issuer: '<%=request.getParameter("issuer")%>'</p> 
        	<p>Serial number <%=request.getParameter("serno")%></p>
<%
            if (revinfo.getReason() != RevokedCertInfo.NOT_REVOKED) {
%>
  <h1>The certificate has been REVOKED!</h1>
  <p>The revocation date is <%=revinfo.getRevocationDate()%>.<br /> 
  The reason for revocation was '<%=revinfo.getReason()%>'. 
<%
            } else {
%>
  <p>The certificate has <strong>NOT</strong> been revoked.
<%
            }
        } else {
%>
  <p>The certificate does not exist!</p> 
<%
        }
    }
} catch(Exception ex) {
    ex.printStackTrace();
}                                             
%>
</div>
<%@ include file="footer.inc" %>
