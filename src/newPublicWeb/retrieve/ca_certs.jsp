<%@ page pageEncoding="ISO-8859-1"%>
<%@ page contentType="text/html; charset=@page.encoding@" %>
<%@ page language="Java" import="javax.naming.*,javax.rmi.*,java.util.*,java.net.URLEncoder,java.security.cert.*,org.ejbca.core.ejb.ca.sign.*,org.ejbca.core.ejb.ca.caadmin.*,org.ejbca.core.model.ca.caadmin.*,org.ejbca.core.model.log.Admin"%>
<%@ include file="header.inc" %>
<h1 class="title">@EJBCA@ Fetch CA Certificate</h1>
<p align="center"> 
  <%
try  {
    Admin admin = new Admin(Admin.TYPE_PUBLIC_WEB_USER, request.getRemoteAddr());
    InitialContext ctx = new InitialContext();
    ISignSessionHome home = home = (ISignSessionHome) PortableRemoteObject.narrow(ctx.lookup("RSASignSession"), ISignSessionHome.class );
    ISignSessionRemote ss = home.create();
    ICAAdminSessionHome cahome = (ICAAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(ctx.lookup("CAAdminSession"), ICAAdminSessionHome.class );            
    ICAAdminSessionRemote caadminsession = cahome.create();          
    Collection caids = caadminsession.getAvailableCAs(admin);
    Iterator iter = caids.iterator();
    while (iter.hasNext()) {
        int caid = ((Integer)iter.next()).intValue();
        CAInfo ca = caadminsession.getCAInfo(admin, caid);
%>
  <hr>
  <h2>CA: <%= ca.getName() %></h2>
<%
        Collection chain = ss.getCertificateChain(admin, caid);
        // Get the CA-cert
        Iterator chainiter = chain.iterator();
        String issuerdn = null;
        if (chainiter.hasNext()) {
        	X509Certificate cert = (X509Certificate)chainiter.next();
        	issuerdn = URLEncoder.encode(cert.getSubjectDN().getName(), "UTF-8");
        }
        if (chain.size() == 0) {
%>
  No CA certificates exist 
  <%
        } else {
%>
</p>
<div align="center">In PEM format:<br>
</div>
<div align="center">
<%
            int i = 0;
            chainiter = chain.iterator();
            while (chainiter.hasNext()) {
            	X509Certificate cert = (X509Certificate)chainiter.next();
            	String subjectdn = URLEncoder.encode(cert.getSubjectDN().getName(), "UTF-8");
%>
</div>
  <div align="center">
  	<a href="../certdist?cmd=cacert&issuer=<%= issuerdn %>&level=<%= i %>"><%= cert.getSubjectDN().getName() %></a>, 
  	<a href="../certdist?cmd=ocspcert&issuer=<%= subjectdn %>">OCSPResponder certificate</a>
  </div>
<div align="center">
<%
				i++;
            }
%>
</div>
<br>
<div align="center">For Netscape/Mozilla:<br>
</div>
<div align="center">
<%
            i = 0;
            chainiter = chain.iterator();
            while (chainiter.hasNext()) {
            	X509Certificate cert = (X509Certificate)chainiter.next();
            	String subjectdn = URLEncoder.encode(cert.getSubjectDN().getName(), "UTF-8");
%>
</div>
<div align="center">
  	<a href="../certdist?cmd=nscacert&issuer=<%= issuerdn %>&level=<%= i %>"><%= cert.getSubjectDN().getName() %></a>,
  	<a href="../certdist?cmd=nsocspcert&issuer=<%= subjectdn %>">OCSPResponder certificate</a>
</div>
<div align="center">
<%
                i++;
            }
%>
</div>
<br>
<div align="center">For Internet Explorer:<br>
</div>
<div align="center">
<%
            i = 0;
            chainiter = chain.iterator();
            while (chainiter.hasNext()) {
            	X509Certificate cert = (X509Certificate)chainiter.next();
            	String subjectdn = URLEncoder.encode(cert.getSubjectDN().getName(), "UTF-8");
%>
</div>
<div align="center">
  	<a href="../certdist?cmd=iecacert&issuer=<%= issuerdn %>&level=<%= i %>"><%= cert.getSubjectDN().getName() %></a>,
  	<a href="../certdist?cmd=ieocspcert&issuer=<%= subjectdn %>">OCSPResponder certificate</a></div>
<div align="center">
<%
                i++;
            }
        }
    }
} catch(Exception ex) {
    ex.printStackTrace();
}                                             
%>
</div>
<%@ include file="footer.inc" %>
