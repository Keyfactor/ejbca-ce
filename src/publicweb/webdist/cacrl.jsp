<%@ page language="Java" import="javax.naming.*,javax.rmi.*,java.util.*,java.security.cert.*,java.net.*,se.anatom.ejbca.ca.sign.*,se.anatom.ejbca.ca.caadmin.*,se.anatom.ejbca.log.Admin"%>

<HTML>
<HEAD>
<TITLE>EJBCA - Fetch CA CRL</TITLE>
<link rel="stylesheet" href="indexmall.css" type="text/css">
</HEAD>
<BODY>
<p align="center"><span class="E">E</span><span class="J">J</span><span class="B">B</span><span class="C">C</span><span class="A">A 
  </span> <span class="titel">Fetch CA CRL</span> </p>
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
        String urlsubjectdn = URLEncoder.encode(ca.getSubjectDN(), "UTF-8"); 
%>
<hr>
<div align="center">CA: <%= ca.getName() %></div>
</p>
<div align="center"><a href="certdist?cmd=crl&issuer=<%= urlsubjectdn %>">Root CA</a></div>
<div align="center">
<%
    }
} catch(Exception ex) {
    ex.printStackTrace();
}                                             
%>
</div>
</BODY>
</HTML>
