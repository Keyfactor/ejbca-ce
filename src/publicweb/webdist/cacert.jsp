<%@ page language="Java" import="javax.naming.*,javax.rmi.*,java.util.*,java.security.cert.*,se.anatom.ejbca.ca.sign.*,se.anatom.ejbca.ca.caadmin.*,se.anatom.ejbca.log.Admin"%>

<HTML>
<HEAD>
<TITLE>EJBCA - Fetch CA Certificate</TITLE>
<link rel="stylesheet" href="indexmall.css" type="text/css">
</HEAD>
<BODY>
<p align="center"><span class="E">E</span><span class="J">J</span><span class="B">B</span><span class="C">C</span><span class="A">A 
  </span> <span class="titel">Fetch CA Certificate</span> </p>
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
  <div align="center">CA: <%= ca.getName() %></div>
<%
        Collection chain = ss.getCertificateChain(admin, caid);
        if (chain.size() == 0) {
%>
  No CA certificates exist 
  <%
        } else {
%>
</p>
<div align="center">In PEM format:<br>
</div>
  <div align="center"><a href="certdist?cmd=cacert&level=0">Root CA</a></div>
<div align="center">
  <%
            int i = 0;
            if (chain.size() > 1) {
                for (i=chain.size()-1;i>0;i--) {
%>
</div>
  <div align="center"><a href="certdist?cmd=cacert&level=<%= i %>">CA</a></div>
<div align="center">
  <%
                }
            }
%>
</div>
<br>
<div align="center">For Netscape/Mozilla:<br>
</div>
  <div align="center"><a href="certdist?cmd=nscacert&level=0">Root CA</a></div>
<div align="center">
<%
            if (chain.size() > 1) {
                for (i=chain.size()-1;i>0;i--) {
%>
</div>
  <div align="center"><a href="certdist?cmd=nscacert&level=<%= i %>">CA</a></div>
<div align="center">
  <%
                }
            }
%>
</div>
<br>
<div align="center">For Internet Explorer:<br>
</div>
  <div align="center"><a href="certdist?cmd=iecacert&level=0">Root CA</a></div>
<div align="center">
  <%
            if (chain.size() > 1) {
                for (i=chain.size()-1;i>0;i--) {
%>
</div>
  <div align="center"><a href="certdist?cmd=iecacert&level=<%= i %>">CA</a></div>
<div align="center">
  <%
                }
            }
        }
    }
} catch(Exception ex) {
    ex.printStackTrace();
}                                             
%>
</div>
</BODY>
</HTML>
