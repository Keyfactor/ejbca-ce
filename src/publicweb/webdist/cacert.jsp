<%@ page language="Java" import="javax.naming.*,javax.rmi.*,java.util.*,java.security.cert.*,se.anatom.ejbca.ca.sign.*, se.anatom.ejbca.log.Admin"%>

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
    InitialContext ctx = new InitialContext();
    ISignSessionHome home = home = (ISignSessionHome) PortableRemoteObject.narrow(
            ctx.lookup("RSASignSession"), ISignSessionHome.class );
    ISignSessionRemote ss = home.create();
    Certificate[] chain = ss.getCertificateChain(new Admin(Admin.TYPE_PUBLIC_WEB_USER, request.getRemoteAddr()));
    if (chain.length == 0) {
%>
  No CA certificates exist 
  <%
    } else {
%>
</p>
<div align="center">In PEM format:<br>
</div>
<li>
  <div align="center"><a href="certdist?cmd=cacert&level=0">Root CA</a></div>
</li>
<div align="center">
  <%
        int i = 0;
        if (chain.length > 1) {
            for (i=chain.length-1;i>0;i--) {
%>
</div>
<li>
  <div align="center"><a href="certdist?cmd=cacert&level=<%= i %>">CA</a></div>
</li>
<div align="center">
  <%
            }
        }
%>
</div>
<br>
<div align="center">For Netscape/Mozilla:<br>
</div>
<li>
  <div align="center"><a href="certdist?cmd=nscacert&level=0">Root CA</a></div>
</li>
<div align="center">
  <%
        if (chain.length > 1) {
            for (i=chain.length-1;i>0;i--) {
%>
</div>
<li>
  <div align="center"><a href="certdist?cmd=nscacert&level=<%= i %>">CA</a></div>
</li>
<div align="center">
  <%
            }
        }
%>
</div>
<br>
<div align="center">For Internet Explorer:<br>
</div>
<li>
  <div align="center"><a href="certdist?cmd=iecacert&level=0">Root CA</a></div>
</li>
<div align="center">
  <%
        if (chain.length > 1) {
            for (i=chain.length-1;i>0;i--) {
%>
</div>
<li>
  <div align="center"><a href="certdist?cmd=iecacert&level=<%= i %>">CA</a></div>
</li>
<div align="center">
  <%
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
