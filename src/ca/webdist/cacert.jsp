<%@ page language="Java" import="javax.naming.*,javax.rmi.*,java.util.*,java.security.cert.*,se.anatom.ejbca.ca.sign.*"%>

<HTML>
<HEAD>
<TITLE>EJBCA - Fetch CA Certificate</TITLE>
</HEAD>
<BODY bgcolor="#ffffff" link="black" vlink="black" alink="black">

<h1>EJBCA Fetch CA Certificate</h1>

<%
try  {
    InitialContext ctx = new InitialContext();
    ISignSessionHome home = home = (ISignSessionHome) PortableRemoteObject.narrow(
            ctx.lookup("RSASignSession"), ISignSessionHome.class );
    ISignSessionRemote ss = home.create();
    Certificate[] chain = ss.getCertificateChain();
    if (chain.length == 0) {
%>
No CA certificates exist
<%
    } else {
%>
<hr>In PEM format:<br>
<li><a href="certdist?cmd=cacert&level=0">Root CA</a></li>
<%
        int i = 0;
        if (chain.length > 1) {
            for (i=chain.length-1;i>0;i--) {
%>
<li><a href="certdist?cmd=cacert&level=<%= i %>">CA</a></li>
<%
            }
        }
%>
<hr>For Netscape/Mozilla:<br>
<li><a href="certdist?cmd=nscacert&level=0">Root CA</a></li>
<%
        if (chain.length > 1) {
            for (i=chain.length-1;i>0;i--) {
%>
<li><a href="certdist?cmd=nscacert&level=<%= i %>">CA</a></li>
<%
            }
        }
%>
<hr>For Internet Explorer:<br>
<li><a href="certdist?cmd=iecacert&level=0">Root CA</a></li>
<%
        if (chain.length > 1) {
            for (i=chain.length-1;i>0;i--) {
%>
<li><a href="certdist?cmd=iecacert&level=<%= i %>">CA</a></li>
<%
            }
        }
    }
} catch(Exception ex) {
    ex.printStackTrace();
}                                             
%>
<hr>
</BODY>
</HTML>
