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
    ISignSession ss = home.create();
    Certificate[] chain = ss.getCertificateChain();
    if (chain.length == 0) {
        out.println("No CA certificates exist");
    } else {
        out.println("<hr>In PEM format:<br>");
        out.println("<li><a href=\"/webdist/certdist?cmd=cacert&level=0\">Root CA</a></li>");
        if (chain.length > 1) {
            for (int i=chain.length-2;i>=0;i--) {
                out.println("<li><a href=\"/webdist/certdist?cmd=cacert&level="+i+"\">CA</a></li>");
            }
        }
        out.println("<hr>For Netscape/Mozilla:<br>");
        out.println("<li><a href=\"/webdist/certdist?cmd=nscacert&level=0\">Root CA</a></li>");
        if (chain.length > 1) {
            for (int i=chain.length-2;i>=0;i--) {
                out.println("<li><a href=\"/webdist/certdist?cmd=nscacert&level="+i+"\">CA</a></li>");
            }
        }
        out.println("<hr>For Internet Explorer:<br>");
        out.println("<li><a href=\"/webdist/certdist?cmd=iecacert&level=0\">Root CA</a></li>");
        if (chain.length > 1) {
            for (int i=chain.length-2;i>=0;i--) {
                out.println("<li><a href=\"/webdist/certdist?cmd=iecacert&level="+i+"\">CA</a></li>");
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
