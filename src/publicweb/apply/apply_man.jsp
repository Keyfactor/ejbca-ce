<%@ page language="Java" import="javax.naming.*,javax.rmi.*,java.util.*,java.security.cert.*,se.anatom.ejbca.ca.sign.*,se.anatom.ejbca.apply.RequestHelper, se.anatom.ejbca.log.Admin"%>

<HTML>
<HEAD>
<TITLE>@EJBCA@ manual certificate enroll</TITLE>
<link rel="stylesheet" href="indexmall.css" type="text/css">
</HEAD>
<BODY bgcolor="#ffffff" link="black" vlink="black" alink="black">
<center>
<FONT face=arial size="3"><strong>@EJBCA@ Certificate Enrollment
</strong></FONT>
</center>

<HR>
Welcome to certificate enrollment. <BR>
<!-- If you haven't done so already, you should first fetch the CA certificate(s).

<P>Fetch CA certificates: -->
<%
/*try  {
    InitialContext ctx = new InitialContext();
    ISignSessionHome home = home = (ISignSessionHome) PortableRemoteObject.narrow(
            ctx.lookup("RSASignSession"), ISignSessionHome.class );
    ISignSessionRemote ss = home.create();
    Collection chain = ss.getCertificateChain(new Admin(Admin.TYPE_PUBLIC_WEB_USER, request.getRemoteAddr()), caid);
    if (chain.size() == 0) {
        out.println("No CA certificates exist");
    } else {
        out.println("<li><a href=\"../webdist/certdist?cmd=cacert&level=0&caid="+caid+"\">Root CA</a></li>");
        if (chain.length > 1) {
            for (int i=chain.length-1;i>0;i--) {
                out.println("<li><a href=\"../webdist/certdist?cmd=cacert&level="+i+"&caid="+caid+"\">CA</a></li>");
            }
        }
    }
} catch(Exception ex) {
    ex.printStackTrace();
} */                                            
%>
<hr>
<FORM NAME="EJBCA" ACTION="certreq" ENCTYPE=x-www-form-encoded METHOD=POST>
 Please give your username and password, paste the PEM-formated PKCS10 certification request into the field below and
 click OK to fetch your certificate. 
<p>
A PEM-formatted request is a BASE64 encoded PKCS10 request between the two lines:<BR>
-----BEGIN CERTIFICATE REQUEST-----<br>
-----END CERTIFICATE REQUEST-----
<p>
        Username: <input type=text size=10 name=user value="foo"><br>
        Password: <input type=text size=10 name=password value="foo123"><br>
		  <textarea rows="15" cols="70" name=pkcs10req wrap="physical"></textarea><br>
                  <select name=resulttype>
                     <option value="<%=RequestHelper.ENCODED_CERTIFICATE%>">PEM Certificate</option> 
                     <option value="<%=RequestHelper.ENCODED_PKCS7%>">PKCS7</option>
                  </select>
		<br>
<INPUT type="submit" value="OK">
</FORM>
</BODY>
</HTML>
