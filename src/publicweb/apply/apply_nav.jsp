<HEAD><TITLE>EJBCA Mozilla Certificate enroll</TITLE></HEAD>
<BODY bgcolor="#ffffff" link="black" vlink="black" alink="black">

<center>
<FONT face=arial size="3"><strong>EJBCA Mozilla Certificate Enrollment
</strong></FONT>
</center>

<HR>
Welcome to certificate enrollment. <BR>
<p>
If you you want to, you can manually install the CA certificate(s) in your browser, otherwise this will be done automatically 
when your certificate is retrieved.

<P>Install CA certificates:
<%
try  {
    InitialContext ctx = new InitialContext();
    ISignSessionHome home = home = (ISignSessionHome) PortableRemoteObject.narrow(
            ctx.lookup("RSASignSession"), ISignSessionHome.class );
    ISignSessionRemote ss = home.create();
    Certificate[] chain = ss.getCertificateChain(new Admin(Admin.TYPE_PUBLIC_WEB_USER, request.getRemoteAddr()));
    if (chain.length == 0) {
        out.println("No CA certificates exist");
    } else {
        out.println("<li><a href=\"../webdist/certdist?cmd=nscacert\">Certificate chain</a></li>");
    }
} catch(Exception ex) {
    ex.printStackTrace();
}                                             
%>
<HR>
<FORM ACTION="certreq" ENCTYPE=x-www-form-encoded METHOD="POST">

Please choose keylength, then click OK to fetch your certificate.<BR>
	<INPUT NAME=user TYPE="hidden" VALUE="<%=username%>">
	<INPUT NAME=password TYPE="hidden"  VALUE="<%=password%>">
Key length 
	<KEYGEN TYPE="hidden" NAME="keygen" VALUE="challenge">
<INPUT type="submit" value="OK">

</FORM>
</BODY>
</HTML>
