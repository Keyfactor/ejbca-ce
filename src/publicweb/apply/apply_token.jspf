<%@ page import="org.ejbca.core.ejb.ca.sign.*,org.ejbca.core.model.log.Admin,java.util.Collection"%>

<HEAD><TITLE>@EJBCA@ Certificate enroll</TITLE></HEAD>
<BODY bgcolor="#ffffff" link="black" vlink="black" alink="black">

<center>
<FONT face=arial size="3"><strong>@EJBCA@ Certificate Enrollment
</strong></FONT>
</center>

<p>
If you want to, you can manually install the CA certificate(s) in your browser, otherwise this will be done automatically 
when your certificate is retrieved.

<P>Install CA certificates:
<%
try  {
    InitialContext ctx = new InitialContext();
    ISignSessionHome home = home = (ISignSessionHome) PortableRemoteObject.narrow(
            ctx.lookup("RSASignSession"), ISignSessionHome.class );
    ISignSessionRemote ss = home.create();
    
    Collection chain = ss.getCertificateChain(new Admin(Admin.TYPE_PUBLIC_WEB_USER, request.getRemoteAddr()), caid);
    if (chain.size() == 0) {
        out.println("No CA certificates exist");
    } else {
        out.println("<li><a href=\"../webdist/certdist?cmd=nscacert&caid="+caid +"\">Certificate chain</a></li>");
    }
} catch(Exception ex) {
    ex.printStackTrace();
}                                             
%>
<HR>
<FORM ACTION="certreq" ENCTYPE=x-www-form-encoded METHOD="POST">

Please choose keylength, then click OK to fetch your key store.<BR>
	<INPUT NAME=user TYPE="hidden" VALUE="<%=username%>">
	<INPUT NAME=password TYPE="hidden"  VALUE="<%=password%>">
Key length 
        <SELECT name='keylength' size='1'>
           <% for(int i=0; i<availablekeylengths.length;i++){ %>
           <option  value="<%= availablekeylengths[i] %>">
              <%=availablekeylengths[i]%> bits
           </option>
           <% } %>
           </SELECT>
<p>
Optional selections:<br>
<INPUT TYPE=CHECKBOX NAME="openvpn">Create an OpenVPN installer. This options requires special configuration on the CA.
<p>
<INPUT type="submit" value="OK">

</FORM>
</BODY>
</HTML>
