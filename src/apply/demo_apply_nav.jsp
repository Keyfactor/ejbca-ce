<%@ page language="Java" import="javax.naming.*,javax.rmi.*,java.util.*,java.security.cert.*,se.anatom.ejbca.ca.sign.*"%>

<HTML>
<HEAD><TITLE>EJBCA Mozilla Demo Certificate enroll</TITLE></HEAD>
<BODY bgcolor="#ffffff" link="black" vlink="black" alink="black">

<center>
<FONT face=arial size="3"><strong>EJBCA Mozilla Demo Certificate Enrollment
</strong></FONT>
</center>

<HR>
Welcome to certificate enrollment. <BR>
If you haven't done so already, you must first install the CA certificate(s) in your browser.

<P>Install CA certificates:

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
        out.println("<li><a href=\"/webdist/certdist?cmd=nscacert&level=0\">Root CA</a></li>");
        if (chain.length > 1) {
            for (int i=chain.length-2;i>=0;i--) {
                out.println("<li><a href=\"/webdist/certdist?cmd=nscacert&level="+i+"\">CA</a></li>");
            }
        }
    }
} catch(Exception ex) {
    ex.printStackTrace();
}                                             
%>
<HR>

<script language="javaScript">
//*** This function, triggered by clicking the fake Submit button, checks
//*** for, and rejects, blank values in the name and email fields.

function validateForm() {
  var okSoFar=true //-- Changes to false when bad field found.
  //-- Check the common name field, reject if blank.
  if (document.demoreq.cn.value=="") {
    okSoFar=false
    alert("Please fill in the Common Name field!")
    document.demoreq.cn.focus()
  }
  document.demoreq.user.value=document.demoreq.dn.value+document.demoreq.cn.value

  if (document.demoreq.email.value!="") {
     //-- Reject email address if it doesn't contain an @ character.
      var foundAt = document.demoreq.email.value.indexOf("@",0)
      if (foundAt < 1 && okSoFar) {
        okSoFar = false
        alert ("EMail address should contain an @ character!")
        document.demoreq.email.focus()
      }
  document.demoreq.user.value=document.demoreq.user.value+",EmailAddress="+document.demoreq.email.value
  }
  //-- If all fields OK go ahead and submit the form and put up a message.
  if (okSoFar==true) {
    //-- The statement below actually submits the form, if all OK.
    document.demoreq.submit()
  }
}
</script>
<FORM name="demoreq" ACTION="/apply/certreq" ENCTYPE=x-www-form-encoded METHOD="POST">
Certificates issued by this CA comes with absolutely NO WARRANTY whatsoever. 
NO AUTHENTICATION is performed on the information entered below.
<p>
Please give your name, then click OK to fetch your certificate.<BR>

<INPUT name=user type=hidden><br>
<INPUT name=dn type=hidden value="C=SE,O=AnaTom,CN="><br>
Common Name, e.g. Sven Svensson:<br>
	<INPUT NAME=cn TYPE=text SIZE=30><p>
Email (you may leave empty): <INPUT name=email TYPE=text size=20><p>
Key length
	<KEYGEN TYPE="hidden" NAME="keygen" VALUE="challenge">

<input type="button" value="OK" onclick="validateForm()">

</FORM>

<script language="JavaScript">
//-- This little script, executed after form has been rendered, 
  //-- puts the cursor into the userName field so it's ready when page opens.
  document.demoreq.cn.focus()
</script>

</BODY>
</HTML>
