<%@ page language="Java" import="javax.naming.*,javax.rmi.*,java.util.*,java.security.cert.*,se.anatom.ejbca.ca.sign.*"%>

<HTML>
<HEAD><TITLE>EJBCA Mozilla Demo Certificate enroll</TITLE>
<link rel="stylesheet" href="indexmall.css" type="text/css">
</HEAD>
<BODY bgcolor="#ffffff" link="black" vlink="black" alink="black">

<center>
  <strong><span class="E">E</span><span class="J">J</span><span class="B">B</span><span class="C">C</span><span class="A">A 
  </span></strong><span class="titel">Mozilla Demo Certificate Enrollment</span> 
</center>

<HR width="450">
<div align="center">Welcome to the certificate enrollment. <BR>
  If you haven't done so already, you must first install<br>
  the CA certificate(s) in your browser. </div>
<P align="center">Install CA certificates: 
  <%
try  {
    InitialContext ctx = new InitialContext();
    ISignSessionHome home = home = (ISignSessionHome) PortableRemoteObject.narrow(
            ctx.lookup("RSASignSession"), ISignSessionHome.class );
    ISignSession ss = home.create();
    Certificate[] chain = ss.getCertificateChain();
    out.println("<div align=\"center\">");
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
    out.println("</div>");
} catch(Exception ex) {
    ex.printStackTrace();
}                                             
%>
  <br>
<HR align="center" width="600">
<div align="center">
  <script language="javaScript">
//*** This function, triggered by clicking the fake Submit button, checks
//*** for, and rejects, blank values in the name and email fields.

function validateForm() {
  var okSoFar=true //-- Changes to false when bad field found.
  //-- Check the common name field, reject if blank.
  if (document.demoreq.cn.value=="") {
    okSoFar=false
    alert("Please fill in the name field!")
    document.demoreq.cn.focus()
  }
  document.demoreq.user.value=document.demoreq.dn.value+document.demoreq.cn.value

  if (document.demoreq.email.value!="") {
     //-- Reject email address if it doesn't contain an @ character.
      var foundAt = document.demoreq.email.value.indexOf("@",0)
      if (foundAt < 1 && okSoFar) {
        okSoFar = false
        alert ("Email address should contain an @ character!")
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
</div>
<FORM name="demoreq" ACTION="/apply/certreq" ENCTYPE=x-www-form-encoded METHOD="POST">
  <div align="center">PLEASE NOTE! Certificates issued by this CA comes with absolutely<br>
    NO WARRANTY whatsoever. NO AUTHENTICATION is <br>
    performed on the information entered below. </div>
  <p align="center"> Please enter your name, then click OK to fetch your certificate.
<INPUT name=user type=hidden>
    <br>
    <INPUT name=dn type=hidden value="C=SE,O=AnaTom,CN=">
    <br>
    Full name, e.g. Sven Svensson: 
    <INPUT NAME=cn TYPE=text SIZE=25 maxlength="60" class="input">
  
  <p align="center"> E-mail (optional): 
    <INPUT name=email TYPE=text size=25 maxlength="60" class="input">
  
  <p align="center"> Key length <KEYGEN TYPE="hidden" NAME="keygen" VALUE="challenge"> 
   <p align="center"> <input type="button" value="OK" onclick="validateForm()">
</FORM>

<script language="JavaScript">
//-- This little script, executed after form has been rendered, 
  //-- puts the cursor into the userName field so it's ready when page opens.
  document.demoreq.cn.focus()
</script>

</BODY>
</HTML>
