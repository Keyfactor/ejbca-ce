<%@ page pageEncoding="ISO-8859-1"%>
<%@ page contentType="text/html; charset=@page.encoding@" %>
<%@ page language="Java" import="org.ejbca.ui.web.RequestHelper"%>

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
