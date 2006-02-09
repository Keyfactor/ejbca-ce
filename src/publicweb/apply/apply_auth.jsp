<%@ page pageEncoding="ISO-8859-1"%>
<%@ page contentType="text/html; charset=@page.encoding@" %>
<%@ page language="Java" import="org.ejbca.ui.web.RequestHelper"%>

<HEAD>
<TITLE>@EJBCA@ IE Certificate Enroll</TITLE>

 
<link rel="stylesheet" href="../indexmall.css" type="text/css">

</HEAD>

<BODY  bgcolor="#ffffff" link="black" vlink="black" alink="black">
<center>
  <strong class="titel">@EJBCA@</span> 
  Certificate Enrollment </strong> 
</center>

<HR>
Welcome to certificate enrollment. <BR>

<HR>
<FORM NAME="CertReqForm" ACTION="<%=THIS_FILENAME%>"  METHOD=POST>
  <input type="hidden" name='<%= ACTION %>' value='<%=ACTION_GENERATETOKEN %>'> 
 <hr>
 Please give your username and password, then click OK to generate your token.<BR>

        Username: <input type=text size=20 name="<%=TEXTFIELD_USERNAME %>" value=""><br>
        Password: <input type=password size=20 name="<%=TEXTFIELD_PASSWORD %>" value=""><br>

    <INPUT TYPE="hidden" NAME="<%=HIDDEN_BROWSER%>" VALUE="<%= BROWSER_UNKNOWN %>">
<%
RequestHelper.setDefaultCharacterEncoding(request);
//  Give the possibility to force a specific browser type
String forcedBrowser = request.getParameter(FORCE_BROWSER);
if (forcedBrowser != null) {
%>
     <INPUT TYPE="hidden" NAME="<%=FORCE_BROWSER%>" VALUE="<%= forcedBrowser %>">
<%
}
%>
<INPUT type="submit" value="OK" name="<%=BUTTON_SUBMIT_USERNAME%>">

</FORM>
<script language="JavaScript">
<!--
 var browserName = navigator.appName;
 var browserNum = parseInt(navigator.appVersion);
 browserSelector ();
 function browserSelector () {
         if(browserName == "Netscape") {
                 document.CertReqForm.<%=HIDDEN_BROWSER%>.value = "<%= BROWSER_NETSCAPE %>";
         }
     else if ((browserName == "Microsoft Internet Explorer") &&(browserNum>= 4)) {
                 document.CertReqForm.<%=HIDDEN_BROWSER%>.value = "<%= BROWSER_EXPLORER %>";
         }
}
// -->
</script>
</BODY>
</HTML>

