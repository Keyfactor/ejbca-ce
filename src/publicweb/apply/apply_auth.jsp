

<HEAD>
<TITLE>EJBCA IE Certificate Enroll</TITLE>

 
<link rel="stylesheet" href="../indexmall.css" type="text/css">

</HEAD>

<BODY  bgcolor="#ffffff" link="black" vlink="black" alink="black">
<center>
  <strong class="titel"><span class="E">E</span><span class="J">J</span><span class="B">B</span><span class="C">C</span><span class="A">A</span> 
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

