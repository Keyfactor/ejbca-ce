<% GlobalConfiguration gc = ejbcawebbean.getGlobalConfiguration(); 
   // This page is not translated because documant root isn't known yet.

%>
<html>
<head>
  <title><%= gc.getEjbcaTitle() %></title>
  <link rel=STYLESHEET href="/<%= ejbcawebbean.getCssFile() %>">
  <script language=javascript src="/<%= gc.getAdminWebPath() %>ejbcajslib.js"></script>
  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">
</head>

<body>
<div align="center"> 
  <h2>Ejbca Web Configuration <br>
  </h2> 
</div>
<form name="webconfiguration" method="post" action="<%=THIS_FILENAME %>">
  <table width="100%" border="0" cellspacing="3" cellpadding="3">
    <tr id="Row0"> 
      <td width="50%" valign="top"> 
        <div align="left"> 
          <h3>&nbsp;</h3>
        </div>
      </td>
      <td width="50%" valign="top"> 
        <div align="right"><A  onclick='displayHelpWindow("/<%=gc.getAdminWebPath() %>/help/configuration_help.en.html#mainconfig")'>
        <u>Help</u> </A> </div>
      </td>
    </tr>
    <tr id="Row0"> 
      <td width="50%" valign="top"> 
        <h3>Title</h3>
        <h5>The title of the site.</h5>
      </td>
      <td width="50%" valign="top"> 
        <input type="text" name="<%=TEXTFIELD_TITLE %>" value="<%= gc.getEjbcaTitle() %>" maxlength="150" size="70">
      </td>
    </tr>
    <tr id="Row1"> 
      <td width="49%" valign="top"> 
        <h3>Head Banner</h3>
        <h5>The name of the head banner jsp or html file. Must be put in the subdirectory 
          '/banners'. </h5>
      </td>
      <td width="51%" valign="top"> 
        <input type="text" name="<%=TEXTFIELD_HEADBANNER %>" value="<%= gc.getHeadBannerFilename() %>" maxlength="150" size="70">
      </td>
    </tr>
    <tr id="Row0"> 
      <td width="49%" valign="top"> 
        <h3>Foot Banner</h3>
        <h5>The name of the foot banner jsp or html file. Must be put in the subdirectory 
          '/banners'. </h5>
      </td>
      <td width="51%" valign="top"> 
        <input type="text" name="<%=TEXTFIELD_FOOTBANNER %>" value="<%= gc.getFootBannerFilename() %>" maxlength="150" size="70">
      </td>
    </tr>
    <tr id="Row1"> 
      <td width="49%" valign="top"> 
        <h3>Enable Authenticated Users Only</h3>
        <h5>Check this field if authentication should be required of all tools. </h5>          
      </td>
      <td width="51%" valign="top"> 
        <input type="checkbox" name="<%=CHECKBOX_ENABLEAUTHENTICATEDUSERSONLY%>" value="<%=CHECKBOX_VALUE %>" 
                                                                                          <% if(gc.getEnableAuthenticatedUsersOnly())
                                                                                                out.write(" CHECKED "); %>> 
      </td>
    </tr>
    <tr id="Row0"> 
      <td width="49%" valign="top"> 
        <h3>Enable End Entity Profile Limitations</h3>
        <h5>Check this field if you want to uses end entity access control. </h5>
      </td>
      <td width="51%" valign="top"> 
        <input type="checkbox" name="<%=CHECKBOX_ENABLEEEPROFILELIMITATIONS%>" value="<%=CHECKBOX_VALUE %>" 
                                                                                          <% if(gc.getEnableEndEntityProfileLimitations())
                                                                                                out.write(" CHECKED "); %>> 
      </td>
    </tr>
    <tr id="Row1"> 
      <td width="49%" valign="top"> 
        <h3>Enable Key Recovery</h3>
        <h5>&nbsp; </h5>          
      </td>
      <td width="51%" valign="top"> 
        <input type="checkbox" name="<%=CHECKBOX_ENABLEKEYRECOVERY%>" value="<%=CHECKBOX_VALUE %>" 
                                                                                          <% if(gc.getEnableKeyRecovery())
                                                                                                out.write(" CHECKED "); %>> 
      </td>
    </tr>
    <tr id="Row0"> 
      <td width="49%" valign="top"> 
        <h3>Issue Hardware Tokens</h3>
        <h5>Check this field if it should be possible to issue hardware tokens. </h5>
      </td>
      <td width="51%" valign="top"> 
        <input type="checkbox" name="<%=CHECKBOX_ISSUEHARDWARETOKENS%>" value="<%=CHECKBOX_VALUE %>" 
                                                                                          <% if(gc.getIssueHardwareTokens())
                                                                                                out.write(" CHECKED "); %>> 
      </td>
    </tr>
    <tr> 
      <td width="49%" valign="top">&nbsp;</td>
      <td width="51%" valign="top">
        <input type="submit" name="<%= BUTTON_NEXT %>" value="Next">
        <input type="submit" name="<%= BUTTON_CANCEL %>" value="Cancel">
      </td>
    </tr>
  </table>
 </form>

</body>
</html>

