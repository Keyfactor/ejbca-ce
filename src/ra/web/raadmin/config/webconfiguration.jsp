<% GlobalConfiguration gc = ejbcawebbean.getGlobalConfiguration(); 
   // This page is not translated because documant root isn't known yet.

%>
<html>
<head>
  <title><%= gc.getEjbcaTitle() %></title>
  <link rel=STYLESHEET href="/<%= ejbcawebbean.getCssFile() %>">
  <script language=javascript src="/<%= gc.getRaAdminPath() %>ejbcajslib.js"></script>
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
        <div align="right"><A  onclick='displayHelpWindow("/<%=gc.getRaAdminPath() %>/help/configuration_help.en.html#mainconfig")'>
        <u>Information and help</u> </A> </div>
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
        <h3>Open Directories</h3>
        <h5>A list of directories where no authorization is done. </h5>
      </td>
      <td width="51%" valign="top"> 
        <input type="text" name="<%=TEXTFIELD_OPENDIRECTORIES%>" value="<%= gc.getOpenDirectoriesAsString() %>" maxlength="150" size="70">
      </td>
    </tr>
    <tr id="Row0"> 
      <td width="49%" valign="top"> 
        <h3>Hidden Directoires</h3>
        <h5>A list of directories not to be shown in the authorization module.</h5>
      </td>
      <td width="51%" valign="top"> 
        <input type="text" name="<%=TEXTFIELD_HIDDENDIRECTORIES%>" value="<%= gc.getHiddenDirectoriesAsString() %>" maxlength="150" size="70">
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

