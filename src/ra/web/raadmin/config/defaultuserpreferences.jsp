<% UserPreference dup = ejbcawebbean.getGlobalConfiguration().getDefaultPreference(); %>
<html>
<head>
<title><%= globalconfiguration .getEjbcaTitle() %></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>">
  <link rel=STYLESHEET href="<%= ejbcawebbean.getCssFile() %>">
  <script language=javascript src="<%= globalconfiguration .getRaAdminPath() %>ejbcajslib.js"></script>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">
</head>

<body>
<div align="center"> 
  <h2><%= ejbcawebbean.getText("EJBCADEFAULTUSERPREF") %><br>
  </h2>
</div>
<form name="defaultuserpreferences" method="post" action="<%= globalconfiguration .getConfigPath() + "/" + THIS_FILENAME %>">
  <table width="100%" border="0" cellspacing="3" cellpadding="3">
    <tr id="Row0"> 
      <td width="50%" valign="top"> 
        <div align="left"> 
          <h3>&nbsp;</h3>
        </div>
      </td>
      <td width="50%" valign="top"> 
        <div align="right"><A  onclick='displayHelpWindow("<%= ejbcawebbean.getHelpfileInfix("configuration_help.html") + "#defaultuserpreference"%>")'>
        <u><%= ejbcawebbean.getText("HELP") %></u> </A></div>
      </td>
    </tr>
    <tr  id="Row0"> 
      <td width="50%" valign="top"> 
        <h3><%= ejbcawebbean.getText("PREFEREDLANGUAGE") %></h3>
        <h5><%= ejbcawebbean.getText("DEFAULTLANGUAGETOUSE") %></h5>
      </td>
      <td width="50%" valign="top"> 
        <select name="<%= LIST_PREFEREDLANGUAGE %>">
          <% String[] availablelanguages = WebLanguages.getAvailableLanguages();                                    
             int preferedlanguage = dup.getPreferedLanguage();
             for(int i = 0; i < availablelanguages.length; i++){
          %>   <option <% if(i == preferedlanguage){ %> selected <% } %>
                     value='<%= availablelanguages[i] %>'><%= availablelanguages[i] %></option>
          <% } %>
        </select>
      </td>
    </tr>
    <tr id="Row1"> 
      <td width="50%" valign="top"> 
        <h3><%= ejbcawebbean.getText("SECONDARYLANGUAGE") %></h3>
        <h5><%= ejbcawebbean.getText("LANGUAGETOUSEWHEN") %></h5>
      </td>
      <td width="50%" valign="top"> 
        <select name="<%= LIST_SECONDARYLANGUAGE %>">
          <% availablelanguages = WebLanguages.getAvailableLanguages();                                    
             int secondarylanguage = dup.getSecondaryLanguage();
             for(int i = 0; i < availablelanguages.length; i++){
          %>   <option <% if(i == secondarylanguage){ %> selected <% } %>
                     value='<%= availablelanguages[i] %>'><%= availablelanguages[i] %></option>
          <% } %>
        </select>
      </td>
    </tr>
    <tr  id="Row0"> 
      <td width="50%" valign="top"> 
        <h3><%= ejbcawebbean.getText("THEME") %></h3>
        <h5><%= ejbcawebbean.getText("THEUSERSTHEMEOFFONTS") %></h5>
      </td>
      <td width="50%" valign="top"> 
        <select name="<%= LIST_THEME %>">
          <% String[] availablethemes = globalconfiguration .getAvailableThemes();                                    
             String theme = dup.getTheme();
             if(availablethemes != null){
               for(int i = 0; i < availablethemes.length; i++){
          %>     <option <% if(availablethemes[i].equals(theme)){ %> selected <% } %>
                     value='<%= availablethemes[i] %>'><%= availablethemes[i] %></option>
          <%   }
             }%>
        </select>
      </td>
    </tr>
    <tr  id="Row1"> 
      <td width="49%" valign="top"> 
        <h3><%= ejbcawebbean.getText("NUMBEROFRECORDSPERPAGE") %></h3>
        <h5><%= ejbcawebbean.getText("THENUMBEROFRECORDSTO") %></h5>
      </td>
      <td width="51%" valign="top"> 
        <select name="<%= LIST_ENTIESPERPAGE %>">
          <% String[] possibleentriesperpage = globalconfiguration .getPossibleEntiresPerPage();                                    
             int entriesperpage = dup.getEntriesPerPage();
             for(int i = 0; i < possibleentriesperpage.length; i++){
          %>   <option <% if(Integer.parseInt(possibleentriesperpage[i]) == entriesperpage){ %> selected <% } %>
                  value='<%= Integer.parseInt(possibleentriesperpage[i]) %>'><%= possibleentriesperpage[i] %></option>
          <% } %>
        </select>
      </td>
    </tr>
    <tr  id="Row0"> 
      <td width="49%" valign="top">&nbsp;</td>
      <td width="51%" valign="top"> 
        <input type="submit" name="<%= BUTTON_PREVIOUS %>" value="<%= ejbcawebbean.getText("PREVIOUS") %>">
        <input type="submit" name="<%= BUTTON_SAVE %>" value="<%= ejbcawebbean.getText("SAVE") %>">
        <input type="submit" name="<%= BUTTON_CANCEL %>" value="<%= ejbcawebbean.getText("CANCEL") %>">
      </td>
    </tr>
  </table>
 </form>
<% // Include Footer 
   String footurl = globalconfiguration .getFootBanner(); %>
   
  <jsp:include page="<%= footurl %>" />
 
</body>
</html>


