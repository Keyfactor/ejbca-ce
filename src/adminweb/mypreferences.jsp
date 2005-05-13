<%@ page pageEncoding="ISO-8859-1"%>
<%@page  errorPage="errorpage.jsp" import="se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean,se.anatom.ejbca.ra.raadmin.GlobalConfiguration, 
                se.anatom.ejbca.ra.raadmin.AdminPreference, se.anatom.ejbca.webdist.webconfiguration.GlobalConfigurationDataHandler,
                se.anatom.ejbca.webdist.webconfiguration.WebLanguages, se.anatom.ejbca.webdist.webconfiguration.AdminPreferenceDataHandler"%>

<jsp:useBean id="ejbcawebbean" scope="session" class="se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean" />
<jsp:setProperty name="ejbcawebbean" property="*" /> 

<%! // Declarations 

  static final String ACTION                                 = "action";
  static final String ACTION_SAVE                            = "actionsave";
  static final String ACTION_CANCEL                          = "actioncancel";

  static final String BUTTON_SAVE                            = "buttonsave";
  static final String BUTTON_CANCEL                          = "buttoncancel";

  static final String LIST_PREFEREDLANGUAGE                  = "listpreferedlanguage";
  static final String LIST_SECONDARYLANGUAGE                 = "listsecondarylanguage";
  static final String LIST_THEME                             = "listtheme";
  static final String LIST_ENTIESPERPAGE                     = "listentriesperpage";

%>
<% 
   // Initialize environment.
  GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request,"/administrator"); 

  final String THIS_FILENAME                          = globalconfiguration.getAdminWebPath() + "mypreferences.jsp";

  String forwardurl = globalconfiguration.getMainFilename(); 

    // Determine action 
  if( request.getParameter(BUTTON_CANCEL) != null){
       // Cancel current values and go back to old ones.
       ejbcawebbean.initialize(request,"/");
      
%>  <jsp:forward page="<%= forwardurl %>"/>
<%  }
     if( request.getParameter(BUTTON_SAVE) != null){
        // Save global configuration.
        AdminPreference dup = ejbcawebbean.getAdminPreference();
        String[] languages = ejbcawebbean.getAvailableLanguages();
        if(request.getParameter(LIST_PREFEREDLANGUAGE) != null){
          String preferedlanguage = request.getParameter(LIST_PREFEREDLANGUAGE); 
          dup.setPreferedLanguage(languages, preferedlanguage.trim());
        }
        if(request.getParameter(LIST_SECONDARYLANGUAGE) != null){
          String secondarylanguage = request.getParameter(LIST_SECONDARYLANGUAGE); 
          dup.setSecondaryLanguage(languages, secondarylanguage.trim());
        }
        if(request.getParameter(LIST_THEME) != null){
          String theme = request.getParameter(LIST_THEME); 
          dup.setTheme(theme.trim());
        }
        if(request.getParameter(LIST_ENTIESPERPAGE) != null){
          String entriesperpage = request.getParameter(LIST_ENTIESPERPAGE); 
          dup.setEntriesPerPage(Integer.parseInt(entriesperpage.trim()));
        }
        if(!ejbcawebbean.existsAdminPreference()){
          ejbcawebbean.addAdminPreference(dup);
        }
        else{
          ejbcawebbean.changeAdminPreference(dup);
        }
        
%>          
 <jsp:forward page="<%=forwardurl %>"/>
<%   }


   AdminPreference dup = ejbcawebbean.getAdminPreference(); %>
<html>
<head>
<title><%= globalconfiguration.getEjbcaTitle() %></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>">
  <link rel=STYLESHEET href="<%= ejbcawebbean.getCssFile() %>">
  <script language=javascript src="<%= globalconfiguration.getAdminWebPath() %>ejbcajslib.js"></script>
</head>

<body>
<div align="center"> 
  <h2><%= ejbcawebbean.getText("EJBCAADMINPREFERENCES") %><br>
      <%= ejbcawebbean.getText("FORADMIN")+" " + ejbcawebbean.getUsersCommonName() %>
  </h2>
</div>
<form name="defaultmypreferences" method="post" action="<%=THIS_FILENAME %>">
  <table width="100%" border="0" cellspacing="3" cellpadding="3">
    <tr id="Row0"> 
      <td width="50%" valign="top"> 
        <div align="left"> 
          <h3>&nbsp;</h3>
        </div>
      </td>
      <td width="50%" valign="top"> 
      <!--  <div align="right"><A  onclick='displayHelpWindow("<%= ejbcawebbean.getHelpfileInfix("mypreferences_help.html") %>")'>
        <u><%= ejbcawebbean.getText("HELP") %></u> </A></div> -->
      </td>
    </tr>
    <tr  id="Row0"> 
      <td width="50%" valign="top"> 
        <h3><%= ejbcawebbean.getText("PREFEREDLANGUAGE") %></h3>
        <h5><%= ejbcawebbean.getText("DEFAULTLANGUAGETOUSE") %></h5>
      </td>
      <td width="50%" valign="top"> 
        <select name="<%= LIST_PREFEREDLANGUAGE %>">
          <% String[] availablelanguages = ejbcawebbean.getAvailableLanguages();                                    
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
          <% availablelanguages = ejbcawebbean.getAvailableLanguages();                                    
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
        <h5><%= ejbcawebbean.getText("THEADMINSTHEMEOFFONTS") %></h5>
      </td>
      <td width="50%" valign="top"> 
        <select name="<%= LIST_THEME %>">
          <% String[] availablethemes = globalconfiguration.getAvailableThemes();                                    
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
          <% String[] possibleentriesperpage = globalconfiguration.getPossibleEntiresPerPage();                                    
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
        <input type="submit" name="<%= BUTTON_SAVE %>" value="<%= ejbcawebbean.getText("SAVE") %>">
        <input type="submit" name="<%= BUTTON_CANCEL %>" value="<%= ejbcawebbean.getText("CANCEL") %>">
      </td>
    </tr>
  </table>
 </form>
<% // Include Footer 
   String footurl =   globalconfiguration.getFootBanner(); %>
   
  <jsp:include page="<%= footurl %>" />
 
</body>
</html>