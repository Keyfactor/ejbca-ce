<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib uri="http://www.owasp.org/index.php/Category:OWASP_CSRFGuard_Project/Owasp.CsrfGuard.tld" prefix="csrf" %>
<%@ page pageEncoding="ISO-8859-1"%>
<% response.setContentType("text/html; charset="+org.ejbca.config.WebConfiguration.getWebContentEncoding()); %>
<%@page  errorPage="errorpage.jsp" import="org.ejbca.config.GlobalConfiguration, 
    org.ejbca.ui.web.RequestHelper,org.ejbca.core.model.ra.raadmin.AdminPreference,
    org.ejbca.core.model.authorization.AccessRulesConstants"%>

<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />
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
  static final String CHECKBOX_CASTATUSFIRSTPAGE			 = "castatusfirstpage";
  static final String CHECKBOX_PUBQSTATUSFIRSTPAGE 			 = "pubqstatusfirstpage";
  
  static final String CHECKBOX_VALUE						 = "true";

%>
<% 
   // Initialize environment.
  GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, AccessRulesConstants.ROLE_ADMINISTRATOR); 

  final String THIS_FILENAME                          = globalconfiguration.getAdminWebPath() + "mypreferences.jsp";

  String forwardurl = globalconfiguration.getMainFilename(); 

  RequestHelper.setDefaultCharacterEncoding(request);
    // Determine action 
  if( request.getParameter(BUTTON_CANCEL) != null){
       // Cancel current values and go back to old ones.
       //ejbcawebbean.initialize(request,"/administrator");
      
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
        
        String value = request.getParameter(CHECKBOX_CASTATUSFIRSTPAGE); 
        dup.setFrontpageCaStatus(value != null && CHECKBOX_VALUE.equals(value.trim()));
        
        value = request.getParameter(CHECKBOX_PUBQSTATUSFIRSTPAGE); 
        dup.setFrontpagePublisherQueueStatus(value != null && CHECKBOX_VALUE.equals(value.trim()));
        
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
  <title><c:out value="<%= globalconfiguration.getEjbcaTitle() %>" /></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>" />
  <link rel="stylesheet" type="text/css" href="<c:out value='<%=ejbcawebbean.getCssFile() %>' />" />
  <script type="text/javascript" src="<%= globalconfiguration.getAdminWebPath() %>ejbcajslib.js"></script>
</head>

<body>

<h1><c:out value="<%= ejbcawebbean.getText(\"ADMINISTRATORPREFERENCES\") %>" /></h1>

<h2><c:out value="<%= ejbcawebbean.getText(\"FORADMIN\")+\" \" + ejbcawebbean.getUsersCommonName() %>" /></h2>

<form name="defaultmypreferences" method="post" action="<%=THIS_FILENAME %>">
  <input type="hidden" name="<csrf:tokenname/>" value="<csrf:tokenvalue/>"/>
  <table class="action" id="config" width="100%" border="0" cellspacing="3" cellpadding="3">

    <tr id="Row0"> 
      <td width="50%" valign="top"> 
        &nbsp;
      </td>
      <td width="50%" valign="top" align="right"> 
        &nbsp;
      </td>
    </tr>
    
    <tr  id="Row1"> 
      <td width="50%" valign="top"> 
        <h3><c:out value="<%= ejbcawebbean.getText(\"PREFEREDLANGUAGE\") %>" /></h3>
        <p class="help"><c:out value="<%= ejbcawebbean.getText(\"PREFEREDLANGUAGE_HELP\") %>" /></p>
      </td>
      <td width="50%" valign="top"> 
        <select name="<%= LIST_PREFEREDLANGUAGE %>">
          <% String[] availablelanguages = ejbcawebbean.getAvailableLanguages();
             String[] languagesenglishnames = ejbcawebbean.getLanguagesEnglishNames();
             String[] languagesnativenames = ejbcawebbean.getLanguagesNativeNames();
             int preferedlanguage = dup.getPreferedLanguage();
             for(int i = 0; i < availablelanguages.length; i++){
          %>   <option <% if(i == preferedlanguage){ %> selected <% } %>
                     value='<c:out value="<%= availablelanguages[i] %>"/>'><c:out value="<%= languagesenglishnames[i] %>" />
                     <% if (languagesenglishnames[i] != null && languagesnativenames[i] != null) { %> - <% } %>
                     <c:out value="<%= languagesnativenames[i] %>" />
                     [<c:out value="<%= availablelanguages[i] %>"/>]</option>
          <% } %>
        </select>
      </td>
    </tr>
    <tr id="Row1"> 
      <td width="50%" valign="top"> 
        <h3><c:out value="<%= ejbcawebbean.getText(\"SECONDARYLANGUAGE\") %>" /></h3>
        <p class="help"><c:out value="<%= ejbcawebbean.getText(\"SECONDARYLANGUAGE_HELP\") %>" /></p>
      </td>
      <td width="50%" valign="top"> 
        <select name="<%= LIST_SECONDARYLANGUAGE %>">
          <% //availablelanguages = ejbcawebbean.getAvailableLanguages();                                    
             //languagesenglishnames = ejbcawebbean.getLanguagesEnglishNames();
             //languagesnativenames = ejbcawebbean.getLanguagesNativeNames();
             int secondarylanguage = dup.getSecondaryLanguage();
             for(int i = 0; i < availablelanguages.length; i++){
          %>   <option <% if(i == secondarylanguage){ %> selected <% } %>
                     value='<c:out value="<%= availablelanguages[i] %>"/>'><c:out value="<%= languagesenglishnames[i] %>" />
                     <% if (languagesenglishnames[i] != null && languagesnativenames[i] != null) { %> - <% } %>
                     <c:out value="<%= languagesnativenames[i] %>" />
                     [<c:out value="<%= availablelanguages[i] %>"/>]</option>
          <% } %>
        </select>
      </td>
    </tr>
    <tr  id="Row0"> 
      <td width="50%" valign="top"> 
        <h3><c:out value="<%= ejbcawebbean.getText(\"THEME\") %>" /></h3>
        <p class="help"><c:out value="<%= ejbcawebbean.getText(\"THEME_HELP\") %>" /></p>
      </td>
      <td width="50%" valign="top"> 
        <select name="<%= LIST_THEME %>">
          <% String[] availablethemes = globalconfiguration.getAvailableThemes();                                    
             String theme;
             try {
             	theme = ejbcawebbean.getCleanOption(dup.getTheme(), availablethemes);
             } catch(IllegalArgumentException e) {
                 %>
                 <c:out value="Chosen theme not found. This may be due to an attempted XSS attack. Setting default theme."/>
             	<%
             	theme = availablethemes[0];
             }
             if(availablethemes != null){
               for(int i = 0; i < availablethemes.length; i++){
          %>     <option <% if(availablethemes[i].equals(theme)){ %> selected <% } %>
                     value='<c:out value="<%= availablethemes[i] %>"/>'><c:out value="<%= availablethemes[i] %>" /></option>
          <%   }
             }%>
        </select>
      </td>
    </tr>
    <tr  id="Row1"> 
      <td width="49%" valign="top"> 
        <h3><c:out value="<%= ejbcawebbean.getText(\"NUMBEROFRECORDSPERPAGE\") %>" /></h3>
        <p class="help"><c:out value="<%= ejbcawebbean.getText(\"NUMBEROFRECORDSPERPAGE_HELP\") %>" /></p>
      </td>
      <td width="51%" valign="top"> 
        <select name="<%= LIST_ENTIESPERPAGE %>" class="number">
          <% String[] possibleentriesperpage = globalconfiguration.getPossibleEntiresPerPage();                                    
             int entriesperpage = Integer.parseInt(ejbcawebbean.getCleanOption(String.valueOf(dup.getEntriesPerPage()), possibleentriesperpage));
             for(int i = 0; i < possibleentriesperpage.length; i++){
          %>   <option <% if(Integer.parseInt(possibleentriesperpage[i]) == entriesperpage){ %> selected <% } %>
                  value='<c:out value="<%= Integer.parseInt(possibleentriesperpage[i]) %>"/>'><c:out value="<%= possibleentriesperpage[i] %>" /></option>
          <% } %>
        </select>
      </td>
    </tr>
    <tr  id="Row0"> 
      <td width="49%" valign="top"> 
        <h3><c:out value="<%= ejbcawebbean.getText(\"CASTATUSONHOMEPAGE\") %>" /></h3>
        <p class="help"><c:out value="<%= ejbcawebbean.getText(\"CASTATUSONHOMEPAGE_HELP\") %>" /></p>
      </td>
      <td width="51%" valign="top"> 
        <input name="<%= CHECKBOX_CASTATUSFIRSTPAGE %>" type="checkbox" value="<%=CHECKBOX_VALUE%>" <%=dup.getFrontpageCaStatus() ? "checked=\"checked\"" : ""%>
        	id="<%=CHECKBOX_CASTATUSFIRSTPAGE%>" />
         <label for="<%=CHECKBOX_CASTATUSFIRSTPAGE%>"><c:out value="<%= ejbcawebbean.getText(\"SHOW\") %>" /></label>
      </td>
    </tr>
    <tr  id="Row0"> 
      <td width="49%" valign="top"> 
        <h3><c:out value="<%= ejbcawebbean.getText(\"PUBLISHERQUEUESTATUSON\") %>" /></h3>
        <p class="help"><c:out value="<%= ejbcawebbean.getText(\"PUBLISHERQUEUESTATUSON_HELP\") %>" /></p>
      </td>
      <td width="51%" valign="top"> 
        <input name="<%= CHECKBOX_PUBQSTATUSFIRSTPAGE %>" type="checkbox" value="<%=CHECKBOX_VALUE%>" <%=dup.getFrontpagePublisherQueueStatus() ? "checked=\"checked\"" : ""%>
        	id="<%=CHECKBOX_PUBQSTATUSFIRSTPAGE%>" />
        <label for="<%=CHECKBOX_PUBQSTATUSFIRSTPAGE%>"><c:out value="<%= ejbcawebbean.getText(\"SHOW\") %>" /></label>
      </td>
    </tr>
    
    <%-- Form buttons --%>
    
    <tr  id="Row1"> 
      <td width="49%" valign="top">&nbsp;</td>
      <td width="51%" valign="top"> 
        <input type="submit" name="<%= BUTTON_SAVE %>" value='<c:out value="<%= ejbcawebbean.getText(\"SAVE\") %>"/>'>
        &nbsp;&nbsp;&nbsp;
        <input type="submit" name="<%= BUTTON_CANCEL %>" value='<c:out value="<%= ejbcawebbean.getText(\"CANCEL\") %>"/>'>
      </td>
    </tr>
    
  </table>
  
</form>
<% // Include Footer 
   String footurl =   globalconfiguration.getFootBanner(); %>
   
  <jsp:include page="<%= footurl %>" />
 
</body>
</html>
