<%@page contentType="text/html"%>
<%@page errorPage="/errorpage.jsp"  import="se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean,se.anatom.ejbca.ra.raadmin.GlobalConfiguration, 
                se.anatom.ejbca.ra.raadmin.AdminPreference, se.anatom.ejbca.webdist.webconfiguration.GlobalConfigurationDataHandler,
                se.anatom.ejbca.webdist.webconfiguration.WebLanguages"%>

<jsp:useBean id="ejbcawebbean" scope="session" class="se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean" />

<%! // Declarations 

  static final String ACTION                                 = "action";
  static final String ACTION_NEXT_DEFAULT_PREFERENCES        = "actionnextdefaultpreferences";
  static final String ACTION_SAVE                            = "actionsave";
  static final String ACTION_CANCEL                          = "actioncancel";


  static final String BUTTON_NEXT                            = "buttonnext"; 
  static final String BUTTON_PREVIOUS                        = "buttonprevious"; 
  static final String BUTTON_SAVE                            = "buttonsave";
  static final String BUTTON_CANCEL                          = "buttoncancel";

// Textfields used in webconfiguration.jsp
  static final String TEXTFIELD_TITLE                        = "textfieldtitle";
  static final String TEXTFIELD_HEADBANNER                   = "textfieldheadbanner";
  static final String TEXTFIELD_FOOTBANNER                   = "textfieldfootbanner";


  static final String CHECKBOX_ENABLEEEPROFILELIMITATIONS    = "checkboxendentityprofilelimitations"; 
  static final String CHECKBOX_ENABLEAUTHENTICATEDUSERSONLY  = "checkboxauthenticatedusersonly"; 
  static final String CHECKBOX_ENABLEKEYRECOVERY             = "checkboxenablekeyrecovery";
  static final String CHECKBOX_ISSUEHARDWARETOKENS           = "checkboxissuehardwaretokens";

// Lists used in defaultuserprefereces.jsp
  static final String LIST_PREFEREDLANGUAGE                  = "listpreferedlanguage";
  static final String LIST_SECONDARYLANGUAGE                 = "listsecondarylanguage";
  static final String LIST_THEME                             = "listtheme";
  static final String LIST_ENTIESPERPAGE                     = "listentriesperpage";


  static final String CHECKBOX_VALUE             = "true";
%> 
<% 
  // Initialize environment.
  final String THIS_FILENAME                          =  "configuration.jsp";

  GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, "/super_administrator"); 

  String forwardurl = "/" + globalconfiguration .getMainFilename(); 

    // Determine action 
  if( request.getParameter(BUTTON_CANCEL) != null){
       // Cancel current values and go back to old ones.
       ejbcawebbean.reloadGlobalConfiguration ();
      
%> 
 <jsp:forward page="<%= forwardurl %>"/>
<%  }
    if( request.getParameter(BUTTON_PREVIOUS) != null){
      // Return to Webconfiguration
      // Temporatly save preivous settings
        AdminPreference dup = ejbcawebbean.getDefaultAdminPreference();
        if(request.getParameter(LIST_PREFEREDLANGUAGE) != null){
          String preferedlanguage = request.getParameter(LIST_PREFEREDLANGUAGE); 
          dup.setPreferedLanguage(preferedlanguage.trim());
        }
        if(request.getParameter(LIST_SECONDARYLANGUAGE) != null){
          String secondarylanguage = request.getParameter(LIST_SECONDARYLANGUAGE); 
          dup.setSecondaryLanguage(secondarylanguage.trim());
        }
        if(request.getParameter(LIST_THEME) != null){
          String theme = request.getParameter(LIST_THEME); 
          dup.setTheme(theme.trim());
        }
        if(request.getParameter(LIST_ENTIESPERPAGE) != null){
          String entriesperpage = request.getParameter(LIST_ENTIESPERPAGE); 
          dup.setEntriesPerPage(Integer.parseInt(entriesperpage.trim()));
        }
        ejbcawebbean.saveDefaultAdminPreference(dup);
%>
       <%@ include file="webconfiguration.jsp" %>
<%  }

    if( request.getParameter(BUTTON_NEXT) != null){
       // Change global configuration and proceed with default user preferences.
      GlobalConfiguration gc = ejbcawebbean.getGlobalConfiguration();
       if(request.getParameter(TEXTFIELD_TITLE) != null){
         String title = request.getParameter(TEXTFIELD_TITLE); 
         gc.setEjbcaTitle(title);
       }
       if(request.getParameter(TEXTFIELD_HEADBANNER) != null){
         String headbanner = request.getParameter(TEXTFIELD_HEADBANNER); 
         gc.setHeadBanner(headbanner);
       }
       if(request.getParameter(TEXTFIELD_FOOTBANNER) != null){
         String footbanner = request.getParameter(TEXTFIELD_FOOTBANNER); 
         gc.setFootBanner(footbanner);
       }
       if(request.getParameter(CHECKBOX_ENABLEEEPROFILELIMITATIONS) != null){
         gc.setEnableEndEntityProfileLimitations(request.getParameter(CHECKBOX_ENABLEEEPROFILELIMITATIONS).equals(CHECKBOX_VALUE));
       }
       else{
         gc.setEnableEndEntityProfileLimitations(false);
       }
       if(request.getParameter(CHECKBOX_ENABLEAUTHENTICATEDUSERSONLY) != null){
         gc.setEnableAuthenticatedUsersOnly(request.getParameter(CHECKBOX_ENABLEAUTHENTICATEDUSERSONLY).equals(CHECKBOX_VALUE));
       }
       else{
         gc.setEnableAuthenticatedUsersOnly(false);
       }
       if(request.getParameter(CHECKBOX_ENABLEKEYRECOVERY) != null){
         gc.setEnableKeyRecovery(request.getParameter(CHECKBOX_ENABLEKEYRECOVERY).equals(CHECKBOX_VALUE));
       }
       else{
         gc.setEnableKeyRecovery(false);
       }
       if(request.getParameter(CHECKBOX_ISSUEHARDWARETOKENS) != null){
         gc.setIssueHardwareTokens(request.getParameter(CHECKBOX_ISSUEHARDWARETOKENS).equals(CHECKBOX_VALUE));
       }
       else{
         gc.setIssueHardwareTokens(false);
       }


%>  
           <%@ include file="defaultuserpreferences.jsp" %>
<%  }
     if( request.getParameter(BUTTON_SAVE) != null){
        // Save global configuration.
        AdminPreference dup = ejbcawebbean.getDefaultAdminPreference();
        if(request.getParameter(LIST_PREFEREDLANGUAGE) != null){
          String preferedlanguage = request.getParameter(LIST_PREFEREDLANGUAGE); 
          dup.setPreferedLanguage(preferedlanguage.trim());
        }
        if(request.getParameter(LIST_SECONDARYLANGUAGE) != null){
          String secondarylanguage = request.getParameter(LIST_SECONDARYLANGUAGE); 
          dup.setSecondaryLanguage(secondarylanguage.trim());
        }
        if(request.getParameter(LIST_THEME) != null){
          String theme = request.getParameter(LIST_THEME); 
          dup.setTheme(theme.trim());
        }
        if(request.getParameter(LIST_ENTIESPERPAGE) != null){
          String entriesperpage = request.getParameter(LIST_ENTIESPERPAGE); 
          dup.setEntriesPerPage(Integer.parseInt(entriesperpage.trim()));
        }
        ejbcawebbean.saveGlobalConfiguration();
        ejbcawebbean.saveDefaultAdminPreference(dup);
%>          
 <jsp:forward page="<%=forwardurl %>"/>
<%   }
     if(request.getParameter(BUTTON_SAVE) == null &&
        request.getParameter(BUTTON_NEXT) == null &&
        request.getParameter(BUTTON_CANCEL) == null &&
        request.getParameter(BUTTON_PREVIOUS) == null){
 
      // get current global configuration.
        ejbcawebbean.reloadGlobalConfiguration();
%>
           <%@ include file="webconfiguration.jsp" %>
<%  }  %>




