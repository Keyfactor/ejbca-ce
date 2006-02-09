<%@ page pageEncoding="ISO-8859-1"%>
<%@ page contentType="text/html; charset=@page.encoding@" %>
<%@page errorPage="/errorpage.jsp" import="org.ejbca.ui.web.admin.configuration.EjbcaWebBean,org.ejbca.core.model.ra.raadmin.GlobalConfiguration
               , org.ejbca.ui.web.admin.configuration.AuthorizationDataHandler,
                org.ejbca.ui.web.admin.configuration.AccessRulesView, org.ejbca.core.model.authorization.*,
                org.ejbca.ui.web.admin.rainterface.RAInterfaceBean, java.util.*"%>

<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />
<jsp:useBean id="rabean" scope="session" class="org.ejbca.ui.web.admin.rainterface.RAInterfaceBean" />
<jsp:useBean id="cabean" scope="session" class="org.ejbca.ui.web.admin.cainterface.CAInterfaceBean" />

<%! // Declarations  
  static final String ACTION                        = "action";
  static final String ACTION_EDIT_GROUPS            = "editgroup";
  static final String ACTION_EDIT_ACCESSRULES       = "editaccessrules";
  static final String ACTION_EDIT_ADMINENTITIES     = "editadminentities";
  static final String ACTION_EDIT_BASICACCESSRULES  = "editbasicaccessrules";
  
  static final String MODE                          = "mode"; 
  static final String MODE_BASIC                    = "modebasic"; 
  static final String MODE_ADVANCED                 = "modeadvanced";

  static final String BUTTON_EDIT_ADMINS        = "buttoneditadmins"; 
  static final String BUTTON_EDIT_ACCESSRULES  = "buttoneditaccessrules";
  static final String BUTTON_DELETE_ADMINGROUP  = "buttondeleteadmingroup"; 
  static final String BUTTON_ADD_ADMINGROUP     = "buttonaddadmingroup"; 
  static final String BUTTON_RENAME_SELECTED   = "buttonrenameselected"; 


  static final String SELECT_ADMINGROUPS        = "selectedadmingroups";
  static final String SELECT_CA                 = "selectca";
  static final String TEXTFIELD_GROUPNAME       = "textfieldadmingroupname";
  static final String HIDDEN_GROUPNAME          = "hiddenadmingroupname";



 // Used in editaccessrules.jsp
  static final String BUTTON_ADD_ACCESSRULES      = "addaccessrules"; 
  static final String BUTTON_DELETE_ACCESSRULES   = "deleteaccessrules"; 

  static final String CHECKBOX_DELETEROW    = "checkboxdeleterow";
  static final String CHECKBOX_ADDROW       = "checkboxaddrow"; 
  static final String CHECKBOX_RECURSIVEROW = "checkboxrecursiverow";
  static final String CHECKBOX_VALUE        = "true";
  static final String HIDDEN_DELETEROW      = "hiddendeleterow";
  static final String HIDDEN_ADDRESOURCE    = "hiddenaddresource";
  static final String SELECT_ADDRULE        = "selectaddrule";
  static final String SELECT_MODE           = "selectmode";

// Used in editbasicaccessrules.jsp
  static final String BUTTON_SAVE           = "buttonsave"; 
  static final String BUTTON_CANCEL         = "buttoncancel";

  static final String SELECT_ROLE               = "selectrole";
  static final String SELECT_CAS                = "selectcas";
  static final String SELECT_ENDENTITYRULES     = "selectendentityrules";
  static final String SELECT_ENDENTITYPROFILES  = "selectendentityprofiles";
  static final String SELECT_OTHER              = "selectother";

// Used in editadminentities.jsp
  static final String BUTTON_ADD_ADMINENTITY      = "buttonaddadminentity"; 
  static final String BUTTON_DELETE_ADMINENTITIES = "buttondeleteadminentities"; 

  static final String SELECT_MATCHWITH           = "selectmatchwith";
  static final String SELECT_MATCHTYPE           = "selectmatchtype";
  static final String TEXTFIELD_MATCHVALUE       = "textfieldmatchvalue";
  static final String CHECKBOX_DELETE_ADMINENTITY = "checkboxdeleteadminentity";
  static final String HIDDEN_MATCHWITH           = "hiddenmatchwith";
  static final String HIDDEN_MATCHTYPE           = "hiddenmatchtype";
  static final String HIDDEN_MATCHVALUE          = "hiddenmatchvalue";

  static final int    ADMINGROUPNAME             = 0;
  static final int    CAID                       = 1;

%>
<% 
  boolean admingroupexists = false;

  String[] admingroup = null;
  // Initialize environment
  String includefile = "editadmingroups.jspf";
  GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, "/system_functionality/edit_administrator_privileges"); 
                                            cabean.initialize(request, ejbcawebbean);       
                                            rabean.initialize(request, ejbcawebbean); 
 
  String THIS_FILENAME            =  globalconfiguration.getAuthorizationPath()  + "/administratorprivileges.jsp";
  AuthorizationDataHandler adh    = ejbcawebbean.getAuthorizationDataHandler(); 
  HashMap  caidtonamemap  = cabean.getCAIdToNameMap();
  int caid = 0;
%>
<html>
<head>
  <title><%= globalconfiguration .getEjbcaTitle() %></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>">
  <link rel=STYLESHEET href="<%= ejbcawebbean.getCssFile() %>">
  <script language=javascript src="<%= globalconfiguration .getAdminWebPath() %>ejbcajslib.js"></script>
</head>
<body>

<%  // Determine action 

  if( request.getParameter(ACTION) != null){
    if( request.getParameter(ACTION).equals(ACTION_EDIT_GROUPS)){
      if( request.getParameter(BUTTON_EDIT_ADMINS) != null && request.getParameter(SELECT_ADMINGROUPS) != null){
          // Display adminentity jsp page.
         admingroup = request.getParameter(SELECT_ADMINGROUPS).split(";");
         if(admingroup != null){
           if(!admingroup[ADMINGROUPNAME].equals("")){ 
              caid = Integer.parseInt(admingroup[CAID]); 
              includefile="editadminentities.jspf"; 
           }
           else{ 
             admingroup= null;
           }  
         }
        if(admingroup == null){   
          includefile="editadmingroups.jspf";     
        }
      }
      if( request.getParameter(BUTTON_EDIT_ACCESSRULES) != null && request.getParameter(SELECT_ADMINGROUPS) != null) {
          // Display access rules jsp page.
         admingroup = request.getParameter(SELECT_ADMINGROUPS).split(";");
         if(admingroup != null){
           if(!admingroup[ADMINGROUPNAME].trim().equals("")){
             caid = Integer.parseInt(admingroup[CAID]);
             includefile="editaccessrules.jspf";
           }
           else{ 
            admingroup= null;
           } 
         }
         if(admingroup == null){  
           includefile="editadmingroups.jspf";     
         }
      }
      if( request.getParameter(BUTTON_DELETE_ADMINGROUP) != null && request.getParameter(SELECT_ADMINGROUPS) != null) {
          // Delete admingroup and display main group editing page. 
          admingroup = request.getParameter(SELECT_ADMINGROUPS).split(";");
          if(admingroup != null){
            if(!admingroup[ADMINGROUPNAME].trim().equals("")){       
              adh.removeAdminGroup(admingroup[ADMINGROUPNAME], Integer.parseInt(admingroup[CAID]));
            }
          }
          includefile="editadmingroups.jspf";             
      }
      if( request.getParameter(BUTTON_RENAME_SELECTED) != null && request.getParameter(SELECT_ADMINGROUPS) != null){ 
         // Rename selected admingroup and display main group editing page.
       String newadmingroup = request.getParameter(TEXTFIELD_GROUPNAME);
       String[] oldadmingroup = request.getParameter(SELECT_ADMINGROUPS).split(";");
       if(oldadmingroup != null && newadmingroup != null){
         if(!newadmingroup.trim().equals("") && !oldadmingroup[ADMINGROUPNAME].trim().equals("")){    
             try{
               adh.renameAdminGroup(oldadmingroup[ADMINGROUPNAME], newadmingroup, Integer.parseInt(oldadmingroup[CAID]));
             }catch(AdminGroupExistsException e){ admingroupexists = true;}
         }
       }      
          includefile="editadmingroups.jspf"; 
      }
      if( request.getParameter(BUTTON_ADD_ADMINGROUP) != null){
         // Add admingroup and display main group editing page.
         String admingroupname = request.getParameter(TEXTFIELD_GROUPNAME);
         caid = Integer.parseInt(request.getParameter(SELECT_CA));
         if(admingroupname != null){
           if(!admingroupname.trim().equals("") && admingroupname.indexOf(';') == -1){
             try{
               System.out.println("Trying to add " + admingroupname.trim() + ", " + caid + "\n\n\n");
               adh.addAdminGroup(admingroupname.trim(), caid);
             }catch(AdminGroupExistsException e){ admingroupexists = true; }
           }      
         }
         includefile="editadmingroups.jspf"; 
      }
    }
    if( request.getParameter(ACTION).equals(ACTION_EDIT_ACCESSRULES)){
         // Display edit access rules page.
       admingroup = request.getParameter(HIDDEN_GROUPNAME).split(";");
       if(admingroup != null){
         if(!admingroup[ADMINGROUPNAME].trim().equals("")){
             caid = Integer.parseInt(admingroup[CAID]);
             includefile="editaccessrules.jspf";
             if(request.getParameter(MODE) != null && request.getParameter(MODE).equals(MODE_BASIC)){

                if(request.getParameter(BUTTON_SAVE) != null){
                  // get role
                  int role = Integer.parseInt(request.getParameter(SELECT_ROLE));
                  // get currentcas
                  ArrayList currentcas = new ArrayList();
                  String[] values = request.getParameterValues(SELECT_CAS);
                  if(values != null){
                    for(int i=0;i < values.length; i++){
                      currentcas.add(new Integer(values[i]));
                    }
                  }  
                  // get current end entity rules
                  ArrayList currentententityrules = new ArrayList();
                  values = request.getParameterValues(SELECT_ENDENTITYRULES);
                  if(values != null){
                    for(int i=0;i < values.length; i++){
                      currentententityrules.add(new Integer(values[i]));
                    } 
                  }
                  // get current end entity profiles
                  ArrayList currentententityprofiles = new ArrayList();
                  values = request.getParameterValues(SELECT_ENDENTITYPROFILES);
                  if(values != null){
                    for(int i=0;i < values.length; i++){
                      currentententityprofiles.add(new Integer(values[i]));
                    }
                  } 
                  // get other rules
                  ArrayList currentother = new ArrayList();
                  values = request.getParameterValues(SELECT_OTHER);
                  if(values != null){
                    for(int i=0;i < values.length; i++){
                       currentother.add(new Integer(values[i]));
                    } 
                  }

                  BasicAccessRuleSetDecoder barsd = new BasicAccessRuleSetDecoder(role, currentcas, currentententityrules, currentententityprofiles,currentother);
                   
                  adh.replaceAccessRules(admingroup[ADMINGROUPNAME],caid,barsd.getCurrentAdvancedRuleSet());  

                  includefile="editadmingroups.jspf";    
                }
                if(request.getParameter(BUTTON_SAVE) != null){
                  includefile="editadmingroups.jspf";    
                }
             }
      
         
         }
         else{ 
            admingroup= null;
          } 
        }
        if(admingroup == null){            
          includefile="editadmingroups.jspf";    
        }
    }
    if( request.getParameter(ACTION).equals(ACTION_EDIT_ADMINENTITIES)){
         // Display edit admin entity page.
       admingroup = request.getParameter(HIDDEN_GROUPNAME).split(";");
       if(admingroup != null){
         if(!admingroup[ADMINGROUPNAME].trim().equals("")){
           caid = Integer.parseInt(admingroup[CAID]);
           includefile="editadminentities.jspf"; 
         }
          else{ 
            admingroup= null;
          } 
        }
        if(admingroup == null){ 
          includefile="editadmingroups.jspf"; 
        }
     }
  }

 // Include page
  if( includefile.equals("editadmingroups.jspf")){ %>
   <%@ include file="editadmingroups.jspf" %>
<%}
  if( includefile.equals("editadminentities.jspf")){ %>
   <%@ include file="editadminentities.jspf" %> 
<%}
  if( includefile.equals("editaccessrules.jspf")){ %>
    <%@ include file="editaccessrules.jspf" %>
<%}

   // Include Footer 
   String footurl =   globalconfiguration .getFootBanner(); %>
   
  <jsp:include page="<%= footurl %>" />

</body>
</html>
