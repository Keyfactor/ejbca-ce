<%@page contentType="text/html"%>
<%@page errorPage="/errorpage.jsp" import="se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean,se.anatom.ejbca.ra.raadmin.GlobalConfiguration
               ,se.anatom.ejbca.authorization.AccessRule, se.anatom.ejbca.webdist.webconfiguration.AuthorizationDataHandler,
                se.anatom.ejbca.webdist.webconfiguration.AccessRulesView, se.anatom.ejbca.authorization.AvailableAccessRules,
                se.anatom.ejbca.authorization.AdminEntity, se.anatom.ejbca.authorization.AdminGroupExistsException,
                se.anatom.ejbca.authorization.AdminGroup, se.anatom.ejbca.webdist.rainterface.RAInterfaceBean, java.util.*"%>

<jsp:useBean id="ejbcawebbean" scope="session" class="se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean" />
<jsp:useBean id="rabean" scope="session" class="se.anatom.ejbca.webdist.rainterface.RAInterfaceBean" />
<jsp:useBean id="cabean" scope="session" class="se.anatom.ejbca.webdist.cainterface.CAInterfaceBean" />

<%! // Declarations  
  static final String ACTION                   = "action";
  static final String ACTION_EDIT_GROUPS       = "editgroup";
  static final String ACTION_EDIT_ACCESSRULES  = "editaccessrules";
  static final String ACTION_EDIT_ADMINENTITIES = "editadminentities";


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
  String includefile = "editadmingroups.jsp";
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
    if( request.getParameter(ACTION).equals(ACTION_EDIT_GROUPS) && request.getParameter(SELECT_ADMINGROUPS) != null){
      if( request.getParameter(BUTTON_EDIT_ADMINS) != null){
          // Display adminentity jsp page.
         admingroup = request.getParameter(SELECT_ADMINGROUPS).split(";");
         if(admingroup != null){
           if(!admingroup[ADMINGROUPNAME].equals("")){ 
              caid = Integer.parseInt(admingroup[CAID]); 
              includefile="editadminentities.jsp"; 
           }
           else{ 
             admingroup= null;
           }  
         }
        if(admingroup == null){   
          includefile="editadmingroups.jsp";     
        }
      }
      if( request.getParameter(BUTTON_EDIT_ACCESSRULES) != null) {
          // Display access rules jsp page.
         admingroup = request.getParameter(SELECT_ADMINGROUPS).split(";");
         if(admingroup != null){
           if(!admingroup[ADMINGROUPNAME].trim().equals("")){
             caid = Integer.parseInt(admingroup[CAID]);
             includefile="editaccessrules.jsp";
           }
           else{ 
            admingroup= null;
           } 
         }
         if(admingroup == null){  
           includefile="editadmingroups.jsp";     
         }
      }
      if( request.getParameter(BUTTON_DELETE_ADMINGROUP) != null) {
          // Delete admingroup and display main group editing page. 
          admingroup = request.getParameter(SELECT_ADMINGROUPS).split(";");
          if(admingroup != null){
            if(!admingroup[ADMINGROUPNAME].trim().equals("")){       
              adh.removeAdminGroup(admingroup[ADMINGROUPNAME], Integer.parseInt(admingroup[CAID]));
            }
          }
          includefile="editadmingroups.jsp";             
      }
      if( request.getParameter(BUTTON_RENAME_SELECTED) != null){ 
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
          includefile="editadmingroups.jsp"; 
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
         includefile="editadmingroups.jsp"; 
      }
    }
    if( request.getParameter(ACTION).equals(ACTION_EDIT_ACCESSRULES)){
         // Display edit access rules page.
       admingroup = request.getParameter(HIDDEN_GROUPNAME).split(";");
       if(admingroup != null){
         if(!admingroup[ADMINGROUPNAME].trim().equals("")){
             caid = Integer.parseInt(admingroup[CAID]);
             includefile="editaccessrules.jsp";
         }
         else{ 
            admingroup= null;
          } 
        }
        if(admingroup == null){            
          includefile="editadmingroups.jsp";    
        }
    }
    if( request.getParameter(ACTION).equals(ACTION_EDIT_ADMINENTITIES)){
         // Display edit admin entity page.
       admingroup = request.getParameter(HIDDEN_GROUPNAME).split(";");
       if(admingroup != null){
         if(!admingroup[ADMINGROUPNAME].trim().equals("")){
           caid = Integer.parseInt(admingroup[CAID]);
           includefile="editadminentities.jsp"; 
         }
          else{ 
            admingroup= null;
          } 
        }
        if(admingroup == null){ 
          includefile="editadmingroups.jsp"; 
        }
     }
  }

 // Include page
  if( includefile.equals("editadmingroups.jsp")){ %>
   <%@ include file="editadmingroups.jsp" %>
<%}
  if( includefile.equals("editadminentities.jsp")){ %>
   <%@ include file="editadminentities.jsp" %> 
<%}
  if( includefile.equals("editaccessrules.jsp")){ %>
    <%@ include file="editaccessrules.jsp" %>
<%}

   // Include Footer 
   String footurl =   globalconfiguration .getFootBanner(); %>
   
  <jsp:include page="<%= footurl %>" />

</body>
</html>
