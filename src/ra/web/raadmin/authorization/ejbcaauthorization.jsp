<%@page contentType="text/html"%>
<%@page errorPage="/errorpage.jsp" import="se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean,se.anatom.ejbca.webdist.webconfiguration.GlobalConfiguration
               ,se.anatom.ejbca.ra.authorization.AccessRule, se.anatom.ejbca.webdist.webconfiguration.AuthorizationDataHandler,
                se.anatom.ejbca.ra.authorization.UserEntity, se.anatom.ejbca.ra.authorization.UsergroupExistsException"%>

<jsp:useBean id="ejbcawebbean" scope="session" class="se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean" />
<jsp:setProperty name="ejbcawebbean" property="*" /> 

<%! // Declarations  
  static final String ACTION                   = "action";
  static final String ACTION_EDIT_GROUPS       = "editgroup";
  static final String ACTION_EDIT_ACCESSRULES  = "editaccessrules";
  static final String ACTION_EDIT_USERENTITIES = "edituserentities";


  static final String BUTTON_EDIT_USERS        = "buttoneditusers"; 
  static final String BUTTON_EDIT_ACCESSRULES  = "buttoneditaccessrules";
  static final String BUTTON_DELETE_USERGROUP  = "buttondeleteusergroup"; 
  static final String BUTTON_ADD_USERGROUP     = "buttonaddusergroup"; 
  static final String BUTTON_RENAME_SELECTED   = "buttonrenameselected"; 


  static final String SELECT_USERGROUPS        = "selectedusergroups";
  static final String TEXTFIELD_GROUPNAME      = "textfieldusergroupname";
  static final String HIDDEN_GROUPNAME         = "hiddenusergroupname";

 // Used in editaccessrules.jsp
  static final String BUTTON_ADD_ACCESSRULES      = "addaccessrules"; 
  static final String BUTTON_DELETE_ACCESSRULES   = "deleteaccessrules"; 
  static final String BUTTON_NEXT_ACCESSRULES     = "buttonnextaccessrules";
  static final String BUTTON_PREVIOUS_ACCESSRULES = "buttonpreviousaccessrules";

  static final String CHECKBOX_DELETEROW    = "checkboxdeleterow";
  static final String CHECKBOX_ADDROW       = "checkboxaddrow"; 
  static final String CHECKBOX_RECURSIVEROW = "checkboxrecursiverow";
  static final String CHECKBOX_VALUE        = "true";
  static final String HIDDEN_DELETEROW      = "hiddendeleterow";
  static final String HIDDEN_ADDDIRECTORY   = "hiddenadddirectory";
  static final String HIDDEN_RECORDNUMBER   = "hiddenrecordnumber"; 
  static final String SELECT_ADDRULE        = "selectaddrule";

// Used in edituserentities.jsp
  static final String BUTTON_ADD_USERENTITY      = "buttonadduserentity"; 
  static final String BUTTON_DELETE_USERENTITIES = "buttondeleteuserentities"; 

  static final String SELECT_MATCHWITH           = "selectmatchwith";
  static final String SELECT_MATCHTYPE           = "selectmatchtype";
  static final String TEXTFIELD_MATCHVALUE       = "textfieldmatchvalue";
  static final String CHECKBOX_DELETE_USERENTITY = "checkboxdeleteuserentity";
  static final String HIDDEN_MATCHWITH           = "hiddenmatchwith";
  static final String HIDDEN_MATCHTYPE           = "hiddenmatchtype";
  static final String HIDDEN_MATCHVALUE          = "hiddenmatchvalue";

  String usergroup = null;

%>
<% 
  boolean usergroupexists = false;

  // Initialize environment
  String includefile = null;
  GlobalConfiguration globalconfiguration =ejbcawebbean.initialize(request); 
  String THIS_FILENAME            =  globalconfiguration .getAuthorizationPath()  + "/ejbcaauthorization.jsp";
  AuthorizationDataHandler adh    = ejbcawebbean.getAuthorizationDataHandler(); %>
<html>
<head>
  <title><%= globalconfiguration .getEjbcaTitle() %></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>">
  <link rel=STYLESHEET href="<%= ejbcawebbean.getCssFile() %>">
  <script language=javascript src="<%= globalconfiguration .getRaAdminPath() %>ejbcajslib.js"></script>
</head>
<body>

<%  // Determine action 
  if( request.getParameter(ACTION) != null){
    if( request.getParameter(ACTION).equals(ACTION_EDIT_GROUPS)){
      if( request.getParameter(BUTTON_EDIT_USERS) != null){
          // Display userentity jsp page.
         usergroup = request.getParameter(SELECT_USERGROUPS);
         if(usergroup != null){
           if(!usergroup.trim().equals("")){
             includefile="edituserentities.jsp"; 
           } 
          else{ 
            usergroup= null;
          } 
        }
        if(usergroup == null){   
          includefile="editusergroups.jsp";     
        }
      }
      if( request.getParameter(BUTTON_EDIT_ACCESSRULES) != null) {
          // Display access rules jsp page.
         usergroup = request.getParameter(SELECT_USERGROUPS);
         if(usergroup != null){
           if(!usergroup.trim().equals("")){
             includefile="editaccessrules.jsp";
           }
           else{ 
            usergroup= null;
           } 
         }
         if(usergroup == null){  
           includefile="editusergroups.jsp";     
         }
      }
      if( request.getParameter(BUTTON_DELETE_USERGROUP) != null) {
          // Delete usergroup and display main group editing page. 
          usergroup = request.getParameter(SELECT_USERGROUPS);
          if(usergroup != null){
            if(!usergroup.trim().equals("")){
              adh.removeUserGroup(usergroup);
            }
          }
          includefile="editusergroups.jsp";             
      }
      if( request.getParameter(BUTTON_RENAME_SELECTED) != null){ 
         // Rename selected usergroup and display main group editing page.
       String newusergroup = request.getParameter(TEXTFIELD_GROUPNAME);
       String oldusergroup = request.getParameter(SELECT_USERGROUPS);
       if(oldusergroup != null && newusergroup != null){
         if(!newusergroup.trim().equals("") && !oldusergroup.trim().equals("")){
           try{
             adh.renameUserGroup(oldusergroup, newusergroup);
           }catch(UsergroupExistsException e){ usergroupexists = true;}
         }
       }      
          includefile="editusergroups.jsp"; 
      }
      if( request.getParameter(BUTTON_ADD_USERGROUP) != null){
         // Add usergroup and display main group editing page.
         usergroup = request.getParameter(TEXTFIELD_GROUPNAME);
         if(usergroup != null){
           if(!usergroup.trim().equals("")){
             try{
               adh.addUserGroup(usergroup);
             }catch(UsergroupExistsException e){ usergroupexists = true; }
           }      
         }
          includefile="editusergroups.jsp"; 
      }
    }
    if( request.getParameter(ACTION).equals(ACTION_EDIT_ACCESSRULES)){
         // Display edit access rules page.
       usergroup = request.getParameter(HIDDEN_GROUPNAME);
       if(usergroup != null){
         if(!usergroup.trim().equals("")){
             includefile="editaccessrules.jsp";
         }
         else{ 
            usergroup= null;
          } 
        }
        if(usergroup == null){            
          includefile="editusergroups.jsp";    
        }
    }
    if( request.getParameter(ACTION).equals(ACTION_EDIT_USERENTITIES)){
         // Display edit user entity page.
       usergroup = request.getParameter(HIDDEN_GROUPNAME);
       if(usergroup != null){
         if(!usergroup.trim().equals("")){
           includefile="edituserentities.jsp"; 
         }
          else{ 
            usergroup= null;
          } 
        }
        if(usergroup == null){ 
          includefile="editusergroups.jsp"; 
        }
     }
  }
  else{ 
    // Display main user group editing page. 
          includefile="editusergroups.jsp"; 

  }
 // Include page
  if( includefile.equals("editusergroups.jsp")){ %>
   <%@ include file="editusergroups.jsp" %>
<%}
  if( includefile.equals("edituserentities.jsp")){ %>
   <%@ include file="edituserentities.jsp" %> 
<%}
  if( includefile.equals("editaccessrules.jsp")){ %>
    <%@ include file="editaccessrules.jsp" %>
<%}

   // Include Footer 
   String footurl =   globalconfiguration .getFootBanner(); %>
   
  <jsp:include page="<%= footurl %>" />

</body>
</html>
