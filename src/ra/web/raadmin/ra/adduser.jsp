<html> 
<%@page contentType="text/html"%>
<%@page  errorPage="/errorpage.jsp" import="se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean,se.anatom.ejbca.ra.GlobalConfiguration, se.anatom.ejbca.webdist.rainterface.UserView,
                 se.anatom.ejbca.webdist.rainterface.RAInterfaceBean, se.anatom.ejbca.webdist.rainterface.ProfileDataHandler, se.anatom.ejbca.ra.raadmin.Profile, se.anatom.ejbca.ra.UserDataRemote,
                 javax.ejb.CreateException, java.rmi.RemoteException" %>
<jsp:useBean id="ejbcawebbean" scope="session" class="se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean" />
<jsp:setProperty name="ejbcawebbean" property="*" /> 
<jsp:useBean id="rabean" scope="session" class="se.anatom.ejbca.webdist.rainterface.RAInterfaceBean" />
<jsp:setProperty name="rabean" property="*" /> 
<%! // Declarations

  static final String ACTION                   = "action";
  static final String ACTION_ADDUSER           = "adduser";

  static final String BUTTON_ADDUSER          = "buttonadduser"; 
  static final String BUTTON_RESET            = "buttonreset"; 
  static final String BUTTON_RELOAD           = "buttonreload";

  static final String TEXTFIELD_USERNAME          = "textfieldusername";
  static final String TEXTFIELD_PASSWORD          = "textfieldpassword";
  static final String TEXTFIELD_CONFIRMPASSWORD   = "textfieldconfirmpassword";
  static final String TEXTFIELD_COMMONNAME        = "textfieldcommonname";
  static final String TEXTFIELD_ORGANIZATIONUNIT  = "textfieldorganizationunit";
  static final String TEXTFIELD_ORGANIZATION      = "textfieldorganization";
  static final String TEXTFIELD_LOCALE            = "textfieldlocale";
  static final String TEXTFIELD_STATE             = "textfieldstate";
  static final String TEXTFIELD_COUNTRY           = "textfieldcountry";
  static final String TEXTFIELD_EMAIL             = "textfieldemail";

  static final String SELECT_PROFILE              = "selectprofile";

  static final String CHECKBOX_CLEARTEXTPASSWORD          = "checkboxcleartextpassword";
  static final String CHECKBOX_TYPEENDUSER                = "checkboxtypeenduser";
  static final String CHECKBOX_TYPERA                     = "checkboxtypera";
  static final String CHECKBOX_TYPERAADMIN                = "checkboxtyperaadmin";
  static final String CHECKBOX_TYPECA                     = "checkboxtypeca";
  static final String CHECKBOX_TYPECAADMIN                = "checkboxtypecaadmin";
  static final String CHECKBOX_TYPEROOTCA                 = "checkboxtyperootca";

  static final String CHECKBOX_REQUIRED_USERNAME          = "checkboxrequiredusername";
  static final String CHECKBOX_REQUIRED_PASSWORD          = "checkboxrequiredpassword";
  static final String CHECKBOX_REQUIRED_CLEARTEXTPASSWORD = "checkboxrequiredcleartextpassword";
  static final String CHECKBOX_REQUIRED_COMMONNAME        = "checkboxrequiredcommonname";
  static final String CHECKBOX_REQUIRED_ORGANIZATIONUNIT  = "checkboxrequiredorganizationunit";
  static final String CHECKBOX_REQUIRED_ORGANIZATION      = "checkboxrequiredorganization";
  static final String CHECKBOX_REQUIRED_LOCALE            = "checkboxrequiredlocale";
  static final String CHECKBOX_REQUIRED_STATE             = "checkboxrequiredstate";
  static final String CHECKBOX_REQUIRED_COUNTRY           = "checkboxrequiredcountry";
  static final String CHECKBOX_REQUIRED_EMAIL             = "checkboxrequiredemail";
  static final String CHECKBOX_REQUIRED_TYPEENDUSER       = "checkboxrequiredrequiredtypeenduser";
  static final String CHECKBOX_REQUIRED_TYPERA            = "checkboxrequiredtypera";
  static final String CHECKBOX_REQUIRED_TYPERAADMIN       = "checkboxrequiredtyperaadmin";
  static final String CHECKBOX_REQUIRED_TYPECA            = "checkboxrequiredtypeca";
  static final String CHECKBOX_REQUIRED_TYPECAADMIN       = "checkboxrequiredtypecaadmin";
  static final String CHECKBOX_REQUIRED_TYPEROOTCA        = "checkboxrequiredtyperootca";

  static final String CHECKBOX_VALUE             = "true";

  static final String USER_PARAMETER           = "userparameter";
  static final String SUBJECTDN_PARAMETER      = "subjectdnparameter";

  static final String VIEWUSER_LINK            = "viewuser.jsp";
  static final String EDITUSER_LINK            = "edituser.jsp";

  static final String HIDDEN_USERNAME           = "hiddenusername";

%><%
  // Initialize environment.
  GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request); 

  String THIS_FILENAME            =  globalconfiguration.getRaPath()  + "/adduser.jsp";
  String[][][] profiles            = rabean.getProfilesAsString();
  String[] profilenames            = rabean.getProfileNames();
  String lastprofilename        = ejbcawebbean.getLastProfile();
  boolean userexists               = false;
  boolean useradded                = false;
  boolean useoldprofile            = false;
  String[][] oldprofile            = null;

  if( request.getParameter(ACTION) != null){
    if( request.getParameter(ACTION).equals(ACTION_ADDUSER)){
      if( request.getParameter(BUTTON_ADDUSER) != null || request.getParameter(BUTTON_RELOAD) != null ){
         String[] newuser = new String[UserView.NUMBEROF_USERFIELDS];
         String oldprofilename = null;
 
         // Get previous chosen profile.
         String index = request.getParameter(SELECT_PROFILE); 
         if(index != null){
           oldprofilename = profilenames[Integer.parseInt(index)];       
           ejbcawebbean.setLastProfile(oldprofilename);
         }

         if(oldprofilename != null){
           oldprofile = rabean.getProfileAsString(oldprofilename);
           newuser[UserView.PROFILE]= oldprofilename;
         }

         String value = request.getParameter(TEXTFIELD_USERNAME);
         if(value !=null){
           value=value.trim(); 
           if(!value.equals("")){
             newuser[UserView.USERNAME] = value;
             oldprofile[Profile.USERNAME][Profile.VALUE] = value;
           }
         }
         value = request.getParameter(TEXTFIELD_PASSWORD);
         if(value !=null){
           value=value.trim(); 
           if(!value.equals("")){
             newuser[UserView.PASSWORD] = value;              
             oldprofile[Profile.PASSWORD][Profile.VALUE] = value;
           }
         }
         value = request.getParameter(CHECKBOX_CLEARTEXTPASSWORD);
         if(value !=null){
           if(value.equals(CHECKBOX_VALUE)){
             newuser[UserView.CLEARTEXTPASSWORD] = UserView.TRUE;
             oldprofile[Profile.PASSWORD][Profile.VALUE] = Profile.TRUE;             
           }
           else{
               newuser[UserView.CLEARTEXTPASSWORD] = UserView.FALSE;
               oldprofile[Profile.PASSWORD][Profile.VALUE] = Profile.FALSE;    
             }
           }
           value = request.getParameter(TEXTFIELD_COMMONNAME);
           if(value !=null){
             value=value.trim(); 
             if(!value.equals("")){
               newuser[UserView.COMMONNAME] = value;
               oldprofile[Profile.COMMONNAME][Profile.VALUE] = value;  
             }
           }
           value = request.getParameter(TEXTFIELD_ORGANIZATIONUNIT);
           if(value !=null){
             value=value.trim(); 
             if(!value.equals("")){
               newuser[UserView.ORGANIZATIONUNIT] = value;
               oldprofile[Profile.ORGANIZATIONUNIT][Profile.VALUE] = value;  
             }
           }
           value = request.getParameter(TEXTFIELD_ORGANIZATION);
           if(value !=null){
             value=value.trim(); 
             if(!value.equals("")){
               newuser[UserView.ORGANIZATION] = value;
               oldprofile[Profile.ORGANIZATION][Profile.VALUE] = value;  
             }
           }
           value = request.getParameter(TEXTFIELD_LOCALE);
           if(value !=null){
             value=value.trim(); 
             if(!value.equals("")){
               newuser[UserView.LOCALE] = value;
               oldprofile[Profile.LOCALE][Profile.VALUE] = value;  
             }
           }
           value = request.getParameter(TEXTFIELD_STATE);
           if(value !=null){
             value=value.trim(); 
             if(!value.equals("")){
               newuser[UserView.STATE] = value;
               oldprofile[Profile.STATE][Profile.VALUE] = value;  
             }
           }
           value = request.getParameter(TEXTFIELD_COUNTRY);
           if(value !=null){
             value=value.trim(); 
             if(!value.equals("")){
               newuser[UserView.COUNTRY] = value;
               oldprofile[Profile.COUNTRY][Profile.VALUE] = value;  
             }
           }
           value = request.getParameter(TEXTFIELD_EMAIL);
           if(value !=null){
             value=value.trim(); 
             if(!value.equals("")){
               newuser[UserView.EMAIL] = value;
               oldprofile[Profile.EMAIL][Profile.VALUE] = value;  
             }
           }
           value = request.getParameter(CHECKBOX_TYPEENDUSER);
           if(value !=null){
             if(value.equals(CHECKBOX_VALUE)){
               newuser[UserView.TYPE_ENDUSER] = UserView.TRUE;   
               oldprofile[Profile.TYPE_ENDUSER][Profile.VALUE] = Profile.TRUE;  
             }
             else{
               newuser[UserView.TYPE_ENDUSER] = UserView.FALSE;   
               oldprofile[Profile.TYPE_ENDUSER][Profile.VALUE] = Profile.FALSE;   
             }
           }
           value = request.getParameter(CHECKBOX_TYPERA);
           if(value !=null){
             if(value.equals(CHECKBOX_VALUE)){
               newuser[UserView.TYPE_RA] = UserView.TRUE;   
               oldprofile[Profile.TYPE_RA][Profile.VALUE] = Profile.TRUE;                                  
             }
             else{
               newuser[UserView.TYPE_RA] = UserView.FALSE;   
               oldprofile[Profile.TYPE_RA][Profile.VALUE] = Profile.FALSE;                  
             }
           }  
           value = request.getParameter(CHECKBOX_TYPERAADMIN);
           if(value !=null){
             if(value.equals(CHECKBOX_VALUE)){
               newuser[UserView.TYPE_RAADMIN] = UserView.TRUE;   
               oldprofile[Profile.TYPE_RAADMIN][Profile.VALUE] = Profile.TRUE;                     
             }
             else{
               newuser[UserView.TYPE_RAADMIN] = UserView.FALSE;   
               oldprofile[Profile.TYPE_RAADMIN][Profile.VALUE] = Profile.FALSE;        
             }
           }
           value = request.getParameter(CHECKBOX_TYPECA);
           if(value !=null){
             if(value.equals(CHECKBOX_VALUE)){
               newuser[UserView.TYPE_CA] = UserView.TRUE;   
               oldprofile[Profile.TYPE_CA][Profile.VALUE] = Profile.TRUE;                
             }
             else{
               newuser[UserView.TYPE_CA] = UserView.FALSE;   
               oldprofile[Profile.TYPE_CA][Profile.VALUE] = Profile.FALSE;   
             }
           }
           value = request.getParameter(CHECKBOX_TYPECAADMIN);
           if(value !=null){
             if(value.equals(CHECKBOX_VALUE)){
               newuser[UserView.TYPE_CAADMIN] = UserView.TRUE;   
               oldprofile[Profile.TYPE_CAADMIN][Profile.VALUE] = Profile.TRUE;                 
             }
             else{
               newuser[UserView.TYPE_CAADMIN] = UserView.FALSE;   
               oldprofile[Profile.TYPE_CAADMIN][Profile.VALUE] = Profile.FALSE;   
             }
           }
           value = request.getParameter(CHECKBOX_TYPEROOTCA);
           if(value !=null){
             if(value.equals(CHECKBOX_VALUE)){
               newuser[UserView.TYPE_ROOTCA] = UserView.TRUE;   
               oldprofile[Profile.TYPE_ROOTCA][Profile.VALUE] = Profile.TRUE;         
             }
             else{
               newuser[UserView.TYPE_ROOTCA] = UserView.FALSE;   
               oldprofile[Profile.TYPE_ROOTCA][Profile.VALUE] = Profile.FALSE;   
             }
           }


           // See if user already exists
           if(rabean.userExist(newuser[UserView.USERNAME]) || request.getParameter(BUTTON_RELOAD) != null ){
             userexists = true;
             lastprofilename = oldprofilename;
             useoldprofile = true;   
           } 
           else{
             rabean.addUser(newuser); 
             useradded=true;
           }           
         }
      }
    }
  

    int numberofrows = ejbcawebbean.getEntriesPerPage();
    String[][] addedusers = rabean.getAddedUsers(numberofrows);

%>
<head>
  <title><%= globalconfiguration.getEjbcaTitle() %></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>">
  <link rel=STYLESHEET href="<%= ejbcawebbean.getCssFile() %>">
  <script language=javascript>
   <!--
      var TRUE  = "<%= Profile.TRUE %>";
      var FALSE = "<%= Profile.FALSE %>";

      var VALUE      = <%= Profile.VALUE %>; 
      var ISREQUIRED = <%= Profile.ISREQUIRED %>;
      var CHANGEABLE = <%= Profile.CHANGEABLE %>

      var USERNAME          = <%= Profile.USERNAME %>;
      var PASSWORD          = <%= Profile.PASSWORD %>;
      var CLEARTEXTPASSWORD = <%= Profile.CLEARTEXTPASSWORD %>; 
      var COMMONNAME        = <%= Profile.COMMONNAME %>;
      var ORGANIZATIONUNIT  = <%= Profile.ORGANIZATIONUNIT %>;
      var ORGANIZATION      = <%= Profile.ORGANIZATION %>;
      var LOCALE            = <%= Profile.LOCALE %>;
      var STATE             = <%= Profile.STATE %>;
      var COUNTRY           = <%= Profile.COUNTRY %>;
      var EMAIL             = <%= Profile.EMAIL %>;
      var TYPE_ENDUSER      = <%= Profile.TYPE_ENDUSER %>;
      var TYPE_CA           = <%= Profile.TYPE_CA %>;
      var TYPE_RA           = <%= Profile.TYPE_RA %>;
      var TYPE_ROOTCA       = <%= Profile.TYPE_ROOTCA %>;
      var TYPE_CAADMIN      = <%= Profile.TYPE_CAADMIN %>;
      var TYPE_RAADMIN      = <%= Profile.TYPE_RAADMIN %>;
      
      var profiles = new Array(<%= profilenames.length %>);
      <% for(int i = 0; i < profilenames.length; i++){ %>
      profiles[<%= i %>] = new Array(<%= Profile.NUMBEROFPARAMETERS %>);        
          <% for(int j = 0; j < Profile.NUMBEROFPARAMETERS; j++){ %>
      profiles[<%= i %>][<%= j %>] = new Array(2);
      profiles[<%= i %>][<%= j %>][VALUE] = "<% if(profiles[i][j][Profile.VALUE] != null)
                                                  out.write(profiles[i][j][Profile.VALUE]); %>";
      profiles[<%= i %>][<%= j %>][ISREQUIRED] = <% if(profiles[i][j][Profile.ISREQUIRED] != null)
                                                       out.write(profiles[i][j][Profile.ISREQUIRED]);
                                                     else
                                                       out.write("false"); %>;
      profiles[<%= i %>][<%= j %>][CHANGEABLE] = <% if(profiles[i][j][Profile.CHANGEABLE] != null)
                                                       out.write(profiles[i][j][Profile.CHANGEABLE]);
                                                     else
                                                       out.write("false"); %>;
          <% } 
         } %>
   <% if(oldprofile != null){   %>
      var oldprofile = new Array(<%= Profile.NUMBEROFPARAMETERS %>);
     <% for(int i = 0; i < Profile.NUMBEROFPARAMETERS; i++){ %>
      oldprofile[<%= i %>] = new Array(2);
      oldprofile[<%= i %>][VALUE] = "<% if(oldprofile[i][Profile.VALUE] != null)
                                          out.write(oldprofile[i][Profile.VALUE]); %>";
      oldprofile[<%= i %>][ISREQUIRED] = <% if(oldprofile[i][Profile.ISREQUIRED] != null)
                                              out.write(oldprofile[i][Profile.ISREQUIRED]);
                                            else
                                              out.write("false"); %>;
      oldprofile[<%= i %>][CHANGEABLE] = <% if(oldprofile[i][Profile.CHANGEABLE] != null)
                                              out.write(oldprofile[i][Profile.CHANGEABLE]);
                                            else
                                              out.write("false"); %>;
     <% } 
      } %>




function fillfromprofile(){
  index = document.adduser.<%= SELECT_PROFILE %>.selectedIndex;

  document.adduser.<%= TEXTFIELD_USERNAME %>.value = profiles[index][USERNAME][VALUE];
  document.adduser.<%= TEXTFIELD_USERNAME %>.disabled = !profiles[index][USERNAME][CHANGEABLE];
  document.adduser.<%= TEXTFIELD_PASSWORD %>.value = profiles[index][PASSWORD][VALUE];
  document.adduser.<%= TEXTFIELD_PASSWORD %>.disabled = !profiles[index][PASSWORD][CHANGEABLE];
  document.adduser.<%= TEXTFIELD_CONFIRMPASSWORD %>.value = profiles[index][PASSWORD][VALUE];
  document.adduser.<%= TEXTFIELD_CONFIRMPASSWORD %>.disabled = !profiles[index][PASSWORD][CHANGEABLE];
  document.adduser.<%= TEXTFIELD_COMMONNAME %>.value = profiles[index][COMMONNAME][VALUE];
  document.adduser.<%= TEXTFIELD_COMMONNAME %>.disabled = !profiles[index][COMMONNAME][CHANGEABLE];
  document.adduser.<%= TEXTFIELD_ORGANIZATIONUNIT %>.value = profiles[index][ORGANIZATIONUNIT][VALUE];
  document.adduser.<%= TEXTFIELD_ORGANIZATIONUNIT %>.disabled = !profiles[index][ORGANIZATIONUNIT][CHANGEABLE];
  document.adduser.<%= TEXTFIELD_ORGANIZATION %>.value = profiles[index][ORGANIZATION][VALUE];
  document.adduser.<%= TEXTFIELD_ORGANIZATION %>.disabled = !profiles[index][ORGANIZATION][CHANGEABLE];
  document.adduser.<%= TEXTFIELD_LOCALE %>.value = profiles[index][LOCALE][VALUE];
  document.adduser.<%= TEXTFIELD_LOCALE %>.disabled = !profiles[index][LOCALE][CHANGEABLE];
  document.adduser.<%= TEXTFIELD_STATE %>.value = profiles[index][STATE][VALUE];
  document.adduser.<%= TEXTFIELD_STATE %>.disabled = !profiles[index][STATE][CHANGEABLE];
  document.adduser.<%= TEXTFIELD_COUNTRY %>.value = profiles[index][COUNTRY][VALUE];
  document.adduser.<%= TEXTFIELD_COUNTRY %>.disabled = !profiles[index][COUNTRY][CHANGEABLE];
  document.adduser.<%= TEXTFIELD_EMAIL %>.value = profiles[index][EMAIL][VALUE];
  document.adduser.<%= TEXTFIELD_EMAIL %>.disabled = !profiles[index][EMAIL][CHANGEABLE];
  document.adduser.<%= CHECKBOX_CLEARTEXTPASSWORD %>.checked = eval(profiles[index][CLEARTEXTPASSWORD][VALUE]);
  document.adduser.<%= CHECKBOX_CLEARTEXTPASSWORD %>.disabled = profiles[index][CLEARTEXTPASSWORD][ISREQUIRED];
  document.adduser.<%= CHECKBOX_TYPEENDUSER %>.checked = eval(profiles[index][TYPE_ENDUSER][VALUE]);
  document.adduser.<%= CHECKBOX_TYPEENDUSER %>.disabled = profiles[index][TYPE_ENDUSER][ISREQUIRED];
  document.adduser.<%= CHECKBOX_TYPERA %>.checked = eval(profiles[index][TYPE_RA][VALUE]);
  document.adduser.<%= CHECKBOX_TYPERA %>.disabled = profiles[index][TYPE_RA][ISREQUIRED];
  document.adduser.<%= CHECKBOX_TYPERAADMIN %>.checked = eval(profiles[index][TYPE_RAADMIN][VALUE]);
  document.adduser.<%= CHECKBOX_TYPERAADMIN %>.disabled = profiles[index][TYPE_RAADMIN][ISREQUIRED];
  document.adduser.<%= CHECKBOX_TYPECA %>.checked = eval(profiles[index][TYPE_CA][VALUE]);
  document.adduser.<%= CHECKBOX_TYPECA %>.disabled = profiles[index][TYPE_CA][ISREQUIRED];
  document.adduser.<%= CHECKBOX_TYPECAADMIN %>.checked = eval(profiles[index][TYPE_CAADMIN][VALUE]);
  document.adduser.<%= CHECKBOX_TYPECAADMIN %>.disabled = profiles[index][TYPE_CAADMIN][ISREQUIRED];
  document.adduser.<%= CHECKBOX_TYPEROOTCA %>.checked = eval(profiles[index][TYPE_ROOTCA][VALUE]);
  document.adduser.<%= CHECKBOX_TYPEROOTCA %>.disabled = profiles[index][TYPE_ROOTCA][ISREQUIRED];

  document.adduser.<%= CHECKBOX_REQUIRED_USERNAME %>.checked = eval(profiles[index][USERNAME][ISREQUIRED]);
  document.adduser.<%= CHECKBOX_REQUIRED_PASSWORD %>.checked = eval(profiles[index][PASSWORD][ISREQUIRED]);
  document.adduser.<%= CHECKBOX_REQUIRED_COMMONNAME %>.checked = eval(profiles[index][COMMONNAME][ISREQUIRED]);
  document.adduser.<%= CHECKBOX_REQUIRED_ORGANIZATIONUNIT %>.checked = eval(profiles[index][ORGANIZATIONUNIT][ISREQUIRED]);
  document.adduser.<%= CHECKBOX_REQUIRED_ORGANIZATION %>.checked = eval(profiles[index][ORGANIZATION][ISREQUIRED]);
  document.adduser.<%= CHECKBOX_REQUIRED_LOCALE %>.checked = eval(profiles[index][LOCALE][ISREQUIRED]);
  document.adduser.<%= CHECKBOX_REQUIRED_STATE %>.checked = eval(profiles[index][STATE][ISREQUIRED]);
  document.adduser.<%= CHECKBOX_REQUIRED_COUNTRY%>.checked = eval(profiles[index][COUNTRY][ISREQUIRED]);
  document.adduser.<%= CHECKBOX_REQUIRED_EMAIL%>.checked = eval(profiles[index][EMAIL][ISREQUIRED]);
}

function fillfromoldprofile(){

  document.adduser.<%= TEXTFIELD_USERNAME %>.value = oldprofile[USERNAME][VALUE];
  document.adduser.<%= TEXTFIELD_USERNAME %>.disabled = !oldprofile[USERNAME][CHANGEABLE];
  document.adduser.<%= TEXTFIELD_PASSWORD %>.value = oldprofile[PASSWORD][VALUE];
  document.adduser.<%= TEXTFIELD_PASSWORD %>.disabled = !oldprofile[PASSWORD][CHANGEABLE];
  document.adduser.<%= TEXTFIELD_CONFIRMPASSWORD %>.value = oldprofile[PASSWORD][VALUE];
  document.adduser.<%= TEXTFIELD_CONFIRMPASSWORD %>.disabled = !oldprofile[PASSWORD][CHANGEABLE];
  document.adduser.<%= TEXTFIELD_COMMONNAME %>.value = oldprofile[COMMONNAME][VALUE];
  document.adduser.<%= TEXTFIELD_COMMONNAME %>.disabled = !oldprofile[COMMONNAME][CHANGEABLE];
  document.adduser.<%= TEXTFIELD_ORGANIZATIONUNIT %>.value = oldprofile[ORGANIZATIONUNIT][VALUE];
  document.adduser.<%= TEXTFIELD_ORGANIZATIONUNIT %>.disabled = !oldprofile[ORGANIZATIONUNIT][CHANGEABLE];
  document.adduser.<%= TEXTFIELD_ORGANIZATION %>.value = oldprofile[ORGANIZATION][VALUE];
  document.adduser.<%= TEXTFIELD_ORGANIZATION %>.disabled = !oldprofile[ORGANIZATION][CHANGEABLE];
  document.adduser.<%= TEXTFIELD_LOCALE %>.value = oldprofile[LOCALE][VALUE];
  document.adduser.<%= TEXTFIELD_LOCALE %>.disabled = !oldprofile[LOCALE][CHANGEABLE];
  document.adduser.<%= TEXTFIELD_STATE %>.value = oldprofile[STATE][VALUE];
  document.adduser.<%= TEXTFIELD_STATE %>.disabled = !oldprofile[STATE][CHANGEABLE];
  document.adduser.<%= TEXTFIELD_COUNTRY %>.value = oldprofile[COUNTRY][VALUE];
  document.adduser.<%= TEXTFIELD_COUNTRY %>.disabled = !oldprofile[COUNTRY][CHANGEABLE];
  document.adduser.<%= TEXTFIELD_EMAIL %>.value = oldprofile[EMAIL][VALUE];
  document.adduser.<%= TEXTFIELD_EMAIL %>.disabled = !oldprofile[EMAIL][CHANGEABLE];
  document.adduser.<%= CHECKBOX_CLEARTEXTPASSWORD %>.checked = eval(oldprofile[CLEARTEXTPASSWORD][VALUE]);
  document.adduser.<%= CHECKBOX_CLEARTEXTPASSWORD %>.disabled = oldprofile[CLEARTEXTPASSWORD][ISREQUIRED];
  document.adduser.<%= CHECKBOX_TYPEENDUSER %>.checked = eval(oldprofile[TYPE_ENDUSER][VALUE]);
  document.adduser.<%= CHECKBOX_TYPEENDUSER %>.disabled = oldprofile[TYPE_ENDUSER][ISREQUIRED];
  document.adduser.<%= CHECKBOX_TYPERA %>.checked = eval(oldprofile[TYPE_RA][VALUE]);
  document.adduser.<%= CHECKBOX_TYPERA %>.disabled = oldprofile[TYPE_RA][ISREQUIRED];
  document.adduser.<%= CHECKBOX_TYPERAADMIN %>.checked = eval(oldprofile[TYPE_RAADMIN][VALUE]);
  document.adduser.<%= CHECKBOX_TYPERAADMIN %>.disabled = oldprofile[TYPE_RAADMIN][ISREQUIRED];
  document.adduser.<%= CHECKBOX_TYPECA %>.checked = eval(oldprofile[TYPE_CA][VALUE]);
  document.adduser.<%= CHECKBOX_TYPECA %>.disabled = oldprofile[TYPE_CA][ISREQUIRED];
  document.adduser.<%= CHECKBOX_TYPECAADMIN %>.checked = eval(oldprofile[TYPE_CAADMIN][VALUE]);
  document.adduser.<%= CHECKBOX_TYPECAADMIN %>.disabled = oldprofile[TYPE_CAADMIN][ISREQUIRED];
  document.adduser.<%= CHECKBOX_TYPEROOTCA %>.checked = eval(oldprofile[TYPE_ROOTCA][VALUE]);
  document.adduser.<%= CHECKBOX_TYPEROOTCA %>.disabled = oldprofile[TYPE_ROOTCA][ISREQUIRED];

  document.adduser.<%= CHECKBOX_REQUIRED_USERNAME %>.checked = eval(oldprofile[USERNAME][ISREQUIRED]);
  document.adduser.<%= CHECKBOX_REQUIRED_PASSWORD %>.checked = eval(oldprofile[PASSWORD][ISREQUIRED]);
  document.adduser.<%= CHECKBOX_REQUIRED_COMMONNAME %>.checked = eval(oldprofile[COMMONNAME][ISREQUIRED]);
  document.adduser.<%= CHECKBOX_REQUIRED_ORGANIZATIONUNIT %>.checked = eval(oldprofile[ORGANIZATIONUNIT][ISREQUIRED]);
  document.adduser.<%= CHECKBOX_REQUIRED_ORGANIZATION %>.checked = eval(oldprofile[ORGANIZATION][ISREQUIRED]);
  document.adduser.<%= CHECKBOX_REQUIRED_LOCALE %>.checked = eval(oldprofile[LOCALE][ISREQUIRED]);
  document.adduser.<%= CHECKBOX_REQUIRED_STATE %>.checked = eval(oldprofile[STATE][ISREQUIRED]);
  document.adduser.<%= CHECKBOX_REQUIRED_COUNTRY%>.checked = eval(oldprofile[COUNTRY][ISREQUIRED]);
  document.adduser.<%= CHECKBOX_REQUIRED_EMAIL%>.checked = eval(oldprofile[EMAIL][ISREQUIRED]);

}

function checkallfields(){
    var illegalfields = 0;

    if(!checkfieldforlegalchars("document.adduser.<%=TEXTFIELD_USERNAME%>","<%= ejbcawebbean.getText("ONLYCHARACTERS2") %>"))
      illegalfields++;

    if(!checkfieldforlegalchars("document.adduser.<%=TEXTFIELD_PASSWORD%>","<%= ejbcawebbean.getText("ONLYCHARACTERS2") %>"))
      illegalfields++;
 
    if(!checkfieldforlegalchars("document.adduser.<%=TEXTFIELD_COMMONNAME%>","<%= ejbcawebbean.getText("ONLYCHARACTERS2") %>"))
      illegalfields++;
  
    if(!checkfieldforlegalchars("document.adduser.<%=TEXTFIELD_ORGANIZATIONUNIT%>","<%= ejbcawebbean.getText("ONLYCHARACTERS2") %>"))
      illegalfields++;
  
    if(!checkfieldforlegalchars("document.adduser.<%=TEXTFIELD_ORGANIZATION%>","<%= ejbcawebbean.getText("ONLYCHARACTERS2") %>"))
      illegalfields++;

    if(!checkfieldforlegalchars("document.adduser.<%=TEXTFIELD_LOCALE%>","<%= ejbcawebbean.getText("ONLYCHARACTERS2") %>"))
      illegalfields++;
  
    if(!checkfieldforlegalchars("document.adduser.<%=TEXTFIELD_STATE%>","<%= ejbcawebbean.getText("ONLYCHARACTERS2") %>"))
      illegalfields++;

    if(!checkfieldforlegalchars("document.adduser.<%=TEXTFIELD_COUNTRY%>","<%= ejbcawebbean.getText("ONLYCHARACTERS2") %>"))
      illegalfields++;

    if(!checkfieldforlegalemailchars("document.adduser.<%=TEXTFIELD_EMAIL%>","<%= ejbcawebbean.getText("ONLYEMAILCHARS") %>"))
      illegalfields++;

    index = document.adduser.<%= SELECT_PROFILE %>.selectedIndex; 

    if((document.adduser.<%= TEXTFIELD_USERNAME %>.value == "") && profiles[index][USERNAME][ISREQUIRED]){
      alert("<%= ejbcawebbean.getText("REQUIREDUSERNAME") %>");
      illegalfields++;
    } 

    if((document.adduser.<%= TEXTFIELD_PASSWORD %>.value == "") && profiles[index][PASSWORD][ISREQUIRED]){
      alert("<%= ejbcawebbean.getText("REQUIREDPASSWORD") %>");
      illegalfields++;
    } 

    if((document.adduser.<%= TEXTFIELD_COMMONNAME %>.value == "") && profiles[index][COMMONNAME][ISREQUIRED]){
      alert("<%= ejbcawebbean.getText("REQUIREDCOMMONNAME") %>");
      illegalfields++;
    } 

    if((document.adduser.<%= TEXTFIELD_ORGANIZATIONUNIT %>.value == "") && profiles[index][ORGANIZATIONUNIT][ISREQUIRED]){
      alert("<%= ejbcawebbean.getText("REQUIREDORGANIZATIONUNIT") %>");
      illegalfields++;
    } 

    if((document.adduser.<%= TEXTFIELD_ORGANIZATION %>.value == "") && profiles[index][ORGANIZATION][ISREQUIRED]){
      alert("<%= ejbcawebbean.getText("REQUIREDORGANIZATION") %>");
      illegalfields++;
    } 

    if((document.adduser.<%= TEXTFIELD_LOCALE %>.value == "") && profiles[index][LOCALE][ISREQUIRED]){
      alert("<%= ejbcawebbean.getText("REQUIREDLOCALE") %>");
      illegalfields++;
    }

    if((document.adduser.<%= TEXTFIELD_STATE %>.value == "") && profiles[index][STATE][ISREQUIRED]){
      alert("<%= ejbcawebbean.getText("REQUIREDSTATE") %>");
      illegalfields++;
    }

    if((document.adduser.<%= TEXTFIELD_COUNTRY %>.value == "") && profiles[index][COUNTRY][ISREQUIRED]){
      alert("<%= ejbcawebbean.getText("REQUIREDCOUNTRY") %>");
      illegalfields++;
    }

    if((document.adduser.<%= TEXTFIELD_EMAIL %>.value == "") && profiles[index][EMAIL][ISREQUIRED]){
      alert("<%= ejbcawebbean.getText("REQUIREDEMAIL") %>");
      illegalfields++;
    }

    if(document.adduser.<%= TEXTFIELD_PASSWORD %>.value != document.adduser.<%= TEXTFIELD_CONFIRMPASSWORD %>.value){
      alert("<%= ejbcawebbean.getText("PASSWORDSDOESNTMATCH") %>");
      illegalfields++;
    } 

    if(illegalfields == 0){
      document.adduser.<%= TEXTFIELD_USERNAME %>.disabled = false;
      document.adduser.<%= TEXTFIELD_PASSWORD %>.disabled = false;
      document.adduser.<%= TEXTFIELD_CONFIRMPASSWORD %>.disabled = false;
      document.adduser.<%= TEXTFIELD_COMMONNAME %>.disabled = false;
      document.adduser.<%= TEXTFIELD_ORGANIZATIONUNIT %>.disabled = false;
      document.adduser.<%= TEXTFIELD_ORGANIZATION %>.disabled = false;
      document.adduser.<%= TEXTFIELD_LOCALE %>.disabled = false;
      document.adduser.<%= TEXTFIELD_STATE %>.disabled = false;
      document.adduser.<%= TEXTFIELD_COUNTRY %>.disabled = false;
      document.adduser.<%= TEXTFIELD_EMAIL %>.disabled = false;
      document.adduser.<%= CHECKBOX_CLEARTEXTPASSWORD %>.disabled = false;
      document.adduser.<%= CHECKBOX_TYPEENDUSER %>.disabled = false;
      document.adduser.<%= CHECKBOX_TYPERA %>.disabled = false;
      document.adduser.<%= CHECKBOX_TYPERAADMIN %>.disabled = false;
      document.adduser.<%= CHECKBOX_TYPECA %>.disabled = false;
      document.adduser.<%= CHECKBOX_TYPECAADMIN %>.disabled = false;
      document.adduser.<%= CHECKBOX_TYPEROOTCA %>.disabled = false;
    }

     return illegalfields == 0;  
}
   -->
  </script>
  <script language=javascript src="<%= globalconfiguration .getRaAdminPath() %>ejbcajslib.js"></script>
</head>
<body onload='<% if(useoldprofile)
                   out.write("fillfromoldprofile()");
                 else
                   out.write("fillfromprofile()"); %>'>
  <h2 align="center"><%= ejbcawebbean.getText("ADDUSER") %></h2>
  <div align="right"><A  onclick='displayHelpWindow("<%= ejbcawebbean.getHelpfileInfix("ra_help.html") + "#adduser"%>")'>
    <u><%= ejbcawebbean.getText("HELP") %></u> </A>
  </div>
  <% if(userexists){ %>
  <div align="center"><h4 id="alert"><%=ejbcawebbean.getText("USERALREADYEXISTS") %></h4></div>
  <% } %>
  <% if(useradded){ %>
  <div align="center"><h4 id="alert"><% out.write(ejbcawebbean.getText("USER")+ " ");
                                        if(oldprofile[Profile.USERNAME][Profile.VALUE] != null)
                                          out.write(oldprofile[Profile.USERNAME][Profile.VALUE] + " ");
                                        out.write(ejbcawebbean.getText("ADDEDSUCCESSFULLY"));%></h4></div>
  <% } %>
  <form name="adduser" action="<%= THIS_FILENAME %>" method="post">
     <input type="hidden" name='<%= ACTION %>' value='<%=ACTION_ADDUSER %>'>
     <table border="0" cellpadding="0" cellspacing="2" width="792">
       <tr>
         <td></td>
	 <td align="right"><%= ejbcawebbean.getText("PROFILE") %></td>
	 <td><select name="<%=SELECT_PROFILE %>" size="1" tabindex="1" onchange='fillfromprofile()'>
                <% for(int i = 0; i < profiles.length;i++){ %>
	 	<option value="<%=i %>" <% if(profilenames[i].equals(lastprofilename))
                                             out.write("selected"); %>>
 
                         <%= profilenames[i] %>
                </option>
                <% } %>
	     </select>
         </td>
	<td><%= ejbcawebbean.getText("REQUIRED") %></td>
      </tr>
      <tr>
	<td></td>
	<td></td>
	<td></td>
	<td></td>
      </tr>
      <tr id="Row0">
	<td></td>
	<td align="right"><%= ejbcawebbean.getText("USERNAME") %></td>
	<td><input type="text" name="<%= TEXTFIELD_USERNAME %>" size="40" maxlength="255" tabindex="2">
        </td>
	<td><input type="checkbox" name="<%= CHECKBOX_REQUIRED_USERNAME %>" value="<%= CHECKBOX_VALUE %>"  disabled="true" ></td>
      </tr>
      <tr id="Row1">
        <td>&nbsp&nbsp&nbsp&nbsp&nbsp;&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp
&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp
        </td>
        <td align="right"><%= ejbcawebbean.getText("PASSWORD") %></td>
	<td><input type="password" name="<%= TEXTFIELD_PASSWORD %>" size="40" maxlength="255" tabindex="3">
        </td>
	<td><input type="checkbox" name="<%= CHECKBOX_REQUIRED_PASSWORD %>" value="<%= CHECKBOX_VALUE %>"  disabled="true" ></td>
      </tr>
      <tr id="Row0">
	<td></td>
	<td align="right"><%= ejbcawebbean.getText("CONFIRMPASSWORD") %></td>
	<td><input type="password" name="<%= TEXTFIELD_CONFIRMPASSWORD %>" size="40" maxlength="255" tabindex="4">        
        </td>
	<td>&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp
&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp</td> 
      </tr>
      <tr id="Row0">
	<td></td>
	<td align="right"><h4><%= ejbcawebbean.getText("CLEARTEXTPASSWORD") %></h4></td>
	<td><input type="checkbox" name="<%= CHECKBOX_CLEARTEXTPASSWORD %>" value="<%= CHECKBOX_VALUE %>" tabindex="5">
        </td>
	<td></td> 
      </tr>
      <tr id="Row1">
	<td></td>
	<td>&nbsp;</td>
	<td>&nbsp;</td>
	<td></td>
       </tr>
       <tr id="Row0">
	 <td></td>
	 <td align="right"><%= ejbcawebbean.getText("COMMONNAME") %></td>
	 <td><input type="text" name="<%= TEXTFIELD_COMMONNAME %>" size="40" maxlength="255" tabindex="6">        
         </td>
	 <td><input type="checkbox" name="<%= CHECKBOX_REQUIRED_COMMONNAME %>" value="<%= CHECKBOX_VALUE %>"  disabled="true" ></td>
       </tr>
       <tr id="Row1">
	 <td></td>
	 <td align="right"><%= ejbcawebbean.getText("ORGANIZATIONUNIT") %></td>
	 <td><input type="text" name="<%= TEXTFIELD_ORGANIZATIONUNIT %>" size="40" maxlength="255" tabindex="7">            
         </td>
	 <td><input type="checkbox" name="<%= CHECKBOX_REQUIRED_ORGANIZATIONUNIT %>" value="<%= CHECKBOX_VALUE %>"  disabled="true" ></td>
       </tr>
       <tr id="Row0">
	 <td></td>
	 <td align="right"><%= ejbcawebbean.getText("ORGANIZATION") %></td>
	 <td><input type="text" name="<%= TEXTFIELD_ORGANIZATION %>" size="40" maxlength="255" tabindex="8">
         </td>
	 <td><input type="checkbox" name="<%= CHECKBOX_REQUIRED_ORGANIZATION %>" value="<%= CHECKBOX_VALUE %>"  disabled="true" ></td>
       </tr>
       <tr id="Row1">
	 <td></td>
	 <td align="right"><%= ejbcawebbean.getText("LOCALE") %></td>
	 <td><input type="text" name="<%= TEXTFIELD_LOCALE %>" size="40" maxlength="255" tabindex="9">
         </td>
	 <td><input type="checkbox" name="<%= CHECKBOX_REQUIRED_LOCALE %>" value="<%= CHECKBOX_VALUE %>"  disabled="true" ></td>
       </tr>
       <tr id="Row0">
	 <td></td>
	 <td align="right"><%= ejbcawebbean.getText("STATE") %></td>
	 <td><input type="text" name="<%= TEXTFIELD_STATE %>" size="40" maxlength="255" tabindex="10">
         </td>
	 <td><input type="checkbox" name="<%= CHECKBOX_REQUIRED_STATE %>" value="<%= CHECKBOX_VALUE %>"  disabled="true" ></td>
       </tr>
       <tr id="Row1">
	 <td></td>
	 <td align="right"><%= ejbcawebbean.getText("COUNTRY") %></td>
	 <td><input type="text" name="<%= TEXTFIELD_COUNTRY %>" size="2" maxlength="2" tabindex="11">
          </td>
	 <td><input type="checkbox" name="<%= CHECKBOX_REQUIRED_COUNTRY %>" value="<%= CHECKBOX_VALUE %>"  disabled="true" ></td>
       </tr>
       <tr id="Row0">
	 <td>&nbsp;</td>
	 <td>&nbsp;</td>
	 <td>&nbsp;</td>
	 <td>&nbsp;</td>
       </tr>
       <tr id="Row1">
	 <td></td>
	 <td align="right"><%= ejbcawebbean.getText("EMAIL") %></td>
	 <td><input type="text" name="<%= TEXTFIELD_EMAIL %>" size="40" maxlength="255" tabindex="12">
         </td>
	 <td><input type="checkbox" name="<%= CHECKBOX_REQUIRED_EMAIL %>" value="<%= CHECKBOX_VALUE %>"  disabled="true" ></td>
       </tr>
       <tr id="Row0">
	 <td></td>
	 <td align="right"><%= ejbcawebbean.getText("TYPES") %></td>
	 <td>
         </td>
	 <td></td>
       </tr>
    <tr  id="Row1"> 
      <td></td>
      <td  align="right"> 
        <%= ejbcawebbean.getText("TYPEENDUSER") %> <br>
      </td>
      <td > 
        <input type="checkbox" name="<%=CHECKBOX_TYPEENDUSER%>" value="<%=CHECKBOX_VALUE %>" tabindex="13"> 
      </td>
      <td></td>
    </tr>
    <tr  id="Row0"> 
      <td></td>
      <td  align="right"> 
        <%= ejbcawebbean.getText("TYPERA") %> 
      </td>
      <td> 
        <input type="checkbox" name="<%=CHECKBOX_TYPERA%>" value="<%=CHECKBOX_VALUE %>" tabindex="14"> 
      </td>
      <td></td>
    </tr>
    <tr  id="Row1"> 
      <td></td>
      <td align="right"> 
        <%= ejbcawebbean.getText("TYPERAADMIN") %> 
      </td>
      <td > 
        <input type="checkbox" name="<%=CHECKBOX_TYPERAADMIN%>" value="<%=CHECKBOX_VALUE %>" tabindex="15"> 
      </td>
      <td></td>
    </tr>
    <tr  id="Row0"> 
      <td></td>
      <td  align="right"> 
        <%= ejbcawebbean.getText("TYPECA") %> 
      </td>
      <td > 
        <input type="checkbox" name="<%=CHECKBOX_TYPECA%>" value="<%=CHECKBOX_VALUE %>" tabindex="16"> 
      </td>
      <td></td>
    </tr>
    <tr  id="Row1">
       <td></td>
      <td align="right"> 
        <%= ejbcawebbean.getText("TYPECAADMIN") %> 
      </td>
      <td> 
        <input type="checkbox" name="<%=CHECKBOX_TYPECAADMIN%>" value="<%=CHECKBOX_VALUE %>" tabindex="17"> 
      </td>
      <td></td>
    </tr>
    <tr  id="Row0"> 
      <td></td>
      <td  align="right"> 
        <%= ejbcawebbean.getText("TYPEROOTCA") %> 
      </td>
      <td > 
        <input type="checkbox" name="<%=CHECKBOX_TYPEROOTCA%>" value="<%=CHECKBOX_VALUE %>" tabindex="18"> 
      </td>
      <td></td>
    </tr>
       <tr id="Row1">
	 <td></td>
	 <td></td>
	 <td><input type="submit" name="<%= BUTTON_ADDUSER %>" value="<%= ejbcawebbean.getText("ADDUSER") %>" tabindex="19"
                    onClick='return checkallfields()'> 
             <input type="reset" name="<%= BUTTON_RESET %>" value="<%= ejbcawebbean.getText("RESET") %>" tabindex="20"></td>
         <td></td>
       </tr> 
     </table> 
   
  <script language=javascript>
<!--
function viewuser(row){
    var hiddenusernamefield = eval("document.adduser.<%= HIDDEN_USERNAME %>" + row);
    var username = hiddenusernamefield.value;
    var link = "<%= VIEWUSER_LINK %>?<%= USER_PARAMETER %>="+username;
    window.open(link, 'view_cert',config='height=600,width=500,scrollbars=yes,toolbar=no,resizable=1');
}

function edituser(row){
    var hiddenusernamefield = eval("document.adduser.<%= HIDDEN_USERNAME %>" + row);
    var username = hiddenusernamefield.value;
    var link = "<%= EDITUSER_LINK %>?<%= USER_PARAMETER %>="+username;
    window.open(link, 'edit_user',config='height=600,width=500,scrollbars=yes,toolbar=no,resizable=1');
}

-->
</script>

 

  <% if(addedusers == null || addedusers.length == 0){     %>
  <table width="100%" border="0" cellspacing="1" cellpadding="0">
  <tr id="Row0"> 
    <td width="10%">&nbsp;</td>
    <td width="20%">&nbsp;</td>
    <td width="20%">&nbsp;</td>
    <td width="20%">&nbsp;</td>
    <td width="30%">&nbsp;</td>
  </tr>
  <% } else{ %>
  <div align="center"><H4><%= ejbcawebbean.getText("PREVIOUSLYADDEDUSERS") %> </H4></div>
  <p>
    <input type="submit" name="<%=BUTTON_RELOAD %>" value="<%= ejbcawebbean.getText("RELOAD") %>">
  </p>
  <table width="100%" border="0" cellspacing="1" cellpadding="0">
  <tr> 
    <td width="10%"><%= ejbcawebbean.getText("USERNAME") %>              
    </td>
    <td width="20%"><%= ejbcawebbean.getText("COMMONNAME") %>
    </td>
    <td width="20%"><%= ejbcawebbean.getText("ORGANIZATIONUNIT") %>
    </td>
    <td width="20%"><%= ejbcawebbean.getText("ORGANIZATION") %>                 
    </td>
    <td width="30%"> &nbsp;
    </td>
  </tr>
    <%   for(int i=0; i < addedusers.length; i++){
            if(addedusers[i][UserView.USERNAME] != null){ 
      %>
     
  <tr id="Row<%= i%2 %>"> 

    <td width="15%"><%= addedusers[i][UserView.USERNAME] %>
       <input type="hidden" name='<%= HIDDEN_USERNAME + i %>' value='<%= addedusers[i][UserView.USERNAME] %>'>
    </td>
    <td width="20%"><% if(addedusers[i][UserView.COMMONNAME]!= null) out.print(addedusers[i][UserView.COMMONNAME]); %></td>
    <td width="20%"><% if(addedusers[i][UserView.ORGANIZATIONUNIT]!= null) out.print(addedusers[i][UserView.ORGANIZATIONUNIT]); %></td>
    <td width="20%"><% if(addedusers[i][UserView.ORGANIZATION]!= null) out.print(addedusers[i][UserView.ORGANIZATION]); %></td>
    <td width="25%">
        <A  onclick='viewuser(<%= i %>)'>
        <u><%= ejbcawebbean.getText("VIEWUSER") %></u> </A>
        <A  onclick='edituser(<%= i %>)'>
        <u><%= ejbcawebbean.getText("EDITUSER") %></u> </A>
    </td>
  </tr>
 <%      }
       }
     } %>
  </table>
  </form>
   <p></p>

  <%// Include Footer 
   String footurl =   globalconfiguration .getFootBanner(); %>
   
  <jsp:include page="<%= footurl %>" />
</body>
</html>