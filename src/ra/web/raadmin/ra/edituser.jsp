<html> 
<%@page contentType="text/html"%>
<%@page  errorPage="/errorpage.jsp" import="RegularExpression.RE, se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean,se.anatom.ejbca.ra.GlobalConfiguration, se.anatom.ejbca.webdist.rainterface.UserView,
                 se.anatom.ejbca.webdist.rainterface.RAInterfaceBean, se.anatom.ejbca.webdist.rainterface.ProfileDataHandler, se.anatom.ejbca.ra.raadmin.Profile, se.anatom.ejbca.ra.UserDataRemote,
                 javax.ejb.CreateException, java.rmi.RemoteException, se.anatom.ejbca.ra.authorization.AuthorizationDeniedException" %>
<jsp:useBean id="ejbcawebbean" scope="session" class="se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean" />
<jsp:setProperty name="ejbcawebbean" property="*" /> 
<jsp:useBean id="rabean" scope="session" class="se.anatom.ejbca.webdist.rainterface.RAInterfaceBean" />
<jsp:setProperty name="rabean" property="*" /> 
<%! // Declarations


  static final String ACTION                   = "action";
  static final String ACTION_EDITUSER          = "edituser";
  static final String ACTION_CHANGEPROFILE     = "changeprofile";

  static final String BUTTON_SAVE             = "buttonedituser"; 
  static final String BUTTON_SAVEANDCLOSE     = "buttonsaveandclose"; 
  static final String BUTTON_CLOSE            = "buttonclose"; 


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
  static final String SELECT_CERTIFICATETYPE      = "selectcertificatetype";
  static final String SELECT_USERNAME             = "selectusername";
  static final String SELECT_PASSWORD             = "selectpassword";
  static final String SELECT_CONFIRMPASSWORD      = "selectconfirmpassword";
  static final String SELECT_COMMONNAME           = "selectcommonname";
  static final String SELECT_ORGANIZATIONUNIT     = "selectorganizationunit";
  static final String SELECT_ORGANIZATION         = "selectorganization";
  static final String SELECT_LOCALE               = "selectlocale";
  static final String SELECT_STATE                = "selectstate";
  static final String SELECT_COUNTRY              = "selectcountry";
  static final String SELECT_EMAIL                = "selectemail";

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

  static final String HIDDEN_USERNAME           = "hiddenusername";
  static final String HIDDEN_PROFILE            = "hiddenprofile";

%><%
  // Initialize environment.
  GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request); 
                                            rabean.initialize(request);

  String THIS_FILENAME             =  globalconfiguration.getRaPath()  + "/edituser.jsp";
  String username                  = null;
  Profile  profile                 = null;
  String[] profilenames            = null;  
  String[] userdata                  = null;
  if(globalconfiguration.getUseStrongAuthorization())
     profilenames                  = rabean.getEditAuthorizedProfileNames();
  else
     profilenames                  = rabean.getProfileNames();
  int profileid = 0;

  boolean userchanged              = false;
  boolean nouserparameter          = false;
  boolean notauthorized            = true;
  
  if( request.getParameter(USER_PARAMETER) != null ){
    username = request.getParameter(USER_PARAMETER);
    try{
      userdata = rabean.findUserForEdit(username).getValues();
      notauthorized = false;
      profileid=Integer.parseInt(userdata[UserView.PROFILE]);
    } catch(AuthorizationDeniedException e){
    }
    nouserparameter = false;
  }  

  if( request.getParameter(ACTION) != null){
    if( request.getParameter(ACTION).equals(ACTION_EDITUSER)){
      if( request.getParameter(BUTTON_SAVE) != null ||  request.getParameter(BUTTON_SAVEANDCLOSE) != null){
         String[] newuser = new String[UserView.NUMBEROF_USERFIELDS];
         for(int i=0; i<  UserView.NUMBEROF_USERFIELDS ; i++){
           newuser[i] = userdata[i];
         } 

         profileid = Integer.parseInt(userdata[UserView.PROFILE]);
         System.out.println("Setting profile id to : " +  profileid );
         String value = request.getParameter(TEXTFIELD_USERNAME);
         if(value !=null){
           value=value.trim(); 
           if(!value.equals("")){
             newuser[UserView.USERNAME] = value;
           }
         }

         value = request.getParameter(TEXTFIELD_PASSWORD);
         if(value !=null){
           value=value.trim(); 
           if(!value.equals("")){
             newuser[UserView.PASSWORD] = value;           
           }
         }

         value = request.getParameter(SELECT_PASSWORD);
          if(value !=null){
           if(!value.equals("")){
             newuser[UserView.PASSWORD] = value; 
           }
         } 

         value = request.getParameter(CHECKBOX_CLEARTEXTPASSWORD);
         if(value !=null){
           if(value.equals(CHECKBOX_VALUE)){
             newuser[UserView.CLEARTEXTPASSWORD] = UserView.TRUE;            
           }
           else{
               newuser[UserView.CLEARTEXTPASSWORD] = UserView.FALSE;   
             }
           }

           value = request.getParameter(TEXTFIELD_COMMONNAME);
           if(value !=null){
             value=value.trim(); 
             if(!value.equals("")){
               newuser[UserView.COMMONNAME] = value; 
             }
           }
           value = request.getParameter(SELECT_COMMONNAME);
           if(value !=null){
             if(!value.equals("")){
              newuser[UserView.COMMONNAME] = value;
            }
          } 

           value = request.getParameter(TEXTFIELD_ORGANIZATIONUNIT);
           if(value !=null){
             value=value.trim(); 
             if(!value.equals("")){
               newuser[UserView.ORGANIZATIONUNIT] = value;
             }
           }
           value = request.getParameter(SELECT_ORGANIZATIONUNIT);
           if(value !=null){
             if(!value.equals("")){
              newuser[UserView.ORGANIZATIONUNIT] = value;
            }
          } 

           value = request.getParameter(TEXTFIELD_ORGANIZATION);
           if(value !=null){
             value=value.trim(); 
             if(!value.equals("")){
               newuser[UserView.ORGANIZATION] = value;
             }
           }
           value = request.getParameter(SELECT_ORGANIZATION);
           if(value !=null){
             if(!value.equals("")){
              newuser[UserView.ORGANIZATION] = value;
            }
          } 
           value = request.getParameter(TEXTFIELD_LOCALE);
           if(value !=null){
             value=value.trim(); 
             if(!value.equals("")){
               newuser[UserView.LOCALE] = value;
             }
           }
           value = request.getParameter(SELECT_LOCALE);
           if(value !=null){
             if(!value.equals("")){
              newuser[UserView.LOCALE] = value;
            }
          } 

           value = request.getParameter(TEXTFIELD_STATE);
           if(value !=null){
             value=value.trim(); 
             if(!value.equals("")){
               newuser[UserView.STATE] = value;
             }
           }
           value = request.getParameter(SELECT_STATE);
           if(value !=null){
             if(!value.equals("")){
              newuser[UserView.STATE] = value;
            }
          } 

           value = request.getParameter(TEXTFIELD_COUNTRY);
           if(value !=null){
             value=value.trim(); 
             if(!value.equals("")){
               newuser[UserView.COUNTRY] = value;
             }
           }
           value = request.getParameter(SELECT_COUNTRY);
           if(value !=null){
             if(!value.equals("")){
              newuser[UserView.COUNTRY] = value;
            }
          } 

           value = request.getParameter(TEXTFIELD_EMAIL);
           if(value !=null){
             value=value.trim(); 
             if(!value.equals("")){
               newuser[UserView.EMAIL] = value;
             }
           }
           value = request.getParameter(SELECT_EMAIL);
           if(value !=null){
             if(!value.equals("")){
              newuser[UserView.EMAIL] = value;
            }
          } 

           value = request.getParameter(CHECKBOX_TYPEENDUSER);
           if(value !=null){
             if(value.equals(CHECKBOX_VALUE)){
               newuser[UserView.TYPE_ENDUSER] = UserView.TRUE;   
             }
             else{
               newuser[UserView.TYPE_ENDUSER] = UserView.FALSE;    
             }
           }
           value = request.getParameter(CHECKBOX_TYPERA);
           if(value !=null){
             if(value.equals(CHECKBOX_VALUE)){
               newuser[UserView.TYPE_RA] = UserView.TRUE;                            
             }
             else{
               newuser[UserView.TYPE_RA] = UserView.FALSE;                
             }
           }  
           value = request.getParameter(CHECKBOX_TYPERAADMIN);
           if(value !=null){
             if(value.equals(CHECKBOX_VALUE)){
               newuser[UserView.TYPE_RAADMIN] = UserView.TRUE;                       
             }
             else{
               newuser[UserView.TYPE_RAADMIN] = UserView.FALSE;      
             }
           }
           value = request.getParameter(CHECKBOX_TYPECA);
           if(value !=null){
             if(value.equals(CHECKBOX_VALUE)){
               newuser[UserView.TYPE_CA] = UserView.TRUE;              
             }
             else{
               newuser[UserView.TYPE_CA] = UserView.FALSE;   
             }
           }
           value = request.getParameter(CHECKBOX_TYPECAADMIN);
           if(value !=null){
             if(value.equals(CHECKBOX_VALUE)){
               newuser[UserView.TYPE_CAADMIN] = UserView.TRUE;               
             }
             else{
               newuser[UserView.TYPE_CAADMIN] = UserView.FALSE;   
             }
           }
           value = request.getParameter(CHECKBOX_TYPEROOTCA);
           if(value !=null){
             if(value.equals(CHECKBOX_VALUE)){
               newuser[UserView.TYPE_ROOTCA] = UserView.TRUE;       
             }
             else{
               newuser[UserView.TYPE_ROOTCA] = UserView.FALSE;   
             }
           }
           value = request.getParameter(SELECT_CERTIFICATETYPE);
           newuser[UserView.CERTIFICATETYPE] = value;   


           // Send changes to database.
           rabean.changeUserData(newuser);
           userdata = newuser;

         }
      }
    }
  
    profile = rabean.getProfile(profileid);
    

    int row = 0;
%>
<head>
  <title><%= globalconfiguration.getEjbcaTitle() %></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>">
  <link rel=STYLESHEET href="<%= ejbcawebbean.getCssFile() %>">
  <script language=javascript>
   <!--
      var TRUE  = "<%= Profile.TRUE %>";
      var FALSE = "<%= Profile.FALSE %>";



function checkallfields(){
    var illegalfields = 0;

    <%   
       if(profile.getUse(Profile.COMMONNAME)){
         if(profile.isChangeable(Profile.COMMONNAME)){%> 
    if(!checkfieldforlegalchars("document.edituser.<%=TEXTFIELD_COMMONNAME%>","<%= ejbcawebbean.getText("ONLYCHARACTERS2") %>"))
      illegalfields++;
    <%  if(profile.isRequired(Profile.COMMONNAME)){%>
    if((document.edituser.<%= TEXTFIELD_COMMONNAME %>.value == "")){
      alert("<%= ejbcawebbean.getText("REQUIREDCOMMONNAME") %>");
      illegalfields++;
    } 
    <%    }
        }
       }
       if(profile.getUse(Profile.ORGANIZATIONUNIT)){
         if(profile.isChangeable(Profile.ORGANIZATIONUNIT)){%>  
    if(!checkfieldforlegalchars("document.edituser.<%=TEXTFIELD_ORGANIZATIONUNIT%>","<%= ejbcawebbean.getText("ONLYCHARACTERS2") %>"))
      illegalfields++;
    <%  if(profile.isRequired(Profile.ORGANIZATIONUNIT)){%>
    if((document.edituser.<%= TEXTFIELD_ORGANIZATIONUNIT %>.value == "")){
      alert("<%= ejbcawebbean.getText("REQUIREDORGANIZATIONUNIT") %>");
      illegalfields++;
    } 
    <%    }
        }
       }
       if(profile.getUse(Profile.ORGANIZATION)){
         if(profile.isChangeable(Profile.ORGANIZATION)){%>  
    if(!checkfieldforlegalchars("document.edituser.<%=TEXTFIELD_ORGANIZATION%>","<%= ejbcawebbean.getText("ONLYCHARACTERS2") %>"))
      illegalfields++;
    <%  if(profile.isRequired(Profile.ORGANIZATION)){%>
    if((document.edituser.<%= TEXTFIELD_ORGANIZATION %>.value == "")){
      alert("<%= ejbcawebbean.getText("REQUIREDORGANIZATION") %>");
      illegalfields++;
    } 
    <%    }
        }
       }
       if(profile.getUse(Profile.LOCALE)){
         if(profile.isChangeable(Profile.LOCALE)){%>
    if(!checkfieldforlegalchars("document.edituser.<%=TEXTFIELD_LOCALE%>","<%= ejbcawebbean.getText("ONLYCHARACTERS2") %>"))
      illegalfields++;
    <%  if(profile.isRequired(Profile.LOCALE)){%>
    if((document.edituser.<%= TEXTFIELD_LOCALE %>.value == "")){
      alert("<%= ejbcawebbean.getText("REQUIREDLOCALE") %>");
      illegalfields++;
    } 
    <%    }
        }
       }
       if(profile.getUse(Profile.STATE)){
         if(profile.isChangeable(Profile.STATE)){%>  
    if(!checkfieldforlegalchars("document.edituser.<%=TEXTFIELD_STATE%>","<%= ejbcawebbean.getText("ONLYCHARACTERS2") %>"))
      illegalfields++;
    <%  if(profile.isRequired(Profile.STATE)){%>
    if((document.edituser.<%= TEXTFIELD_STATE %>.value == "")){
      alert("<%= ejbcawebbean.getText("REQUIREDSTATE") %>");
      illegalfields++;
    } 
    <%    }
        }
       }
       if(profile.getUse(Profile.COUNTRY)){
         if(profile.isChangeable(Profile.COUNTRY)){%>
    if(!checkfieldforlegalchars("document.edituser.<%=TEXTFIELD_COUNTRY%>","<%= ejbcawebbean.getText("ONLYCHARACTERS2") %>"))
      illegalfields++;  
    <%  if(profile.isRequired(Profile.COUNTRY)){%>
    if((document.edituser.<%= TEXTFIELD_COUNTRY %>.value == "")){
      alert("<%= ejbcawebbean.getText("REQUIREDCOUNTRY") %>");
      illegalfields++;
    } 
    <%    }
        }
       }
       if(profile.getUse(Profile.EMAIL)){
         if(profile.isChangeable(Profile.EMAIL)){%>
    if(!checkfieldforlegalemailchars("document.edituser.<%=TEXTFIELD_EMAIL%>","<%= ejbcawebbean.getText("ONLYEMAILCHARS") %>"))
      illegalfields++;
      <%  if(profile.isRequired(Profile.EMAIL)){%>
    if((document.edituser.<%= TEXTFIELD_EMAIL %>.value == "")){
      alert("<%= ejbcawebbean.getText("REQUIREDEMAIL") %>");
      illegalfields++;
    } 
    <%    }
        }
      }
 
       if(profile.getUse(Profile.PASSWORD)){%>  
    if(document.edituser.<%= TEXTFIELD_PASSWORD %>.value != document.edituser.<%= TEXTFIELD_CONFIRMPASSWORD %>.value){
      alert("<%= ejbcawebbean.getText("PASSWORDSDOESNTMATCH") %>");
      illegalfields++;
    } 
    <% } %>
    if(document.edituser.<%=SELECT_CERTIFICATETYPE%>.options.selectedIndex == -1){
      alert("<%=  ejbcawebbean.getText("CERTIFICATETYPEMUST") %>");
      illegalfields++;
    }

    if(illegalfields == 0){      
      document.edituser.<%= TEXTFIELD_USERNAME %>.disabled = false;
      <% if(profile.getUse(Profile.CLEARTEXTPASSWORD)){%> 
      document.edituser.<%= CHECKBOX_CLEARTEXTPASSWORD %>.disabled = false;
      <% } if(profile.getUse(Profile.TYPE_ENDUSER)){%> 
      document.edituser.<%= CHECKBOX_TYPEENDUSER %>.disabled = false;
      <% } if(profile.getUse(Profile.TYPE_RA)){%> 
      document.edituser.<%= CHECKBOX_TYPERA %>.disabled = false;
      <% } if(profile.getUse(Profile.TYPE_RAADMIN)){%> 
      document.edituser.<%= CHECKBOX_TYPERAADMIN %>.disabled = false;
      <% } if(profile.getUse(Profile.TYPE_CA)){%> 
      document.edituser.<%= CHECKBOX_TYPECA %>.disabled = false;
      <% } if(profile.getUse(Profile.TYPE_CAADMIN)){%> 
      document.edituser.<%= CHECKBOX_TYPECAADMIN %>.disabled = false;
      <% } if(profile.getUse(Profile.TYPE_ROOTCA)){%> 
      document.edituser.<%= CHECKBOX_TYPEROOTCA %>.disabled = false;
      <% } %>
    }

     return illegalfields == 0;  
}

function checksaveclose(){
  var returnval = checkallfields();
 
  if(returnval){
    self.close();
  }
 
  return returnval;
}

   -->
  </script>
  <script language=javascript src="<%= globalconfiguration .getRaAdminPath() %>ejbcajslib.js"></script>
</head>
<body>
  <h2 align="center"><%= ejbcawebbean.getText("EDITUSER") %></h2>
  <div align="right"><A  onclick='displayHelpWindow("<%= ejbcawebbean.getHelpfileInfix("ra_help.html") + "#edituser"%>")'>
    <u><%= ejbcawebbean.getText("HELP") %></u> </A>
  </div>
 <%if(nouserparameter){%>
  <div align="center"><h4 id="alert"><%=ejbcawebbean.getText("YOUMUSTSPECIFYUSERNAME") %></h4></div> 
  <% } 
     else{
       if(notauthorized){%>
  <div align="center"><h4 id="alert"><%=ejbcawebbean.getText("NOTAUTHORIZEDTOEDIT") %></h4></div> 
    <% }
       else{
         if(userdata == null){%>
  <div align="center"><h4 id="alert"><%=ejbcawebbean.getText("USERDOESNTEXIST") %></h4></div> 
    <%   }
         else{%>



     <table border="0" cellpadding="0" cellspacing="2" width="500">
<!--       <form name="changeprofile" action="<%= THIS_FILENAME %>" method="post">
       <input type="hidden" name='<%= ACTION %>' value='<%=ACTION_CHANGEPROFILE %>'>
       <input type="hidden" name='<%= USER_PARAMETER %>' value='<%= username%>'>
       <tr>
	 <td align="right"><%= ejbcawebbean.getText("PROFILE") %></td>
	 <td><select name="<%=SELECT_PROFILE %>" size="1" tabindex="1" onchange="document.changeprofile.submit()"'>
                <% for(int i = 0; i < profilenames.length;i++){
                      int pid = rabean.getProfileId(profilenames[i]);
                      %>                
	 	<option value="<%=pid %>" <% if(pid == profileid)
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
      </tr>
      </form> -->
      <tr id="Row<%=(row++)%2%>">
	 <td align="right"><%= ejbcawebbean.getText("PROFILE") + " :"%></td>  
         <td><% if(rabean.getProfileName(profileid)==null)
                  out.write(ejbcawebbean.getText("NOPROFILEDEFINED"));
                else
                  out.write(rabean.getProfileName(profileid));%>
         </td>
         <td><%= ejbcawebbean.getText("REQUIRED") %></td>
      <tr id="Row<%=(row++)%2%>">
	<td></td>
	<td></td>
	<td></td>
      </tr>
      </tr>
       <form name="edituser" action="<%= THIS_FILENAME %>" method="post">   
         <input type="hidden" name='<%= ACTION %>' value='<%=ACTION_EDITUSER %>'>   
         <input type="hidden" name='<%= HIDDEN_PROFILE %>' value='<%=profileid %>'>    
         <input type="hidden" name='<%= USER_PARAMETER %>' value='<%= username%>'>
          <% if(profile.getUse(Profile.USERNAME)){ %>
      <tr id="Row<%=(row++)%2%>">
	<td align="right"><%= ejbcawebbean.getText("USERNAME") %></td> 
	<td>
          <input type="text" name="<%= TEXTFIELD_USERNAME %>" size="40" maxlength="255" tabindex="2" value='<%= userdata[UserView.USERNAME] %>' disabled='true'  >
        </td>
	<td></td>
      </tr>
         <% }%>
          <% if(profile.getUse(Profile.PASSWORD)){ %>
      <tr id="Row<%=(row++)%2%>">
	<td align="right"><%= ejbcawebbean.getText("PASSWORD") %></td>
        <td>   
             <%
               if(!profile.isChangeable(Profile.PASSWORD)){ 
               %>
           <select name="<%= SELECT_PASSWORD %>" size="1" tabindex="3">
               <% if( profile.getValue(Profile.PASSWORD) != null){ %>
             <option value='<%=profile.getValue(Profile.PASSWORD).trim()%>' > 
               <%=profile.getValue(Profile.PASSWORD).trim()%>
             </option>                
               <%   
                  }
                %>
           </select>
           <% }else{ %> 
             <input type="password" name="<%= TEXTFIELD_PASSWORD %>" size="40" maxlength="255" tabindex="3" value='<%= userdata[UserView.PASSWORD] %>'>
           <% } %>
 
        </td>
	<td><input type="checkbox" name="<%= CHECKBOX_REQUIRED_PASSWORD %>" value="<%= CHECKBOX_VALUE %>"  disabled="true" <% if(profile.isRequired(Profile.PASSWORD)) out.write(" CHECKED "); %>></td>
      </tr>
       <% } 
          if(profile.getUse(Profile.PASSWORD)){%>
      <tr id="Row<%=(row++)%2%>">
	<td align="right"><%= ejbcawebbean.getText("CONFIRMPASSWORD") %></td>
        <td>
          <%   if(!profile.isChangeable(Profile.PASSWORD)){ 
               %>
           <select name="<%= SELECT_CONFIRMPASSWORD %>" size="1" tabindex="4">
               <% if( profile.getValue(Profile.PASSWORD) != null){ %>
             <option value='<%=profile.getValue(Profile.PASSWORD).trim()%>' > 
               <%= profile.getValue(Profile.PASSWORD).trim() %>
             </option>                
               <%   
                  }
                %>
           </select>
           <% }else{ %> 
             <input type="password" name="<%= TEXTFIELD_CONFIRMPASSWORD %>" size="40" maxlength="255" tabindex="4" value='<%= userdata[UserView.PASSWORD]%>'>
           <% } %>
        </td>
	<td>&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp
&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp</td> 
      </tr>
      <% }
          if(profile.getUse(Profile.CLEARTEXTPASSWORD)){%>
      <tr id="Row<%=(row++)%2%>">
	<td align="right"><%= ejbcawebbean.getText("CLEARTEXTPASSWORD") %></td>
	<td><input type="checkbox" name="<%= CHECKBOX_CLEARTEXTPASSWORD %>" value="<%= CHECKBOX_VALUE %>" tabindex="5" <% 
                                                                                                               boolean checked = false;
                                                                                                               if(userdata[UserView.CLEARTEXTPASSWORD].equals(UserView.TRUE))
                                                                                                                 checked = true;
                                                                                                               if(profile.isRequired(Profile.CLEARTEXTPASSWORD)){
                                                                                                                 out.write(" disabled='true'"); 
                                                                                                                 checked = true;
                                                                                                               }
                                                                                                               if(checked)
                                                                                                                 out.write(" CHECKED ");
                                                                                                             %>> 
        </td>
	<td></td> 
      </tr>
      <% } %>
      <tr id="Row<%=(row++)%2%>">
	<td>&nbsp;</td>
	<td>&nbsp;</td>
	<td></td>
       </tr>
   <%  if(profile.getUse(Profile.COMMONNAME)){%>
       <tr id="Row<%=(row++)%2%>">
	 <td align="right"><%= ejbcawebbean.getText("COMMONNAME") %></td>
	 <td>      
          <%   if(!profile.isChangeable(Profile.COMMONNAME)){ 
                 String[] options = new RE(Profile.SPLITCHAR, false).split(profile.getValue(Profile.COMMONNAME));
               %>
           <select name="<%= SELECT_COMMONNAME %>" size="1" tabindex="6">
               <% if( options != null){
                    for(int i=0;i < options.length;i++){ %>
             <option value='<%=options[i].trim()%>' <% if(userdata[UserView.COMMONNAME].equals(options[i])) out.write(" selected "); %>> 
                <%=options[i].trim()%>
             </option>                
               <%   }
                  }
                %>
           </select>
           <% }else{ %> 
             <input type="text" name="<%= TEXTFIELD_COMMONNAME %>" size="40" maxlength="255" tabindex="6" value='<%= userdata[UserView.COMMONNAME] %>'>
           <% } %>
        </td>
	<td><input type="checkbox" name="<%= CHECKBOX_REQUIRED_COMMONNAME %>" value="<%= CHECKBOX_VALUE %>"  disabled="true" <% if(profile.isRequired(Profile.COMMONNAME)) out.write(" CHECKED "); %>></td>
      </tr>
     <% } 
        if(profile.getUse(Profile.ORGANIZATIONUNIT)){%>
       <tr id="Row<%=(row++)%2%>">
	 <td align="right"><%= ejbcawebbean.getText("ORGANIZATIONUNIT") %></td>
	 <td>      
          <%  if(!profile.isChangeable(Profile.ORGANIZATIONUNIT)){ 
                 String[] options = new RE(Profile.SPLITCHAR, false).split(profile.getValue(Profile.ORGANIZATIONUNIT));
               %>
           <select name="<%= SELECT_ORGANIZATIONUNIT %>" size="1" tabindex="7">
               <% if( options != null){
                    for(int i=0;i < options.length;i++){ %>
             <option value='<%=options[i].trim()%>' <% if(userdata[UserView.ORGANIZATIONUNIT].equals(options[i])) out.write(" selected "); %>>
                <%=options[i].trim()%> 
             </option>                
               <%   }
                  }
                %>
           </select>
           <% }else{ %> 
             <input type="text" name="<%= TEXTFIELD_ORGANIZATIONUNIT %>" size="40" maxlength="255" tabindex="7" value='<%= userdata[UserView.ORGANIZATIONUNIT] %>'>
           <% } %>
        </td>
	<td><input type="checkbox" name="<%= CHECKBOX_REQUIRED_ORGANIZATIONUNIT %>" value="<%= CHECKBOX_VALUE %>"  disabled="true" <% if(profile.isRequired(Profile.ORGANIZATIONUNIT)) out.write(" CHECKED "); %>></td>
      </tr>
       <% } 
       if(profile.getUse(Profile.ORGANIZATION)){ %>
       <tr id="Row<%=(row++)%2%>">
	 <td align="right"><%= ejbcawebbean.getText("ORGANIZATION") %></td>
	 <td>      
          <%   if(!profile.isChangeable(Profile.ORGANIZATION)){ 
                 String[] options = new RE(Profile.SPLITCHAR, false).split(profile.getValue(Profile.ORGANIZATION));
               %>
           <select name="<%= SELECT_ORGANIZATION %>" size="1" tabindex="8">
               <% if( options != null){
                    for(int i=0;i < options.length;i++){ %>
             <option value='<%=options[i].trim()%>' <% if(userdata[UserView.ORGANIZATION].equals(options[i])) out.write(" selected "); %>>
                <%=options[i].trim()%> 
             </option>                
               <%   }
                  }
                %>
           </select>
           <% }else{ %> 
             <input type="text" name="<%= TEXTFIELD_ORGANIZATION %>" size="40" maxlength="255" tabindex="8" value='<%= userdata[UserView.ORGANIZATION] %>'>
           <% } %>
        </td>
	<td><input type="checkbox" name="<%= CHECKBOX_REQUIRED_ORGANIZATION %>" value="<%= CHECKBOX_VALUE %>"  disabled="true" <% if(profile.isRequired(Profile.ORGANIZATION)) out.write(" CHECKED "); %>></td>
      </tr>
     <% }
        if(profile.getUse(Profile.LOCALE)){%>
       <tr id="Row<%=(row++)%2%>">
	 <td align="right"><%= ejbcawebbean.getText("LOCALE") %></td>
	 <td>      
          <%   if(!profile.isChangeable(Profile.LOCALE)){ 
                 String[] options = new RE(Profile.SPLITCHAR, false).split(profile.getValue(Profile.LOCALE));
               %>
           <select name="<%= SELECT_LOCALE %>" size="1" tabindex="9">
               <% if( options != null){
                    for(int i=0;i < options.length;i++){ %>
             <option value='<%=options[i].trim()%>' <% if(userdata[UserView.LOCALE].equals(options[i])) out.write(" selected "); %>>
                <%=options[i].trim()%>  
             </option>                
               <%   }
                  }
                %>
           </select>
           <% }else{ %> 
             <input type="text" name="<%= TEXTFIELD_LOCALE %>" size="40" maxlength="255" tabindex="9" value='<%= userdata[UserView.LOCALE] %>'>
           <% }%>
        </td>
	<td><input type="checkbox" name="<%= CHECKBOX_REQUIRED_LOCALE %>" value="<%= CHECKBOX_VALUE %>"  disabled="true" <% if(profile.isRequired(Profile.LOCALE)) out.write(" CHECKED "); %>></td>
       </tr>
        <% }
           if(profile.getUse(Profile.STATE)){%>
       <tr id="Row<%=(row++)%2%>">
	 <td align="right"><%= ejbcawebbean.getText("STATE") %></td>
	 <td>      
          <%   if(!profile.isChangeable(Profile.STATE)){ 
                 String[] options =new RE(Profile.SPLITCHAR, false).split(profile.getValue(Profile.STATE));
               %>
           <select name="<%= SELECT_STATE %>" size="1" tabindex="10">
               <% if( options != null){
                    for(int i=0;i < options.length;i++){ %>
             <option value='<%=options[i].trim()%>' <% if(userdata[UserView.STATE].equals(options[i])) out.write(" selected "); %>>
                <%=options[i].trim()%>  
             </option>                
               <%   }
                  }
                %>
           </select>
           <% }else{ %> 
             <input type="text" name="<%= TEXTFIELD_STATE %>" size="40" maxlength="255" tabindex="10" value='<%=userdata[UserView.STATE] %>'>
           <% } %>

        </td>
	<td><input type="checkbox" name="<%= CHECKBOX_REQUIRED_STATE %>" value="<%= CHECKBOX_VALUE %>"  disabled="true" <% if(profile.isRequired(Profile.STATE)) out.write(" CHECKED "); %>></td>
       </tr>
      <% }
         if(profile.getUse(Profile.COUNTRY)){ %>      
       <tr id="Row<%=(row++)%2%>">
	 <td align="right"><%= ejbcawebbean.getText("COUNTRY") %></td>
	 <td>      
          <% if(!profile.isChangeable(Profile.COUNTRY)){ 
                 String[] options = new RE(Profile.SPLITCHAR, false).split(profile.getValue(Profile.COUNTRY));
               %>
           <select name="<%= SELECT_COUNTRY %>" size="1" tabindex="11">
               <% if( options != null){
                    for(int i=0;i < options.length;i++){ %>
             <option value='<%=options[i].trim()%>' <% if(userdata[UserView.COUNTRY].equals(options[i])) out.write(" selected "); %>>
                <%=options[i].trim()%>  
             </option>                
               <%   }
                  }
                %>
           </select>
           <% }else{ %> 
             <input type="text" name="<%= TEXTFIELD_COUNTRY %>" size="40" maxlength="255" tabindex="11" value='<%= userdata[UserView.COUNTRY] %>'>
           <% } %>
        </td>
	<td><input type="checkbox" name="<%= CHECKBOX_REQUIRED_COUNTRY %>" value="<%= CHECKBOX_VALUE %>"  disabled="true" <% if(profile.isRequired(Profile.COUNTRY)) out.write(" CHECKED "); %>></td>
       </tr>
         <% }  %>
       <tr id="Row<%=(row++)%2%>">
	 <td>&nbsp;</td>
	 <td>&nbsp;</td>
	 <td>&nbsp;</td>
       </tr>
       <% if(profile.getUse(Profile.EMAIL)){ %>
       <tr id="Row<%=(row++)%2%>">
	 <td align="right"><%= ejbcawebbean.getText("EMAIL") %></td>
	 <td>      
          <% if(!profile.isChangeable(Profile.EMAIL)){ 
                 String[] options = new RE(Profile.SPLITCHAR, false).split(profile.getValue(Profile.EMAIL));
               %>
           <select name="<%= SELECT_EMAIL %>" size="1" tabindex="12">
               <% if( options != null){
                    for(int i=0;i < options.length;i++){ %>
             <option value='<%=options[i].trim()%>' <% if(userdata[UserView.EMAIL].equals(options[i])) out.write(" selected "); %>>
                <%=options[i].trim()%>  
             </option>                
               <%   }
                  }
                %>
           </select>
           <% }else{ %> 
             <input type="text" name="<%= TEXTFIELD_EMAIL %>" size="40" maxlength="255" tabindex="12" value='<%= userdata[UserView.EMAIL] %>'>
           <% } %>
        </td>
	<td><input type="checkbox" name="<%= CHECKBOX_REQUIRED_EMAIL %>" value="<%= CHECKBOX_VALUE %>"  disabled="true" <% if(profile.isRequired(Profile.EMAIL)) out.write(" CHECKED "); %>></td>
       </tr>
       <% }%>
       <tr id="Row<%=(row++)%2%>">
	 <td align="right"><%= ejbcawebbean.getText("CERTIFICATETYPE") %></td>
	 <td>
         <select name="<%= SELECT_CERTIFICATETYPE %>" size="1" tabindex="13">
         <%
           String[] availablecerttypes = new RE(Profile.SPLITCHAR, false).split(profile.getValue(Profile.AVAILABLECERTTYPES));

           if( availablecerttypes != null){
             for(int i =0; i< availablecerttypes.length;i++){
         %>
         <option value='<%=availablecerttypes[i]%>' <% if(userdata[UserView.CERTIFICATETYPE].equals(availablecerttypes[i])) out.write(" selected "); %> >
            <%= rabean.getCertificateTypeName(Integer.parseInt(availablecerttypes[i])) %>
         </option>
         <%
             }
           }
         %>
         </select>
         </td>
	 <td><input type="checkbox" name="checkbox" value="true"  disabled="true" CHECKED></td>
       </tr>
       <tr id="Row<%=(row++)%2%>">
	 <td align="right"><%= ejbcawebbean.getText("TYPES") %></td>
	 <td>
         </td>
	 <td></td>
       </tr>
      <% if(profile.getUse(Profile.TYPE_ENDUSER)){ %>
    <tr  id="Row<%=(row++)%2%>"> 
      <td  align="right"> 
        <%= ejbcawebbean.getText("TYPEENDUSER") %> <br>
      </td>
      <td > 
        <input type="checkbox" name="<%=CHECKBOX_TYPEENDUSER%>" value="<%=CHECKBOX_VALUE %>" tabindex="14" <% 
                                                                                                               boolean checked = false;
                                                                                                               if(userdata[UserView.TYPE_ENDUSER].equals(UserView.TRUE))
                                                                                                                 checked = true;
                                                                                                               if(profile.isRequired(Profile.TYPE_ENDUSER)){
                                                                                                                 out.write(" disabled='true'"); 
                                                                                                                 checked = true;
                                                                                                               }
                                                                                                               if(checked)
                                                                                                                 out.write(" CHECKED ");
                                                                                                             %>>  
      </td>
      <td></td>
    </tr>
      <%} if(profile.getUse(Profile.TYPE_RA)){ %>
    <tr  id="Row<%=(row++)%2%>"> 
      <td  align="right"> 
        <%= ejbcawebbean.getText("TYPERA") %> 
      </td>
      <td> 
        <input type="checkbox" name="<%=CHECKBOX_TYPERA%>" value="<%=CHECKBOX_VALUE %>" tabindex="15" <% 
                                                                                                               boolean checked = false;
                                                                                                               if(userdata[UserView.TYPE_RA].equals(UserView.TRUE))
                                                                                                                 checked = true;
                                                                                                               if(profile.isRequired(Profile.TYPE_RA)){
                                                                                                                 out.write(" disabled='true'"); 
                                                                                                                 checked = true;
                                                                                                               }
                                                                                                               if(checked)
                                                                                                                 out.write(" CHECKED ");
                                                                                                             %>>  
      </td>
      <td></td>
    </tr>
    <%} if(profile.getUse(Profile.TYPE_RAADMIN)){ %>
    <tr  id="Row<%=(row++)%2%>"> 
      <td align="right"> 
        <%= ejbcawebbean.getText("TYPERAADMIN") %> 
      </td>
      <td > 
        <input type="checkbox" name="<%=CHECKBOX_TYPERAADMIN%>" value="<%=CHECKBOX_VALUE %>" tabindex="16"<% 
                                                                                                               boolean checked = false;
                                                                                                               if(userdata[UserView.TYPE_RAADMIN].equals(UserView.TRUE))
                                                                                                                 checked = true;
                                                                                                               if(profile.isRequired(Profile.TYPE_RAADMIN)){
                                                                                                                 out.write(" disabled='true'"); 
                                                                                                                 checked = true;
                                                                                                               }
                                                                                                               if(checked)
                                                                                                                 out.write(" CHECKED ");
                                                                                                             %>>  
      </td>
      <td></td>
    </tr>
    <%} if(profile.getUse(Profile.TYPE_CA)){ %>
    <tr  id="Row<%=(row++)%2%>"> 
      <td  align="right"> 
        <%= ejbcawebbean.getText("TYPECA") %> 
      </td>
      <td > 
        <input type="checkbox" name="<%=CHECKBOX_TYPECA%>" value="<%=CHECKBOX_VALUE %>" tabindex="17"<% 
                                                                                                               boolean checked = false;
                                                                                                               if(userdata[UserView.TYPE_CA].equals(UserView.TRUE))
                                                                                                                 checked = true;
                                                                                                               if(profile.isRequired(Profile.TYPE_CA)){
                                                                                                                 out.write(" disabled='true'"); 
                                                                                                                 checked = true;
                                                                                                               }
                                                                                                               if(checked)
                                                                                                                 out.write(" CHECKED ");
                                                                                                             %>>  
      </td>
      <td></td>
    </tr>
    <%} if(profile.getUse(Profile.TYPE_CAADMIN)){ %>
    <tr  id="Row<%=(row++)%2%>">
      <td align="right"> 
        <%= ejbcawebbean.getText("TYPECAADMIN") %> 
      </td>
      <td> 
        <input type="checkbox" name="<%=CHECKBOX_TYPECAADMIN%>" value="<%=CHECKBOX_VALUE %>" tabindex="18"<% 
                                                                                                               boolean checked = false;
                                                                                                               if(userdata[UserView.TYPE_CAADMIN].equals(UserView.TRUE))
                                                                                                                 checked = true;
                                                                                                               if(profile.isRequired(Profile.TYPE_CAADMIN)){
                                                                                                                 out.write(" disabled='true'"); 
                                                                                                                 checked = true;
                                                                                                               }
                                                                                                               if(checked)
                                                                                                                 out.write(" CHECKED ");
                                                                                                             %>>  
      </td>
      <td></td>
    </tr>
    <%} if(profile.getUse(Profile.TYPE_ROOTCA)){ %>
    <tr  id="Row<%=(row++)%2%>"> 
      <td  align="right"> 
        <%= ejbcawebbean.getText("TYPEROOTCA") %> 
      </td>
      <td > 
        <input type="checkbox" name="<%=CHECKBOX_TYPEROOTCA%>" value="<%=CHECKBOX_VALUE %>" tabindex="19"<% 
                                                                                                               boolean checked = false;
                                                                                                               if(userdata[UserView.TYPE_ROOTCA].equals(UserView.TRUE))
                                                                                                                 checked = true;
                                                                                                               if(profile.isRequired(Profile.TYPE_ROOTCA)){
                                                                                                                 out.write(" disabled='true'"); 
                                                                                                                 checked = true;
                                                                                                               }
                                                                                                               if(checked)
                                                                                                                 out.write(" CHECKED ");
                                                                                                             %>> 
      </td>
      <td></td>
    </tr>
   <% } %>
       <tr id="Row<%=(row++)%2%>">
	 <td></td>
	 <td><input type="submit" name="<%= BUTTON_SAVE %>" value="<%= ejbcawebbean.getText("SAVE") %>" tabindex="20"
                    onClick='return checkallfields()'> 
             <input type="submit" name="<%= BUTTON_SAVEANDCLOSE %>" value="<%= ejbcawebbean.getText("SAVEANDCLOSE") %>" tabindex="20"
                    onClick='return checksaveclose()'> 
             <input type="button" name="<%= BUTTON_CLOSE %>" value="<%= ejbcawebbean.getText("CLOSE") %>" tabindex="21" onclick='self.close()'>
         </td>
         <td></td>
       </tr> 
     </table> 
  </form>

  <%// Include Footer 
      }
    }
   }
   String footurl =   globalconfiguration .getFootBanner(); %>
   
  <jsp:include page="<%= footurl %>" />
</body>
</html>