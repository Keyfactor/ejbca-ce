<html> 
<%@page contentType="text/html"%>
<%@page  errorPage="/errorpage.jsp" import="RegularExpression.RE, se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean,se.anatom.ejbca.ra.GlobalConfiguration, se.anatom.ejbca.webdist.rainterface.UserView,
                 se.anatom.ejbca.webdist.rainterface.RAInterfaceBean, se.anatom.ejbca.webdist.rainterface.ProfileDataHandler, se.anatom.ejbca.ra.raadmin.Profile, se.anatom.ejbca.ra.UserDataRemote,
                 javax.ejb.CreateException, java.rmi.RemoteException" %>
<jsp:useBean id="ejbcawebbean" scope="session" class="se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean" />
<jsp:setProperty name="ejbcawebbean" property="*" /> 
<jsp:useBean id="rabean" scope="session" class="se.anatom.ejbca.webdist.rainterface.RAInterfaceBean" />
<jsp:setProperty name="rabean" property="*" /> 
<%! // Declarations

  static final String ACTION                   = "action";
  static final String ACTION_ADDUSER           = "adduser";
  static final String ACTION_CHANGEPROFILE     = "changeprofile";

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

  static final String VIEWUSER_LINK            = "viewuser.jsp";
  static final String EDITUSER_LINK            = "edituser.jsp";

  static final String HIDDEN_USERNAME           = "hiddenusername";
  static final String HIDDEN_PROFILE            = "hiddenprofile";

%><%
  // Initialize environment.
  GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request); 
                                            rabean.initialize(request);

  String THIS_FILENAME             =  globalconfiguration.getRaPath()  + "/adduser.jsp";
  Profile  profile                 = null;
  String[] profilenames            = null; 
  boolean noprofiles               = false; 

  if(globalconfiguration.getUseStrongAuthorization())
     profilenames                  = rabean.getCreateAuthorizedProfileNames();
  else
     profilenames                  = rabean.getProfileNames();
  int profileid = 0;

  if(profilenames== null || profilenames.length == 0) 
     noprofiles=true;

  boolean chooselastprofile = false;
  if(ejbcawebbean.getLastProfile() != null){
    for(int i=0 ; i< profilenames.length; i++){
       if(rabean.getProfileName(Integer.parseInt(ejbcawebbean.getLastProfile())).equals(profilenames[i]))
         chooselastprofile=true;
    }
  }

  if(!noprofiles){
    if(!chooselastprofile)
      profileid = rabean.getProfileId(profilenames[0]);
    else
      profileid = Integer.parseInt(ejbcawebbean.getLastProfile());
  } 

  boolean userexists               = false;
  boolean useradded                = false;
  boolean useoldprofile            = false;
  Profile oldprofile               = null;
  String addedusername             = ""; 

  String lastselectedusername          = "";
  String lastselectedpassword          = "";
  String lastselectedcommonname        = "";
  String lastselectedorganizationunit  = "";
  String lastselectedorganization      = "";
  String lastselectedlocale            = "";
  String lastselectedstate             = "";
  String lastselectedcountry           = "";
  String lastselectedemail             = "";
  String lastselectedcertificatetype   = "";
  

  if( request.getParameter(ACTION) != null){
    if(request.getParameter(ACTION).equals(ACTION_CHANGEPROFILE)){
      profileid = Integer.parseInt(request.getParameter(SELECT_PROFILE)); 
      ejbcawebbean.setLastProfile(Integer.toString(profileid));
    }
    if( request.getParameter(ACTION).equals(ACTION_ADDUSER)){
      if( request.getParameter(BUTTON_ADDUSER) != null || request.getParameter(BUTTON_RELOAD) != null ){
         String[] newuser = new String[UserView.NUMBEROF_USERFIELDS];
         for(int i=0; i< UserView.NUMBEROF_USERFIELDS; i++){
           newuser[i]=""; 
         }
         int oldprofileid = 0;
 
         // Get previous chosen profile.
         String hiddenprofileid = request.getParameter(HIDDEN_PROFILE); 
         oldprofileid = Integer.parseInt(hiddenprofileid);       
         

         oldprofile = rabean.getProfile(oldprofileid);
         newuser[UserView.PROFILE]= Integer.toString(oldprofileid);         

         String value = request.getParameter(TEXTFIELD_USERNAME);
         if(value !=null){
           value=value.trim(); 
           if(!value.equals("")){
             newuser[UserView.USERNAME] = value;
             oldprofile.setValue(Profile.USERNAME, value);
             addedusername = value;
           }
         }

         value = request.getParameter(SELECT_USERNAME);
          if(value !=null){
           if(!value.equals("")){
             newuser[UserView.USERNAME] = value;
             lastselectedusername = value;
             addedusername = value;
           }
         } 

         value = request.getParameter(TEXTFIELD_PASSWORD);
         if(value !=null){
           value=value.trim(); 
           if(!value.equals("")){
             newuser[UserView.PASSWORD] = value;  
             oldprofile.setValue(Profile.PASSWORD, value);            
           }
         }

         value = request.getParameter(SELECT_PASSWORD);
          if(value !=null){
           if(!value.equals("")){
             newuser[UserView.PASSWORD] = value; 
             lastselectedpassword = value;
           }
         } 

         value = request.getParameter(CHECKBOX_CLEARTEXTPASSWORD);
         if(value !=null){
           if(value.equals(CHECKBOX_VALUE)){
             newuser[UserView.CLEARTEXTPASSWORD] = UserView.TRUE;
             oldprofile.setValue(Profile.CLEARTEXTPASSWORD, Profile.TRUE);             
           }
           else{
               newuser[UserView.CLEARTEXTPASSWORD] = UserView.FALSE;
               oldprofile.setValue(Profile.CLEARTEXTPASSWORD, Profile.FALSE);    
             }
           }

           value = request.getParameter(TEXTFIELD_COMMONNAME);
           if(value !=null){
             value=value.trim(); 
             if(!value.equals("")){
               newuser[UserView.COMMONNAME] = value;
               oldprofile.setValue(Profile.COMMONNAME, value);   
             }
           }
           value = request.getParameter(SELECT_COMMONNAME);
           if(value !=null){
             if(!value.equals("")){
              newuser[UserView.COMMONNAME] = value;
              lastselectedcommonname = value;
            }
          } 

           value = request.getParameter(TEXTFIELD_ORGANIZATIONUNIT);
           if(value !=null){
             value=value.trim(); 
             if(!value.equals("")){
               newuser[UserView.ORGANIZATIONUNIT] = value;
               oldprofile.setValue(Profile.ORGANIZATIONUNIT, value); 
             }
           }
           value = request.getParameter(SELECT_ORGANIZATIONUNIT);
           if(value !=null){
             if(!value.equals("")){
              newuser[UserView.ORGANIZATIONUNIT] = value;
              lastselectedorganizationunit = value;
            }
          } 

           value = request.getParameter(TEXTFIELD_ORGANIZATION);
           if(value !=null){
             value=value.trim(); 
             if(!value.equals("")){
               newuser[UserView.ORGANIZATION] = value;
               oldprofile.setValue(Profile.ORGANIZATION, value); 
             }
           }
           value = request.getParameter(SELECT_ORGANIZATION);
           if(value !=null){
             if(!value.equals("")){
              newuser[UserView.ORGANIZATION] = value;
              lastselectedorganization = value;
            }
          } 
           value = request.getParameter(TEXTFIELD_LOCALE);
           if(value !=null){
             value=value.trim(); 
             if(!value.equals("")){
               newuser[UserView.LOCALE] = value;
               oldprofile.setValue(Profile.LOCALE, value); 
             }
           }
           value = request.getParameter(SELECT_LOCALE);
           if(value !=null){
             if(!value.equals("")){
              newuser[UserView.LOCALE] = value;
              lastselectedlocale = value;
            }
          } 

           value = request.getParameter(TEXTFIELD_STATE);
           if(value !=null){
             value=value.trim(); 
             if(!value.equals("")){
               newuser[UserView.STATE] = value;
               oldprofile.setValue(Profile.STATE, value); 
             }
           }
           value = request.getParameter(SELECT_STATE);
           if(value !=null){
             if(!value.equals("")){
              newuser[UserView.STATE] = value;
              lastselectedstate = value;
            }
          } 

           value = request.getParameter(TEXTFIELD_COUNTRY);
           if(value !=null){
             value=value.trim(); 
             if(!value.equals("")){
               newuser[UserView.COUNTRY] = value;
               oldprofile.setValue(Profile.COUNTRY, value); 
             }
           }
           value = request.getParameter(SELECT_COUNTRY);
           if(value !=null){
             if(!value.equals("")){
              newuser[UserView.COUNTRY] = value;
              lastselectedcountry = value;
            }
          } 

           value = request.getParameter(TEXTFIELD_EMAIL);
           if(value !=null){
             value=value.trim(); 
             if(!value.equals("")){
               newuser[UserView.EMAIL] = value;
               oldprofile.setValue(Profile.EMAIL, value); 
             }
           }
           value = request.getParameter(SELECT_EMAIL);
           if(value !=null){
             if(!value.equals("")){
              newuser[UserView.EMAIL] = value;
              lastselectedemail = value;
            }
          } 

           value = request.getParameter(CHECKBOX_TYPEENDUSER);
           if(value !=null){
             if(value.equals(CHECKBOX_VALUE)){
               newuser[UserView.TYPE_ENDUSER] = UserView.TRUE;   
               oldprofile.setValue(Profile.TYPE_ENDUSER, Profile.TRUE);  
             }
             else{
               newuser[UserView.TYPE_ENDUSER] = UserView.FALSE;   
               oldprofile.setValue(Profile.TYPE_ENDUSER, Profile.FALSE); 
             }
           }
           value = request.getParameter(CHECKBOX_TYPERA);
           if(value !=null){
             if(value.equals(CHECKBOX_VALUE)){
               newuser[UserView.TYPE_RA] = UserView.TRUE;   
               oldprofile.setValue(Profile.TYPE_RA, Profile.TRUE);                          
             }
             else{
               newuser[UserView.TYPE_RA] = UserView.FALSE;   
               oldprofile.setValue(Profile.TYPE_RA, Profile.FALSE);               
             }
           }  
           value = request.getParameter(CHECKBOX_TYPERAADMIN);
           if(value !=null){
             if(value.equals(CHECKBOX_VALUE)){
               newuser[UserView.TYPE_RAADMIN] = UserView.TRUE;   
               oldprofile.setValue(Profile.TYPE_RAADMIN, Profile.TRUE);                      
             }
             else{
               newuser[UserView.TYPE_RAADMIN] = UserView.FALSE;   
               oldprofile.setValue(Profile.TYPE_RAADMIN, Profile.FALSE);   
             }
           }
           value = request.getParameter(CHECKBOX_TYPECA);
           if(value !=null){
             if(value.equals(CHECKBOX_VALUE)){
               newuser[UserView.TYPE_CA] = UserView.TRUE;   
               oldprofile.setValue(Profile.TYPE_CA, Profile.TRUE);            
             }
             else{
               newuser[UserView.TYPE_CA] = UserView.FALSE;   
               oldprofile.setValue(Profile.TYPE_CA, Profile.FALSE);
             }
           }
           value = request.getParameter(CHECKBOX_TYPECAADMIN);
           if(value !=null){
             if(value.equals(CHECKBOX_VALUE)){
               newuser[UserView.TYPE_CAADMIN] = UserView.TRUE;   
               oldprofile.setValue(Profile.TYPE_CAADMIN, Profile.TRUE);              
             }
             else{
               newuser[UserView.TYPE_CAADMIN] = UserView.FALSE;   
               oldprofile.setValue(Profile.TYPE_CAADMIN, Profile.FALSE);
             }
           }
           value = request.getParameter(CHECKBOX_TYPEROOTCA);
           if(value !=null){
             if(value.equals(CHECKBOX_VALUE)){
               newuser[UserView.TYPE_ROOTCA] = UserView.TRUE;   
               oldprofile.setValue(Profile.TYPE_ROOTCA, Profile.TRUE);          
             }
             else{
               newuser[UserView.TYPE_ROOTCA] = UserView.FALSE;   
               oldprofile.setValue(Profile.TYPE_ROOTCA, Profile.FALSE);  
             }
           }
           value = request.getParameter(SELECT_CERTIFICATETYPE);
           newuser[UserView.CERTIFICATETYPE] = value;   
           oldprofile.setValue(Profile.DEFAULTCERTTYPE, value);         
           lastselectedcertificatetype = value;


           // See if user already exists
           if(rabean.userExist(newuser[UserView.USERNAME])  ){
             userexists = true;
             useoldprofile = true;   
           } else{
             if( request.getParameter(BUTTON_RELOAD) != null ){
              useoldprofile = true;   
             }else{
               rabean.addUser(newuser); 
               useradded=true;
             }
           }
         }
      }
    }
  
    if(!useoldprofile)
      profile = rabean.getProfile(profileid);
    else
      profile = oldprofile;
    

    int numberofrows = ejbcawebbean.getEntriesPerPage();
    String[][] addedusers = rabean.getAddedUsers(numberofrows);
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

    <% if(profile.getUse(Profile.USERNAME)){
         if(profile.isChangeable(Profile.USERNAME)){ %>
    if(!checkfieldforlegalchars("document.adduser.<%=TEXTFIELD_USERNAME%>","<%= ejbcawebbean.getText("ONLYCHARACTERS2") %>"))
      illegalfields++;
    <%  if(profile.isRequired(Profile.USERNAME)){%>
    if((document.adduser.<%= TEXTFIELD_USERNAME %>.value == "")){
      alert("<%= ejbcawebbean.getText("REQUIREDUSERNAME") %>");
      illegalfields++;
    } 
    <%    }
        }
       }
       if(profile.getUse(Profile.PASSWORD)){
         if(profile.isChangeable(Profile.PASSWORD)){%>

    <%  if(profile.isRequired(Profile.PASSWORD)){%>
    if((document.adduser.<%= TEXTFIELD_PASSWORD %>.value == "")){
      alert("<%= ejbcawebbean.getText("REQUIREDPASSWORD") %>");
      illegalfields++;
    } 
    <%    }
        }
       }
       if(profile.getUse(Profile.COMMONNAME)){
         if(profile.isChangeable(Profile.COMMONNAME)){%> 
    if(!checkfieldforlegalchars("document.adduser.<%=TEXTFIELD_COMMONNAME%>","<%= ejbcawebbean.getText("ONLYCHARACTERS2") %>"))
      illegalfields++;
    <%  if(profile.isRequired(Profile.COMMONNAME)){%>
    if((document.adduser.<%= TEXTFIELD_COMMONNAME %>.value == "")){
      alert("<%= ejbcawebbean.getText("REQUIREDCOMMONNAME") %>");
      illegalfields++;
    } 
    <%    }
        }
       }
       if(profile.getUse(Profile.ORGANIZATIONUNIT)){
         if(profile.isChangeable(Profile.ORGANIZATIONUNIT)){%>  
    if(!checkfieldforlegalchars("document.adduser.<%=TEXTFIELD_ORGANIZATIONUNIT%>","<%= ejbcawebbean.getText("ONLYCHARACTERS2") %>"))
      illegalfields++;
    <%  if(profile.isRequired(Profile.ORGANIZATIONUNIT)){%>
    if((document.adduser.<%= TEXTFIELD_ORGANIZATIONUNIT %>.value == "")){
      alert("<%= ejbcawebbean.getText("REQUIREDORGANIZATIONUNIT") %>");
      illegalfields++;
    } 
    <%    }
        }
       }
       if(profile.getUse(Profile.ORGANIZATION)){
         if(profile.isChangeable(Profile.ORGANIZATION)){%>  
    if(!checkfieldforlegalchars("document.adduser.<%=TEXTFIELD_ORGANIZATION%>","<%= ejbcawebbean.getText("ONLYCHARACTERS2") %>"))
      illegalfields++;
    <%  if(profile.isRequired(Profile.ORGANIZATION)){%>
    if((document.adduser.<%= TEXTFIELD_ORGANIZATION %>.value == "")){
      alert("<%= ejbcawebbean.getText("REQUIREDORGANIZATION") %>");
      illegalfields++;
    } 
    <%    }
        }
       }
       if(profile.getUse(Profile.LOCALE)){
         if(profile.isChangeable(Profile.LOCALE)){%>
    if(!checkfieldforlegalchars("document.adduser.<%=TEXTFIELD_LOCALE%>","<%= ejbcawebbean.getText("ONLYCHARACTERS2") %>"))
      illegalfields++;
    <%  if(profile.isRequired(Profile.LOCALE)){%>
    if((document.adduser.<%= TEXTFIELD_LOCALE %>.value == "")){
      alert("<%= ejbcawebbean.getText("REQUIREDLOCALE") %>");
      illegalfields++;
    } 
    <%    }
        }
       }
       if(profile.getUse(Profile.STATE)){
         if(profile.isChangeable(Profile.STATE)){%>  
    if(!checkfieldforlegalchars("document.adduser.<%=TEXTFIELD_STATE%>","<%= ejbcawebbean.getText("ONLYCHARACTERS2") %>"))
      illegalfields++;
    <%  if(profile.isRequired(Profile.STATE)){%>
    if((document.adduser.<%= TEXTFIELD_STATE %>.value == "")){
      alert("<%= ejbcawebbean.getText("REQUIREDSTATE") %>");
      illegalfields++;
    } 
    <%    }
        }
       }
       if(profile.getUse(Profile.COUNTRY)){
         if(profile.isChangeable(Profile.COUNTRY)){%>
    if(!checkfieldforlegalchars("document.adduser.<%=TEXTFIELD_COUNTRY%>","<%= ejbcawebbean.getText("ONLYCHARACTERS2") %>"))
      illegalfields++;  
    <%  if(profile.isRequired(Profile.COUNTRY)){%>
    if((document.adduser.<%= TEXTFIELD_COUNTRY %>.value == "")){
      alert("<%= ejbcawebbean.getText("REQUIREDCOUNTRY") %>");
      illegalfields++;
    } 
    <%    }
        }
       }
       if(profile.getUse(Profile.EMAIL)){
         if(profile.isChangeable(Profile.EMAIL)){%>
    if(!checkfieldforlegalemailchars("document.adduser.<%=TEXTFIELD_EMAIL%>","<%= ejbcawebbean.getText("ONLYEMAILCHARS") %>"))
      illegalfields++;
      <%  if(profile.isRequired(Profile.EMAIL)){%>
    if((document.adduser.<%= TEXTFIELD_EMAIL %>.value == "")){
      alert("<%= ejbcawebbean.getText("REQUIREDEMAIL") %>");
      illegalfields++;
    } 
    <%    }
        }
      }
 
       if(profile.getUse(Profile.PASSWORD)){
         if(profile.isChangeable(Profile.PASSWORD)){%>  
    if(document.adduser.<%= TEXTFIELD_PASSWORD %>.value != document.adduser.<%= TEXTFIELD_CONFIRMPASSWORD %>.value){
      alert("<%= ejbcawebbean.getText("PASSWORDSDOESNTMATCH") %>");
      illegalfields++;
    } 
    <%   }else{ %>
    if(document.adduser.<%=SELECT_PASSWORD%>.options.selectedIndex != document.adduser.<%=SELECT_CONFIRMPASSWORD%>.options.selectedIndex ){
      alert("<%= ejbcawebbean.getText("PASSWORDSDOESNTMATCH") %>");
      illegalfields++; 
    }
<%        }   
     } %>
    if(document.adduser.<%=SELECT_CERTIFICATETYPE%>.options.selectedIndex == -1){
      alert("<%=  ejbcawebbean.getText("CERTIFICATETYPEMUST") %>");
      illegalfields++;
    }

    if(illegalfields == 0){
      <% if(profile.getUse(Profile.CLEARTEXTPASSWORD)){%> 
      document.adduser.<%= CHECKBOX_CLEARTEXTPASSWORD %>.disabled = false;
      <% } if(profile.getUse(Profile.TYPE_ENDUSER)){%> 
      document.adduser.<%= CHECKBOX_TYPEENDUSER %>.disabled = false;
      <% } if(profile.getUse(Profile.TYPE_RA)){%> 
      document.adduser.<%= CHECKBOX_TYPERA %>.disabled = false;
      <% } if(profile.getUse(Profile.TYPE_RAADMIN)){%> 
      document.adduser.<%= CHECKBOX_TYPERAADMIN %>.disabled = false;
      <% } if(profile.getUse(Profile.TYPE_CA)){%> 
      document.adduser.<%= CHECKBOX_TYPECA %>.disabled = false;
      <% } if(profile.getUse(Profile.TYPE_CAADMIN)){%> 
      document.adduser.<%= CHECKBOX_TYPECAADMIN %>.disabled = false;
      <% } if(profile.getUse(Profile.TYPE_ROOTCA)){%> 
      document.adduser.<%= CHECKBOX_TYPEROOTCA %>.disabled = false;
      <% } %>
    }

     return illegalfields == 0;  
}
   -->
  </script>
  <script language=javascript src="<%= globalconfiguration .getRaAdminPath() %>ejbcajslib.js"></script>
</head>
<body>
  <h2 align="center"><%= ejbcawebbean.getText("ADDUSER") %></h2>
  <div align="right"><A  onclick='displayHelpWindow("<%= ejbcawebbean.getHelpfileInfix("ra_help.html") + "#adduser"%>")'>
    <u><%= ejbcawebbean.getText("HELP") %></u> </A>
  </div>
  <% if(noprofiles){ %>
    <div align="center"><h4 id="alert"><%=ejbcawebbean.getText("NOTAUTHORIZEDTOCREATEUSER") %></h4></div>
  <% }else{
       if(userexists){ %>
  <div align="center"><h4 id="alert"><%=ejbcawebbean.getText("USERALREADYEXISTS") %></h4></div>
  <% } %>
  <% if(useradded){ %>
  <div align="center"><h4 id="alert"><% out.write(ejbcawebbean.getText("USER")+ " ");
                                        out.write(addedusername + " ");
                                        out.write(ejbcawebbean.getText("ADDEDSUCCESSFULLY"));%></h4></div>
  <% } %>


     <table border="0" cellpadding="0" cellspacing="2" width="792">
       <form name="changeprofile" action="<%= THIS_FILENAME %>" method="post">
       <input type="hidden" name='<%= ACTION %>' value='<%=ACTION_CHANGEPROFILE %>'>
       <tr>
         <td></td>
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
	<td></td>
      </tr>
      </form>
       <form name="adduser" action="<%= THIS_FILENAME %>" method="post">   
         <input type="hidden" name='<%= ACTION %>' value='<%=ACTION_ADDUSER %>'>   
         <input type="hidden" name='<%= HIDDEN_PROFILE %>' value='<%=profileid %>'>    
          <% if(profile.getUse(Profile.USERNAME)){ %>
      <tr id="Row<%=(row++)%2%>">
	<td></td>
	<td align="right"><%= ejbcawebbean.getText("USERNAME") %></td> 
	<td>
            <% if(!profile.isChangeable(Profile.USERNAME)){ 
                 String[] options = new RE(Profile.SPLITCHAR, false).split(profile.getValue(Profile.USERNAME));
               %>
           <select name="<%= SELECT_USERNAME %>" size="1" tabindex="2">
               <% if( options != null){
                    for(int i=0;i < options.length;i++){ %>
             <option value='<%=options[i].trim()%>' <% if(lastselectedusername.equals(options[i])) out.write(" selected "); %>> 
               <%=options[i].trim()%>
             </option>                
               <%   }
                  }
                %>
           </select>
           <% }else{ %> 
             <input type="text" name="<%= TEXTFIELD_USERNAME %>" size="40" maxlength="255" tabindex="2" value='<%= profile.getValue(Profile.USERNAME) %>'>
           <% } %>

        </td>
	<td><input type="checkbox" name="<%= CHECKBOX_REQUIRED_USERNAME %>" value="<%= CHECKBOX_VALUE %>"  disabled="true" <% if(profile.isRequired(Profile.USERNAME)) out.write(" CHECKED "); %>></td>
      </tr>
         <% }%>
          <% if(profile.getUse(Profile.PASSWORD)){ %>
      <tr id="Row<%=(row++)%2%>">
        <td>&nbsp&nbsp&nbsp&nbsp&nbsp;&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp
&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp
        </td>
	<td align="right"><%= ejbcawebbean.getText("PASSWORD") %></td>
        <td>   
             <%
               if(!profile.isChangeable(Profile.PASSWORD)){ 
               %>
           <select name="<%= SELECT_PASSWORD %>" size="1" tabindex="3">
               <% if(profile.getValue(Profile.PASSWORD) != null){ %>
             <option value='<%=profile.getValue(Profile.PASSWORD).trim()%>' > <%=profile.getValue(Profile.PASSWORD)  %>
             </option>                
               <%   
                  }
                %>
           </select>
           <% }else{ %> 
             <input type="password" name="<%= TEXTFIELD_PASSWORD %>" size="40" maxlength="255" tabindex="3" value='<%= profile.getValue(Profile.PASSWORD) %>'>
           <% } %>
 
        </td>
	<td><input type="checkbox" name="<%= CHECKBOX_REQUIRED_PASSWORD %>" value="<%= CHECKBOX_VALUE %>"  disabled="true" <% if(profile.isRequired(Profile.PASSWORD)) out.write(" CHECKED "); %>></td>
      </tr>
       <% } 
          if(profile.getUse(Profile.PASSWORD)){%>
      <tr id="Row<%=(row++)%2%>">
	<td></td>
	<td align="right"><%= ejbcawebbean.getText("CONFIRMPASSWORD") %></td>
        <td>
          <%   if(!profile.isChangeable(Profile.PASSWORD)){ 
               %>
           <select name="<%= SELECT_CONFIRMPASSWORD %>" size="1" tabindex="4">
               <% if( profile.getValue(Profile.PASSWORD) != null){ %>
             <option value='<%=profile.getValue(Profile.PASSWORD).trim()%>'> 
                 <%=profile.getValue(Profile.PASSWORD).trim() %>
             </option>                
               <%   
                  }
                %>
           </select>
           <% }else{ %> 
             <input type="password" name="<%= TEXTFIELD_CONFIRMPASSWORD %>" size="40" maxlength="255" tabindex="4" value='<%= profile.getValue(Profile.PASSWORD) %>'>
           <% } %>
        </td>
	<td>&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp
&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp</td> 
      </tr>
      <% }
          if(profile.getUse(Profile.CLEARTEXTPASSWORD)){%>
      <tr id="Row<%=(row++)%2%>">
	<td></td>
	<td align="right"><%= ejbcawebbean.getText("CLEARTEXTPASSWORD") %></td>
	<td><input type="checkbox" name="<%= CHECKBOX_CLEARTEXTPASSWORD %>" value="<%= CHECKBOX_VALUE %>" tabindex="5" <% if(profile.getValue(Profile.CLEARTEXTPASSWORD).equals(Profile.TRUE))
                                                                                                                 out.write(" CHECKED "); 
                                                                                                               if(profile.isRequired(Profile.CLEARTEXTPASSWORD))
                                                                                                                 out.write(" disabled='true' "); 
                                                                                                             %>> 
        </td>
	<td></td> 
      </tr>
      <% } %>
      <tr id="Row<%=(row++)%2%>">
	<td></td>
	<td>&nbsp;</td>
	<td>&nbsp;</td>
	<td></td>
       </tr>
   <%  if(profile.getUse(Profile.COMMONNAME)){%>
       <tr id="Row<%=(row++)%2%>">
	 <td></td>
	 <td align="right"><%= ejbcawebbean.getText("COMMONNAME") %></td>
	 <td>      
          <%   if(!profile.isChangeable(Profile.COMMONNAME)){ 
                 String[] options = new RE(Profile.SPLITCHAR, false).split(profile.getValue(Profile.COMMONNAME));
               %>
           <select name="<%= SELECT_COMMONNAME %>" size="1" tabindex="6">
               <% if( options != null){
                    for(int i=0;i < options.length;i++){ %>
             <option value='<%=options[i].trim()%>' <% if(lastselectedcommonname.equals(options[i])) out.write(" selected "); %>> 
                <%=options[i].trim()%>
             </option>                
               <%   }
                  }
                %>
           </select>
           <% }else{ %> 
             <input type="text" name="<%= TEXTFIELD_COMMONNAME %>" size="40" maxlength="255" tabindex="6" value='<%= profile.getValue(Profile.COMMONNAME) %>'>
           <% } %>
        </td>
	<td><input type="checkbox" name="<%= CHECKBOX_REQUIRED_COMMONNAME %>" value="<%= CHECKBOX_VALUE %>"  disabled="true" <% if(profile.isRequired(Profile.COMMONNAME)) out.write(" CHECKED "); %>></td>
      </tr>
     <% } 
        if(profile.getUse(Profile.ORGANIZATIONUNIT)){%>
       <tr id="Row<%=(row++)%2%>">
	 <td></td>
	 <td align="right"><%= ejbcawebbean.getText("ORGANIZATIONUNIT") %></td>
	 <td>      
          <%  if(!profile.isChangeable(Profile.ORGANIZATIONUNIT)){ 
                 String[] options = new RE(Profile.SPLITCHAR, false).split(profile.getValue(Profile.ORGANIZATIONUNIT));
               %>
           <select name="<%= SELECT_ORGANIZATIONUNIT %>" size="1" tabindex="7">
               <% if( options != null){
                    for(int i=0;i < options.length;i++){ %>
             <option value='<%=options[i].trim()%>' <% if(lastselectedorganizationunit.equals(options[i])) out.write(" selected "); %>>
                <%=options[i].trim()%> 
             </option>                
               <%   }
                  }
                %>
           </select>
           <% }else{ %> 
             <input type="text" name="<%= TEXTFIELD_ORGANIZATIONUNIT %>" size="40" maxlength="255" tabindex="7" value='<%= profile.getValue(Profile.ORGANIZATIONUNIT) %>'>
           <% } %>
        </td>
	<td><input type="checkbox" name="<%= CHECKBOX_REQUIRED_ORGANIZATIONUNIT %>" value="<%= CHECKBOX_VALUE %>"  disabled="true" <% if(profile.isRequired(Profile.ORGANIZATIONUNIT)) out.write(" CHECKED "); %>></td>
      </tr>
       <% } 
       if(profile.getUse(Profile.ORGANIZATION)){ %>
       <tr id="Row<%=(row++)%2%>">
	 <td></td>
	 <td align="right"><%= ejbcawebbean.getText("ORGANIZATION") %></td>
	 <td>      
          <%   if(!profile.isChangeable(Profile.ORGANIZATION)){ 
                 String[] options = new RE(Profile.SPLITCHAR, false).split(profile.getValue(Profile.ORGANIZATION));
               %>
           <select name="<%= SELECT_ORGANIZATION %>" size="1" tabindex="8">
               <% if( options != null){
                    for(int i=0;i < options.length;i++){ %>
             <option value='<%=options[i].trim()%>' <% if(lastselectedorganization.equals(options[i])) out.write(" selected "); %>>
                <%=options[i].trim()%> 
             </option>                
               <%   }
                  }
                %>
           </select>
           <% }else{ %> 
             <input type="text" name="<%= TEXTFIELD_ORGANIZATION %>" size="40" maxlength="255" tabindex="8" value='<%= profile.getValue(Profile.ORGANIZATION) %>'>
           <% } %>
        </td>
	<td><input type="checkbox" name="<%= CHECKBOX_REQUIRED_ORGANIZATION %>" value="<%= CHECKBOX_VALUE %>"  disabled="true" <% if(profile.isRequired(Profile.ORGANIZATION)) out.write(" CHECKED "); %>></td>
      </tr>
     <% }
        if(profile.getUse(Profile.LOCALE)){%>
       <tr id="Row<%=(row++)%2%>">
	 <td></td>
	 <td align="right"><%= ejbcawebbean.getText("LOCALE") %></td>
	 <td>      
          <%   if(!profile.isChangeable(Profile.LOCALE)){ 
                 String[] options = new RE(Profile.SPLITCHAR, false).split(profile.getValue(Profile.LOCALE));
               %>
           <select name="<%= SELECT_LOCALE %>" size="1" tabindex="9">
               <% if( options != null){
                    for(int i=0;i < options.length;i++){ %>
             <option value='<%=options[i].trim()%>' <% if(lastselectedlocale.equals(options[i])) out.write(" selected "); %>>
                <%=options[i].trim()%>  
             </option>                
               <%   }
                  }
                %>
           </select>
           <% }else{ %> 
             <input type="text" name="<%= TEXTFIELD_LOCALE %>" size="40" maxlength="255" tabindex="9" value='<%= profile.getValue(Profile.LOCALE) %>'>
           <% }%>
        </td>
	<td><input type="checkbox" name="<%= CHECKBOX_REQUIRED_LOCALE %>" value="<%= CHECKBOX_VALUE %>"  disabled="true" <% if(profile.isRequired(Profile.LOCALE)) out.write(" CHECKED "); %>></td>
       </tr>
        <% }
           if(profile.getUse(Profile.STATE)){%>
       <tr id="Row<%=(row++)%2%>">
	 <td></td>
	 <td align="right"><%= ejbcawebbean.getText("STATE") %></td>
	 <td>      
          <%   if(!profile.isChangeable(Profile.STATE)){ 
                 String[] options =new RE(Profile.SPLITCHAR, false).split(profile.getValue(Profile.STATE));
               %>
           <select name="<%= SELECT_STATE %>" size="1" tabindex="10">
               <% if( options != null){
                    for(int i=0;i < options.length;i++){ %>
             <option value='<%=options[i].trim()%>' <% if(lastselectedstate.equals(options[i])) out.write(" selected "); %>>
                <%=options[i].trim()%>  
             </option>                
               <%   }
                  }
                %>
           </select>
           <% }else{ %> 
             <input type="text" name="<%= TEXTFIELD_STATE %>" size="40" maxlength="255" tabindex="10" value='<%= profile.getValue(Profile.STATE) %>'>
           <% } %>

        </td>
	<td><input type="checkbox" name="<%= CHECKBOX_REQUIRED_STATE %>" value="<%= CHECKBOX_VALUE %>"  disabled="true" <% if(profile.isRequired(Profile.STATE)) out.write(" CHECKED "); %>></td>
       </tr>
      <% }
         if(profile.getUse(Profile.COUNTRY)){ %>      
       <tr id="Row<%=(row++)%2%>">
	 <td></td>
	 <td align="right"><%= ejbcawebbean.getText("COUNTRY") %></td>
	 <td>      
          <% if(!profile.isChangeable(Profile.COUNTRY)){ 
                 String[] options = new RE(Profile.SPLITCHAR, false).split(profile.getValue(Profile.COUNTRY));
               %>
           <select name="<%= SELECT_COUNTRY %>" size="1" tabindex="11">
               <% if( options != null){
                    for(int i=0;i < options.length;i++){ %>
             <option value='<%=options[i].trim()%>' <% if(lastselectedcountry.equals(options[i])) out.write(" selected "); %>>
                <%=options[i].trim()%>  
             </option>                
               <%   }
                  }
                %>
           </select>
           <% }else{ %> 
             <input type="text" name="<%= TEXTFIELD_COUNTRY %>" size="40" maxlength="255" tabindex="11" value='<%= profile.getValue(Profile.COUNTRY) %>'>
           <% } %>
        </td>
	<td><input type="checkbox" name="<%= CHECKBOX_REQUIRED_COUNTRY %>" value="<%= CHECKBOX_VALUE %>"  disabled="true" <% if(profile.isRequired(Profile.COUNTRY)) out.write(" CHECKED "); %>></td>
       </tr>
         <% }  %>
       <tr id="Row<%=(row++)%2%>">
	 <td>&nbsp;</td>
	 <td>&nbsp;</td>
	 <td>&nbsp;</td>
	 <td>&nbsp;</td>
       </tr>
       <% if(profile.getUse(Profile.EMAIL)){ %>
       <tr id="Row<%=(row++)%2%>">
	 <td></td>
	 <td align="right"><%= ejbcawebbean.getText("EMAIL") %></td>
	 <td>      
          <% if(!profile.isChangeable(Profile.EMAIL)){ 
                 String[] options = new RE(Profile.SPLITCHAR, false).split(profile.getValue(Profile.EMAIL));
               %>
           <select name="<%= SELECT_EMAIL %>" size="1" tabindex="12">
               <% if( options != null){
                    for(int i=0;i < options.length;i++){ %>
             <option value='<%=options[i].trim()%>' <% if(lastselectedemail.equals(options[i])) out.write(" selected "); %>>
                <%=options[i].trim()%>  
             </option>                
               <%   }
                  }
                %>
           </select>
           <% }else{ %> 
             <input type="text" name="<%= TEXTFIELD_EMAIL %>" size="40" maxlength="255" tabindex="12" value='<%= profile.getValue(Profile.EMAIL) %>'>
           <% } %>
        </td>
	<td><input type="checkbox" name="<%= CHECKBOX_REQUIRED_EMAIL %>" value="<%= CHECKBOX_VALUE %>"  disabled="true" <% if(profile.isRequired(Profile.EMAIL)) out.write(" CHECKED "); %>></td>
       </tr>
       <% }%>
       <tr id="Row<%=(row++)%2%>">
	 <td></td>
	 <td align="right"><%= ejbcawebbean.getText("CERTIFICATETYPE") %></td>
	 <td>
         <select name="<%= SELECT_CERTIFICATETYPE %>" size="1" tabindex="13">
         <%
           String[] availablecerttypes = new RE(Profile.SPLITCHAR, false).split(profile.getValue(Profile.AVAILABLECERTTYPES));
           if(lastselectedcertificatetype.equals(""))
             lastselectedcertificatetype= profile.getValue(Profile.DEFAULTCERTTYPE);

           if( availablecerttypes != null){
             for(int i =0; i< availablecerttypes.length;i++){
         %>
         <option value='<%=availablecerttypes[i]%>' <% if(lastselectedcertificatetype.equals(availablecerttypes[i])) out.write(" selected "); %> >
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
	 <td></td>
	 <td align="right"><%= ejbcawebbean.getText("TYPES") %></td>
	 <td>
         </td>
	 <td></td>
       </tr>
      <% if(profile.getUse(Profile.TYPE_ENDUSER)){ %>
    <tr  id="Row<%=(row++)%2%>"> 
      <td></td>
      <td  align="right"> 
        <%= ejbcawebbean.getText("TYPEENDUSER") %> <br>
      </td>
      <td > 
        <input type="checkbox" name="<%=CHECKBOX_TYPEENDUSER%>" value="<%=CHECKBOX_VALUE %>" tabindex="14" <% if(profile.getValue(Profile.TYPE_ENDUSER).equals(Profile.TRUE))
                                                                                                                 out.write(" CHECKED "); 
                                                                                                               if(profile.isRequired(Profile.TYPE_ENDUSER))
                                                                                                                 out.write(" disabled='true' "); 
                                                                                                             %>> 
      </td>
      <td></td>
    </tr>
      <%} if(profile.getUse(Profile.TYPE_RA)){ %>
    <tr  id="Row<%=(row++)%2%>"> 
      <td></td>
      <td  align="right"> 
        <%= ejbcawebbean.getText("TYPERA") %> 
      </td>
      <td> 
        <input type="checkbox" name="<%=CHECKBOX_TYPERA%>" value="<%=CHECKBOX_VALUE %>" tabindex="15"<% if(profile.getValue(Profile.TYPE_RA).equals(Profile.TRUE))
                                                                                                                 out.write(" CHECKED "); 
                                                                                                               if(profile.isRequired(Profile.TYPE_RA))
                                                                                                                 out.write(" disabled='true' "); 
                                                                                                             %>>  
      </td>
      <td></td>
    </tr>
    <%} if(profile.getUse(Profile.TYPE_RAADMIN)){ %>
    <tr  id="Row<%=(row++)%2%>"> 
      <td></td>
      <td align="right"> 
        <%= ejbcawebbean.getText("TYPERAADMIN") %> 
      </td>
      <td > 
        <input type="checkbox" name="<%=CHECKBOX_TYPERAADMIN%>" value="<%=CHECKBOX_VALUE %>" tabindex="16"<% if(profile.getValue(Profile.TYPE_RAADMIN).equals(Profile.TRUE))
                                                                                                                 out.write(" CHECKED "); 
                                                                                                               if(profile.isRequired(Profile.TYPE_RAADMIN))
                                                                                                                 out.write(" disabled='true' "); 
                                                                                                             %>> 
      </td>
      <td></td>
    </tr>
    <%} if(profile.getUse(Profile.TYPE_CA)){ %>
    <tr  id="Row<%=(row++)%2%>"> 
      <td></td>
      <td  align="right"> 
        <%= ejbcawebbean.getText("TYPECA") %> 
      </td>
      <td > 
        <input type="checkbox" name="<%=CHECKBOX_TYPECA%>" value="<%=CHECKBOX_VALUE %>" tabindex="17"<% if(profile.getValue(Profile.TYPE_CA).equals(Profile.TRUE))
                                                                                                                 out.write(" CHECKED "); 
                                                                                                               if(profile.isRequired(Profile.TYPE_CA))
                                                                                                                 out.write(" disabled='true' "); 
                                                                                                             %>>  
      </td>
      <td></td>
    </tr>
    <%} if(profile.getUse(Profile.TYPE_CAADMIN)){ %>
    <tr  id="Row<%=(row++)%2%>">
       <td></td>
      <td align="right"> 
        <%= ejbcawebbean.getText("TYPECAADMIN") %> 
      </td>
      <td> 
        <input type="checkbox" name="<%=CHECKBOX_TYPECAADMIN%>" value="<%=CHECKBOX_VALUE %>" tabindex="18"<% if(profile.getValue(Profile.TYPE_CAADMIN).equals(Profile.TRUE))
                                                                                                                 out.write(" CHECKED "); 
                                                                                                               if(profile.isRequired(Profile.TYPE_CAADMIN))
                                                                                                                 out.write(" disabled='true' "); 
                                                                                                             %>> 
      </td>
      <td></td>
    </tr>
    <%} if(profile.getUse(Profile.TYPE_ROOTCA)){ %>
    <tr  id="Row<%=(row++)%2%>"> 
      <td></td>
      <td  align="right"> 
        <%= ejbcawebbean.getText("TYPEROOTCA") %> 
      </td>
      <td > 
        <input type="checkbox" name="<%=CHECKBOX_TYPEROOTCA%>" value="<%=CHECKBOX_VALUE %>" tabindex="19"<% if(profile.getValue(Profile.TYPE_ROOTCA).equals(Profile.TRUE))
                                                                                                                 out.write(" CHECKED "); 
                                                                                                               if(profile.isRequired(Profile.TYPE_ROOTCA))
                                                                                                                 out.write(" disabled='true' "); 
                                                                                                             %>>  
      </td>
      <td></td>
    </tr>
   <% } %>
       <tr id="Row<%=(row++)%2%>">
	 <td></td>
	 <td></td>
	 <td><input type="submit" name="<%= BUTTON_ADDUSER %>" value="<%= ejbcawebbean.getText("ADDUSER") %>" tabindex="20"
                    onClick='return checkallfields()'> 
             <input type="reset" name="<%= BUTTON_RESET %>" value="<%= ejbcawebbean.getText("RESET") %>" tabindex="21"></td>
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
    window.open(link, 'edit_user',config='height=600,width=550,scrollbars=yes,toolbar=no,resizable=1');
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
 <%        }
         }
       }
     }%>
  </table>
  </form>
   <p></p>

  <%// Include Footer 
   String footurl =   globalconfiguration .getFootBanner(); %>
   
  <jsp:include page="<%= footurl %>" />
</body>
</html>