<html> 
<%@page contentType="text/html"%>
<%@page  errorPage="/errorpage.jsp" import="java.util.*, se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean,se.anatom.ejbca.ra.raadmin.GlobalConfiguration, se.anatom.ejbca.webdist.rainterface.UserView,
                 se.anatom.ejbca.webdist.rainterface.RAInterfaceBean, se.anatom.ejbca.webdist.rainterface.EndEntityProfileDataHandler, se.anatom.ejbca.ra.raadmin.EndEntityProfile, se.anatom.ejbca.ra.UserDataRemote,
                 javax.ejb.CreateException, java.rmi.RemoteException, se.anatom.ejbca.ra.raadmin.DNFieldExtractor, se.anatom.ejbca.ra.UserAdminData, se.anatom.ejbca.webdist.hardtokeninterface.HardTokenInterfaceBean, 
                 se.anatom.ejbca.hardtoken.HardTokenIssuer, se.anatom.ejbca.hardtoken.HardTokenIssuerData, se.anatom.ejbca.hardtoken.AvailableHardToken,  se.anatom.ejbca.SecConst" %>
<jsp:useBean id="ejbcawebbean" scope="session" class="se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean" />
<jsp:useBean id="rabean" scope="session" class="se.anatom.ejbca.webdist.rainterface.RAInterfaceBean" />
<jsp:useBean id="tokenbean" scope="session" class="se.anatom.ejbca.webdist.hardtokeninterface.HardTokenInterfaceBean" />
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
  static final String TEXTFIELD_SUBJECTDN         = "textfieldsubjectdn";
  static final String TEXTFIELD_SUBJECTALTNAME    = "textfieldsubjectaltname";
  static final String TEXTFIELD_EMAIL             = "textfieldemail";

  static final String SELECT_ENDENTITYPROFILE     = "selectendentityprofile";
  static final String SELECT_CERTIFICATEPROFILE   = "selectcertificateprofile";
  static final String SELECT_TOKEN                = "selecttoken";
  static final String SELECT_USERNAME             = "selectusername";
  static final String SELECT_PASSWORD             = "selectpassword";
  static final String SELECT_CONFIRMPASSWORD      = "selectconfirmpassword";
  static final String SELECT_SUBJECTDN            = "selectsubjectdn";
  static final String SELECT_SUBJECTALTNAME       = "selectsubjectaltname";
  static final String SELECT_EMAIL                = "selectemail";
  static final String SELECT_HARDTOKENISSUER      = "selecthardtokenissuer";
  static final String SELECT_CA                   = "selectca";

  static final String CHECKBOX_CLEARTEXTPASSWORD          = "checkboxcleartextpassword";
  static final String CHECKBOX_SUBJECTDN                 = "checkboxsubjectdn";
  static final String CHECKBOX_SUBJECTALTNAME            = "checkboxsubjectaltname";
  static final String CHECKBOX_ADMINISTRATOR              = "checkboxadministrator";
  static final String CHECKBOX_KEYRECOVERABLE             = "checkboxkeyrecoverable";
  static final String CHECKBOX_SENDNOTIFICATION           = "checkboxsendnotification";


  static final String CHECKBOX_REQUIRED_USERNAME          = "checkboxrequiredusername";
  static final String CHECKBOX_REQUIRED_PASSWORD          = "checkboxrequiredpassword";
  static final String CHECKBOX_REQUIRED_CLEARTEXTPASSWORD = "checkboxrequiredcleartextpassword";
  static final String CHECKBOX_REQUIRED_SUBJECTDN         = "checkboxrequiredsubjectdn";
  static final String CHECKBOX_REQUIRED_SUBJECTALTNAME    = "checkboxrequiredsubjectaltname";
  static final String CHECKBOX_REQUIRED_EMAIL             = "checkboxrequiredemail";
  static final String CHECKBOX_REQUIRED_ADMINISTRATOR     = "checkboxrequiredadministrator";
  static final String CHECKBOX_REQUIRED_KEYRECOVERABLE    = "checkboxrequiredkeyrecoverable";


  static final String CHECKBOX_VALUE             = "true";

  static final String USER_PARAMETER           = "username";
  static final String SUBJECTDN_PARAMETER      = "subjectdnparameter";



  static final String HIDDEN_USERNAME           = "hiddenusername";
  static final String HIDDEN_PROFILE            = "hiddenprofile";

%><%
  // Initialize environment.

  String[] subjectfieldtexts = {"","","", "OLDEMAILDN2", "UID", "COMMONNAME", "SERIALNUMBER1", 
                                "GIVENNAME2", "INITIALS", "SURNAME","TITLE","ORGANIZATIONUNIT","ORGANIZATION",
                                "LOCALE","STATE","DOMAINCOMPONENT","COUNTRY",
                                "RFC822NAME", "DNSNAME", "IPADDRESS", "OTHERNAME", "UNIFORMRESOURCEID", "X400ADDRESS", "DIRECTORYNAME",
                                "EDIPARTNAME", "REGISTEREDID","","","","","","","","","","","UPN"};

  GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request,"/ra_functionality/create_end_entity"); 
                                            rabean.initialize(request, ejbcawebbean);
                                            if(globalconfiguration.getIssueHardwareTokens())
                                              tokenbean.initialize(request, ejbcawebbean);

  final String VIEWUSER_LINK            = "/" + globalconfiguration.getRaPath()  + "/viewendentity.jsp";
  final String EDITUSER_LINK            = "/" + globalconfiguration.getRaPath()  + "/editendentity.jsp";

  String THIS_FILENAME             =  globalconfiguration.getRaPath()  + "/addendentity.jsp";
  EndEntityProfile  profile        = null;
  String[] profilenames            = null; 
  boolean noprofiles               = false; 
  int profileid = 0;


  profilenames                  = (String[]) ejbcawebbean.getInformationMemory().getCreateAuthorizedEndEntityProfileNames().keySet().toArray(new String[0]);


  if(profilenames== null || profilenames.length == 0) 
     noprofiles=true;
  else 
    profileid = rabean.getEndEntityProfileId(profilenames[0]);

  boolean chooselastprofile = false;
  if(ejbcawebbean.getLastEndEntityProfile() != 0 && rabean.getEndEntityProfileName(ejbcawebbean.getLastEndEntityProfile()) != null){
    for(int i=0 ; i< profilenames.length; i++){
       if(rabean.getEndEntityProfileName(ejbcawebbean.getLastEndEntityProfile()).equals(profilenames[i]))
         chooselastprofile=true;
    }
  }

  if(!noprofiles){
    if(!chooselastprofile)
      profileid = rabean.getEndEntityProfileId(profilenames[0]);
    else
      profileid = ejbcawebbean.getLastEndEntityProfile();
  } 

  boolean userexists               = false;
  boolean useradded                = false;
  boolean useoldprofile            = false;
  boolean usehardtokenissuers      = false;
  boolean usekeyrecovery           = false;
  boolean issuperadministrator     = false;
  try{
    issuperadministrator = ejbcawebbean.isAuthorizedNoLog("/super_administrator");
  }catch(se.anatom.ejbca.authorization.AuthorizationDeniedException ade){}   

 
  EndEntityProfile oldprofile      = null;
  String addedusername             = ""; 

  String lastselectedusername           = "";
  String lastselectedpassword           = "";
  String lastselectedemail              = "";
  String lastselectedcertificateprofile = "";
  String lastselectedtoken              = "";
  String lastselectedca                  = "";
  int lastselectedhardtokenissuer       = 1;

  String[] lastselectedsubjectdns       =null;
  String[] lastselectedsubjectaltnames  =null;  
  int[] fielddata = null;

  HashMap caidtonamemap = ejbcawebbean.getInformationMemory().getCAIdToNameMap();

  if( request.getParameter(ACTION) != null){
    if(request.getParameter(ACTION).equals(ACTION_CHANGEPROFILE)){
      profileid = Integer.parseInt(request.getParameter(SELECT_ENDENTITYPROFILE)); 
      ejbcawebbean.setLastEndEntityProfile(profileid);
    }
    if( request.getParameter(ACTION).equals(ACTION_ADDUSER)){
      if( request.getParameter(BUTTON_ADDUSER) != null){
         UserView newuser = new UserView(caidtonamemap);
         int oldprofileid = UserAdminData.NO_ENDENTITYPROFILE;
 
         // Get previous chosen profile.
         String hiddenprofileid = request.getParameter(HIDDEN_PROFILE); 
         oldprofileid = Integer.parseInt(hiddenprofileid);       
         if(globalconfiguration.getEnableEndEntityProfileLimitations()){
           // Check that adminsitrator is authorized to given profileid
           boolean authorizedtoprofile = false;
           for(int i=0 ; i< profilenames.length; i++){
             if(oldprofileid == rabean.getEndEntityProfileId(profilenames[i]))
               authorizedtoprofile=true;
           }
           if(!authorizedtoprofile)
             throw new Exception("Error when trying to add user to non authorized profile");
         }
         

         oldprofile = rabean.getEndEntityProfile(oldprofileid);
         lastselectedsubjectdns       = new String[oldprofile.getSubjectDNFieldOrderLength()];
         lastselectedsubjectaltnames  = new String[oldprofile.getSubjectAltNameFieldOrderLength()];
         newuser.setEndEntityProfileId(oldprofileid);         

         String value = request.getParameter(TEXTFIELD_USERNAME);
         if(value !=null){
           value=value.trim(); 
           if(!value.equals("")){
             newuser.setUsername(value);
             oldprofile.setValue(EndEntityProfile.USERNAME,0,value);
             addedusername = value;
           }
         }

         value = request.getParameter(SELECT_USERNAME);
          if(value !=null){
           if(!value.equals("")){
             newuser.setUsername(value);
             lastselectedusername = value;
             addedusername = value;
           }
         } 

         value = request.getParameter(TEXTFIELD_PASSWORD);
         if(value !=null){
           value=value.trim(); 
           if(!value.equals("")){
             newuser.setPassword(value);
             oldprofile.setValue(EndEntityProfile.PASSWORD, 0, value);            
           }
         }

         value = request.getParameter(SELECT_PASSWORD);
          if(value !=null){
           if(!value.equals("")){
             newuser.setPassword(value);
             lastselectedpassword = value;
           }
         } 

         value = request.getParameter(CHECKBOX_CLEARTEXTPASSWORD);
         if(value !=null){
           if(value.equals(CHECKBOX_VALUE)){
             newuser.setClearTextPassword(true);
             oldprofile.setValue(EndEntityProfile.CLEARTEXTPASSWORD, 0, EndEntityProfile.TRUE);             
           }
           else{
               newuser.setClearTextPassword(false);
               oldprofile.setValue(EndEntityProfile.CLEARTEXTPASSWORD, 0, EndEntityProfile.FALSE);    
             }
           }

 
           value = request.getParameter(TEXTFIELD_EMAIL);
           if(value !=null){
             value=value.trim(); 
             if(!value.equals("")){
               newuser.setEmail(value);
               oldprofile.setValue(EndEntityProfile.EMAIL, 0,  value); 
             }
           }
           value = request.getParameter(SELECT_EMAIL);
           if(value !=null){
             if(!value.equals("")){
               newuser.setEmail(value);
               lastselectedemail = value;
            }
          }

           String subjectdn = "";
           int numberofsubjectdnfields = oldprofile.getSubjectDNFieldOrderLength();
           for(int i=0; i < numberofsubjectdnfields; i++){
             value=null;
             fielddata = oldprofile.getSubjectDNFieldsInOrder(i); 

             if(fielddata[EndEntityProfile.FIELDTYPE] != EndEntityProfile.OLDDNE)
               value = request.getParameter(TEXTFIELD_SUBJECTDN+i);
             else{
               if(request.getParameter(CHECKBOX_SUBJECTDN+i)!=null)
                 if(request.getParameter(CHECKBOX_SUBJECTDN+i).equals(CHECKBOX_VALUE))
                   value = newuser.getEmail();
             }
             if(value !=null){
               value=value.trim(); 
               if(!value.equals("")){
                 if(subjectdn.equals(""))
                   subjectdn = DNFieldExtractor.SUBJECTDNFIELDS[oldprofile.profileFieldIdToUserFieldIdMapper(fielddata[EndEntityProfile.FIELDTYPE])] +value;
                 else
                   subjectdn += ", " + DNFieldExtractor.SUBJECTDNFIELDS[oldprofile.profileFieldIdToUserFieldIdMapper(fielddata[EndEntityProfile.FIELDTYPE])] +value;
                   oldprofile.setValue(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER], value);   
               }
             }
             value = request.getParameter(SELECT_SUBJECTDN+i);
             if(value !=null){
               if(!value.equals("")){
                 if(subjectdn == null)
                   subjectdn = DNFieldExtractor.SUBJECTDNFIELDS[oldprofile.profileFieldIdToUserFieldIdMapper(fielddata[EndEntityProfile.FIELDTYPE])] +value;
                 else
                   subjectdn += ", " + DNFieldExtractor.SUBJECTDNFIELDS[oldprofile.profileFieldIdToUserFieldIdMapper(fielddata[EndEntityProfile.FIELDTYPE])] +value;
                 lastselectedsubjectdns[i] = value;
               }
             } 
           }
           newuser.setSubjectDN(subjectdn);

           String subjectaltname = "";
           int numberofsubjectaltnamefields = oldprofile.getSubjectAltNameFieldOrderLength();
           for(int i=0; i < numberofsubjectaltnamefields; i++){
             fielddata = oldprofile.getSubjectAltNameFieldsInOrder(i); 

             if(fielddata[EndEntityProfile.FIELDTYPE] != EndEntityProfile.RFC822NAME)
               value = request.getParameter(TEXTFIELD_SUBJECTALTNAME+i);
             else{
               value=null;
               if(request.getParameter(CHECKBOX_SUBJECTALTNAME+i)!=null)
                 if(request.getParameter(CHECKBOX_SUBJECTALTNAME+i).equals(CHECKBOX_VALUE))
                   value = newuser.getEmail();
             }
             if(value !=null){
               value=value.trim(); 
               if(!value.equals("")){
                 if(subjectaltname.equals(""))
                   subjectaltname = DNFieldExtractor.SUBJECTALTNAME[oldprofile.profileFieldIdToUserFieldIdMapper(fielddata[EndEntityProfile.FIELDTYPE]) - DNFieldExtractor.SUBJECTALTERNATIVENAMEBOUNDRARY] +value;
                 else
                   subjectaltname += ", " + DNFieldExtractor.SUBJECTALTNAME[oldprofile.profileFieldIdToUserFieldIdMapper(fielddata[EndEntityProfile.FIELDTYPE]) - DNFieldExtractor.SUBJECTALTERNATIVENAMEBOUNDRARY] +value;
                   oldprofile.setValue(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER], value);   
               }
             }
             value = request.getParameter(SELECT_SUBJECTALTNAME+i);
             if(value !=null){
               if(!value.equals("")){
                 if(subjectaltname == null)
                   subjectaltname = DNFieldExtractor.SUBJECTALTNAME[oldprofile.profileFieldIdToUserFieldIdMapper(fielddata[EndEntityProfile.FIELDTYPE]) - DNFieldExtractor.SUBJECTALTERNATIVENAMEBOUNDRARY] +value;
                 else
                   subjectaltname += ", " + DNFieldExtractor.SUBJECTALTNAME[oldprofile.profileFieldIdToUserFieldIdMapper(fielddata[EndEntityProfile.FIELDTYPE])- DNFieldExtractor.SUBJECTALTERNATIVENAMEBOUNDRARY] +value;
                 lastselectedsubjectaltnames[i] = value;
              }
             }
           }
           newuser.setSubjectAltName(subjectaltname);
 
           value = request.getParameter(CHECKBOX_ADMINISTRATOR);
           if(value !=null){
             if(value.equals(CHECKBOX_VALUE)){
               newuser.setAdministrator(true);   
               oldprofile.setValue(EndEntityProfile.ADMINISTRATOR, 0, EndEntityProfile.TRUE);  
             }
             else{
               newuser.setAdministrator(false);  
               oldprofile.setValue(EndEntityProfile.ADMINISTRATOR, 0, EndEntityProfile.FALSE); 
             }
           }
           value = request.getParameter(CHECKBOX_KEYRECOVERABLE);
           if(value !=null){
             if(value.equals(CHECKBOX_VALUE)){
               newuser.setKeyRecoverable(true);   
               oldprofile.setValue(EndEntityProfile.KEYRECOVERABLE, 0, EndEntityProfile.TRUE);                          
             }
             else{
               newuser.setKeyRecoverable(false);   
               oldprofile.setValue(EndEntityProfile.KEYRECOVERABLE, 0, EndEntityProfile.FALSE);               
             }
           }  
           value = request.getParameter(CHECKBOX_SENDNOTIFICATION);
           if(value !=null){
             if(value.equals(CHECKBOX_VALUE)){
               newuser.setSendNotification(true);   
               oldprofile.setValue(EndEntityProfile.SENDNOTIFICATION, 0, EndEntityProfile.TRUE);                          
             }
             else{
               newuser.setSendNotification(false);   
               oldprofile.setValue(EndEntityProfile.SENDNOTIFICATION, 0, EndEntityProfile.FALSE);               
             }
           }  

           value = request.getParameter(SELECT_CERTIFICATEPROFILE);
           newuser.setCertificateProfileId(Integer.parseInt(value));   
           oldprofile.setValue(EndEntityProfile.DEFAULTCERTPROFILE, 0, value);         
           lastselectedcertificateprofile = value;

           value = request.getParameter(SELECT_CA);
           newuser.setCAId(Integer.parseInt(value));   
           oldprofile.setValue(EndEntityProfile.DEFAULTCA, 0, value);         
           lastselectedca = value;

           value = request.getParameter(SELECT_TOKEN);
           int tokentype = Integer.parseInt(value); 
           newuser.setTokenType(tokentype);   
           oldprofile.setValue(EndEntityProfile.DEFKEYSTORE, 0, value);         
           lastselectedtoken = value;

           int hardtokenissuer = SecConst.NO_HARDTOKENISSUER;
           if(tokentype > SecConst.TOKEN_SOFT){
             value = request.getParameter(SELECT_HARDTOKENISSUER);
             hardtokenissuer = Integer.parseInt(value);  
             oldprofile.setValue(EndEntityProfile.DEFAULTTOKENISSUER, 0, value);  
           }
           lastselectedhardtokenissuer = hardtokenissuer;
           newuser.setHardTokenIssuerId(lastselectedhardtokenissuer);   
       

           // See if user already exists
           if(rabean.userExist(newuser.getUsername())){
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

    int numberofrows = ejbcawebbean.getEntriesPerPage();
    UserView[] addedusers = rabean.getAddedUsers(numberofrows);
    int row = 0;
    int tabindex = 0;
  
    if(!noprofiles){
      if(!useoldprofile)
        profile = rabean.getEndEntityProfile(profileid);
      else
        profile = oldprofile;
    }else
        profile = new EndEntityProfile();



     String[] tokentexts = RAInterfaceBean.tokentexts;
     int[] tokenids = RAInterfaceBean.tokenids;

     if(globalconfiguration.getIssueHardwareTokens()){
        AvailableHardToken[] availabletokens = tokenbean.getAvailableHardTokens();

        tokentexts = new String[RAInterfaceBean.tokentexts.length + availabletokens.length];
        tokenids   = new int[tokentexts.length];
        for(int i=0; i < RAInterfaceBean.tokentexts.length; i++){
          tokentexts[i]= RAInterfaceBean.tokentexts[i];
          tokenids[i] = RAInterfaceBean.tokenids[i];
        }
        for(int i=0; i < availabletokens.length;i++){
          tokentexts[i+RAInterfaceBean.tokentexts.length]= availabletokens[i].getName();
          tokenids[i+RAInterfaceBean.tokentexts.length] = Integer.parseInt(availabletokens[i].getId());         
        }
     }

      String[] availabletokens = profile.getValue(EndEntityProfile.AVAILKEYSTORE, 0).split(EndEntityProfile.SPLITCHAR);
      String[] availablehardtokenissuers = profile.getValue(EndEntityProfile.AVAILTOKENISSUER, 0).split(EndEntityProfile.SPLITCHAR);
      if(lastselectedhardtokenissuer==-1){
        String value = profile.getValue(EndEntityProfile.DEFAULTTOKENISSUER,0);
        if(value != null && !value.equals(""))
          lastselectedhardtokenissuer = Integer.parseInt(value);
      }
      ArrayList[] tokenissuers = null;

      usekeyrecovery = globalconfiguration.getEnableKeyRecovery() && profile.getUse(EndEntityProfile.KEYRECOVERABLE,0);
      usehardtokenissuers = globalconfiguration.getIssueHardwareTokens() && profile.getUse(EndEntityProfile.AVAILTOKENISSUER,0);
      if(usehardtokenissuers){       
        tokenissuers = new ArrayList[availabletokens.length];
        for(int i=0;i < availabletokens.length;i++){
          if(Integer.parseInt(availabletokens[i]) > SecConst.TOKEN_SOFT){
            tokenissuers[i] = new ArrayList();
            for(int j=0; j < availablehardtokenissuers.length; j++){
              HardTokenIssuerData issuerdata = tokenbean.getHardTokenIssuerData(Integer.parseInt(availablehardtokenissuers[j]));
              if(issuerdata !=null){
                Iterator iter = issuerdata.getHardTokenIssuer().getAvailableHardTokens().iterator();
                while(iter.hasNext()){
                  if(Integer.parseInt(availabletokens[i]) == ((Integer) iter.next()).intValue())
                    tokenissuers[i].add(new Integer(availablehardtokenissuers[j]));
                }
              }
            }
          }  
        } 
      }

      HashMap availablecas = null;
      Collection authcas = null;

      if(issuperadministrator)
        if(profileid == SecConst.EMPTY_ENDENTITYPROFILE)
          authcas = ejbcawebbean.getAuthorizedCAIds();
        else
          authcas = profile.getAvailableCAs();
      else
        availablecas = ejbcawebbean.getInformationMemory().getEndEntityAvailableCAs(profileid);
  
%>
<head>
  <title><%= globalconfiguration.getEjbcaTitle() %></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>">
  <link rel=STYLESHEET href="<%= ejbcawebbean.getCssFile() %>">
  <script language=javascript>

  <% if(!noprofiles){ %>
   <!--
      var TRUE  = "<%= EndEntityProfile.TRUE %>";
      var FALSE = "<%= EndEntityProfile.FALSE %>";


   <% if(usehardtokenissuers){ %>

       var TOKENID         = 0;
       var NUMBEROFISSUERS = 1;
       var ISSUERIDS       = 2;
       var ISSUERNAMES     = 3;

       var tokenissuers = new Array(<%=availabletokens.length%>);
       <% for(int i=0; i < availabletokens.length; i++){
            int numberofissuers = 0;
            if (Integer.parseInt(availabletokens[i]) > SecConst.TOKEN_SOFT) numberofissuers=tokenissuers[i].size();           
           %>
         tokenissuers[<%=i%>] = new Array(4);
         tokenissuers[<%=i%>][TOKENID] = <%= availabletokens[i] %>;
         tokenissuers[<%=i%>][NUMBEROFISSUERS] = <%= numberofissuers %>;
         tokenissuers[<%=i%>][ISSUERIDS] = new Array(<%= numberofissuers %>);
         tokenissuers[<%=i%>][ISSUERNAMES] = new Array(<%= numberofissuers %>);    
         <%  for(int j=0; j < numberofissuers; j++){ %>
         tokenissuers[<%=i%>][ISSUERIDS][<%=j%>]= <%= ((Integer) tokenissuers[i].get(j)).intValue() %>;
         tokenissuers[<%=i%>][ISSUERNAMES][<%=j%>]= "<%= tokenbean.getHardTokenIssuerAlias(((Integer) tokenissuers[i].get(j)).intValue())%>";
         <%  }
           } %>
       
function setAvailableHardTokenIssuers(){
    var seltoken = document.adduser.<%=SELECT_TOKEN%>.options.selectedIndex;
    issuers   =  document.adduser.<%=SELECT_HARDTOKENISSUER%>;

    numofissuers = issuers.length;
    for( i=numofissuers-1; i >= 0; i-- ){
       issuers.options[i]=null;
    }    
    issuers.disabled=true;

    if( seltoken > -1){
      var token = document.adduser.<%=SELECT_TOKEN%>.options[seltoken].value;
      if(token > <%= SecConst.TOKEN_SOFT%>){
        issuers.disabled=false;
        var tokenindex = 0;  
        for( i=0; i < tokenissuers.length; i++){
          if(tokenissuers[i][TOKENID] == token)
            tokenindex = i;
        }
        for( i=0; i < tokenissuers[tokenindex][NUMBEROFISSUERS] ; i++){
          issuers.options[i]=new Option(tokenissuers[tokenindex][ISSUERNAMES][i],tokenissuers[tokenindex][ISSUERIDS][i]);
          if(tokenissuers[tokenindex][ISSUERIDS][i] == <%=lastselectedhardtokenissuer %>)
            issuers.options.selectedIndex=i;
        }      
      }
    }
}

   <% } 
      if(usekeyrecovery){ %>
function isKeyRecoveryPossible(){
   var seltoken = document.adduser.<%=SELECT_TOKEN%>.options.selectedIndex; 
   var token = document.adduser.<%=SELECT_TOKEN%>.options[seltoken].value;
   if(token == <%=SecConst.TOKEN_SOFT_BROWSERGEN %>){
     document.adduser.<%=CHECKBOX_KEYRECOVERABLE%>.checked=false;
     document.adduser.<%=CHECKBOX_KEYRECOVERABLE%>.disabled=true;
   }else{
     <% if(profile.isRequired(EndEntityProfile.KEYRECOVERABLE,0)){ %>
       document.adduser.<%=CHECKBOX_KEYRECOVERABLE%>.disabled=true; 
     <% }else{ %>
     document.adduser.<%=CHECKBOX_KEYRECOVERABLE%>.disabled=false;
     <%}
       if(profile.getValue(EndEntityProfile.KEYRECOVERABLE,0).equals(EndEntityProfile.TRUE)){ %>
     document.adduser.<%=CHECKBOX_KEYRECOVERABLE%>.checked=true;
   <% }else{ %>  
     document.adduser.<%=CHECKBOX_KEYRECOVERABLE%>.checked=false;
     <% } %>
   }
}

   <% } %>


  

  <% if(issuperadministrator){ %>
  var availablecas = new Array(<%= authcas.size()%>);
 
  var CANAME       = 0;
  var CAID         = 1;
<%
      Iterator iter = authcas.iterator();
      int i = 0;
      while(iter.hasNext()){
        Object next = iter.next();
        Integer nextca = null;   
        if(next instanceof String)
           nextca =  new Integer((String) next);
        else
           nextca = (Integer) next;
    %> 
    
    availablecas[<%=i%>] = new Array(2);
    availablecas[<%=i%>][CANAME] = "<%= caidtonamemap.get(nextca) %>";      
    availablecas[<%=i%>][CAID] = <%= nextca.intValue() %>;
    
   <%   i++; 
      } %>

function fillCAField(){
   var caselect   =  document.adduser.<%=SELECT_CA%>; 

   var numofcas = caselect.length;
   for( i=numofcas-1; i >= 0; i-- ){
       caselect.options[i]=null;
    }   

   for( i=0; i < availablecas.length; i ++){
     caselect.options[i]=new Option(availablecas[i][CANAME],
                                     availablecas[i][CAID]);    
     if(availablecas[i][CAID] == "<%= lastselectedca %>")
       caselect.options.selectedIndex=i;
   }
}

 <% } else { %>

  var certprofileids = new Array(<%= availablecas.keySet().size()%>);
  var CERTPROFID   = 0;
  var AVAILABLECAS = 1;

  var CANAME       = 0;
  var CAID         = 1;
<%
  Iterator iter = availablecas.keySet().iterator();
  int i = 0;
  while(iter.hasNext()){ 
    Integer next = (Integer) iter.next();
    Collection nextcaset = (Collection) availablecas.get(next);
  %>
    certprofileids[<%=i%>] = new Array(2);
    certprofileids[<%=i%>][CERTPROFID] = <%= next.intValue() %> ;
    certprofileids[<%=i%>][AVAILABLECAS] = new Array(<%= nextcaset.size() %>);
<% Iterator iter2 = nextcaset.iterator();
   int j = 0;
   while(iter2.hasNext()){
     Integer nextca = (Integer) iter2.next(); %>
    certprofileids[<%=i%>][AVAILABLECAS][<%=j%>] = new Array(2);
    certprofileids[<%=i%>][AVAILABLECAS][<%=j%>][CANAME] = "<%= caidtonamemap.get(nextca) %>";      
    certprofileids[<%=i%>][AVAILABLECAS][<%=j%>][CAID] = <%= nextca.intValue() %>;
  <% j++ ;
   }
   i++;
 } %>     

function fillCAField(){
   var selcertprof = document.adduser.<%=SELECT_CERTIFICATEPROFILE%>.options.selectedIndex; 
   var certprofid = document.adduser.<%=SELECT_CERTIFICATEPROFILE%>.options[selcertprof].value; 
   var caselect   =  document.adduser.<%=SELECT_CA%>; 

   var numofcas = caselect.length;
   for( i=numofcas-1; i >= 0; i-- ){
       caselect.options[i]=null;
    }   

    if( selcertprof > -1){
      for( i=0; i < certprofileids.length; i ++){
        if(certprofileids[i][CERTPROFID] == certprofid){
          for( j=0; j < certprofileids[i][AVAILABLECAS].length; j++ ){
            caselect.options[j]=new Option(certprofileids[i][AVAILABLECAS][j][CANAME],
                                           certprofileids[i][AVAILABLECAS][j][CAID]);    
            if(certprofileids[i][AVAILABLECAS][j][CAID] == "<%= lastselectedca %>")
              caselect.options.selectedIndex=j;
          }
        }
      }
    }
}

  <% } %> 

function checkallfields(){
    var illegalfields = 0;

    <% if(profile.isModifyable(EndEntityProfile.USERNAME,0)){ %>
    if(!checkfieldforlegalchars("document.adduser.<%=TEXTFIELD_USERNAME%>","<%= ejbcawebbean.getText("ONLYCHARACTERS") + " " + ejbcawebbean.getText("USERNAME") %>"))
      illegalfields++;
    <%  if(profile.isRequired(EndEntityProfile.USERNAME,0)){%>
    if((document.adduser.<%= TEXTFIELD_USERNAME %>.value == "")){
      alert("<%= ejbcawebbean.getText("REQUIREDUSERNAME") %>");
      illegalfields++;
    } 
    <%    }
        }
       if(profile.getUse(EndEntityProfile.PASSWORD,0)){
         if(profile.isModifyable(EndEntityProfile.PASSWORD,0)){%>

    <%  if(profile.isRequired(EndEntityProfile.PASSWORD,0)){%>
    if((document.adduser.<%= TEXTFIELD_PASSWORD %>.value == "")){
      alert("<%= ejbcawebbean.getText("REQUIREDPASSWORD") %>");
      illegalfields++;
    } 
    <%    }
        }
       }
       for(int i=0; i < profile.getSubjectDNFieldOrderLength(); i++){
         fielddata = profile.getSubjectDNFieldsInOrder(i);
         if( fielddata[EndEntityProfile.FIELDTYPE] != EndEntityProfile.OLDDNE ){
           if(profile.isModifyable(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER])){ %>
    if(!checkfieldforlegaldnchars("document.adduser.<%=TEXTFIELD_SUBJECTDN+i%>","<%= ejbcawebbean.getText("ONLYCHARACTERS") + " " + ejbcawebbean.getText(subjectfieldtexts[fielddata[EndEntityProfile.FIELDTYPE]]) %>"))
      illegalfields++;
    <%     if(profile.isRequired(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER])){%>
    if((document.adduser.<%= TEXTFIELD_SUBJECTDN+i %>.value == "")){
      alert("<%= ejbcawebbean.getText("YOUAREREQUIRED") + " " + ejbcawebbean.getText(subjectfieldtexts[fielddata[EndEntityProfile.FIELDTYPE]])%>");
      illegalfields++;
    } 
    <%     }
          }
         }
         else{ %>
    document.adduser.<%= CHECKBOX_SUBJECTDN+i %>.disabled = false;          
     <%  }
       }
       for(int i=0; i < profile.getSubjectAltNameFieldOrderLength(); i++){
         fielddata = profile.getSubjectAltNameFieldsInOrder(i);
         if(fielddata[EndEntityProfile.FIELDTYPE] != EndEntityProfile.RFC822NAME){
           if(profile.isModifyable(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER])){
             if(fielddata[EndEntityProfile.FIELDTYPE] == EndEntityProfile.IPADDRESS){ %>
    if(!checkfieldforipaddess("document.adduser.<%=TEXTFIELD_SUBJECTALTNAME+i%>","<%= ejbcawebbean.getText("ONLYNUMBERALSANDDOTS") + " " + ejbcawebbean.getText(subjectfieldtexts[fielddata[EndEntityProfile.FIELDTYPE]]) %>"))
      illegalfields++;
           <%  }else{ %>
    if(!checkfieldforlegaldnchars("document.adduser.<%=TEXTFIELD_SUBJECTALTNAME+i%>","<%= ejbcawebbean.getText("ONLYCHARACTERS") + " " + ejbcawebbean.getText(subjectfieldtexts[fielddata[EndEntityProfile.FIELDTYPE]]) %>"))
      illegalfields++;
    <%    if(profile.isRequired(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER])){%>
    if((document.adduser.<%= TEXTFIELD_SUBJECTALTNAME+i %>.value == "")){
      alert("<%= ejbcawebbean.getText("YOUAREREQUIRED") + " " + ejbcawebbean.getText(subjectfieldtexts[fielddata[EndEntityProfile.FIELDTYPE]])%>");
      illegalfields++;
    } 
    <%      }
           }
          }
         }
         else{ %>
      document.adduser.<%= CHECKBOX_SUBJECTALTNAME+i %>.disabled = false;          
     <%  }
       }
       if(profile.getUse(EndEntityProfile.EMAIL,0)){
         if(profile.isModifyable(EndEntityProfile.EMAIL,0)){%>
    if(!checkfieldforlegalemailchars("document.adduser.<%=TEXTFIELD_EMAIL%>","<%= ejbcawebbean.getText("ONLYEMAILCHARS") %>"))
      illegalfields++;
      <%  if(profile.isRequired(EndEntityProfile.EMAIL,0)){%>
    if((document.adduser.<%= TEXTFIELD_EMAIL %>.value == "")){
      alert("<%= ejbcawebbean.getText("REQUIREDEMAIL") %>");
      illegalfields++;
    } 
    <%    }
        }
      }
 
       if(profile.getUse(EndEntityProfile.PASSWORD,0)){
         if(profile.isModifyable(EndEntityProfile.PASSWORD,0)){%>  
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
    if(document.adduser.<%=SELECT_CERTIFICATEPROFILE%>.options.selectedIndex == -1){
      alert("<%=  ejbcawebbean.getText("CERTIFICATEPROFILEMUST") %>");
      illegalfields++;
    }
    if(document.adduser.<%=SELECT_CA%>.options.selectedIndex == -1){
      alert("<%=  ejbcawebbean.getText("CAMUST") %>");
      illegalfields++;
    }
    if(document.adduser.<%=SELECT_TOKEN%>.options.selectedIndex == -1){
      alert("<%=  ejbcawebbean.getText("TOKENMUST") %>");
      illegalfields++;
    }

    <%  if(profile.getUse(EndEntityProfile.SENDNOTIFICATION,0) && profile.isModifyable(EndEntityProfile.EMAIL,0)){%>
    if(document.adduser.<%=CHECKBOX_SENDNOTIFICATION %>.checked && (document.adduser.<%= TEXTFIELD_EMAIL %>.value == "")){
      alert("<%= ejbcawebbean.getText("NOTIFICATIONADDRESSMUSTBE") %>");
      illegalfields++;
    } 
    <% } %>

    if(illegalfields == 0){
      <% if(profile.getUse(EndEntityProfile.CLEARTEXTPASSWORD,0)){%> 
      document.adduser.<%= CHECKBOX_CLEARTEXTPASSWORD %>.disabled = false;
      <% } if(profile.getUse(EndEntityProfile.ADMINISTRATOR,0)){%> 
      document.adduser.<%= CHECKBOX_ADMINISTRATOR %>.disabled = false;
      <% } if(profile.getUse(EndEntityProfile.KEYRECOVERABLE,0) && globalconfiguration.getEnableKeyRecovery()){%> 
      document.adduser.<%= CHECKBOX_KEYRECOVERABLE %>.disabled = false;
      <% } if(profile.getUse(EndEntityProfile.SENDNOTIFICATION,0)){%> 
      document.adduser.<%= CHECKBOX_SENDNOTIFICATION %>.disabled = false;
      <% }%>
    }

     return illegalfields == 0;  
}
  <% } %>
   -->
  </script>
  <script language=javascript src="<%= globalconfiguration .getAdminWebPath() %>ejbcajslib.js"></script>
</head>
<body onload='<% if(usehardtokenissuers) out.write("setAvailableHardTokenIssuers();");
                 if(usekeyrecovery) out.write(" isKeyRecoveryPossible();");%>
                 fillCAField();'>
  <h2 align="center"><%= ejbcawebbean.getText("ADDENDENTITY") %></h2>
  <!-- <div align="right"><A  onclick='displayHelpWindow("<%= ejbcawebbean.getHelpfileInfix("ra_help.html") + "#addendentity"%>")'>
    <u><%= ejbcawebbean.getText("HELP") %></u> </A> -->
  </div>
  <% if(noprofiles){ %>
    <div align="center"><h4 id="alert"><%=ejbcawebbean.getText("NOTAUTHORIZEDTOCREATEENDENTITY") %></h4></div>
  <% }else{
       if(userexists){ %>
  <div align="center"><h4 id="alert"><%=ejbcawebbean.getText("ENDENTITYALREADYEXISTS") %></h4></div>
  <% } %>
  <% if(useradded){ %>
  <div align="center"><h4 id="alert"><% out.write(ejbcawebbean.getText("ENDENTITY")+ " ");
                                        out.write(addedusername + " ");
                                        out.write(ejbcawebbean.getText("ADDEDSUCCESSFULLY"));%></h4></div>
  <% } %>


     <table border="0" cellpadding="0" cellspacing="2" width="792">
       <form name="changeprofile" action="<%= THIS_FILENAME %>" method="post">
       <input type="hidden" name='<%= ACTION %>' value='<%=ACTION_CHANGEPROFILE %>'>
       <tr>
         <td></td>
	 <td align="right"><%= ejbcawebbean.getText("ENDENTITYPROFILE") %></td>
	 <td><select name="<%=SELECT_ENDENTITYPROFILE %>" size="1" tabindex="<%=tabindex++%>" onchange="document.changeprofile.submit()"'>
                <% for(int i = 0; i < profilenames.length;i++){
                      int pid = rabean.getEndEntityProfileId(profilenames[i]);
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
          <% if(profile.getUse(EndEntityProfile.USERNAME,0)){ %>
      <tr id="Row<%=(row++)%2%>">
	<td></td>
	<td align="right"><%= ejbcawebbean.getText("USERNAME") %></td> 
	<td>
            <% if(!profile.isModifyable(EndEntityProfile.USERNAME,0)){ 
                 String[] options = profile.getValue(EndEntityProfile.USERNAME, 0).split(EndEntityProfile.SPLITCHAR);
               %>
           <select name="<%= SELECT_USERNAME %>" size="1" tabindex="<%=tabindex++%>">
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
             <input type="text" name="<%= TEXTFIELD_USERNAME %>" size="40" maxlength="255" tabindex="<%=tabindex++%>" value='<%= profile.getValue(EndEntityProfile.USERNAME,0) %>'>
           <% } %>

        </td>
	<td><input type="checkbox" name="<%= CHECKBOX_REQUIRED_USERNAME %>" value="<%= CHECKBOX_VALUE %>"  disabled="true" <% if(profile.isRequired(EndEntityProfile.USERNAME,0)) out.write(" CHECKED "); %>></td>
      </tr>
         <% }%>
          <% if(profile.getUse(EndEntityProfile.PASSWORD,0)){ %>
      <tr id="Row<%=(row++)%2%>">
        <td>&nbsp&nbsp&nbsp&nbsp&nbsp;&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp
&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp
        </td>
	<td align="right"><%= ejbcawebbean.getText("PASSWORD") %></td>
        <td>   
             <%
               if(!profile.isModifyable(EndEntityProfile.PASSWORD,0)){ 
               %>
           <select name="<%= SELECT_PASSWORD %>" size="1" tabindex="3">
               <% if(profile.getValue(EndEntityProfile.PASSWORD,0) != null){ %>
             <option value='<%=profile.getValue(EndEntityProfile.PASSWORD,0).trim()%>' > <%=profile.getValue(EndEntityProfile.PASSWORD,0)  %>
             </option>                
               <%   
                  }
                %>
           </select>
           <% }else{ %> 
             <input type="password" name="<%= TEXTFIELD_PASSWORD %>" size="40" maxlength="255" tabindex="<%=tabindex++%>" value='<%= profile.getValue(EndEntityProfile.PASSWORD,0) %>'>
           <% } %>
 
        </td>
	<td><input type="checkbox" name="<%= CHECKBOX_REQUIRED_PASSWORD %>" value="<%= CHECKBOX_VALUE %>"  disabled="true" <% if(profile.isRequired(EndEntityProfile.PASSWORD,0)) out.write(" CHECKED "); %>></td>
      </tr>
       <% } 
          if(profile.getUse(EndEntityProfile.PASSWORD,0)){%>
      <tr id="Row<%=(row++)%2%>">
	<td></td>
	<td align="right"><%= ejbcawebbean.getText("CONFIRMPASSWORD") %></td>
        <td>
          <%   if(!profile.isModifyable(EndEntityProfile.PASSWORD,0)){ 
               %>
           <select name="<%= SELECT_CONFIRMPASSWORD %>" size="1" tabindex="4">
               <% if( profile.getValue(EndEntityProfile.PASSWORD,0) != null){ %>
             <option value='<%=profile.getValue(EndEntityProfile.PASSWORD,0).trim()%>'> 
                 <%=profile.getValue(EndEntityProfile.PASSWORD,0).trim() %>
             </option>                
               <%   
                  }
                %>
           </select>
           <% }else{ %> 
             <input type="password" name="<%= TEXTFIELD_CONFIRMPASSWORD %>" size="40" maxlength="255" tabindex="<%=tabindex++%>" value='<%= profile.getValue(EndEntityProfile.PASSWORD,0) %>'>
           <% } %>
        </td>
	<td>&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp
&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp</td> 
      </tr>
      <% }
          if(profile.getUse(EndEntityProfile.CLEARTEXTPASSWORD,0)){%>
      <tr id="Row<%=(row++)%2%>">
	<td></td>
	<td align="right"><%= ejbcawebbean.getText("USEINBATCH") %></td>
	<td><input type="checkbox" name="<%= CHECKBOX_CLEARTEXTPASSWORD %>" value="<%= CHECKBOX_VALUE %>" tabindex="<%=tabindex++%>" <% if(profile.getValue(EndEntityProfile.CLEARTEXTPASSWORD,0).equals(EndEntityProfile.TRUE))
                                                                                                                 out.write(" CHECKED "); 
                                                                                                               if(profile.isRequired(EndEntityProfile.CLEARTEXTPASSWORD,0))
                                                                                                                 out.write(" disabled='true' "); 
                                                                                                             %>> 
        </td>
	<td></td> 
      </tr>
      <% } 
         if(profile.getUse(EndEntityProfile.EMAIL,0)){ %>
       <tr id="Row<%=(row++)%2%>">
	 <td></td>
	 <td align="right"><%= ejbcawebbean.getText("EMAIL") %></td>
	 <td>      
          <% if(!profile.isModifyable(EndEntityProfile.EMAIL,0)){ 
                 String[] options = profile.getValue(EndEntityProfile.EMAIL, 0).split(EndEntityProfile.SPLITCHAR);
               %>
           <select name="<%= SELECT_EMAIL %>" size="1" tabindex="<%=tabindex++%>">
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
             <input type="text" name="<%= TEXTFIELD_EMAIL %>" size="40" maxlength="255" tabindex="<%=tabindex++%>" value='<%= profile.getValue(EndEntityProfile.EMAIL,0) %>'>
           <% } %>
        </td>
	<td><input type="checkbox" name="<%= CHECKBOX_REQUIRED_EMAIL %>" value="<%= CHECKBOX_VALUE %>"  disabled="true" <% if(profile.isRequired(EndEntityProfile.EMAIL,0)) out.write(" CHECKED "); %>></td>
       </tr>
       <% }%>
      <tr id="Row<%=(row++)%2%>">
	<td></td>
	<td align="right"><b><%= ejbcawebbean.getText("SUBJECTDNFIELDS") %></b></td>
	<td>&nbsp;</td>
	<td></td>
       </tr>
       <% int numberofsubjectdnfields = profile.getSubjectDNFieldOrderLength();
          for(int i=0; i < numberofsubjectdnfields; i++){
            fielddata = profile.getSubjectDNFieldsInOrder(i);  %>
       <tr id="Row<%=(row++)%2%>">
	 <td></td>
	 <td align="right"><%= ejbcawebbean.getText(subjectfieldtexts[fielddata[EndEntityProfile.FIELDTYPE]]) %></td>
	 <td>      
          <% 
             if( fielddata[EndEntityProfile.FIELDTYPE] != EndEntityProfile.OLDDNE ){  
                if(!profile.isModifyable(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER])){ 
                 String[] options = profile.getValue(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER]).split(EndEntityProfile.SPLITCHAR);
               %>
           <select name="<%= SELECT_SUBJECTDN + i %>" size="1" tabindex="<%=tabindex++%>">
               <% if( options != null){
                    for(int j=0;j < options.length;j++){ %>
             <option value='<%=options[j].trim()%>' <% if( lastselectedsubjectdns != null) 
                                                         if(lastselectedsubjectdns[i].equals(options[j])) out.write(" selected "); %>> 
                <%=options[j].trim()%>
             </option>                
               <%   }
                  }
                %>
           </select>
           <% }else{ %> 
             <input type="text" name="<%= TEXTFIELD_SUBJECTDN + i %>" size="40" maxlength="255" tabindex="<%=tabindex++%>" value='<%= profile.getValue(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER]) %>'>
           <% }
            }
            else{ %>
              <%= ejbcawebbean.getText("USESEMAILFIELDDATA")+ " :"%>&nbsp;
        <input type="checkbox" name="<%=CHECKBOX_SUBJECTDN + i%>" value="<%=CHECKBOX_VALUE %>" tabindex="<%=tabindex++%>" <% if(profile.isRequired(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER]))
                                                                                                                 out.write(" CHECKED "); 
                                                                                                               if(profile.isRequired(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER]))
                                                                                                                 out.write(" disabled='true' "); 
                                                                                                             %>>
         <% } %>       
        </td>
	<td><input type="checkbox" name="<%= CHECKBOX_REQUIRED_SUBJECTDN + i %>" value="<%= CHECKBOX_VALUE %>"  disabled="true" <% if(profile.isRequired(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER])) out.write(" CHECKED "); %>></td>
      </tr>
     <% } 
        int numberofsubjectaltnamefields = profile.getSubjectAltNameFieldOrderLength();
        if(numberofsubjectaltnamefields > 0){
%> 
      <tr id="Row<%=(row++)%2%>">
	<td></td>
	<td align="right"><b><%= ejbcawebbean.getText("SUBJECTALTNAMEFIELDS") %></b></td>
	<td>&nbsp;</td>
	<td></td>
       </tr>
       <% }
          for(int i=0; i < numberofsubjectaltnamefields; i++){
            fielddata = profile.getSubjectAltNameFieldsInOrder(i);  
            int fieldtype = fielddata[EndEntityProfile.FIELDTYPE];
            if(fieldtype != EndEntityProfile.OTHERNAME && fieldtype != EndEntityProfile.X400ADDRESS && fieldtype != EndEntityProfile.DIRECTORYNAME && 
               fieldtype != EndEntityProfile.EDIPARTNAME && fieldtype != EndEntityProfile.REGISTEREDID ){ // Not implemented yet.%>
       <tr id="Row<%=(row++)%2%>">
	 <td></td>
	 <td align="right"><%= ejbcawebbean.getText(subjectfieldtexts[fielddata[EndEntityProfile.FIELDTYPE]]) %></td>
	 <td>      
          <%
             if( fielddata[EndEntityProfile.FIELDTYPE] != EndEntityProfile.RFC822NAME ){
               if(!profile.isModifyable(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER])){ 
                 String[] options = profile.getValue(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER]).split(EndEntityProfile.SPLITCHAR);
               %>
           <select name="<%= SELECT_SUBJECTALTNAME + i %>" size="1" tabindex="<%=tabindex++%>">
               <% if( options != null){
                    for(int j=0;j < options.length;j++){ %>
             <option value='<%=options[j].trim()%>' <% if( lastselectedsubjectaltnames != null) 
                                                         if(lastselectedsubjectaltnames[i].equals(options[j])) out.write(" selected "); %>> 
                <%=options[j].trim()%>
             </option>                
               <%   }
                  }
                %>
           </select>
           <% }else{ %> 
             <input type="text" name="<%= TEXTFIELD_SUBJECTALTNAME + i %>" size="40" maxlength="255" tabindex="<%=tabindex++%>" value='<%= profile.getValue(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER]) %>'>
           <% }
            }
            else{ %>
              <%= ejbcawebbean.getText("USESEMAILFIELDDATA") + " :"%>&nbsp;
        <input type="checkbox" name="<%=CHECKBOX_SUBJECTALTNAME + i%>" value="<%=CHECKBOX_VALUE %>" tabindex="<%=tabindex++%>" <% if(profile.isRequired(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER]))
                                                                                                                 out.write(" CHECKED "); 
                                                                                                               if(profile.isRequired(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER]))
                                                                                                                 out.write(" disabled='true' "); 
                                                                                                             %>>
         <% } %>   
        </td>
	<td><input type="checkbox" name="<%= CHECKBOX_REQUIRED_SUBJECTALTNAME + i %>" value="<%= CHECKBOX_VALUE %>"  disabled="true" <% if(profile.isRequired(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER])) out.write(" CHECKED "); %>></td>
      </tr>
     <%  } 
       } %> 
       <tr id="Row<%=(row++)%2%>">
	 <td>&nbsp;</td>
	 <td>&nbsp;</td>
	 <td>&nbsp;</td>
	 <td>&nbsp;</td>
       </tr>
       <tr id="Row<%=(row++)%2%>">
	 <td></td>
	 <td align="right"><%= ejbcawebbean.getText("CERTIFICATEPROFILE") %></td>
	 <td>
         <select name="<%= SELECT_CERTIFICATEPROFILE %>" size="1" tabindex="<%=tabindex++%>" onchange='fillCAField()'>
         <%
           String[] availablecertprofiles = profile.getValue(EndEntityProfile.AVAILCERTPROFILES, 0).split(EndEntityProfile.SPLITCHAR);
           if(lastselectedcertificateprofile.equals(""))
             lastselectedcertificateprofile= profile.getValue(EndEntityProfile.DEFAULTCERTPROFILE,0);

           if( availablecertprofiles != null){
             for(int i =0; i< availablecertprofiles.length;i++){
         %>
         <option value='<%=availablecertprofiles[i]%>' <% if(lastselectedcertificateprofile.equals(availablecertprofiles[i])) out.write(" selected "); %> >
            <%= rabean.getCertificateProfileName(Integer.parseInt(availablecertprofiles[i])) %>
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
	 <td align="right"><%= ejbcawebbean.getText("CA") %></td>
	 <td>
         <select name="<%= SELECT_CA %>" size="1" tabindex="<%=tabindex++%>">
         </select>
         </td>
	 <td><input type="checkbox" name="checkbox" value="true"  disabled="true" CHECKED></td>
       </tr>
       <tr id="Row<%=(row++)%2%>">
	 <td></td>
	 <td align="right"><%= ejbcawebbean.getText("TOKEN") %></td>
	 <td>
         <select name="<%= SELECT_TOKEN %>" size="1" tabindex="<%=tabindex++%>" onchange='<% if(usehardtokenissuers) out.write("setAvailableHardTokenIssuers();");
                                                                                             if(usekeyrecovery) out.write(" isKeyRecoveryPossible();");%>'>
         <%
           if(lastselectedtoken.equals(""))
             lastselectedtoken= profile.getValue(EndEntityProfile.DEFKEYSTORE,0);

           if( availabletokens != null){
             for(int i =0; i < availabletokens.length;i++){
         %>
         <option value='<%=availabletokens[i]%>' <% if(lastselectedtoken.equals(availabletokens[i])) out.write(" selected "); %> >
            <% for(int j=0; j < tokentexts.length; j++){
                 if( tokenids[j] == Integer.parseInt(availabletokens[i])) {
                   if( tokenids[j] > SecConst.TOKEN_SOFT)
                     out.write(tokentexts[j]);
                   else
                     out.write(ejbcawebbean.getText(tokentexts[j]));
                 }
               }%>
         </option>
         <%
             }
           }
         %>
         </select>
         </td>
	 <td><input type="checkbox" name="checkbox" value="true"  disabled="true" CHECKED></td>
       </tr>
       <% if(usehardtokenissuers){ %>
       <tr id="Row<%=(row++)%2%>">
	 <td></td>
	 <td align="right"><%= ejbcawebbean.getText("HARDTOKENISSUER") %></td>
	 <td>
         <select name="<%= SELECT_HARDTOKENISSUER %>" size="1" tabindex="<%=tabindex++%>">
         </select>
         </td>
	 <td></td>
       </tr>
       <% } %>
       <% if( profile.getUse(EndEntityProfile.ADMINISTRATOR,0) || usekeyrecovery){ %>
       <tr id="Row<%=(row++)%2%>">
	 <td></td>
	 <td align="right"><%= ejbcawebbean.getText("TYPES") %></td>
	 <td>
         </td>
	 <td></td>
       </tr>
       <% } %>
      <% if(profile.getUse(EndEntityProfile.ADMINISTRATOR,0)){ %>
    <tr  id="Row<%=(row++)%2%>"> 
      <td></td>
      <td  align="right"> 
        <%= ejbcawebbean.getText("ADMINISTRATOR") %> <br>
      </td>
      <td > 
        <input type="checkbox" name="<%=CHECKBOX_ADMINISTRATOR%>" value="<%=CHECKBOX_VALUE %>" tabindex="<%=tabindex++%>" <% if(profile.getValue(EndEntityProfile.ADMINISTRATOR,0).equals(EndEntityProfile.TRUE))
                                                                                                                 out.write(" CHECKED "); 
                                                                                                               if(profile.isRequired(EndEntityProfile.ADMINISTRATOR,0))
                                                                                                                 out.write(" disabled='true' "); 
                                                                                                             %>> 
      </td>
      <td></td>
    </tr>
      <%} if(usekeyrecovery){ %>
    <tr  id="Row<%=(row++)%2%>"> 
      <td></td>
      <td  align="right"> 
        <%= ejbcawebbean.getText("KEYRECOVERABLE") %> 
      </td>
      <td> 
        <input type="checkbox" name="<%=CHECKBOX_KEYRECOVERABLE%>" value="<%=CHECKBOX_VALUE %>" tabindex="<%=tabindex++%>"<% if(profile.getValue(EndEntityProfile.KEYRECOVERABLE,0).equals(EndEntityProfile.TRUE))
                                                                                                                 out.write(" CHECKED "); 
                                                                                                               if(profile.isRequired(EndEntityProfile.KEYRECOVERABLE,0))
                                                                                                                 out.write(" disabled='true' "); 
                                                                                                             %>>  
      </td>
      <td></td>
    </tr>
     <% }if(profile.getUse(EndEntityProfile.SENDNOTIFICATION,0)){ %>
    <tr  id="Row<%=(row++)%2%>"> 
      <td></td>
      <td  align="right"> 
        <%= ejbcawebbean.getText("SENDNOTIFICATION") %> <br>
      </td>
      <td > 
        <input type="checkbox" name="<%=CHECKBOX_SENDNOTIFICATION%>" value="<%=CHECKBOX_VALUE %>" tabindex="<%=tabindex++%>" <% if(profile.getValue(EndEntityProfile.SENDNOTIFICATION,0).equals(EndEntityProfile.TRUE))
                                                                                                                 out.write(" CHECKED "); 
                                                                                                               if(profile.isRequired(EndEntityProfile.SENDNOTIFICATION,0))
                                                                                                                 out.write(" disabled='true' "); 
                                                                                                             %>> 
      </td>
      <td></td>
    </tr>
      <%} %>
       <tr id="Row<%=(row++)%2%>">
	 <td></td>
	 <td></td>
	 <td><input type="submit" name="<%= BUTTON_ADDUSER %>" value="<%= ejbcawebbean.getText("ADDENDENTITY") %>" tabindex="<%=tabindex++%>"
                    onClick='return checkallfields()'> 
             <input type="reset" name="<%= BUTTON_RESET %>" value="<%= ejbcawebbean.getText("RESET") %>" tabindex="<%=tabindex++%>"></td>
         <td></td>
       </tr> 
     </table> 
   
  <script language=javascript>
<!--
function viewuser(row){
    var hiddenusernamefield = eval("document.adduser.<%= HIDDEN_USERNAME %>" + row);
    var username = hiddenusernamefield.value;
    var link = "<%= VIEWUSER_LINK %>?<%= USER_PARAMETER %>="+username;
    link = encodeURI(link);
    window.open(link, 'view_user',config='height=600,width=500,scrollbars=yes,toolbar=no,resizable=1');
}

function edituser(row){
    var hiddenusernamefield = eval("document.adduser.<%= HIDDEN_USERNAME %>" + row);
    var username = hiddenusernamefield.value;
    var link = "<%= EDITUSER_LINK %>?<%= USER_PARAMETER %>="+username;
    link = encodeURI(link);
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
  <div align="center"><H4><%= ejbcawebbean.getText("PREVIOUSLYADDEDENDENTITIES") %> </H4></div>
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
            if(addedusers[i] != null){ 
      %>
     
  <tr id="Row<%= i%2 %>"> 

    <td width="15%"><%= addedusers[i].getUsername() %>
       <input type="hidden" name='<%= HIDDEN_USERNAME + i %>' value='<%=java.net.URLEncoder.encode(addedusers[i].getUsername(),"UTF-8")%>'>
    </td>
    <td width="20%"><%= addedusers[i].getSubjectDNField(DNFieldExtractor.CN,0)  %></td>
    <td width="20%"><%= addedusers[i].getSubjectDNField(DNFieldExtractor.OU,0) %></td>
    <td width="20%"><%= addedusers[i].getSubjectDNField(DNFieldExtractor.O,0) %></td>
    <td width="25%">
        <A  onclick='viewuser(<%= i %>)'>
        <u><%= ejbcawebbean.getText("VIEWENDENTITY") %></u> </A>
        <A  onclick='edituser(<%= i %>)'>
        <u><%= ejbcawebbean.getText("EDITENDENTITY") %></u> </A>
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
