<%@ page pageEncoding="ISO-8859-1"%>
<%@page  errorPage="/errorpage.jsp" import="java.util.*, se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean,se.anatom.ejbca.ra.raadmin.GlobalConfiguration, se.anatom.ejbca.webdist.rainterface.UserView,
                 se.anatom.ejbca.webdist.rainterface.RAInterfaceBean, se.anatom.ejbca.webdist.rainterface.EndEntityProfileDataHandler, se.anatom.ejbca.ra.raadmin.EndEntityProfile, se.anatom.ejbca.ra.UserDataConstants,
                 javax.ejb.CreateException, java.rmi.RemoteException, se.anatom.ejbca.authorization.AuthorizationDeniedException, se.anatom.ejbca.ra.raadmin.DNFieldExtractor, se.anatom.ejbca.common.UserDataVO,
                 se.anatom.ejbca.webdist.hardtokeninterface.HardTokenInterfaceBean, se.anatom.ejbca.hardtoken.HardTokenIssuer, se.anatom.ejbca.hardtoken.HardTokenIssuerData, 
                 se.anatom.ejbca.SecConst, se.anatom.ejbca.util.StringTools" %>
<html> 
<jsp:useBean id="ejbcawebbean" scope="session" class="se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean" />
<jsp:useBean id="rabean" scope="session" class="se.anatom.ejbca.webdist.rainterface.RAInterfaceBean" />
<jsp:useBean id="tokenbean" scope="session" class="se.anatom.ejbca.webdist.hardtokeninterface.HardTokenInterfaceBean" />
<%! // Declarations


  static final String ACTION                   = "action";
  static final String ACTION_EDITUSER          = "edituser";
  static final String ACTION_CHANGEPROFILE     = "changeprofile";

  static final String BUTTON_SAVE             = "buttonedituser"; 
  static final String BUTTON_CLOSE            = "buttonclose"; 


  static final String TEXTFIELD_PASSWORD          = "textfieldpassword";
  static final String TEXTFIELD_CONFIRMPASSWORD   = "textfieldconfirmpassword";
  static final String TEXTFIELD_SUBJECTDN         = "textfieldsubjectdn";
  static final String TEXTFIELD_SUBJECTALTNAME    = "textfieldsubjectaltname";
  static final String TEXTFIELD_EMAIL             = "textfieldemail";
  static final String TEXTFIELD_EMAILDOMAIN       = "textfieldemaildomain";
  static final String TEXTFIELD_UPNNAME           = "textfieldupnnamne";

  static final String SELECT_ENDENTITYPROFILE     = "selectendentityprofile";
  static final String SELECT_CERTIFICATEPROFILE   = "selectcertificateprofile";
  static final String SELECT_TOKEN                = "selecttoken";
  static final String SELECT_USERNAME             = "selectusername";
  static final String SELECT_PASSWORD             = "selectpassword";
  static final String SELECT_CONFIRMPASSWORD      = "selectconfirmpassword";
  static final String SELECT_SUBJECTDN            = "selectsubjectdn";
  static final String SELECT_SUBJECTALTNAME       = "selectsubjectaltname";
  static final String SELECT_EMAILDOMAIN          = "selectemaildomain";
  static final String SELECT_HARDTOKENISSUER      = "selecthardtokenissuer";
  static final String SELECT_CHANGE_STATUS        = "selectchangestatus"; 
  static final String SELECT_CA                   = "selectca";

  static final String CHECKBOX_CLEARTEXTPASSWORD          = "checkboxcleartextpassword";
  static final String CHECKBOX_SUBJECTDN                  = "checkboxsubjectdn";
  static final String CHECKBOX_SUBJECTALTNAME             = "checkboxsubjectaltname";
  static final String CHECKBOX_ADMINISTRATOR              = "checkboxadministrator";
  static final String CHECKBOX_KEYRECOVERABLE             = "checkboxkeyrecoverable";
  static final String CHECKBOX_SENDNOTIFICATION           = "checkboxsendnotification";

  static final String CHECKBOX_REGENERATEPASSWD           = "checkboxregeneratepasswd";

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
  GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request,"/ra_functionality/edit_end_entity"); 
                                            rabean.initialize(request, ejbcawebbean);
                                            if(globalconfiguration.getIssueHardwareTokens())
                                              tokenbean.initialize(request, ejbcawebbean);

  String[] subjectfieldtexts = {"","","", "OLDEMAILDN2", "UID", "COMMONNAME", "SERIALNUMBER1", 
                                "GIVENNAME2", "INITIALS", "SURNAME","TITLE","ORGANIZATIONUNIT","ORGANIZATION",
                                "LOCALE","STATE","DOMAINCOMPONENT","COUNTRY",
                                "RFC822NAME", "DNSNAME", "IPADDRESS", "OTHERNAME", "UNIFORMRESOURCEID", "X400ADDRESS", "DIRECTORYNAME",
                                "EDIPARTNAME", "REGISTEREDID","","","","","","","","","","","UPN", "","","UNSTRUCTUREDADDRESS", "UNSTRUCTUREDNAME","GUID"};

  String THIS_FILENAME             =  globalconfiguration.getRaPath()  + "/editendentity.jsp";
  String username                  = null;
  EndEntityProfile  profile        = null; 
  UserView userdata                = null;
  int profileid                    = UserDataVO.NO_ENDENTITYPROFILE;  
  int[] fielddata                  = null;

  boolean userchanged              = false;
  boolean nouserparameter          = true;
  boolean notauthorized            = true;
  boolean endentitysaved           = false;
  boolean usehardtokenissuers      = false;
  boolean usekeyrecovery           = false;
  
  boolean issuperadministrator     = false;
  try{
    issuperadministrator = ejbcawebbean.isAuthorizedNoLog("/super_administrator");
  }catch(se.anatom.ejbca.authorization.AuthorizationDeniedException ade){}   

  HashMap caidtonamemap = ejbcawebbean.getInformationMemory().getCAIdToNameMap();

  if( request.getParameter(USER_PARAMETER) != null ){
    username = java.net.URLDecoder.decode(request.getParameter(USER_PARAMETER),"UTF-8");
    try{
      userdata = rabean.findUserForEdit(username);
      if(userdata != null){
        notauthorized = false;
        profileid=userdata.getEndEntityProfileId();
        if(!issuperadministrator && profileid == SecConst.EMPTY_ENDENTITYPROFILE)
          profile = null;
        else   
          profile = rabean.getEndEntityProfile(profileid);

        if( request.getParameter(ACTION) != null){
          if( request.getParameter(ACTION).equals(ACTION_EDITUSER)){
            if( request.getParameter(BUTTON_SAVE) != null ){
              UserView newuser = new UserView();

             newuser.setEndEntityProfileId(profileid);
             newuser.setUsername(username);


             String value = request.getParameter(TEXTFIELD_PASSWORD);
             if(value !=null){
               value=value.trim(); 
               if(!value.equals("")){
                 newuser.setPassword(value);         
               }
             }
             
             value = request.getParameter(CHECKBOX_REGENERATEPASSWD);
             if(value !=null){
               if(value.equals(CHECKBOX_VALUE)){
                 newuser.setPassword("NEWPASSWORD");          
               }
               else{
                   newuser.setPassword(null);
               }
             }

             value = request.getParameter(SELECT_PASSWORD);
             if(value !=null){
               if(!value.equals("")){
                 newuser.setPassword(value);
               }
             } 

             value = request.getParameter(CHECKBOX_CLEARTEXTPASSWORD);
             if(value !=null){
               if(value.equals(CHECKBOX_VALUE)){
                 newuser.setClearTextPassword(true);          
               }
               else{
                   newuser.setClearTextPassword(false);
               }
             }

             value = request.getParameter(TEXTFIELD_EMAIL);
             if(value == null || value.trim().equals("")){
               newuser.setEmail("");                   
             }else{
               value=value.trim(); 
               if(!value.equals("")){
                 String emaildomain = request.getParameter(TEXTFIELD_EMAILDOMAIN);
                 if(emaildomain !=null){
                   emaildomain=emaildomain.trim(); 
                   if(!emaildomain.equals("")){
                     newuser.setEmail(value + "@" + emaildomain);            
                   }
                 }

                 emaildomain = request.getParameter(SELECT_EMAILDOMAIN);
                 if(emaildomain !=null){
                   emaildomain=emaildomain.trim(); 
                   if(!emaildomain.equals("")){
                     newuser.setEmail(value + "@" + emaildomain);                   
                   }
                 }
               }
             }

               String subjectdn = "";
               int numberofsubjectdnfields = profile.getSubjectDNFieldOrderLength();
               for(int i=0; i < numberofsubjectdnfields; i++){
                 value=null;
                 fielddata = profile.getSubjectDNFieldsInOrder(i); 
                 if(fielddata[EndEntityProfile.FIELDTYPE] != EndEntityProfile.OLDDNE)
                   value = request.getParameter(TEXTFIELD_SUBJECTDN+i);
                 else{
                   if(request.getParameter(CHECKBOX_SUBJECTDN+i)!=null)
                     if(request.getParameter(CHECKBOX_SUBJECTDN+i).equals(CHECKBOX_VALUE))
                       value = newuser.getEmail();
                 }
                 if(value !=null){
                   value= value.trim(); 
                   if(!value.equals("")){
                     value = org.ietf.ldap.LDAPDN.escapeRDN(DNFieldExtractor.SUBJECTDNFIELDS[profile.profileFieldIdToUserFieldIdMapper(fielddata[EndEntityProfile.FIELDTYPE])] +value);
                     if(subjectdn.equals(""))
                       subjectdn = value;
                     else
                       subjectdn += ", " + value;
                   }
                 }
                 value = request.getParameter(SELECT_SUBJECTDN+i);
                 if(value !=null){                   
                   if(!value.equals("")){
                     value = org.ietf.ldap.LDAPDN.escapeRDN(DNFieldExtractor.SUBJECTDNFIELDS[profile.profileFieldIdToUserFieldIdMapper(fielddata[EndEntityProfile.FIELDTYPE])] +value);
                     if(subjectdn.equals(""))
                       subjectdn = value;
                     else
                       subjectdn += ", "  +value;
                    }
                 } 
               }               

               newuser.setSubjectDN(subjectdn);

               String subjectaltname = "";
               int numberofsubjectaltnamefields = profile.getSubjectAltNameFieldOrderLength();
               for(int i=0; i < numberofsubjectaltnamefields; i++){
                 fielddata = profile.getSubjectAltNameFieldsInOrder(i); 

                 if(fielddata[EndEntityProfile.FIELDTYPE] == EndEntityProfile.RFC822NAME){
                   value=null; 
                   if(request.getParameter(CHECKBOX_SUBJECTALTNAME+i)!=null)
                     if(request.getParameter(CHECKBOX_SUBJECTALTNAME+i).equals(CHECKBOX_VALUE))
                       value = newuser.getEmail();
                 }else{
                   if(fielddata[EndEntityProfile.FIELDTYPE] == EndEntityProfile.UPN){
                     if(request.getParameter(TEXTFIELD_SUBJECTALTNAME+i) != null && request.getParameter(TEXTFIELD_UPNNAME+i) != null){
                       value = request.getParameter(TEXTFIELD_UPNNAME+i) + "@" + 
                               request.getParameter(TEXTFIELD_SUBJECTALTNAME+i);
                     }
                   }else{
                      value = request.getParameter(TEXTFIELD_SUBJECTALTNAME+i);
                   }                    
                 }
                 if(value !=null){                
                   if(!value.equals("")){
                     value = org.ietf.ldap.LDAPDN.escapeRDN(DNFieldExtractor.SUBJECTALTNAME[profile.profileFieldIdToUserFieldIdMapper(fielddata[EndEntityProfile.FIELDTYPE]) - DNFieldExtractor.SUBJECTALTERNATIVENAMEBOUNDRARY] +value);  
                     if(subjectaltname.equals(""))
                       subjectaltname = value;
                     else
                       subjectaltname += ", " + value;   
                   }
                 }
                 value = request.getParameter(SELECT_SUBJECTALTNAME+i);
                 if(value !=null){
                   if(fielddata[EndEntityProfile.FIELDTYPE] == EndEntityProfile.UPN){
                     if(request.getParameter(TEXTFIELD_UPNNAME+i) != null){
                       value = request.getParameter(TEXTFIELD_UPNNAME+i)+ "@" + value;
                     } 
                   }
                   value = org.ietf.ldap.LDAPDN.escapeRDN(DNFieldExtractor.SUBJECTALTNAME[profile.profileFieldIdToUserFieldIdMapper(fielddata[EndEntityProfile.FIELDTYPE]) - DNFieldExtractor.SUBJECTALTERNATIVENAMEBOUNDRARY] +value);
                   if(!value.equals("")){
                     if(subjectaltname.equals(""))
                       subjectaltname = value;
                     else
                       subjectaltname += ", " + value;
                   }
                 }
               }
               
               newuser.setSubjectAltName(subjectaltname);


               value = request.getParameter(CHECKBOX_ADMINISTRATOR);
               if(value !=null){
                 if(value.equals(CHECKBOX_VALUE)){
                   newuser.setAdministrator(true);   
                 }
                 else{
                   newuser.setAdministrator(false);  
                 }
               }
               value = request.getParameter(CHECKBOX_KEYRECOVERABLE);
               if(value !=null){
                 if(value.equals(CHECKBOX_VALUE)){
                   newuser.setKeyRecoverable(true);                  
                 }
                 else{
                   newuser.setKeyRecoverable(false);         
                 }
               }   
               value = request.getParameter(CHECKBOX_SENDNOTIFICATION);
               if(value !=null){
                 if(value.equals(CHECKBOX_VALUE)){
                   newuser.setSendNotification(true);                  
                 }
                 else{
                   newuser.setSendNotification(false);         
                 }
               }   

               value = request.getParameter(SELECT_CERTIFICATEPROFILE);
               newuser.setCertificateProfileId(Integer.parseInt(value));   
 
               value = request.getParameter(SELECT_CA);
               newuser.setCAId(Integer.parseInt(value)); 

               value = request.getParameter(SELECT_TOKEN);
               int tokentype = Integer.parseInt(value); 
               newuser.setTokenType(Integer.parseInt(value));   

               int hardtokenissuer = SecConst.NO_HARDTOKENISSUER;
               if(tokentype > SecConst.TOKEN_SOFT && request.getParameter(SELECT_HARDTOKENISSUER) != null){
                 value = request.getParameter(SELECT_HARDTOKENISSUER);
                 hardtokenissuer = Integer.parseInt(value);  
               }
               newuser.setHardTokenIssuerId(hardtokenissuer);   
  
              if(request.getParameter(SELECT_CHANGE_STATUS)!=null){
                int newstatus = Integer.parseInt(request.getParameter(SELECT_CHANGE_STATUS));
                if(newstatus == UserDataConstants.STATUS_NEW || newstatus == UserDataConstants.STATUS_GENERATED || newstatus == UserDataConstants.STATUS_HISTORICAL || newstatus == UserDataConstants.STATUS_KEYRECOVERY )
                  newuser.setStatus(newstatus); 
              }
               // Send changes to database.
               rabean.changeUserData(newuser);
               endentitysaved = true;
               userdata = newuser;
  
             }
          }
        }
      }
    } catch(AuthorizationDeniedException e){
    }
    nouserparameter = false;
  } 
  
   String[] tokentexts = RAInterfaceBean.tokentexts;
   int[] tokenids = RAInterfaceBean.tokenids;
   String[] availabletokens = null;
   String[] availablehardtokenissuers = null;
   ArrayList[] tokenissuers = null;

   if( userdata != null && profile != null){
     if(globalconfiguration.getIssueHardwareTokens() ){
        TreeMap hardtokenprofiles = ejbcawebbean.getInformationMemory().getHardTokenProfiles();

        tokentexts = new String[RAInterfaceBean.tokentexts.length + hardtokenprofiles.keySet().size()];
        tokenids   = new int[tokentexts.length];
        for(int i=0; i < RAInterfaceBean.tokentexts.length; i++){
          tokentexts[i]= RAInterfaceBean.tokentexts[i];
          tokenids[i] = RAInterfaceBean.tokenids[i];
        }
        Iterator iter = hardtokenprofiles.keySet().iterator();
        int index=0;
        while(iter.hasNext()){       
          String name = (String) iter.next();
          tokentexts[index+RAInterfaceBean.tokentexts.length]= name;
          tokenids[index+RAInterfaceBean.tokentexts.length] = ((Integer) hardtokenprofiles.get(name)).intValue();
          index++;
        }
     }

      availabletokens = profile.getValue(EndEntityProfile.AVAILKEYSTORE, 0).split(EndEntityProfile.SPLITCHAR);
      availablehardtokenissuers = profile.getValue(EndEntityProfile.AVAILTOKENISSUER, 0).split(EndEntityProfile.SPLITCHAR);

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
                  Iterator iter = issuerdata.getHardTokenIssuer().getAvailableHardTokenProfiles().iterator();
                  while(iter.hasNext()){
                    if(Integer.parseInt(availabletokens[i]) == ((Integer) iter.next()).intValue())
                      tokenissuers[i].add(new Integer(availablehardtokenissuers[j]));
                  }
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

    int row = 0;
    int tabindex = 1;
%>
<head>
  <title><%= globalconfiguration.getEjbcaTitle() %></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>">
  <link rel=STYLESHEET href="<%= ejbcawebbean.getCssFile() %>">
  <script language=javascript>
   <!--

<% if(profile != null && userdata != null){ %>
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
    var seltoken = document.edituser.<%=SELECT_TOKEN%>.options.selectedIndex;
    issuers   =  document.edituser.<%=SELECT_HARDTOKENISSUER%>;

    numofissuers = issuers.length;
    for( i=numofissuers-1; i >= 0; i-- ){
       issuers.options[i]=null;
    }    
    issuers.disabled=true;

    if( seltoken > -1){
      var token = document.edituser.<%=SELECT_TOKEN%>.options[seltoken].value;
      if(token > <%= SecConst.TOKEN_SOFT%>){
        issuers.disabled=false;
        var tokenindex = 0;  
        for( i=0; i < tokenissuers.length; i++){
          if(tokenissuers[i][TOKENID] == token)
            tokenindex = i;
        }
        for( i=0; i < tokenissuers[tokenindex][NUMBEROFISSUERS] ; i++){
          issuers.options[i]=new Option(tokenissuers[tokenindex][ISSUERNAMES][i],tokenissuers[tokenindex][ISSUERIDS][i]);
          if(tokenissuers[tokenindex][ISSUERIDS][i] == <%=userdata.getHardTokenIssuerId()%>)
            issuers.options.selectedIndex=i;
        }      
      }
    }
}

   <% }      
      if(usekeyrecovery){ %>
function isKeyRecoveryPossible(){
   var seltoken = document.edituser.<%=SELECT_TOKEN%>.options.selectedIndex; 
   var token = document.edituser.<%=SELECT_TOKEN%>.options[seltoken].value;
   if(token == <%=SecConst.TOKEN_SOFT_BROWSERGEN %>){
     document.edituser.<%=CHECKBOX_KEYRECOVERABLE%>.checked=false;
     document.edituser.<%=CHECKBOX_KEYRECOVERABLE%>.disabled=true;
   }else{
     <% if(profile.isRequired(EndEntityProfile.KEYRECOVERABLE,0)){ %>
       document.edituser.<%=CHECKBOX_KEYRECOVERABLE%>.disabled=true; 
     <% }else{ %>
     document.edituser.<%=CHECKBOX_KEYRECOVERABLE%>.disabled=false;
     <%} %>
     document.edituser.<%=CHECKBOX_KEYRECOVERABLE%>.checked=<%= userdata.getKeyRecoverable() %>
     
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
   var caselect   =  document.edituser.<%=SELECT_CA%>; 

   var numofcas = caselect.length;
   for( i=numofcas-1; i >= 0; i-- ){
       caselect.options[i]=null;
    }   

   for( i=0; i < availablecas.length; i ++){
     caselect.options[i]=new Option(availablecas[i][CANAME],
                                     availablecas[i][CAID]);    
     if(availablecas[i][CAID] == "<%= userdata.getCAId() %>")
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
   var selcertprof = document.edituser.<%=SELECT_CERTIFICATEPROFILE%>.options.selectedIndex; 
   var certprofid = document.edituser.<%=SELECT_CERTIFICATEPROFILE%>.options[selcertprof].value; 
   var caselect   =  document.edituser.<%=SELECT_CA%>; 

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
            if(certprofileids[i][AVAILABLECAS][j][CAID] == "<%= userdata.getCAId() %>")
              caselect.options.selectedIndex=j;
          }
        }
      }
    }
}

  <% } %> 

function checkallfields(){
    var illegalfields = 0;

 <%    for(int i=0; i < profile.getSubjectDNFieldOrderLength(); i++){
         fielddata = profile.getSubjectDNFieldsInOrder(i);
         if(fielddata[EndEntityProfile.FIELDTYPE] != EndEntityProfile.OLDDNE){
           if(profile.isModifyable(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER])){ %>
    if(!checkfieldforlegaldnchars("document.edituser.<%=TEXTFIELD_SUBJECTDN+i%>","<%= ejbcawebbean.getText("ONLYCHARACTERS") + " " + ejbcawebbean.getText(subjectfieldtexts[fielddata[EndEntityProfile.FIELDTYPE]]) %>"))
      illegalfields++;
    <%     if(profile.isRequired(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER])){%>
    if((document.edituser.<%= TEXTFIELD_SUBJECTDN+i %>.value == "")){
      alert("<%= ejbcawebbean.getText("YOUAREREQUIRED") + " " + ejbcawebbean.getText(subjectfieldtexts[fielddata[EndEntityProfile.FIELDTYPE]])%>");
      illegalfields++;
    } 
    <%     }
          }
         }        
         else{ %>
    document.edituser.<%= CHECKBOX_SUBJECTDN+i %>.disabled = false;          
     <%  }
       }
       for(int i=0; i < profile.getSubjectAltNameFieldOrderLength(); i++){
         fielddata = profile.getSubjectAltNameFieldsInOrder(i);
         int fieldtype = fielddata[EndEntityProfile.FIELDTYPE];
         if(fieldtype != EndEntityProfile.OTHERNAME && fieldtype != EndEntityProfile.X400ADDRESS && fieldtype != EndEntityProfile.DIRECTORYNAME && 
            fieldtype != EndEntityProfile.EDIPARTNAME && fieldtype != EndEntityProfile.REGISTEREDID ){ // Not implemented yet.
           if(fielddata[EndEntityProfile.FIELDTYPE] != EndEntityProfile.RFC822NAME){
             if(fielddata[EndEntityProfile.FIELDTYPE] == EndEntityProfile.UPN){%>
    if(!checkfieldforlegaldnchars("document.edituser.<%=TEXTFIELD_UPNNAME+i%>","<%= ejbcawebbean.getText("ONLYCHARACTERS") + " " + ejbcawebbean.getText(subjectfieldtexts[fielddata[EndEntityProfile.FIELDTYPE]]) %>"))
      illegalfields++;
    <%         if(profile.isRequired(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER])){ %>    
              if((document.edituser.<%= TEXTFIELD_UPNNAME+i %>.value == "")){ 
                alert("<%= ejbcawebbean.getText("YOUAREREQUIRED") + " " + ejbcawebbean.getText(subjectfieldtexts[fielddata[EndEntityProfile.FIELDTYPE]])%>");
                illegalfields++;
              } 
        <%     }
             }  
             if(profile.isModifyable(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER])){
               if(fielddata[EndEntityProfile.FIELDTYPE] == EndEntityProfile.IPADDRESS ){ %>
    if(!checkfieldforipaddess("document.edituser.<%=TEXTFIELD_SUBJECTALTNAME+i%>","<%= ejbcawebbean.getText("ONLYNUMBERALSANDDOTS") + " " + ejbcawebbean.getText(subjectfieldtexts[fielddata[EndEntityProfile.FIELDTYPE]]) %>"))
      illegalfields++;
           <%  }else{ %>
    if(!checkfieldforlegaldnchars("document.edituser.<%=TEXTFIELD_SUBJECTALTNAME+i%>","<%= ejbcawebbean.getText("ONLYCHARACTERS") + " " + ejbcawebbean.getText(subjectfieldtexts[fielddata[EndEntityProfile.FIELDTYPE]]) %>"))
      illegalfields++;
    <%    if(profile.isRequired(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER])){ %>
    if((document.edituser.<%= TEXTFIELD_SUBJECTALTNAME+i %>.value == "")){
      alert("<%= ejbcawebbean.getText("YOUAREREQUIRED") + " " + ejbcawebbean.getText(subjectfieldtexts[fielddata[EndEntityProfile.FIELDTYPE]])%>");
      illegalfields++;
    } 
    <%        }
             }
            }
           }else{ %>
           document.edituser.<%= CHECKBOX_SUBJECTALTNAME+i %>.disabled = false;          
     <%    }
         }                   
       }
       if(profile.getUse(EndEntityProfile.EMAIL,0)){ %>
    if(!checkfieldforlegalemailcharswithoutat("document.edituser.<%=TEXTFIELD_EMAIL%>","<%= ejbcawebbean.getText("ONLYEMAILCHARSNOAT") %>"))
      illegalfields++;

    <%  if(profile.isRequired(EndEntityProfile.EMAIL,0)){%>
    if((document.edituser.<%= TEXTFIELD_EMAIL %>.value == "")){
      alert("<%= ejbcawebbean.getText("REQUIREDEMAIL") %>");
      illegalfields++;
    } 
    <%    }

          if(profile.isModifyable(EndEntityProfile.EMAIL,0)){%>
    if(!checkfieldforlegalemailcharswithoutat("document.edituser.<%=TEXTFIELD_EMAILDOMAIN%>","<%= ejbcawebbean.getText("ONLYEMAILCHARSNOAT") %>"))
      illegalfields++;
          
      <%  if(profile.isRequired(EndEntityProfile.EMAIL,0)){%>
    if((document.edituser.<%= TEXTFIELD_EMAILDOMAIN %>.value == "")){
      alert("<%= ejbcawebbean.getText("REQUIREDEMAIL") %>");
      illegalfields++;
    } 
    <%    }
        }
      } 
       if(profile.getUse(EndEntityProfile.PASSWORD,0)){
         if(profile.isModifyable(EndEntityProfile.PASSWORD,0)){%>  
    if(document.edituser.<%= TEXTFIELD_PASSWORD %>.value != document.edituser.<%= TEXTFIELD_CONFIRMPASSWORD %>.value){
      alert("<%= ejbcawebbean.getText("PASSWORDSDOESNTMATCH") %>");
      illegalfields++;
    } 
    <%   }else{ %>
    if(document.edituser.<%=SELECT_PASSWORD%>.options.selectedIndex != document.edituser.<%=SELECT_CONFIRMPASSWORD%>.options.selectedIndex ){
      alert("<%= ejbcawebbean.getText("PASSWORDSDOESNTMATCH") %>");
      illegalfields++; 
    }
<%        }   
     } %>
    if(document.edituser.<%=SELECT_CERTIFICATEPROFILE%>.options.selectedIndex == -1){
      alert("<%=  ejbcawebbean.getText("CERTIFICATEPROFILEMUST") %>");
      illegalfields++;
    }
    if(document.edituser.<%=SELECT_CA%>.options.selectedIndex == -1){
      alert("<%=  ejbcawebbean.getText("CAMUST") %>");
      illegalfields++;
    }
    if(document.edituser.<%=SELECT_TOKEN%>.options.selectedIndex == -1){
      alert("<%=  ejbcawebbean.getText("TOKENMUST") %>");
      illegalfields++;
    }

    <%  if(profile.getUse(EndEntityProfile.SENDNOTIFICATION,0) && profile.isModifyable(EndEntityProfile.EMAIL,0)){%>
    if(document.edituser.<%=CHECKBOX_SENDNOTIFICATION %>.checked && (document.edituser.<%= TEXTFIELD_EMAIL %>.value == "")){
      alert("<%= ejbcawebbean.getText("NOTIFICATIONADDRESSMUSTBE") %>");
      illegalfields++;
    } 
    <% } %>

   var selstatus = document.edituser.<%=SELECT_CHANGE_STATUS%>.options.selectedIndex;
   var status = document.edituser.<%=SELECT_CHANGE_STATUS%>.options[selstatus].value;
   var seltoken = document.edituser.<%=SELECT_TOKEN%>.options.selectedIndex;
   var token = document.edituser.<%=SELECT_TOKEN%>.options[seltoken].value

  <% if(profile.getUse(EndEntityProfile.PASSWORD,0)){ 
       if(profile.isModifyable(EndEntityProfile.PASSWORD,0)){%>  
   if((status == <%= UserDataConstants.STATUS_NEW%> || status == <%= UserDataConstants.STATUS_KEYRECOVERY%>) && status != <%= userdata.getStatus() %> && document.edituser.<%= TEXTFIELD_PASSWORD %>.value == ""){
      alert("<%= ejbcawebbean.getText("REQUIREDPASSWORD") %>");
      illegalfields++;
   }

  <%   } else { %>
   if((status == <%= UserDataConstants.STATUS_NEW%> || status == <%= UserDataConstants.STATUS_KEYRECOVERY%>) && status != <%= userdata.getStatus() %> && document.edituser.<%= TEXTFIELD_PASSWORD %>.options.selectedIndex == -1){
      alert("<%= ejbcawebbean.getText("REQUIREDPASSWORD") %>");
      illegalfields++;
   }
 <%   }
    }else{%>
   if((status == <%= UserDataConstants.STATUS_NEW%> || status == <%= UserDataConstants.STATUS_KEYRECOVERY%>) && status != <%= userdata.getStatus() %> && document.edituser.<%= CHECKBOX_REGENERATEPASSWD %>.checked == false && token <= <%= SecConst.TOKEN_SOFT%> ){
      alert("<%= ejbcawebbean.getText("PASSWORDMUSTBEREGEN") %>");
      illegalfields++;
   }
 <% } %>
   if(status != <%= UserDataConstants.STATUS_NEW%> && status != <%= UserDataConstants.STATUS_KEYRECOVERY%> && status != <%= UserDataConstants.STATUS_GENERATED%> && status != <%= UserDataConstants.STATUS_HISTORICAL%>){
      alert("<%= ejbcawebbean.getText("ONLYSTATUSCANBESELECTED") %>");
      illegalfields++;
    }
    if(illegalfields == 0){
      <% if(profile.getUse(EndEntityProfile.CLEARTEXTPASSWORD,0)){%> 
      document.edituser.<%= CHECKBOX_CLEARTEXTPASSWORD %>.disabled = false;
      <% } if(profile.getUse(EndEntityProfile.ADMINISTRATOR,0)){%> 
      document.edituser.<%= CHECKBOX_ADMINISTRATOR %>.disabled = false;
      <% } if(profile.getUse(EndEntityProfile.KEYRECOVERABLE,0) && globalconfiguration.getEnableKeyRecovery()){%> 
      document.edituser.<%= CHECKBOX_KEYRECOVERABLE %>.disabled = false;
      <% } if(profile.getUse(EndEntityProfile.SENDNOTIFICATION,0)){%> 
      document.edituser.<%= CHECKBOX_SENDNOTIFICATION %>.disabled = false;
      <% }%>
    }

     return illegalfields == 0;  
}
<% if(profile.getUse(EndEntityProfile.CLEARTEXTPASSWORD,0)){%> 
function checkUseInBatch(){
  var returnval = false;
  <% if(profile.getUse(EndEntityProfile.PASSWORD,0)){  %>   
  if(document.edituser.<%= CHECKBOX_CLEARTEXTPASSWORD %>.checked){
  <% if(!profile.isModifyable(EndEntityProfile.PASSWORD,0)){ %>
    returnval = document.edituser.<%= SELECT_PASSWORD %>.options.selectedIndex == -1;
  <% }else { %>
    returnval = document.edituser.<%= TEXTFIELD_PASSWORD %>.value == "";
  <% } %> 

  }

  if(returnval){
    alert("<%= ejbcawebbean.getText("PASSWORDREQUIRED") %>");    
    document.edituser.<%= CHECKBOX_CLEARTEXTPASSWORD %>.checked  = false;  
  }

  <% } %>

  return !returnval;
}
<% } 
  }
 %>   

   -->
  </script>
  <script language=javascript src="<%= globalconfiguration.getAdminWebPath() %>ejbcajslib.js"></script>
</head>
<body onload='<% if(usehardtokenissuers) out.write("setAvailableHardTokenIssuers();");
                 if(usekeyrecovery) out.write(" isKeyRecoveryPossible(); ");%>
                 fillCAField();'>
  <h2 align="center"><%= ejbcawebbean.getText("EDITENDENTITYTITLE") %></h2>
 <!-- <div align="right"><A  onclick='displayHelpWindow("<%= ejbcawebbean.getHelpfileInfix("ra_help.html") + "#editendentity"%>")'>
    <u><%= ejbcawebbean.getText("HELP") %></u> </A> -->
  </div>
 <%if(nouserparameter){%>
  <div align="center"><h4 id="alert"><%=ejbcawebbean.getText("YOUMUSTSPECIFYUSERNAME") %></h4></div> 
  <% } 
     else{
       if(userdata == null){%>
  <div align="center"><h4 id="alert"><%=ejbcawebbean.getText("ENDENTITYDOESNTEXIST") %></h4></div> 
    <% }
       else{
         if(notauthorized || profile == null){%>
  <div align="center"><h4 id="alert"><%=ejbcawebbean.getText("NOTAUTHORIZEDTOEDIT") %></h4></div> 
    <%   }
         else{ 
           if(endentitysaved){%>
  <div align="center"><h4><%=ejbcawebbean.getText("ENDENTITYSAVED") %></h4></div> 
    <%     } %>


     <table border="0" cellpadding="0" cellspacing="2" width="500">
      <tr id="Row<%=(row++)%2%>">
	 <td align="right"><%= ejbcawebbean.getText("ENDENTITYPROFILE")%></td>  
         <td><% if(rabean.getEndEntityProfileName(profileid)==null)
                  out.write(ejbcawebbean.getText("NOENDENTITYPROFILEDEFINED"));
                else
                  out.write(rabean.getEndEntityProfileName(profileid));%>
         </td>
         <td><%= ejbcawebbean.getText("REQUIRED") %></td>
      <tr id="Row<%=(row++)%2%>">
	<td>&nbsp;</td>
	<td>&nbsp;</td>
	<td>&nbsp;</td>
      </tr>
      </tr>
       <form name="edituser" action="<%= THIS_FILENAME %>" method="post">   
         <input type="hidden" name='<%= ACTION %>' value='<%=ACTION_EDITUSER %>'>   
         <input type="hidden" name='<%= HIDDEN_PROFILE %>' value='<%=profileid %>'>    
         <input type="hidden" name='<%= USER_PARAMETER %>' value='<%= username%>'>
      <tr id="Row<%=(row++)%2%>">
	<td align="right"><%= ejbcawebbean.getText("USERNAME") %></td> 
	<td>
          <%= userdata.getUsername() %>
        </td>
	<td></td>
      </tr>
          <% if(profile.getUse(EndEntityProfile.PASSWORD,0)){ %>
      <tr id="Row<%=(row++)%2%>">
	<td align="right"><%= ejbcawebbean.getText("PASSWORD") %></td>
        <td>   
             <%
               if(!profile.isModifyable(EndEntityProfile.PASSWORD,0)){ 
               %>
           <select name="<%= SELECT_PASSWORD %>" size="1" tabindex="<%=tabindex++%>">
               <% if( profile.getValue(EndEntityProfile.PASSWORD,0) != null){ %>
             <option value='<%=profile.getValue(EndEntityProfile.PASSWORD,0).trim()%>' > 
               <%=profile.getValue(EndEntityProfile.PASSWORD,0).trim()%>
             </option>                
               <%   
                  }
                %>
           </select>
           <% }else{ %> 
             <input type="password" name="<%= TEXTFIELD_PASSWORD %>" size="40" maxlength="255" tabindex="<%=tabindex++%>" value='<% if(userdata.getPassword()!= null) out.write(userdata.getPassword()); %>'>
           <% } %>
 
        </td>
	<td>&nbsp;</td>
      </tr>
       <% }else{ %>
      <tr id="Row<%=(row++)%2%>">
	<td align="right"><%= ejbcawebbean.getText("REGENERATENEWPASSWORD") %></td>
        <td>              
         <input type="checkbox" name="<%= CHECKBOX_REGENERATEPASSWD %>" value="<%= CHECKBOX_VALUE %>"  tabindex="<%=tabindex++%>">
        </td>
	<td>&nbsp;</td>
      </tr>
      <% } 
          if(profile.getUse(EndEntityProfile.PASSWORD,0)){%>
      <tr id="Row<%=(row++)%2%>">
	<td align="right"><%= ejbcawebbean.getText("CONFIRMPASSWORD") %></td>
        <td>
          <%   if(!profile.isModifyable(EndEntityProfile.PASSWORD,0)){ 
               %>
           <select name="<%= SELECT_CONFIRMPASSWORD %>" size="1" tabindex="<%=tabindex++%>">
               <% if( profile.getValue(EndEntityProfile.PASSWORD,0) != null){ %>
             <option value='<%=profile.getValue(EndEntityProfile.PASSWORD,0).trim()%>' > 
               <%= profile.getValue(EndEntityProfile.PASSWORD,0).trim() %>
             </option>                
               <%   
                  }
                %>
           </select>
           <% }else{ %> 
             <input type="password" name="<%= TEXTFIELD_CONFIRMPASSWORD %>" size="40" maxlength="255" tabindex="<%=tabindex++%>" value='<% if(userdata.getPassword()!= null) out.write(userdata.getPassword()); %>'>
           <% } %>
        </td>
	<td>&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp
&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp</td> 
      </tr>
      <% }
          if(profile.getUse(EndEntityProfile.CLEARTEXTPASSWORD,0)){%>
      <tr id="Row<%=(row++)%2%>">
	<td align="right"><%= ejbcawebbean.getText("USEINBATCH") %></td>
	<td><input type="checkbox" name="<%= CHECKBOX_CLEARTEXTPASSWORD %>" value="<%= CHECKBOX_VALUE %>"  onchange='return checkUseInBatch()' tabindex="<%=tabindex++%>" <% 
                                                                                                               if(profile.isRequired(EndEntityProfile.CLEARTEXTPASSWORD,0))
                                                                                                                 out.write(" disabled='true'"); 
                                                                                                               if(profile.isRequired(EndEntityProfile.CLEARTEXTPASSWORD,0) || userdata.getClearTextPassword())
                                                                                                                 out.write(" CHECKED ");
                                                                                                             %>> 
        </td>
	<td></td> 
      </tr>
      <% } 
         if(profile.getUse(EndEntityProfile.EMAIL,0)){ 
           String emailname = "";
           String emaildomain = "";
           if(userdata.getEmail() != null && !userdata.getEmail().equals("")){
             emailname   = userdata.getEmail().substring(0,userdata.getEmail().indexOf('@'));
             emaildomain = userdata.getEmail().substring(userdata.getEmail().indexOf('@')+1);
           }

 
%>
       <tr id="Row<%=(row++)%2%>">	 
	 <td align="right"><%= ejbcawebbean.getText("EMAIL") %></td>
	 <td>      
           <input type="text" name="<%= TEXTFIELD_EMAIL %>" size="20" maxlength="255" tabindex="<%=tabindex++%>" value='<%=emailname%>'>@
          <% if(!profile.isModifyable(EndEntityProfile.EMAIL,0)){ 
                 String[] options = profile.getValue(EndEntityProfile.EMAIL, 0).split(EndEntityProfile.SPLITCHAR);
               %>
           <select name="<%= SELECT_EMAILDOMAIN %>" size="1" tabindex="<%=tabindex++%>">
               <% if( options != null){
                    for(int i=0;i < options.length;i++){ %>
             <option value='<%=options[i].trim()%>' <% if(emaildomain.equals(options[i])) out.write(" selected "); %>>
                <%=options[i].trim()%>  
             </option>                
               <%   }
                  }
                %>
           </select>
           <% }else{ %> 
             <input type="text" name="<%= TEXTFIELD_EMAILDOMAIN %>" size="20" maxlength="255" tabindex="<%=tabindex++%>"  value='<%=emaildomain%>'>
           <% } %>
        </td>
	<td><input type="checkbox" name="<%= CHECKBOX_REQUIRED_EMAIL %>" value="<%= CHECKBOX_VALUE %>"  disabled="true" <% if(profile.isRequired(EndEntityProfile.EMAIL,0)) out.write(" CHECKED "); %>></td>
       </tr>
       <% }%>
      <tr id="Row<%=(row++)%2%>">
	<td align="right"><b><%= ejbcawebbean.getText("SUBJECTDNFIELDS") %></b></td>
	<td>&nbsp;</td>
	<td></td>
       </tr>
       <% int numberofsubjectdnfields = profile.getSubjectDNFieldOrderLength();
          for(int i=0; i < numberofsubjectdnfields; i++){
            fielddata = profile.getSubjectDNFieldsInOrder(i);  %>
       <tr id="Row<%=(row++)%2%>">
	 <td align="right"><%= ejbcawebbean.getText(subjectfieldtexts[fielddata[EndEntityProfile.FIELDTYPE]]) %></td>
	 <td>      
          <% 
             if( fielddata[EndEntityProfile.FIELDTYPE]  != EndEntityProfile.OLDDNE ){  
                if(!profile.isModifyable(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER])){ 
                 String[] options = profile.getValue(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER]).split(EndEntityProfile.SPLITCHAR);
               %>
           <select name="<%= SELECT_SUBJECTDN + i %>" size="1" tabindex="<%=tabindex++%>">
               <% if( options != null){
                    for(int j=0;j < options.length;j++){ %>
             <option value='<%=options[j].trim()%>' <% if(userdata.getSubjectDNField(profile.profileFieldIdToUserFieldIdMapper(fielddata[EndEntityProfile.FIELDTYPE]),fielddata[EndEntityProfile.NUMBER]).equals(options[j].trim())) out.write(" selected "); %>> 
                <%=options[j].trim()%>
             </option>                
               <%   }
                  }
                %>
           </select>
           <% }else{ %> 
             <input type="text" name="<%= TEXTFIELD_SUBJECTDN + i %>" size="40" maxlength="255" tabindex="<%=tabindex++%>" value='<%= userdata.getSubjectDNField(profile.profileFieldIdToUserFieldIdMapper(fielddata[EndEntityProfile.FIELDTYPE]),fielddata[EndEntityProfile.NUMBER]) %>'>
           <% }
            }
            else{ %>
              <%= ejbcawebbean.getText("USESEMAILFIELDDATA") + " :"%>&nbsp;
        <input type="checkbox" name="<%=CHECKBOX_SUBJECTDN + i%>" value="<%=CHECKBOX_VALUE %>" tabindex="<%=tabindex++%>" <% if(!userdata.getSubjectDNField(profile.profileFieldIdToUserFieldIdMapper(fielddata[EndEntityProfile.FIELDTYPE]),fielddata[EndEntityProfile.NUMBER]).equals("") || profile.isRequired(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER]))
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
        if(numberofsubjectaltnamefields > 0 ){
      %> 
      <tr id="Row<%=(row++)%2%>">
	<td align="right"><b><%= ejbcawebbean.getText("SUBJECTALTNAMEFIELDS") %></b></td>
	<td>&nbsp;</td>
	<td></td>
       </tr>
      <% } %>
       <% for(int i=0; i < numberofsubjectaltnamefields; i++){
            fielddata = profile.getSubjectAltNameFieldsInOrder(i);
            int fieldtype = fielddata[EndEntityProfile.FIELDTYPE];
            if(fieldtype != EndEntityProfile.OTHERNAME && fieldtype != EndEntityProfile.X400ADDRESS && fieldtype != EndEntityProfile.DIRECTORYNAME && 
               fieldtype != EndEntityProfile.EDIPARTNAME && fieldtype != EndEntityProfile.REGISTEREDID ){ // Not implemented yet.%>
       <tr id="Row<%=(row++)%2%>">
	 <td align="right"><%= ejbcawebbean.getText(subjectfieldtexts[fielddata[EndEntityProfile.FIELDTYPE]]) %></td>
	 <td>      
          <%
             if( fieldtype != EndEntityProfile.RFC822NAME ){
               if(fieldtype == EndEntityProfile.UPN){ 
                 String upnname = "";
                 String upndomain = "";            
                 String fullupn = userdata.getSubjectAltNameField(profile.profileFieldIdToUserFieldIdMapper(fielddata[EndEntityProfile.FIELDTYPE]),fielddata[EndEntityProfile.NUMBER]);
                 if(fullupn != null && !fullupn.equals("")){
                   upnname   = fullupn.substring(0,fullupn.indexOf('@'));
                   upndomain = fullupn.substring(fullupn.indexOf('@')+1);
                 } %>
                 <input type="text" name="<%= TEXTFIELD_UPNNAME +i%>" size="20" maxlength="255" tabindex="<%=tabindex++%>" value="<%= upnname %>">@
          <%     if(!profile.isModifyable(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER])){ 
                 String[] options = profile.getValue(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER]).split(EndEntityProfile.SPLITCHAR); %>
                <select name="<%= SELECT_SUBJECTALTNAME + i %>" size="1" tabindex="<%=tabindex++%>">
                  <% if( options != null){
                      for(int j=0;j < options.length;j++){ %>
                  <option value='<%=options[j].trim()%>' <%  if(upndomain.equals(options[j].trim())) out.write(" selected "); %>> 
                    <%=options[j].trim()%>
                  </option>                
               <%   }
                 }
                %>
                </select>
             <% }else{ %> 
             <input type="text" name="<%= TEXTFIELD_SUBJECTALTNAME + i %>" size="40" maxlength="255" tabindex="<%=tabindex++%>" value='<%= upndomain %>'>
             <% }
              }else{    
               if(!profile.isModifyable(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER])){ 
                 String[] options = profile.getValue(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER]).split(EndEntityProfile.SPLITCHAR); %>
           <select name="<%= SELECT_SUBJECTALTNAME + i %>" size="1" tabindex="<%=tabindex++%>">
               <% if( options != null){
                    for(int j=0;j < options.length;j++){ %>
             <option value='<%=options[j].trim()%>' <%  if(userdata.getSubjectAltNameField(profile.profileFieldIdToUserFieldIdMapper(fielddata[EndEntityProfile.FIELDTYPE]),fielddata[EndEntityProfile.NUMBER]).equals(options[j].trim())) out.write(" selected "); %>> 
                <%=options[j].trim()%>
             </option>                
               <%   }
                  }
                %>
           </select>
           <% }else{ %>
             <input type="text" name="<%= TEXTFIELD_SUBJECTALTNAME + i %>" size="40" maxlength="255" tabindex="<%=tabindex++%>" value='<%= userdata.getSubjectAltNameField(profile.profileFieldIdToUserFieldIdMapper(fielddata[EndEntityProfile.FIELDTYPE]),fielddata[EndEntityProfile.NUMBER]) %>'>
           <% }
            }
            }else{ %>
              <%= ejbcawebbean.getText("USESEMAILFIELDDATA")+ " :"%>&nbsp;
        <input type="checkbox" name="<%=CHECKBOX_SUBJECTALTNAME + i%>" value="<%=CHECKBOX_VALUE %>" tabindex="<%=tabindex++%>" 
          <% if(profile.isRequired(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER])) out.write(" disabled='true' ");     
             if(!userdata.getSubjectAltNameField(profile.profileFieldIdToUserFieldIdMapper(fielddata[EndEntityProfile.FIELDTYPE]),fielddata[EndEntityProfile.NUMBER]).equals("") || profile.isRequired(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER]))
                                                                                                                 out.write(" CHECKED ");
                                                                                                             %>>
         <% } %>  
        </td>
	<td><input type="checkbox" name="<%= CHECKBOX_REQUIRED_SUBJECTALTNAME + i %>" value="<%= CHECKBOX_VALUE %>"  disabled="true" <% if(profile.isRequired(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER])) out.write(" CHECKED "); %>></td>
      </tr>
     <%   }
        }%> 
       <tr id="Row<%=(row++)%2%>">
	 <td>&nbsp;</td>
	 <td>&nbsp;</td>
	 <td>&nbsp;</td>
       </tr>
       <tr id="Row<%=(row++)%2%>">
	 <td align="right"><%= ejbcawebbean.getText("CERTIFICATEPROFILE") %></td>
	 <td>
         <select name="<%= SELECT_CERTIFICATEPROFILE %>" size="1" tabindex="<%=tabindex++%>" onchange='fillCAField()'>
         <%
           String[] availablecertprofiles = profile.getValue(EndEntityProfile.AVAILCERTPROFILES, 0).split(EndEntityProfile.SPLITCHAR);
           if( availablecertprofiles != null){
             for(int i =0; i< availablecertprofiles.length;i++){
         %>
         <option value='<%=availablecertprofiles[i]%>' <% if(userdata.getCertificateProfileId() ==Integer.parseInt(availablecertprofiles[i])) out.write(" selected "); %> >
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
	 <td align="right"><%= ejbcawebbean.getText("CA") %></td>
	 <td>
         <select name="<%= SELECT_CA %>" size="1" tabindex="<%=tabindex++%>">
         </select>
         </td>
	 <td><input type="checkbox" name="checkbox" value="true"  disabled="true" CHECKED></td>
       </tr>
       <tr id="Row<%=(row++)%2%>">
	 <td align="right"><%= ejbcawebbean.getText("TOKEN") %></td>
	 <td>
         <select name="<%= SELECT_TOKEN %>" size="1" tabindex="<%=tabindex++%>" onchange='<% if(usehardtokenissuers) out.write("setAvailableHardTokenIssuers();");
                                                                                             if(usekeyrecovery) out.write(" isKeyRecoveryPossible();");%>'>
         <%
           if( availabletokens != null){
             for(int i =0; i < availabletokens.length;i++){
         %>
         <option value='<%=availabletokens[i]%>' <% if(userdata.getTokenType() ==Integer.parseInt(availabletokens[i])) out.write(" selected "); %> >
            <% for(int j=0; j < tokentexts.length; j++){
                 if( tokenids[j] == Integer.parseInt(availabletokens[i])){ 
                   if( tokenids[j] > SecConst.TOKEN_SOFT)
                     out.write(tokentexts[j]);
                   else
                     out.write(ejbcawebbean.getText(tokentexts[j]));
                 }
               } %>
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
	 <td align="right"><%= ejbcawebbean.getText("TYPES") %></td>
	 <td>
         </td>
	 <td></td>
       </tr>
       <% } %>
      <% if(profile.getUse(EndEntityProfile.ADMINISTRATOR,0)){ %>
    <tr  id="Row<%=(row++)%2%>"> 
      <td  align="right"> 
        <%= ejbcawebbean.getText("ADMINISTRATOR") %> <br>
      </td>
      <td > 
        <input type="checkbox" name="<%=CHECKBOX_ADMINISTRATOR%>" value="<%=CHECKBOX_VALUE %>" tabindex="<%=tabindex++%>" <% 
                                                                                                               if(profile.isRequired(EndEntityProfile.ADMINISTRATOR,0))
                                                                                                                 out.write(" disabled='true'"); 
                                                                                                               if(userdata.getAdministrator())
                                                                                                                 out.write(" CHECKED ");
                                                                                                             %>>  
      </td>
      <td></td>
    </tr>
      <%} if(usekeyrecovery){ %>
    <tr  id="Row<%=(row++)%2%>"> 
      <td  align="right"> 
        <%= ejbcawebbean.getText("KEYRECOVERABLE") %> 
      </td>
      <td> 
        <input type="checkbox" name="<%=CHECKBOX_KEYRECOVERABLE%>" value="<%=CHECKBOX_VALUE %>" tabindex="<%=tabindex++%>" <% 
                                                                                                               if(profile.isRequired(EndEntityProfile.KEYRECOVERABLE,0))
                                                                                                                 out.write(" disabled='true'"); 
                                                                                                               if( userdata.getKeyRecoverable())
                                                                                                                 out.write(" CHECKED ");
                                                                                                             %>>  
      </td>
      <td></td>
    </tr>
     <% }if(profile.getUse(EndEntityProfile.SENDNOTIFICATION,0)){ %>
    <tr  id="Row<%=(row++)%2%>"> 
      <td  align="right"> 
        <%= ejbcawebbean.getText("SENDNOTIFICATION") %> <br>
      </td>
      <td > 
        <input type="checkbox" name="<%=CHECKBOX_SENDNOTIFICATION%>" value="<%=CHECKBOX_VALUE %>" tabindex="<%=tabindex++%>" <% 
                                                                                                               if(profile.isRequired(EndEntityProfile.SENDNOTIFICATION,0))
                                                                                                                 out.write(" disabled='true'"); 
                                                                                                               if( userdata.getSendNotification())
                                                                                                                 out.write(" CHECKED ");
                                                                                                             %>>  
      </td>
      <td></td>
    </tr>
    <%} %>
    <tr  id="Row<%=(row++)%2%>"> 
      <td  align="right"> 
        &nbsp;
      </td>
      <td > 
        &nbsp;
      </td>
      <td></td>
    </tr>
    <tr  id="Row<%=(row++)%2%>"> 
      <td  align="right"> 
        <%= ejbcawebbean.getText("STATUS") %> <br>
      </td>
      <td > 
        <select name="<%=SELECT_CHANGE_STATUS %>" tabindex="<%=tabindex++%>" >
         <%if(userdata.getStatus()== UserDataConstants.STATUS_KEYRECOVERY){ %>
           <option selected value='<%= UserDataConstants.STATUS_KEYRECOVERY %>'><%= ejbcawebbean.getText("STATUSKEYRECOVERY") %></option>
         <% }else{ %>  
         <option <%if(userdata.getStatus()== UserDataConstants.STATUS_NEW) out.write(" selected ");%> value='<%= UserDataConstants.STATUS_NEW %>'><%= ejbcawebbean.getText("STATUSNEW") %></option>
         <% } %>
         <option <%if(userdata.getStatus()== UserDataConstants.STATUS_FAILED) out.write(" selected ");%> value='<%= UserDataConstants.STATUS_FAILED %>'><%= ejbcawebbean.getText("STATUSFAILED") %></option>  -->
         <option <%if(userdata.getStatus()== UserDataConstants.STATUS_INITIALIZED) out.write(" selected ");%> value='<%= UserDataConstants.STATUS_INITIALIZED %>'><%= ejbcawebbean.getText("STATUSINITIALIZED") %></option>  -->
         <option <%if(userdata.getStatus()== UserDataConstants.STATUS_INPROCESS) out.write(" selected ");%> value='<%= UserDataConstants.STATUS_INPROCESS %>'><%= ejbcawebbean.getText("STATUSINPROCESS") %></option>  -->
         <option <%if(userdata.getStatus()== UserDataConstants.STATUS_GENERATED) out.write(" selected ");%> value='<%= UserDataConstants.STATUS_GENERATED %>'><%= ejbcawebbean.getText("STATUSGENERATED") %></option>  
         <option <%if(userdata.getStatus()== UserDataConstants.STATUS_REVOKED) out.write(" selected ");%> value='<%= UserDataConstants.STATUS_REVOKED %>'><%= ejbcawebbean.getText("STATUSREVOKED") %></option>  -->
         <option <%if(userdata.getStatus()== UserDataConstants.STATUS_HISTORICAL) out.write(" selected ");%> value='<%= UserDataConstants.STATUS_HISTORICAL %>'><%= ejbcawebbean.getText("STATUSHISTORICAL") %></option>
        </select>
      </td>
      <td></td>
    </tr>
       <tr id="Row<%=(row++)%2%>">
	 <td></td>
	 <td><input type="submit" name="<%= BUTTON_SAVE %>" value="<%= ejbcawebbean.getText("SAVE") %>" tabindex="20"
                    onClick='return checkallfields()'> 
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
