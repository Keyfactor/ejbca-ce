<%@ page pageEncoding="ISO-8859-1"%>
<%@page errorPage="/errorpage.jsp"  import="java.util.TreeMap, java.util.Iterator, se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean, se.anatom.ejbca.ra.raadmin.GlobalConfiguration, 
                 se.anatom.ejbca.webdist.rainterface.UserView, se.anatom.ejbca.webdist.rainterface.RAInterfaceBean, se.anatom.ejbca.SecConst,
                 se.anatom.ejbca.ra.raadmin.EndEntityProfile,se.anatom.ejbca.authorization.AuthorizationDeniedException,  se.anatom.ejbca.ra.UserDataConstants,
                 javax.ejb.CreateException, java.rmi.RemoteException, se.anatom.ejbca.webdist.hardtokeninterface.HardTokenInterfaceBean, 
                 se.anatom.ejbca.hardtoken.HardTokenIssuer, se.anatom.ejbca.hardtoken.HardTokenIssuerData" %>
<html>
<jsp:useBean id="ejbcawebbean" scope="session" class="se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean" />
<jsp:useBean id="rabean" scope="session" class="se.anatom.ejbca.webdist.rainterface.RAInterfaceBean" />
<jsp:useBean id="tokenbean" scope="session" class="se.anatom.ejbca.webdist.hardtokeninterface.HardTokenInterfaceBean" />
<%! // Declarations
 
  static final String USER_PARAMETER           = "username";

  static final String BUTTON_CLOSE             = "buttonclose"; 

  static final String CHECKBOX_CLEARTEXTPASSWORD          = "checkboxcleartextpassword";
  static final String CHECKBOX_ADMINISTRATOR              = "checkboxadministrator";
  static final String CHECKBOX_KEYRECOVERABLE             = "checkboxkeyrecoverable";
  static final String CHECKBOX_SENDNOTIFICATION           = "checkboxsendnotification";

  static final String CHECKBOX_VALUE             = "true";


%><%
  // Initialize environment.
  GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, "/ra_functionality/view_end_entity"); 
                                            rabean.initialize(request, ejbcawebbean);
                                            if(globalconfiguration.getIssueHardwareTokens())
                                              tokenbean.initialize(request, ejbcawebbean);
  String THIS_FILENAME                    = globalconfiguration.getRaPath()  + "/viewendentity.jsp";

  boolean nouserparameter          = true;
  boolean notauthorized            = false;

  String[] subjectfieldtexts = {"","","", "OLDEMAILDN2", "UID", "COMMONNAME", "SERIALNUMBER1", 
                                "GIVENNAME2", "INITIALS", "SURNAME","TITLE","ORGANIZATIONUNIT","ORGANIZATION",
                                "LOCALE","STATE","DOMAINCOMPONENT","COUNTRY",
                                "RFC822NAME", "DNSNAME", "IPADDRESS", "OTHERNAME", "UNIFORMRESOURCEID", "X400ADDRESS", "DIRECTORYNAME",
                                "EDIPARTNAME", "REGISTEREDID","","","","","","","","","","","UPN", "", "", "UNSTRUCTUREDADDRESS", "UNSTRUCTUREDNAME","GUID"};
   
   int[] statusids            = {UserDataConstants.STATUS_NEW ,UserDataConstants.STATUS_FAILED, UserDataConstants.STATUS_INITIALIZED, UserDataConstants.STATUS_INPROCESS
                                , UserDataConstants.STATUS_GENERATED, UserDataConstants.STATUS_REVOKED , UserDataConstants.STATUS_HISTORICAL, UserDataConstants.STATUS_KEYRECOVERY};
   String[] statustexts         = {"STATUSNEW", "STATUSFAILED", "STATUSINITIALIZED", "STATUSINPROCESS", "STATUSGENERATED", "STATUSREVOKED", "STATUSHISTORICAL", "STATUSKEYRECOVERY"};

  UserView userdata = null;
  String   username = null;
  EndEntityProfile  profile  = null;
  int[]  fielddata  = null;
  String fieldvalue = null;

   String[] tokentexts = RAInterfaceBean.tokentexts;
   int[] tokenids = RAInterfaceBean.tokenids;

   if(globalconfiguration.getIssueHardwareTokens()){
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

  if( request.getParameter(USER_PARAMETER) != null ){
    username = java.net.URLDecoder.decode(request.getParameter(USER_PARAMETER),"UTF-8");
    try{
      userdata = rabean.findUser(username);
    } catch(AuthorizationDeniedException e){
       notauthorized = true;
    }
    nouserparameter = false;
    if(userdata!=null)
      profile = rabean.getEndEntityProfile(userdata.getEndEntityProfileId());
  }  

  int row = 0; 
  int columnwidth = 200;
%>
<head>
  <title><%= globalconfiguration.getEjbcaTitle() %></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>">
  <link rel=STYLESHEET href="<%= ejbcawebbean.getCssFile() %>">
  <script language=javascript src="<%= globalconfiguration.getAdminWebPath() %>ejbcajslib.js"></script>
</head>
<body >
  <h2 align="center"><%= ejbcawebbean.getText("VIEWENDENTITY2") %></h2>
  <!-- <div align="right"><A  onclick='displayHelpWindow("<%= ejbcawebbean.getHelpfileInfix("ra_help.html")  + "#viewendentity"%>")'>
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
         if(notauthorized){ %>
  <div align="center"><h4 id="alert"><%=ejbcawebbean.getText("NOTAUTHORIZEDTOVIEW") %></h4></div> 
     <%  }else{%>

  <form name="adduser" action="<%= THIS_FILENAME %>" method="post">
     <input type="hidden" name='<%= USER_PARAMETER %>' value='<%=username %>'>
     <table border="0" cellpadding="0" cellspacing="2" width="400">
      <tr id="Row<%=(row++)%2%>">
	<td align="right" width="<%=columnwidth%>"><%= ejbcawebbean.getText("USERNAME") %></td>
	<td><% if(userdata.getUsername() != null) out.write(userdata.getUsername()); %>
        </td>
      </tr>
      <tr id="Row<%=(row++)%2%>">
	<td align="right" width="<%=columnwidth%>"><%= ejbcawebbean.getText("ENDENTITYPROFILE") %></td>
	<td><% if(userdata.getEndEntityProfileId() != 0)
                    out.write(rabean.getEndEntityProfileName(userdata.getEndEntityProfileId()));
                 else out.write(ejbcawebbean.getText("NOENDENTITYPROFILEDEFINED"));%>
        </td>
      </tr>
      <% if(profile.getUse(EndEntityProfile.CLEARTEXTPASSWORD,0)){ %>
      <tr id="Row<%=(row++)%2%>">
	<td align="right" width="<%=columnwidth%>"><%= ejbcawebbean.getText("USEINBATCH") %></td>
	<td><input type="checkbox" name="<%= CHECKBOX_CLEARTEXTPASSWORD %>" value="<%= CHECKBOX_VALUE %>" disabled="true"
            <%if(userdata.getClearTextPassword())
                   out.write("CHECKED");%>>
        </td>
      </tr>
      <% } %>
      <tr id="Row<%=(row++)%2%>">
      <td>&nbsp;</td>
      <td>&nbsp</td>
      </tr> 
       <tr id="Row<%=(row++)%2%>">
	 <td align="right" width="<%=columnwidth%>"><%= ejbcawebbean.getText("SUBJECTDNFIELDS") %></td>
	 <td>
         </td>
       </tr>
      <% int subjectfieldsize = profile.getSubjectDNFieldOrderLength();
         for(int i = 0; i < subjectfieldsize; i++){
            fielddata = profile.getSubjectDNFieldsInOrder(i);
            fieldvalue = userdata.getSubjectDNField(profile.profileFieldIdToUserFieldIdMapper(fielddata[EndEntityProfile.FIELDTYPE]),fielddata[EndEntityProfile.NUMBER]);
         %>
       <tr id="Row<%=(row++)%2%>">
	 <td align="right" width="<%=columnwidth%>"><%= ejbcawebbean.getText(subjectfieldtexts[fielddata[EndEntityProfile.FIELDTYPE]]) %></td>
	 <td><% if(fieldvalue != null) out.write(fieldvalue); %> 
         </td>
       </tr>
       <% } 
          subjectfieldsize = profile.getSubjectAltNameFieldOrderLength();
          if(subjectfieldsize > 0){
       %> 
       <tr id="Row<%=(row++)%2%>">
         <td>&nbsp;</td>
         <td>&nbsp</td>
       </tr>
       <tr id="Row<%=(row++)%2%>">
	 <td align="right" width="<%=columnwidth%>"><%= ejbcawebbean.getText("SUBJECTALTNAMEFIELDS") %></td>
	 <td>
         </td>
       </tr>
      <% }
         for(int i = 0; i < subjectfieldsize; i++){
            fielddata = profile.getSubjectAltNameFieldsInOrder(i);
            int fieldtype = fielddata[EndEntityProfile.FIELDTYPE];
            if(fieldtype != EndEntityProfile.OTHERNAME && fieldtype != EndEntityProfile.X400ADDRESS && fieldtype != EndEntityProfile.DIRECTORYNAME && 
               fieldtype != EndEntityProfile.EDIPARTNAME && fieldtype != EndEntityProfile.REGISTEREDID ){ // Not implemented yet.
            fieldvalue = userdata.getSubjectAltNameField(profile.profileFieldIdToUserFieldIdMapper(fielddata[EndEntityProfile.FIELDTYPE]),fielddata[EndEntityProfile.NUMBER]);
         %>
       <tr id="Row<%=(row++)%2%>">
	 <td align="right" width="<%=columnwidth%>"><%= ejbcawebbean.getText(subjectfieldtexts[fielddata[EndEntityProfile.FIELDTYPE]]) %></td>
	 <td><% if(fieldvalue != null) out.write(fieldvalue); %> 
         </td>
       </tr>
       <%   }
          }%>  
       <tr id="Row<%=(row++)%2%>">
	 <td>&nbsp;</td>
	 <td>&nbsp;</td>
       </tr>
      <% if(profile.getUse(EndEntityProfile.EMAIL,0)){ %>
       <tr id="Row<%=(row++)%2%>">
	 <td align="right" width="<%=columnwidth%>"><%= ejbcawebbean.getText("EMAIL") %></td>
	 <td><% if(userdata.getEmail() != null) out.write(userdata.getEmail()); %>
         </td>
       </tr>
       <% } %>
       <tr id="Row<%=(row++)%2%>">
	 <td align="right" width="<%=columnwidth%>"><%= ejbcawebbean.getText("CERTIFICATEPROFILE") %></td>
	 <td><% if(userdata.getCertificateProfileId() != 0)
                  out.write(rabean.getCertificateProfileName(userdata.getCertificateProfileId())); 
                else out.write(ejbcawebbean.getText("NOCERTIFICATEPROFILEDEFINED")); %>
         </td>
       </tr>
       <tr id="Row<%=(row++)%2%>">
	 <td align="right" width="<%=columnwidth%>"><%= ejbcawebbean.getText("CA") %></td>
	 <td><%= userdata.getCAName()  %>
         </td>
       </tr>
       <tr id="Row<%=(row++)%2%>">
	 <td align="right" width="<%=columnwidth%>"><%= ejbcawebbean.getText("TOKEN") %></td>
         <td>   
            <% for(int i=0; i < tokentexts.length;i++){
                if(tokenids[i] == userdata.getTokenType())
                   if( tokenids[i] > SecConst.TOKEN_SOFT)
                     out.write(tokentexts[i]);
                   else
                     out.write(ejbcawebbean.getText(tokentexts[i]));
              } %>
         </td> 
       </tr>
       <% if(globalconfiguration.getIssueHardwareTokens()){ %>
       <tr id="Row<%=(row++)%2%>">
	 <td align="right" width="<%=columnwidth%>"><%= ejbcawebbean.getText("HARDTOKENISSUER") %></td>
         <td>   
            <% if(userdata.getHardTokenIssuerId() == SecConst.NO_HARDTOKENISSUER)
                 out.write(ejbcawebbean.getText("NONE"));
               else
                 out.write(tokenbean.getHardTokenIssuerAlias(userdata.getHardTokenIssuerId()));
            %>
         </td> 
       </tr>
       <% } 
       if( profile.getUse(EndEntityProfile.ADMINISTRATOR,0) || profile.getUse(EndEntityProfile.KEYRECOVERABLE,0) && globalconfiguration.getEnableKeyRecovery()){
        %>
       <tr id="Row<%=(row++)%2%>">
	 <td align="right" width="<%=columnwidth%>"><%= ejbcawebbean.getText("TYPES") %></td>
	 <td>
         </td>
       </tr>
      <% } if(profile.getUse(EndEntityProfile.ADMINISTRATOR,0)){ %>
    <tr  id="Row<%=(row++)%2%>"> 
      <td  align="right" width="<%=columnwidth%>"> 
        <%= ejbcawebbean.getText("ADMINISTRATOR") %> <br>
      </td>
      <td > 
        <input type="checkbox" name="<%=CHECKBOX_ADMINISTRATOR%>" value="<%=CHECKBOX_VALUE %>" tabindex="12"
                <%if(userdata.getAdministrator())
                   out.write("CHECKED");%> disabled="true"> 
      </td>
    </tr>
      <% } if(profile.getUse(EndEntityProfile.KEYRECOVERABLE,0) && globalconfiguration.getEnableKeyRecovery()){ %>
    <tr  id="Row<%=(row++)%2%>"> 
      <td  align="right" width="<%=columnwidth%>"> 
        <%= ejbcawebbean.getText("KEYRECOVERABLE") %> 
      </td>
      <td> 
        <input type="checkbox" name="<%=CHECKBOX_KEYRECOVERABLE%>" value="<%=CHECKBOX_VALUE %>" tabindex="13"
                <%if(userdata.getKeyRecoverable())
                   out.write("CHECKED");%> disabled="true"> 
      </td>
    </tr>
      <% } if(profile.getUse(EndEntityProfile.SENDNOTIFICATION,0)){ %>
    <tr  id="Row<%=(row++)%2%>"> 
      <td  align="right" width="<%=columnwidth%>"> 
        <%= ejbcawebbean.getText("SENDNOTIFICATION") %> <br>
      </td>
      <td > 
        <input type="checkbox" name="<%=CHECKBOX_SENDNOTIFICATION%>" value="<%=CHECKBOX_VALUE %>" tabindex="12"
                <%if(userdata.getSendNotification())
                   out.write("CHECKED");%> disabled="true"> 
      </td>
    </tr>
      <% } %>
    <tr id="Row<%=(row++)%2%>">
      <td>&nbsp;</td>
      <td>&nbsp</td>
    </tr> 
    <tr id="Row0">
      <td align="right" width="<%=columnwidth%>"><%= ejbcawebbean.getText("CREATED") %></td>
      <td>
         <%= ejbcawebbean.printDateTime(userdata.getTimeCreated()) %>
       </td>
    </tr> 
    <tr id="Row<%=(row++)%2%>">
      <td align="right" width="<%=columnwidth%>"><%= ejbcawebbean.getText("MODIFIED") %></td>
      <td>
         <%= ejbcawebbean.printDateTime(userdata.getTimeModified()) %>
       </td>
     </tr> 
    <tr id="Row<%=(row++)%2%>">
      <td align="right" width="<%=columnwidth%>"><%= ejbcawebbean.getText("STATUS") %></td>
      <td>
        <% for(int i=0; i < statusids.length; i++)
             if(userdata.getStatus()==statusids[i])
               out.write(ejbcawebbean.getText(statustexts[i])); %>
       </td>
     </tr> 
       <tr id="Row<%=(row++)%2%>">
	 <td width="<%=columnwidth%>"></td>
	 <td>
             <input type="reset" name="<%= BUTTON_CLOSE %>" value="<%= ejbcawebbean.getText("CLOSE") %>" tabindex="20"
                    onClick='self.close()'>
       </td>
       </tr> 
     </table> 
   </form>
   <p></p>
   <% }
    }
   }%>

</body>
</html>