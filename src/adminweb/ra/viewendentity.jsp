<%@ page pageEncoding="ISO-8859-1"%>
<%@ page contentType="text/html; charset=@page.encoding@" %>
<%@page errorPage="/errorpage.jsp"  import="org.ejbca.core.model.ra.raadmin.GlobalConfiguration, 
                 org.ejbca.core.model.SecConst, org.ejbca.core.model.ra.raadmin.EndEntityProfile,
                 org.ejbca.ui.web.admin.rainterface.ViewEndEntityHelper" %>
<html>
<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />
<jsp:useBean id="rabean" scope="session" class="org.ejbca.ui.web.admin.rainterface.RAInterfaceBean" />
<jsp:useBean id="cabean" scope="session" class="org.ejbca.ui.web.admin.cainterface.CAInterfaceBean" />
<jsp:useBean id="tokenbean" scope="session" class="org.ejbca.ui.web.admin.hardtokeninterface.HardTokenInterfaceBean" />
<jsp:useBean id="helper" scope="session" class="org.ejbca.ui.web.admin.rainterface.ViewEndEntityHelper" />
<%! // Declarations
 



%><%
  // Initialize environment.
  GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, "/ra_functionality/view_end_entity"); 
                                            rabean.initialize(request, ejbcawebbean);
                                            cabean.initialize(request, ejbcawebbean);
                                            if(globalconfiguration.getIssueHardwareTokens())
                                              tokenbean.initialize(request, ejbcawebbean);
  String THIS_FILENAME                    = globalconfiguration.getRaPath()  + "/viewendentity.jsp";

  helper.initialize(ejbcawebbean,rabean,cabean);
  
  helper.parseRequest(request);

%>
<head>
  <title><%= globalconfiguration.getEjbcaTitle() %></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>">
  <link rel=STYLESHEET href="<%= ejbcawebbean.getCssFile() %>">
  <script language=javascript src="<%= globalconfiguration.getAdminWebPath() %>ejbcajslib.js"></script>
</head>
<body >
  <h2 align="center"><%= ejbcawebbean.getText("VIEWENDENTITY2") %></h2>
  <%if(helper.nouserparameter){%>
  <div align="center"><h4 id="alert"><%=ejbcawebbean.getText("YOUMUSTSPECIFYUSERNAME") %></h4></div> 
  <% }else{
       if(helper.userdata == null){%>
  <div align="center"><h4 id="alert"><%=ejbcawebbean.getText("ENDENTITYDOESNTEXIST") %></h4></div> 
    <% }else{ 
         if(helper.notauthorized){ %>
  <div align="center"><h4 id="alert"><%=ejbcawebbean.getText("NOTAUTHORIZEDTOVIEW") %></h4></div>   
     <%  }else{
           if(helper.profilenotfound){ %>
         <div align="center"><h4 id="alert"><%=ejbcawebbean.getText("CANNOTVIEWUSERPROFREM") %></h4></div>   
        <%  }else{    
         if(helper.currentuserindex == 0){ %>
        	   <div align="center"><h4><%=ejbcawebbean.getText("CURRENTUSERDATA") %></h4></div> 
       <%}else{ %>
               <div align="center"><h4><%=ejbcawebbean.getText("HISTORICALUSERDATA") %></h4></div> 
       <% } %>
   
  <form name="pageuser" action="<%= THIS_FILENAME %>" method="post">
       <input type="hidden" name='<%= ViewEndEntityHelper.ACTION %>' value='<%= ViewEndEntityHelper.ACTION_PAGE%>'>
     <input type="hidden" name='<%= ViewEndEntityHelper.USER_PARAMETER %>' value='<%= java.net.URLEncoder.encode(helper.username,"UTF-8")%>'>
     <table border="0" cellpadding="0" cellspacing="2" width="400">
      <tr id="Row<%=(helper.row++)%2%>">
	<td align="right" width="<%=ViewEndEntityHelper.columnwidth%>"><%= ejbcawebbean.getText("USERNAME") %></td>
	<td><% if(helper.userdata.getUsername() != null) out.write(helper.userdata.getUsername()); %>
        </td>
      </tr>
      <tr id="Row<%=(helper.row++)%2%>">
	<td align="right" width="<%=ViewEndEntityHelper.columnwidth%>"><%= ejbcawebbean.getText("ENDENTITYPROFILE") %></td>
	<td><% if(helper.userdata.getEndEntityProfileId() != 0)
                    out.write(rabean.getEndEntityProfileName(helper.userdata.getEndEntityProfileId()));
                 else out.write(ejbcawebbean.getText("NOENDENTITYPROFILEDEFINED"));%>
        </td>
      </tr>
      <% if(helper.profile.getUse(EndEntityProfile.CLEARTEXTPASSWORD,0)){ %>
      <tr id="Row<%=(helper.row++)%2%>">
	<td align="right" width="<%=ViewEndEntityHelper.columnwidth%>"><%= ejbcawebbean.getText("USEINBATCH") %></td>
	<td><input type="checkbox" name="<%= ViewEndEntityHelper.CHECKBOX_CLEARTEXTPASSWORD %>" value="<%= ViewEndEntityHelper.CHECKBOX_VALUE %>" disabled="true"
            <% if(helper.userdata.getClearTextPassword())
                   out.write("CHECKED");%>>
        </td>
      </tr>
      <% } %>
      <tr id="Row<%=(helper.row++)%2%>">
      <td>&nbsp;</td>
      <td>&nbsp;</td>
      </tr> 
       <tr id="Row<%=(helper.row++)%2%>">
	 <td align="right" width="<%=ViewEndEntityHelper.columnwidth%>"><%= ejbcawebbean.getText("SUBJECTDNFIELDS") %></td>
	 <td>
         </td>
       </tr>
      <% int subjectfieldsize = helper.profile.getSubjectDNFieldOrderLength();
         for(int i = 0; i < subjectfieldsize; i++){
        	 helper.fielddata = helper.profile.getSubjectDNFieldsInOrder(i);
        	 helper.fieldvalue = helper.userdata.getSubjectDNField(EndEntityProfile.profileFieldIdToUserFieldIdMapper(helper.fielddata[EndEntityProfile.FIELDTYPE]),helper.fielddata[EndEntityProfile.NUMBER]);
         %>
       <tr id="Row<%=(helper.row++)%2%>">
	 <td align="right" width="<%=ViewEndEntityHelper.columnwidth%>"><%= ejbcawebbean.getText(ViewEndEntityHelper.subjectfieldtexts[helper.fielddata[EndEntityProfile.FIELDTYPE]]) %></td>
	 <td><% if(helper.fieldvalue != null) out.write(helper.fieldvalue); %> 
         </td>
       </tr>
       <% } 
          subjectfieldsize = helper.profile.getSubjectAltNameFieldOrderLength();
          if(subjectfieldsize > 0){
       %> 
       <tr id="Row<%=(helper.row++)%2%>">
         <td>&nbsp;</td>
         <td>&nbsp;</td>
       </tr>
       <tr id="Row<%=(helper.row++)%2%>">
	 <td align="right" width="<%=ViewEndEntityHelper.columnwidth%>"><%= ejbcawebbean.getText("SUBJECTALTNAMEFIELDS") %></td>
	 <td>
         </td>
       </tr>
      <% }
         for(int i = 0; i < subjectfieldsize; i++){
        	 helper.fielddata = helper.profile.getSubjectAltNameFieldsInOrder(i);
            int fieldtype = helper.fielddata[EndEntityProfile.FIELDTYPE];
            if(fieldtype != EndEntityProfile.OTHERNAME && fieldtype != EndEntityProfile.X400ADDRESS && fieldtype != EndEntityProfile.DIRECTORYNAME && 
               fieldtype != EndEntityProfile.EDIPARTNAME && fieldtype != EndEntityProfile.REGISTEREDID ){ // Not implemented yet.
            	helper.fieldvalue = helper.userdata.getSubjectAltNameField(EndEntityProfile.profileFieldIdToUserFieldIdMapper(helper.fielddata[EndEntityProfile.FIELDTYPE]),helper.fielddata[EndEntityProfile.NUMBER]);
         %>
       <tr id="Row<%=(helper.row++)%2%>">
	 <td align="right" width="<%=ViewEndEntityHelper.columnwidth%>"><%= ejbcawebbean.getText(ViewEndEntityHelper.subjectfieldtexts[helper.fielddata[EndEntityProfile.FIELDTYPE]]) %></td>
	 <td><% if(helper.fieldvalue != null) out.write(helper.fieldvalue); %> 
         </td>
       </tr>
       <%   }
          }%>  
       <tr id="Row<%=(helper.row++)%2%>">
	 <td>&nbsp;</td>
	 <td>&nbsp;</td>
       </tr>
      <% if(helper.profile.getUse(EndEntityProfile.EMAIL,0)){ %>
       <tr id="Row<%=(helper.row++)%2%>">
	 <td align="right" width="<%=ViewEndEntityHelper.columnwidth%>"><%= ejbcawebbean.getText("EMAIL") %></td>
	 <td><% if(helper.userdata.getEmail() != null) out.write(helper.userdata.getEmail()); %>
         </td>
       </tr>
       <% } %>
       <tr id="Row<%=(helper.row++)%2%>">
	 <td align="right" width="<%=ViewEndEntityHelper.columnwidth%>"><%= ejbcawebbean.getText("CERTIFICATEPROFILE") %></td>
	 <td><% if(helper.userdata.getCertificateProfileId() != 0)
                  out.write(rabean.getCertificateProfileName(helper.userdata.getCertificateProfileId())); 
                else out.write(ejbcawebbean.getText("NOCERTIFICATEPROFILEDEFINED")); %>
         </td>
       </tr>
       <tr id="Row<%=(helper.row++)%2%>">
	 <td align="right" width="<%=ViewEndEntityHelper.columnwidth%>"><%= ejbcawebbean.getText("CA") %></td>
	 <td><%= helper.userdata.getCAName()  %>
         </td>
       </tr>
       <tr id="Row<%=(helper.row++)%2%>">
	 <td align="right" width="<%=ViewEndEntityHelper.columnwidth%>"><%= ejbcawebbean.getText("TOKEN") %></td>
         <td>   
            <% for(int i=0; i < helper.tokentexts.length;i++){
                if(helper.tokenids[i] == helper.userdata.getTokenType())
                   if( helper.tokenids[i] > SecConst.TOKEN_SOFT)
                     out.write(helper.tokentexts[i]);
                   else
                     out.write(ejbcawebbean.getText(helper.tokentexts[i]));
              } %>
         </td> 
       </tr>
       <% if(globalconfiguration.getIssueHardwareTokens()){ %>
       <tr id="Row<%=(helper.row++)%2%>">
	 <td align="right" width="<%=ViewEndEntityHelper.columnwidth%>"><%= ejbcawebbean.getText("HARDTOKENISSUER") %></td>
         <td>   
            <% if(helper.userdata.getHardTokenIssuerId() == SecConst.NO_HARDTOKENISSUER)
                 out.write(ejbcawebbean.getText("NONE"));
               else
                 out.write(tokenbean.getHardTokenIssuerAlias(helper.userdata.getHardTokenIssuerId()));
            %>
         </td> 
       </tr>
       <% } 
       if( helper.profile.getUse(EndEntityProfile.ADMINISTRATOR,0) || helper.profile.getUse(EndEntityProfile.KEYRECOVERABLE,0) && globalconfiguration.getEnableKeyRecovery()){
        %>
       <tr id="Row<%=(helper.row++)%2%>">
	 <td align="right" width="<%=ViewEndEntityHelper.columnwidth%>"><%= ejbcawebbean.getText("TYPES") %></td>
	 <td>
         </td>
       </tr>
      <% } if(helper.profile.getUse(EndEntityProfile.ADMINISTRATOR,0)){ %>
    <tr  id="Row<%=(helper.row++)%2%>"> 
      <td  align="right" width="<%=ViewEndEntityHelper.columnwidth%>"> 
        <%= ejbcawebbean.getText("ADMINISTRATOR") %> <br>
      </td>
      <td > 
        <input type="checkbox" name="<%=ViewEndEntityHelper.CHECKBOX_ADMINISTRATOR%>" value="<%=ViewEndEntityHelper.CHECKBOX_VALUE %>" tabindex="12"
                <%if(helper.userdata.getAdministrator())
                   out.write("CHECKED");%> disabled="true"> 
      </td>
    </tr>
      <% } if(helper.profile.getUse(EndEntityProfile.KEYRECOVERABLE,0) && globalconfiguration.getEnableKeyRecovery()){ %>
    <tr  id="Row<%=(helper.row++)%2%>"> 
      <td  align="right" width="<%=helper.columnwidth%>"> 
        <%= ejbcawebbean.getText("KEYRECOVERABLE") %> 
      </td>
      <td> 
        <input type="checkbox" name="<%=ViewEndEntityHelper.CHECKBOX_KEYRECOVERABLE%>" value="<%=ViewEndEntityHelper.CHECKBOX_VALUE %>" tabindex="13"
                <%if(helper.userdata.getKeyRecoverable())
                   out.write("CHECKED");%> disabled="true"> 
      </td>
    </tr>
      <% } if(helper.profile.getUse(EndEntityProfile.SENDNOTIFICATION,0)){ %>
    <tr  id="Row<%=(helper.row++)%2%>"> 
      <td  align="right" width="<%=ViewEndEntityHelper.columnwidth%>"> 
        <%= ejbcawebbean.getText("SENDNOTIFICATION") %> <br>
      </td>
      <td > 
        <input type="checkbox" name="<%=ViewEndEntityHelper.CHECKBOX_SENDNOTIFICATION%>" value="<%=ViewEndEntityHelper.CHECKBOX_VALUE %>" tabindex="12"
                <%if(helper.userdata.getSendNotification())
                   out.write("CHECKED");%> disabled="true"> 
      </td>
    </tr>
      <% } %>
    <tr id="Row<%=(helper.row++)%2%>">
      <td>&nbsp;</td>
      <td>&nbsp;</td>
    </tr> 
    <tr id="Row0">
      <td align="right" width="<%=ViewEndEntityHelper.columnwidth%>"><%= ejbcawebbean.getText("CREATED") %></td>
      <td>
         <%= ejbcawebbean.printDateTime(helper.userdata.getTimeCreated()) %>
       </td>
    </tr> 
    <tr id="Row<%=(helper.row++)%2%>">
      <td align="right" width="<%=ViewEndEntityHelper.columnwidth%>"><%= ejbcawebbean.getText("MODIFIED") %></td>
      <td>
         <%= ejbcawebbean.printDateTime(helper.userdata.getTimeModified()) %>
       </td>
     </tr> 
     <% if(helper.currentuserindex == 0){ %>
    <tr id="Row<%=(helper.row++)%2%>">
      <td align="right" width="<%=ViewEndEntityHelper.columnwidth%>"><%= ejbcawebbean.getText("STATUS") %></td>
      <td>
        <% for(int i=0; i < ViewEndEntityHelper.statusids.length; i++)
             if(helper.userdata.getStatus()==ViewEndEntityHelper.statusids[i])
               out.write(ejbcawebbean.getText(ViewEndEntityHelper.statustexts[i])); %>
       </td>
     </tr> 
     <% } %> 
       <tr id="Row<%=(helper.row++)%2%>">
	 <td width="<%=ViewEndEntityHelper.columnwidth%>">
          <% if(helper.currentuserindex > 0 ){ %>
           <input type="submit" name="<%= ViewEndEntityHelper.BUTTON_PREVIOUS %>" value="<%= ejbcawebbean.getText("VIEWNEWER") %>" tabindex="1">&nbsp;&nbsp;&nbsp;
          <% } %>	 
	 </td>
	 <td>
             <input type="reset" name="<%= ViewEndEntityHelper.BUTTON_CLOSE %>" value="<%= ejbcawebbean.getText("CLOSE") %>" tabindex="20"
                    onClick='self.close()'>
                     <% if((helper.currentuserindex+1) < helper.userdatas.length){ %>
          &nbsp;&nbsp;&nbsp;<input type="submit" name="<%= ViewEndEntityHelper.BUTTON_NEXT %>" value="<%= ejbcawebbean.getText("VIEWOLDER") %>" tabindex="3">
          <% } %>
       </td>
       </tr> 
     </table> 
   </form>
   <p></p>
   <% }
     }
    }
   }%>

</body>
</html>