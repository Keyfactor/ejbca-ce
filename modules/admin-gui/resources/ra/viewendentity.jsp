<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ page pageEncoding="ISO-8859-1"%>
<% response.setContentType("text/html; charset="+org.ejbca.config.WebConfiguration.getWebContentEncoding()); %>
<%@page errorPage="/errorpage.jsp"  import="org.ejbca.core.model.ra.raadmin.GlobalConfiguration, java.math.BigInteger,
                 org.ejbca.core.model.SecConst, org.ejbca.core.model.ra.raadmin.EndEntityProfile,
                 org.ejbca.ui.web.admin.rainterface.ViewEndEntityHelper, org.ejbca.util.dn.DnComponents,
                 org.ejbca.core.model.ra.ExtendedInformation, org.apache.commons.lang.time.FastDateFormat, org.apache.commons.lang.time.DateUtils, java.util.Locale, org.ejbca.core.model.ra.ExtendedInformation, org.ejbca.core.model.ca.crl.RevokedCertInfo" %>
<html>
<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />
<jsp:useBean id="rabean" scope="session" class="org.ejbca.ui.web.admin.rainterface.RAInterfaceBean" />
<jsp:useBean id="cabean" scope="session" class="org.ejbca.ui.web.admin.cainterface.CAInterfaceBean" />
<jsp:useBean id="tokenbean" scope="session" class="org.ejbca.ui.web.admin.hardtokeninterface.HardTokenInterfaceBean" />
<jsp:useBean id="viewendentityhelper" scope="session" class="org.ejbca.ui.web.admin.rainterface.ViewEndEntityHelper" />
<%! // Declarations
 



%><%
  // Initialize environment.
  GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, "/ra_functionality/view_end_entity"); 
                                            rabean.initialize(request, ejbcawebbean);
                                            cabean.initialize(request, ejbcawebbean);
                                            if(globalconfiguration.getIssueHardwareTokens())
                                              tokenbean.initialize(request, ejbcawebbean);
  String THIS_FILENAME                    = globalconfiguration.getRaPath()  + "/viewendentity.jsp";

  viewendentityhelper.initialize(ejbcawebbean,rabean,cabean);
  
  viewendentityhelper.parseRequest(request);

%>
<head>
  <title><%= globalconfiguration.getEjbcaTitle() %></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>" />
  <link rel="shortcut icon" href="<%=ejbcawebbean.getImagefileInfix("favicon.png")%>" type="image/png" />
  <link rel="stylesheet" type="text/css" href="<%= ejbcawebbean.getCssFile() %>" />
  <script type="text/javascript" src="<%= globalconfiguration.getAdminWebPath() %>ejbcajslib.js"></script>
</head>

<body class="popup" id="viewendentity">
  <h2><%= ejbcawebbean.getText("VIEWENDENTITY2") %></h2>
  <%if(viewendentityhelper.nouserparameter){%>
  <div align="center"><h4 id="alert"><%=ejbcawebbean.getText("YOUMUSTSPECIFYUSERNAME") %></h4></div> 
  <% }else{
       if(viewendentityhelper.userdata == null){%>
  <div align="center"><h4 id="alert"><%=ejbcawebbean.getText("ENDENTITYDOESNTEXIST") %></h4></div> 
    <% }else{ 
         if(viewendentityhelper.notauthorized){ %>
  <div align="center"><h4 id="alert"><%=ejbcawebbean.getText("NOTAUTHORIZEDTOVIEW") %></h4></div>   
     <%  }else{
           if(viewendentityhelper.profilenotfound){ %>
         <div align="center"><h4 id="alert"><%=ejbcawebbean.getText("CANNOTVIEWUSERPROFREM") %></h4></div>   
        <%  }else{    
         if(viewendentityhelper.currentuserindex == 0){ %>
        	   <div align="center"><h4><%=ejbcawebbean.getText("CURRENTUSERDATA") %></h4></div> 
       <%}else{ %>
               <div align="center"><h4><%=ejbcawebbean.getText("HISTORICALUSERDATA") %></h4></div> 
       <% } %>
   
  <form name="pageuser" action="<%= THIS_FILENAME %>" method="post">
       <input type="hidden" name='<%= ViewEndEntityHelper.ACTION %>' value='<%= ViewEndEntityHelper.ACTION_PAGE%>'>
     <input type="hidden" name='<%= ViewEndEntityHelper.USER_PARAMETER %>' value='<%= java.net.URLEncoder.encode(viewendentityhelper.username,"UTF-8")%>'>
     <table border="0" cellpadding="0" cellspacing="2" width="400">
      <tr id="Row<%=(viewendentityhelper.row++)%2%>">
	<td align="right" width="<%=ViewEndEntityHelper.columnwidth%>"><%= ejbcawebbean.getText("USERNAME") %></td>
	<td><% if(viewendentityhelper.userdata.getUsername() != null) out.write(viewendentityhelper.userdata.getUsername()); %>
        </td>
      </tr>
      <tr id="Row<%=(viewendentityhelper.row++)%2%>">
	<td align="right" width="<%=ViewEndEntityHelper.columnwidth%>"><%= ejbcawebbean.getText("ENDENTITYPROFILE") %></td>
	<td><% if(viewendentityhelper.userdata.getEndEntityProfileId() != 0)
                    out.write(rabean.getEndEntityProfileName(viewendentityhelper.userdata.getEndEntityProfileId()));
                 else out.write(ejbcawebbean.getText("NOENDENTITYPROFILEDEFINED"));%>
        </td>
      </tr>
      <% if(viewendentityhelper.profile.getUse(EndEntityProfile.CLEARTEXTPASSWORD,0)){ %>
      <tr id="Row<%=(viewendentityhelper.row++)%2%>">
	<td align="right" width="<%=ViewEndEntityHelper.columnwidth%>"><%= ejbcawebbean.getText("USEINBATCH") %></td>
	<td><input type="checkbox" name="<%= ViewEndEntityHelper.CHECKBOX_CLEARTEXTPASSWORD %>" value="<%= ViewEndEntityHelper.CHECKBOX_VALUE %>" disabled="true"
            <% if(viewendentityhelper.userdata.getClearTextPassword())
                   out.write("CHECKED");%>>
        </td>
      </tr>
      <% } %>
      <tr id="Row<%=(viewendentityhelper.row++)%2%>">
      <td>&nbsp;</td>
      <td>&nbsp;</td>
      </tr> 
       <tr id="Row<%=(viewendentityhelper.row++)%2%>">
	 <td align="right" width="<%=ViewEndEntityHelper.columnwidth%>"><%= ejbcawebbean.getText("CERT_SUBJECTDN") %></td>
	 <td>
         </td>
       </tr>
      <% int subjectfieldsize = viewendentityhelper.profile.getSubjectDNFieldOrderLength();
         for(int i = 0; i < subjectfieldsize; i++){
        	 viewendentityhelper.fielddata = viewendentityhelper.profile.getSubjectDNFieldsInOrder(i);
        	 viewendentityhelper.fieldvalue = viewendentityhelper.userdata.getSubjectDNField(DnComponents.profileIdToDnId(viewendentityhelper.fielddata[EndEntityProfile.FIELDTYPE]),viewendentityhelper.fielddata[EndEntityProfile.NUMBER]);
         %>
       <tr id="Row<%=(viewendentityhelper.row++)%2%>">
	 <td align="right" width="<%=ViewEndEntityHelper.columnwidth%>"><%= ejbcawebbean.getText(DnComponents.getLanguageConstantFromProfileId(viewendentityhelper.fielddata[EndEntityProfile.FIELDTYPE])) %></td>
	 <td><% if(viewendentityhelper.fieldvalue != null) out.write(viewendentityhelper.fieldvalue); %> 
         </td>
       </tr>
       <% } 
          subjectfieldsize = viewendentityhelper.profile.getSubjectAltNameFieldOrderLength();
          if(subjectfieldsize > 0){
       %> 
       <tr id="Row<%=(viewendentityhelper.row++)%2%>">
         <td>&nbsp;</td>
         <td>&nbsp;</td>
       </tr>
       <tr id="Row<%=(viewendentityhelper.row++)%2%>">
	 <td align="right" width="<%=ViewEndEntityHelper.columnwidth%>"><%= ejbcawebbean.getText("SUBJECTALTNAMEFIELDS") %></td>
	 <td>
         </td>
       </tr>
      <% }
         for(int i = 0; i < subjectfieldsize; i++){
        	 viewendentityhelper.fielddata = viewendentityhelper.profile.getSubjectAltNameFieldsInOrder(i);
            int fieldtype = viewendentityhelper.fielddata[EndEntityProfile.FIELDTYPE];
            if(EndEntityProfile.isFieldImplemented(fieldtype)){
            	viewendentityhelper.fieldvalue = viewendentityhelper.userdata.getSubjectAltNameField(DnComponents.profileIdToDnId(viewendentityhelper.fielddata[EndEntityProfile.FIELDTYPE]),viewendentityhelper.fielddata[EndEntityProfile.NUMBER]);
         %>
       <tr id="Row<%=(viewendentityhelper.row++)%2%>">
	 <td align="right" width="<%=ViewEndEntityHelper.columnwidth%>"><%= ejbcawebbean.getText(DnComponents.getLanguageConstantFromProfileId(viewendentityhelper.fielddata[EndEntityProfile.FIELDTYPE])) %></td>
	 <td><% if(viewendentityhelper.fieldvalue != null) out.write(viewendentityhelper.fieldvalue); %> 
         </td>
       </tr>
       <%   }
          }
          subjectfieldsize = viewendentityhelper.profile.getSubjectDirAttrFieldOrderLength();
          if(subjectfieldsize > 0){
       %>
       <tr id="Row<%=(viewendentityhelper.row++)%2%>">
         <td>&nbsp;</td>
         <td>&nbsp;</td>
       </tr>
       <tr id="Row<%=(viewendentityhelper.row++)%2%>">
	 <td align="right" width="<%=ViewEndEntityHelper.columnwidth%>"><%= ejbcawebbean.getText("SUBJECTDIRATTRFIELDS") %></td>
	 <td>
         </td>
       </tr>
      <% }
         for(int i = 0; i < subjectfieldsize; i++){
        	 viewendentityhelper.fielddata = viewendentityhelper.profile.getSubjectDirAttrFieldsInOrder(i);
            int fieldtype = viewendentityhelper.fielddata[EndEntityProfile.FIELDTYPE];
          	viewendentityhelper.fieldvalue = viewendentityhelper.userdata.getSubjectDirAttributeField(DnComponents.profileIdToDnId(viewendentityhelper.fielddata[EndEntityProfile.FIELDTYPE]),viewendentityhelper.fielddata[EndEntityProfile.NUMBER]);
         %>
       <tr id="Row<%=(viewendentityhelper.row++)%2%>">
	 <td align="right" width="<%=ViewEndEntityHelper.columnwidth%>"><%= ejbcawebbean.getText(DnComponents.getLanguageConstantFromProfileId(viewendentityhelper.fielddata[EndEntityProfile.FIELDTYPE])) %></td>
	 <td><% if(viewendentityhelper.fieldvalue != null) out.write(viewendentityhelper.fieldvalue); %> 
         </td>
       </tr>
       <% } %>  
          
          
       <tr id="Row<%=(viewendentityhelper.row++)%2%>">
	 <td>&nbsp;</td>
	 <td>&nbsp;</td>
       </tr>
      <% if(viewendentityhelper.profile.getUse(EndEntityProfile.EMAIL,0)){ %>
       <tr id="Row<%=(viewendentityhelper.row++)%2%>">
	 <td align="right" width="<%=ViewEndEntityHelper.columnwidth%>"><%= ejbcawebbean.getText("EMAIL") %></td>
	 <td><% if(viewendentityhelper.userdata.getEmail() != null) out.write(viewendentityhelper.userdata.getEmail()); %>
         </td>
       </tr>
       <% } %>
       <tr id="Row<%=(viewendentityhelper.row++)%2%>">
	 <td align="right" width="<%=ViewEndEntityHelper.columnwidth%>"><%= ejbcawebbean.getText("CERTIFICATEPROFILE") %></td>
	 <td><% if(viewendentityhelper.userdata.getCertificateProfileId() != 0)
                  out.write(rabean.getCertificateProfileName(viewendentityhelper.userdata.getCertificateProfileId())); 
                else out.write(ejbcawebbean.getText("NOCERTIFICATEPROFILEDEFINED")); %>
         </td>
       </tr>
       
        <% int revstatus = RevokedCertInfo.NOT_REVOKED;
           ExtendedInformation revei = viewendentityhelper.userdata.getExtendedInformation();
		   if ( revei != null ) {
 		       String value = revei.getCustomData(ExtendedInformation.CUSTOM_REVOCATIONREASON);
	           if((value != null) && (((String) value).length() > 0)) {
	               revstatus = (Integer.valueOf(value).intValue());
	           }
		   }
        %>
       <tr id="Row<%=(viewendentityhelper.row++)%2%>">
    	 <td align="right" width="<%=ViewEndEntityHelper.columnwidth%>"><%= ejbcawebbean.getText("ISSUANCEREVOCATIONREASON") %></td>
	     <td>
	     <% if(revstatus == RevokedCertInfo.NOT_REVOKED) {%><%= ejbcawebbean.getText("ACTIVE") %><%}%>
	     <% if(revstatus == RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD) {%><%= ejbcawebbean.getText("SUSPENDED") %>: <%= ejbcawebbean.getText("REV_CERTIFICATEHOLD")  %><%}%>
	     <% if(revstatus == RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED) {%><%= ejbcawebbean.getText("REVOKED") %>: <%= ejbcawebbean.getText("REV_UNSPECIFIED")  %><%}%>
	     <% if(revstatus == RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE) {%><%= ejbcawebbean.getText("REVOKED") %>: <%= ejbcawebbean.getText("REV_KEYCOMPROMISE")  %><%}%>
	     <% if(revstatus == RevokedCertInfo.REVOCATION_REASON_CACOMPROMISE) {%><%= ejbcawebbean.getText("REVOKED") %>: <%= ejbcawebbean.getText("REV_CACOMPROMISE")  %><%}%>
	     <% if(revstatus == RevokedCertInfo.REVOCATION_REASON_AFFILIATIONCHANGED) {%><%= ejbcawebbean.getText("REVOKED") %>: <%= ejbcawebbean.getText("REV_AFFILIATIONCHANGED")  %><%}%>
	     <% if(revstatus == RevokedCertInfo.REVOCATION_REASON_SUPERSEDED) {%><%= ejbcawebbean.getText("REVOKED") %>: <%= ejbcawebbean.getText("REV_SUPERSEDED")  %><%}%>
	     <% if(revstatus == RevokedCertInfo.REVOCATION_REASON_CESSATIONOFOPERATION) {%><%= ejbcawebbean.getText("REVOKED") %>: <%= ejbcawebbean.getText("REV_CESSATIONOFOPERATION")  %><%}%>
	     <% if(revstatus == RevokedCertInfo.REVOCATION_REASON_PRIVILEGESWITHDRAWN) {%><%= ejbcawebbean.getText("REVOKED") %>: <%= ejbcawebbean.getText("REV_PRIVILEGEWITHDRAWN")  %><%}%>
	     <% if(revstatus == RevokedCertInfo.REVOCATION_REASON_AACOMPROMISE) {%><%= ejbcawebbean.getText("REVOKED") %>: <%= ejbcawebbean.getText("REV_AACOMPROMISE")  %><%}%>
         </td>
       </tr>
       
       
       <tr id="Row<%=(viewendentityhelper.row++)%2%>">
	 <td align="right" width="<%=ViewEndEntityHelper.columnwidth%>"><%= ejbcawebbean.getText("CA") %></td>
	 <td><%= viewendentityhelper.userdata.getCAName()  %>
         </td>
       </tr>
       <tr id="Row<%=(viewendentityhelper.row++)%2%>">
	 <td align="right" width="<%=ViewEndEntityHelper.columnwidth%>"><%= ejbcawebbean.getText("TOKEN") %></td>
         <td>   
            <% for(int i=0; i < viewendentityhelper.tokentexts.length;i++){
                if(viewendentityhelper.tokenids[i] == viewendentityhelper.userdata.getTokenType())
                   if( viewendentityhelper.tokenids[i] > SecConst.TOKEN_SOFT)
                     out.write(viewendentityhelper.tokentexts[i]);
                   else
                     out.write(ejbcawebbean.getText(viewendentityhelper.tokentexts[i]));
              } %>
         </td> 
       </tr>
       <% if(globalconfiguration.getIssueHardwareTokens()){ %>
       <tr id="Row<%=(viewendentityhelper.row++)%2%>">
	 <td align="right" width="<%=ViewEndEntityHelper.columnwidth%>"><%= ejbcawebbean.getText("HARDTOKENISSUER") %></td>
         <td>   
            <% if(viewendentityhelper.userdata.getHardTokenIssuerId() == SecConst.NO_HARDTOKENISSUER)
                 out.write(ejbcawebbean.getText("NONE"));
               else
                 out.write(tokenbean.getHardTokenIssuerAlias(viewendentityhelper.userdata.getHardTokenIssuerId()));
            %>
         </td> 
       </tr>
       <% } 
       if( (viewendentityhelper.profile.getUse(EndEntityProfile.KEYRECOVERABLE,0) && globalconfiguration.getEnableKeyRecovery())
    	  || viewendentityhelper.profile.getUse(EndEntityProfile.SENDNOTIFICATION,0) || viewendentityhelper.profile.getUsePrinting() ){
        %>
       <tr id="Row<%=(viewendentityhelper.row++)%2%>">
	 <td align="right" width="<%=ViewEndEntityHelper.columnwidth%>"><%= ejbcawebbean.getText("OTHERDATA") %></td>
	 <td>
         </td>
       </tr>
      <% } if(viewendentityhelper.profile.getUse(EndEntityProfile.KEYRECOVERABLE,0) && globalconfiguration.getEnableKeyRecovery()){ %>
    <tr  id="Row<%=(viewendentityhelper.row++)%2%>"> 
      <td  align="right" width="<%=viewendentityhelper.columnwidth%>"> 
        <%= ejbcawebbean.getText("KEYRECOVERABLE") %> 
      </td>
      <td> 
        <input type="checkbox" name="<%=ViewEndEntityHelper.CHECKBOX_KEYRECOVERABLE%>" value="<%=ViewEndEntityHelper.CHECKBOX_VALUE %>" tabindex="13"
                <%if(viewendentityhelper.userdata.getKeyRecoverable())
                   out.write("CHECKED");%> disabled="true"> 
      </td>
    </tr>
      <%} if(viewendentityhelper.profile.getUse(EndEntityProfile.CARDNUMBER,0)){ %>
       <tr id="Row<%=(viewendentityhelper.row++)%2%>">
	 <td align="right" width="<%=ViewEndEntityHelper.columnwidth%>"><%= ejbcawebbean.getText("CARDNUMBER") %></td>
	 <td><% if(viewendentityhelper.userdata.getCardNumber() != null) out.write(viewendentityhelper.userdata.getCardNumber()); %>
	 <td><% if(viewendentityhelper.userdata.getEmail() != null) out.write(viewendentityhelper.userdata.getEmail()); %>

         </td>
       </tr>

      <% } if(viewendentityhelper.profile.getUse(EndEntityProfile.SENDNOTIFICATION,0)){ %>
    <tr  id="Row<%=(viewendentityhelper.row++)%2%>"> 
      <td  align="right" width="<%=ViewEndEntityHelper.columnwidth%>"> 
        <%= ejbcawebbean.getText("SENDNOTIFICATION") %>
      </td>
      <td > 
        <input type="checkbox" name="<%=ViewEndEntityHelper.CHECKBOX_SENDNOTIFICATION%>" value="<%=ViewEndEntityHelper.CHECKBOX_VALUE %>" tabindex="12"
                <%if(viewendentityhelper.userdata.getSendNotification())
                   out.write("CHECKED");%> disabled="true"> 
      </td>
    </tr>
      <% } if(viewendentityhelper.profile.getUsePrinting()){ %>
    <tr  id="Row<%=(viewendentityhelper.row++)%2%>"> 
      <td  align="right" width="<%=ViewEndEntityHelper.columnwidth%>"> 
        <%= ejbcawebbean.getText("PRINTUSERDATA") %>
      </td>
      <td > 
        <input type="checkbox" name="<%=ViewEndEntityHelper.CHECKBOX_PRINT%>" value="<%=ViewEndEntityHelper.CHECKBOX_VALUE %>" tabindex="12"
                <%if(viewendentityhelper.userdata.getPrintUserData())
                   out.write("CHECKED");%> disabled="true"> 
      </td>
    </tr>
      <% } %>
	<%
		String startTime = null;
		String endTime = null;
		if ( viewendentityhelper.profile.getUse(EndEntityProfile.STARTTIME, 0) || viewendentityhelper.profile.getUse(EndEntityProfile.ENDTIME, 0) ) {
			ExtendedInformation ei = viewendentityhelper.userdata.getExtendedInformation();
			if ( ei != null ) {
				startTime = ei.getCustomData(EndEntityProfile.STARTTIME);
				endTime = ei.getCustomData(EndEntityProfile.ENDTIME);
			} 
		} if ( startTime != null || endTime != null ) { %>
			<tr id="Row<%=(viewendentityhelper.row++)%2%>"><td>&nbsp;</td><td>&nbsp;</td></tr>
	<%	} if ( startTime != null ) { %>
    <tr id="Row<%=(viewendentityhelper.row++)%2%>">
		<td align="right" width="<%=ViewEndEntityHelper.columnwidth%>"><%= ejbcawebbean.getText("TIMEOFSTART") %></td>
		<td>
		<%	if ( !startTime.matches("^\\d+:\\d?\\d:\\d?\\d$") ) { %>		
				<% String[] dp = {"yyyy-MM-dd HH:mm"};
					ejbcawebbean.printDateTime(DateUtils.parseDate(startTime, dp)); %>
		<%	} else { %>
				<%= startTime %>
		<%	} %>
		</td>
    </tr> 
	<%	} if ( endTime != null ) { %>
    <tr id="Row<%=(viewendentityhelper.row++)%2%>">
		<td align="right" width="<%=ViewEndEntityHelper.columnwidth%>"><%= ejbcawebbean.getText("TIMEOFEND") %></td>
		<td>
		<%	if ( !endTime.matches("^\\d+:\\d?\\d:\\d?\\d$") ) { %>
				<%  String[] dp = {"yyyy-MM-dd HH:mm"};
					ejbcawebbean.printDateTime(DateUtils.parseDate(endTime, dp)); %>
		<%	} else { %>
				<%= endTime %>
		<%	} %>
		</td>
    </tr> 
	<%	} %>
	<%{
		final ExtendedInformation ei = viewendentityhelper.userdata.getExtendedInformation();
		final BigInteger oldNr = ei!=null ? ei.certificateSerialNumber() : null;
		final String certSerialNr = oldNr!=null ? oldNr.toString(16) : null;
		if ( certSerialNr!=null ) { %>
			<tr id="Row<%=(viewendentityhelper.row++)%2%>">
			<td align="right" width="<%=ViewEndEntityHelper.columnwidth%>"><%= ejbcawebbean.getText("CERT_SERIALNUMBER_HEXA") %></td>
			<td><%= certSerialNr %></td>
			</tr> 
	<%	} }%>
    <tr id="Row<%=(viewendentityhelper.row++)%2%>">
      <td>&nbsp;</td>
      <td>&nbsp;</td>
    </tr> 
    <tr id="Row<%=(viewendentityhelper.row++)%2%>">
      <td align="right" width="<%=ViewEndEntityHelper.columnwidth%>"><%= ejbcawebbean.getText("CREATED") %></td>
      <td>
         <%= ejbcawebbean.printDateTime(viewendentityhelper.userdata.getTimeCreated()) %>
       </td>
    </tr> 
    <tr id="Row<%=(viewendentityhelper.row++)%2%>">
      <td align="right" width="<%=ViewEndEntityHelper.columnwidth%>"><%= ejbcawebbean.getText("MODIFIED") %></td>
      <td>
         <%= ejbcawebbean.printDateTime(viewendentityhelper.userdata.getTimeModified()) %>
       </td>
     </tr> 
     <% if(viewendentityhelper.currentuserindex == 0){ %>
    <tr id="Row<%=(viewendentityhelper.row++)%2%>">
      <td align="right" width="<%=ViewEndEntityHelper.columnwidth%>"><%= ejbcawebbean.getText("STATUS") %></td>
      <td>
        <% for(int i=0; i < ViewEndEntityHelper.statusids.length; i++)
             if(viewendentityhelper.userdata.getStatus()==ViewEndEntityHelper.statusids[i])
               out.write(ejbcawebbean.getText(ViewEndEntityHelper.statustexts[i])); %>
       </td>
     </tr> 
     <% } %> 
       <tr id="Row<%=(viewendentityhelper.row++)%2%>">
	 <td width="<%=ViewEndEntityHelper.columnwidth%>">
          <% if(viewendentityhelper.currentuserindex > 0 ){ %>
           <input type="submit" name="<%= ViewEndEntityHelper.BUTTON_PREVIOUS %>" value="<%= ejbcawebbean.getText("VIEWNEWER") %>" tabindex="1">&nbsp;&nbsp;&nbsp;
          <% } %>	 
	 </td>
	 <td>
             <input type="reset" name="<%= ViewEndEntityHelper.BUTTON_CLOSE %>" value="<%= ejbcawebbean.getText("CLOSE") %>" tabindex="20"
                    onClick='self.close()'>
                     <% if((viewendentityhelper.currentuserindex+1) < viewendentityhelper.userdatas.length){ %>
          &nbsp;&nbsp;&nbsp;<input type="submit" name="<%= ViewEndEntityHelper.BUTTON_NEXT %>" value="<%= ejbcawebbean.getText("VIEWOLDER") %>" tabindex="3">
          <% } %>
       </td>
       </tr> 
     </table> 
   </form>

   <% }
     }
    }
   }%>

</body>
</html>
