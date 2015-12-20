<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ page pageEncoding="ISO-8859-1"%>
<% response.setContentType("text/html; charset="+org.ejbca.config.WebConfiguration.getWebContentEncoding()); %>
<%@page errorPage="/errorpage.jsp"  import="org.ejbca.config.GlobalConfiguration, java.math.BigInteger,
                 org.ejbca.core.model.SecConst, org.ejbca.core.model.ra.raadmin.EndEntityProfile,
                 org.ejbca.ui.web.admin.rainterface.ViewEndEntityHelper, org.cesecore.certificates.util.DnComponents,
                 org.cesecore.certificates.endentity.ExtendedInformation, org.apache.commons.lang.time.DateUtils, java.util.Locale,
                 org.ejbca.core.model.ra.ExtendedInformationFields, org.cesecore.certificates.crl.RevokedCertInfo,
                 org.ejbca.core.model.authorization.AccessRulesConstants" %>
<html>
<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />
<jsp:useBean id="rabean" scope="session" class="org.ejbca.ui.web.admin.rainterface.RAInterfaceBean" />
<jsp:useBean id="cabean" scope="session" class="org.ejbca.ui.web.admin.cainterface.CAInterfaceBean" />
<jsp:useBean id="tokenbean" scope="session" class="org.ejbca.ui.web.admin.hardtokeninterface.HardTokenInterfaceBean" />
<jsp:useBean id="viewendentityhelper" scope="session" class="org.ejbca.ui.web.admin.rainterface.ViewEndEntityHelper" />
<jsp:useBean id="editendentitybean" scope="page" class="org.ejbca.ui.web.admin.rainterface.EditEndEntityBean" />
<%! // Declarations
 



%><%
  // Initialize environment.
  GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, AccessRulesConstants.ROLE_ADMINISTRATOR, AccessRulesConstants.REGULAR_VIEWENDENTITY); 
                                            rabean.initialize(request, ejbcawebbean);
                                            cabean.initialize(ejbcawebbean);
                                            if(globalconfiguration.getIssueHardwareTokens())
                                              tokenbean.initialize(request, ejbcawebbean);
  String THIS_FILENAME                    = globalconfiguration.getRaPath()  + "/viewendentity.jsp";

  viewendentityhelper.initialize(ejbcawebbean,rabean,cabean);
  
  viewendentityhelper.parseRequest(request);
  
  viewendentityhelper.row = 0;

    // Initialize EditEndEntityBean
    if (viewendentityhelper.userdata != null) {
        ExtendedInformation userEi = viewendentityhelper.userdata.getExtendedInformation();
        if (userEi == null) {
            userEi = new ExtendedInformation();
        }
        editendentitybean.setExtendedInformation(userEi);
    }
%>
<head>
  <title><c:out value="<%= globalconfiguration.getEjbcaTitle() %>" /></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>" />
  <link rel="shortcut icon" href="<%=ejbcawebbean.getImagefileInfix("favicon.png")%>" type="image/png" />
  <link rel="stylesheet" type="text/css" href="<c:out value='<%=ejbcawebbean.getCssFile() %>' />" />
  <script type="text/javascript" src="<%= globalconfiguration.getAdminWebPath() %>ejbcajslib.js"></script>
</head>

<body class="popup" id="viewendentity">

  <h2><%= ejbcawebbean.getText("VIEWENDENTITY2") %></h2>

  <%if(viewendentityhelper.nouserparameter){%>
  <div class="message alert"><%=ejbcawebbean.getText("YOUMUSTSPECIFYUSERNAME") %></div> 
  <% }else{
       if(viewendentityhelper.userdata == null){%>
  <div class="message alert"><%=ejbcawebbean.getText("ENDENTITYDOESNTEXIST") %></div> 
    <% }else{ 
         if(viewendentityhelper.notauthorized){ %>
  <div class="message alert"><%=ejbcawebbean.getText("NOTAUTHORIZEDTOVIEW") %>></div>   
     <%  }else{
           if(viewendentityhelper.profilenotfound){ %>
         <div class="message alert"><%=ejbcawebbean.getText("CANNOTVIEWUSERPROFREM") %></div>   
        <%  }else{    
         if(viewendentityhelper.currentuserindex == 0){ %>
        	   <div class="message info"><%=ejbcawebbean.getText("CURRENTUSERDATA") %></div> 
       <%}else{ %>
               <div class="message info"><%=ejbcawebbean.getText("HISTORICALUSERDATA") %></div> 
       <% } %>


  <form name="pageuser" action="<%= THIS_FILENAME %>" method="post">
     <input type="hidden" name='<%= ViewEndEntityHelper.ACTION %>' value='<%= ViewEndEntityHelper.ACTION_PAGE%>'>
     <input type="hidden" name='<%= ViewEndEntityHelper.USER_PARAMETER %>' value='<%= java.net.URLEncoder.encode(viewendentityhelper.username,"UTF-8")%>'>

     <table class="view" border="0" cellpadding="0" cellspacing="2" width="100%">

    <!-- ---------- Title -------------------- -->

      <tr id="Row<%=(viewendentityhelper.row++)%2%>" class="title">
	<td align="right" width="<%=ViewEndEntityHelper.columnwidth%>"><strong><%= ejbcawebbean.getText("USERNAME") %></strong></td>
	<td><strong><% if(viewendentityhelper.userdata.getUsername() != null) {%> <c:out value="<%= viewendentityhelper.userdata.getUsername() %>"/><%}%>
        </strong></td>
      </tr>


    <!-- ---------- End-entity information -------------------- -->

     <% if(viewendentityhelper.currentuserindex == 0){ %>
    <tr id="Row<%=(viewendentityhelper.row++)%2%>">
      <td align="right" width="<%=ViewEndEntityHelper.columnwidth%>"><%= ejbcawebbean.getText("STATUS") %></td>
      <td>
        <% for(int i=0; i < ViewEndEntityHelper.statusids.length; i++)
             if(viewendentityhelper.userdata.getStatus()==ViewEndEntityHelper.statusids[i])
               out.write(ejbcawebbean.getText(ViewEndEntityHelper.statustexts[i])); %>
       </td>
     </tr> 
     <% } else { %> 
    <tr id="Row<%=(viewendentityhelper.row++)%2%>">
      <td>&nbsp;</td>
      <td>&nbsp;</td>
    </tr> 
     <% } %> 

    <tr id="Row<%=(viewendentityhelper.row++)%2%>">
      <td align="right" width="<%=ViewEndEntityHelper.columnwidth%>"><%= ejbcawebbean.getText("CREATED") %></td>
      <td>
         <%= ejbcawebbean.formatAsISO8601(viewendentityhelper.userdata.getTimeCreated()) %>
       </td>
    </tr> 

    <tr id="Row<%=(viewendentityhelper.row++)%2%>">
      <td align="right" width="<%=ViewEndEntityHelper.columnwidth%>"><%= ejbcawebbean.getText("MODIFIED") %></td>
      <td>
         <%= ejbcawebbean.formatAsISO8601(viewendentityhelper.userdata.getTimeModified()) %>
       </td>
     </tr> 


    <!-- ---------- Index -------------------- -->

       <tr id="Row<%=(viewendentityhelper.row++)%2%>">
	 <td width="<%=ViewEndEntityHelper.columnwidth%>" style="text-align:right;">
          &nbsp;
          <% if((viewendentityhelper.currentuserindex+1) < viewendentityhelper.userdatas.length){ %>
           <input type="submit" name="<%= ViewEndEntityHelper.BUTTON_VIEW_OLDER %>" value="&lt; <%= ejbcawebbean.getText("VIEWOLDER") %>" tabindex="1">
          <% } %>
	   </td>
	 <td style="text-align:left;">
          <% if(viewendentityhelper.currentuserindex > 0 ){ %>
           <input type="submit" name="<%= ViewEndEntityHelper.BUTTON_VIEW_NEWER %>" value="<%= ejbcawebbean.getText("VIEWNEWER") %> &gt;" tabindex="2">
          <% } %>	 
          &nbsp;
       </td>
       </tr> 


    <!-- ---------- Main -------------------- -->

      <tr id="Row<%=(viewendentityhelper.row++)%2%>">
	<td align="right" width="<%=ViewEndEntityHelper.columnwidth%>"><%= ejbcawebbean.getText("ENDENTITYPROFILE") %></td>
	<td><% if(viewendentityhelper.userdata.getEndEntityProfileId() != 0) {%>
	                <c:out value="<%= rabean.getEndEntityProfileName(viewendentityhelper.userdata.getEndEntityProfileId()) %>"/>
                 <%} else out.write(ejbcawebbean.getText("NOENDENTITYPROFILEDEFINED"));%>
        </td>
      </tr>

      <% if(viewendentityhelper.profile.getUse(EndEntityProfile.CLEARTEXTPASSWORD,0)){ %>
      <tr id="Row<%=(viewendentityhelper.row++)%2%>">
	<td align="right" width="<%=ViewEndEntityHelper.columnwidth%>"><%= ejbcawebbean.getText("USEINBATCH_ABBR") %></td>
	<td><% if(viewendentityhelper.userdata.getClearTextPassword())
                out.write(ejbcawebbean.getText("YES"));
           else out.write(ejbcawebbean.getText("NO"));%>
        </td>
      </tr>
      <% } %>

      <% if(viewendentityhelper.profile.getUse(EndEntityProfile.EMAIL,0)){ %>
       <tr id="Row<%=(viewendentityhelper.row++)%2%>">
	 <td align="right" width="<%=ViewEndEntityHelper.columnwidth%>"><%= ejbcawebbean.getText("EMAIL") %></td>
	 <td><% if(viewendentityhelper.userdata.getEmail() != null) {%><c:out value="<%= viewendentityhelper.userdata.getEmail() %>"/><%}%>
         </td>
       </tr>
       <% } %>


    <!-- ---------- Subject DN -------------------- -->

       <tr id="Row<%=(viewendentityhelper.row++)%2%>" class="section">
	 <td align="right" width="<%=ViewEndEntityHelper.columnwidth%>"><strong><%= ejbcawebbean.getText("CERT_SUBJECTDN") %></strong></td>
	 <td>&nbsp;</td>
       </tr>

      <% int subjectfieldsize = viewendentityhelper.profile.getSubjectDNFieldOrderLength();
         for(int i = 0; i < subjectfieldsize; i++){
        	 viewendentityhelper.fielddata = viewendentityhelper.profile.getSubjectDNFieldsInOrder(i);
        	 viewendentityhelper.fieldvalue = viewendentityhelper.userdata.getSubjectDNField(DnComponents.profileIdToDnId(viewendentityhelper.fielddata[EndEntityProfile.FIELDTYPE]),viewendentityhelper.fielddata[EndEntityProfile.NUMBER]);
         %>
       <tr id="Row<%=(viewendentityhelper.row++)%2%>">
	 <td align="right" width="<%=ViewEndEntityHelper.columnwidth%>"><%= ejbcawebbean.getText(DnComponents.getLanguageConstantFromProfileId(viewendentityhelper.fielddata[EndEntityProfile.FIELDTYPE])) %></td>
	 <td><span class="attribute"><% if(viewendentityhelper.fieldvalue != null) {%><c:out value="<%= viewendentityhelper.fieldvalue %>"/><%}%></span>
         </td>
       </tr>
       <% } %>


    <!-- ---------- Other subject attributes -------------------- -->

       <% if (  viewendentityhelper.profile.getSubjectAltNameFieldOrderLength() > 0
             || viewendentityhelper.profile.getSubjectDirAttrFieldOrderLength() > 0
             ) {
       %> 
       <tr id="Row<%=(viewendentityhelper.row++)%2%>" class="section">
	 <td align="right" width="<%=ViewEndEntityHelper.columnwidth%>"><strong><%= ejbcawebbean.getText("OTHERSUBJECTATTR") %></strong></td>
	 <td>&nbsp;</td>
       </tr>
       <% } %>

       <% subjectfieldsize = viewendentityhelper.profile.getSubjectAltNameFieldOrderLength();
          if(subjectfieldsize > 0){
       %> 
       <tr id="Row<%=(viewendentityhelper.row++)%2%>">
	 <td align="right" width="<%=ViewEndEntityHelper.columnwidth%>"><strong><%= ejbcawebbean.getText("EXT_ABBR_SUBJECTALTNAME") %></strong></td>
	 <td>&nbsp;</td>
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
	 <td><% if(viewendentityhelper.fieldvalue != null) {%> <c:out value="<%= viewendentityhelper.fieldvalue %>"/><%}%> 
         </td>
       </tr>
       <%   }
          } %>

       <%   subjectfieldsize = viewendentityhelper.profile.getSubjectDirAttrFieldOrderLength();
          if(subjectfieldsize > 0){
       %>
       <tr id="Row<%=(viewendentityhelper.row++)%2%>">
	 <td align="right" width="<%=ViewEndEntityHelper.columnwidth%>"><strong><%= ejbcawebbean.getText("EXT_ABBR_SUBJECTDIRATTRS") %></strong></td>
	 <td>&nbsp;</td>
       </tr>
      <% }
         for(int i = 0; i < subjectfieldsize; i++){
        	 viewendentityhelper.fielddata = viewendentityhelper.profile.getSubjectDirAttrFieldsInOrder(i);
            int fieldtype = viewendentityhelper.fielddata[EndEntityProfile.FIELDTYPE];
          	viewendentityhelper.fieldvalue = viewendentityhelper.userdata.getSubjectDirAttributeField(DnComponents.profileIdToDnId(viewendentityhelper.fielddata[EndEntityProfile.FIELDTYPE]),viewendentityhelper.fielddata[EndEntityProfile.NUMBER]);
         %>
       <tr id="Row<%=(viewendentityhelper.row++)%2%>">
	 <td align="right" width="<%=ViewEndEntityHelper.columnwidth%>"><%= ejbcawebbean.getText(DnComponents.getLanguageConstantFromProfileId(viewendentityhelper.fielddata[EndEntityProfile.FIELDTYPE])) %></td>
	 <td><% if(viewendentityhelper.fieldvalue != null) {%> <c:out value="<%= viewendentityhelper.fieldvalue %>"/><%}%> 
         </td>
       </tr>
       <% } %>  


    <!-- ---------- Main certificate data -------------------- -->

       <tr id="Row<%=(viewendentityhelper.row++)%2%>" class="section">
	 <td align="right" width="<%=ViewEndEntityHelper.columnwidth%>"><strong><%= ejbcawebbean.getText("MAINCERTIFICATEDATA") %></strong></td>
	 <td>&nbsp;</td>
       </tr>

       <tr id="Row<%=(viewendentityhelper.row++)%2%>">
	 <td align="right" width="<%=ViewEndEntityHelper.columnwidth%>"><%= ejbcawebbean.getText("CERTIFICATEPROFILE") %></td>
	 <td><% if(viewendentityhelper.userdata.getCertificateProfileId() != 0){%>
                  <c:out value="<%=rabean.getCertificateProfileName(viewendentityhelper.userdata.getCertificateProfileId())%>"/>
                <%} else out.write(ejbcawebbean.getText("NOCERTIFICATEPROFILEDEFINED")); %>
         </td>
       </tr>

       <tr id="Row<%=(viewendentityhelper.row++)%2%>">
	 <td align="right" width="<%=ViewEndEntityHelper.columnwidth%>"><%= ejbcawebbean.getText("CA") %></td>
	 <td><c:out value="<%= viewendentityhelper.userdata.getCAName() %>"/>
         </td>
       </tr>

       <tr id="Row<%=(viewendentityhelper.row++)%2%>">
	 <td align="right" width="<%=ViewEndEntityHelper.columnwidth%>"><%= ejbcawebbean.getText("TOKEN") %></td>
         <td>   
            <% for(int i=0; i < viewendentityhelper.tokentexts.length;i++){
                if(viewendentityhelper.tokenids[i] == viewendentityhelper.userdata.getTokenType())
                   if( viewendentityhelper.tokenids[i] > SecConst.TOKEN_SOFT) {%>
                     <c:out value="<%= viewendentityhelper.tokentexts[i] %>"/>
                   <%} else
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
               else {%>
                 <c:out value="<%= tokenbean.getHardTokenIssuerAlias(viewendentityhelper.userdata.getHardTokenIssuerId()) %>"/>
               <%}
            %>
         </td> 
       </tr>
       <% } %>


    <!-- ---------- Other certificate data -------------------- -->

    <% if (  viewendentityhelper.profile.getUse(EndEntityProfile.CERTSERIALNR, 0)
    	  || viewendentityhelper.profile.getUse(EndEntityProfile.STARTTIME, 0) 
    	  || viewendentityhelper.profile.getUse(EndEntityProfile.ENDTIME, 0)
    	  || viewendentityhelper.profile.getUse(EndEntityProfile.CARDNUMBER, 0)
    	  ) {
        %>
       <tr id="Row<%=(viewendentityhelper.row++)%2%>" class="section">
	 <td align="right" width="<%=ViewEndEntityHelper.columnwidth%>"><strong><%= ejbcawebbean.getText("OTHERCERTIFICATEDATA") %></strong></td>
	 <td>&nbsp;</td>
       </tr>
    <% } %>

	<%{
		final ExtendedInformation ei = viewendentityhelper.userdata.getExtendedInformation();
		final BigInteger oldNr = ei!=null ? ei.certificateSerialNumber() : null;
		final String certSerialNr = oldNr!=null ? oldNr.toString(16) : null;
		if ( certSerialNr!=null ) { %>
			<tr id="Row<%=(viewendentityhelper.row++)%2%>">
			<td align="right" width="<%=ViewEndEntityHelper.columnwidth%>"><%= ejbcawebbean.getText("CERT_SERIALNUMBER") %></td>
			<td><span class="hexa"><c:out value="<%= certSerialNr %>"/></span></td>
			</tr> 
	<%	}
	  } %>

	<%
		String startTime = null;
		String endTime = null;
		if ( viewendentityhelper.profile.getUse(EndEntityProfile.STARTTIME, 0) || viewendentityhelper.profile.getUse(EndEntityProfile.ENDTIME, 0) ) {
			ExtendedInformation ei = viewendentityhelper.userdata.getExtendedInformation();
			if ( ei != null ) {
				startTime = ei.getCustomData(EndEntityProfile.STARTTIME);
				endTime = ei.getCustomData(EndEntityProfile.ENDTIME);
			} 
		} %>
	<% if ( startTime != null ) { %>
    <tr id="Row<%=(viewendentityhelper.row++)%2%>">
		<td align="right" width="<%=ViewEndEntityHelper.columnwidth%>"><%= ejbcawebbean.getText("TIMEOFSTART") %></td>
		<td>
			<%= ejbcawebbean.getISO8601FromImpliedUTCOrRelative(startTime) %>
		</td>
    </tr> 
	<%	} %>
	<% if ( endTime != null ) { %>
    <tr id="Row<%=(viewendentityhelper.row++)%2%>">
		<td align="right" width="<%=ViewEndEntityHelper.columnwidth%>"><%= ejbcawebbean.getText("TIMEOFEND") %></td>
		<td>
			<%= ejbcawebbean.getISO8601FromImpliedUTCOrRelative(endTime) %>
		</td>
    </tr> 
	<%	} %>

      <% if(viewendentityhelper.profile.getUse(EndEntityProfile.CARDNUMBER,0)){ %>
       <tr id="Row<%=(viewendentityhelper.row++)%2%>">
	 <td align="right" width="<%=ViewEndEntityHelper.columnwidth%>"><%= ejbcawebbean.getText("CARDNUMBER") %></td>
	 <td><% if(viewendentityhelper.userdata.getCardNumber() != null) {%><c:out value="<%= viewendentityhelper.userdata.getCardNumber() %>"/><%}%>
         </td>
       </tr>
      <% } %>

      <% if(viewendentityhelper.profile.getUseExtensiondata() || !editendentitybean.getExtensionDataAsMap().isEmpty()){ %>
       <tr id="Row<%=(viewendentityhelper.row++)%2%>">
	 <td align="right" width="<%=ViewEndEntityHelper.columnwidth%>"><%= ejbcawebbean.getText("CERT_EXTENSIONDATA") %></td>
	 <td><table width="100%">
             <c:forEach var="item" items="${editendentitybean.extensionDataAsMap}">
               <tr>
                 <td>
                   <c:out value="${item.key}"/>
                 </td>
                 <td>
                   <c:out value="${item.value}"/>
                 </td>
               </tr>
             </c:forEach>
            </table></td>
       </tr>
      <% } %>

    <!-- ---------- Other data -------------------- -->

    <% if (  viewendentityhelper.profile.getUse(EndEntityProfile.ALLOWEDREQUESTS,0)
      	  ||(viewendentityhelper.profile.getUse(EndEntityProfile.KEYRECOVERABLE,0) && globalconfiguration.getEnableKeyRecovery())
    	  || viewendentityhelper.profile.getUse(EndEntityProfile.ISSUANCEREVOCATIONREASON,0)
    	  || viewendentityhelper.profile.getUse(EndEntityProfile.SENDNOTIFICATION,0)
    	  || viewendentityhelper.profile.getUsePrinting()
    	  ) {
        %>
       <tr id="Row<%=(viewendentityhelper.row++)%2%>" class="section">
	 <td align="right" width="<%=ViewEndEntityHelper.columnwidth%>"><strong><%= ejbcawebbean.getText("OTHERDATA") %></strong></td>
	 <td>&nbsp;</td>
       </tr>
    <% } %>

    <% if(viewendentityhelper.profile.getUse(EndEntityProfile.ALLOWEDREQUESTS,0)){ %>
    <% 
        ExtendedInformation ei = viewendentityhelper.userdata.getExtendedInformation();
        String counter = ei!=null ? ei.getCustomData(ExtendedInformationFields.CUSTOM_REQUESTCOUNTER) : null;
      %>
    <tr  id="Row<%=(viewendentityhelper.row++)%2%>"> 
      <td  align="right" width="<%=ViewEndEntityHelper.columnwidth%>"> 
        <%= ejbcawebbean.getText("ALLOWEDREQUESTS") %> 
      </td>
      <td><% if (counter != null)
                  out.write(counter);
             else out.write("&nbsp;"); %>
      </td>
    </tr>
    <% } %>

      <% if(viewendentityhelper.profile.getUse(EndEntityProfile.KEYRECOVERABLE,0) && globalconfiguration.getEnableKeyRecovery()){ %>
    <tr  id="Row<%=(viewendentityhelper.row++)%2%>"> 
      <td  align="right" width="<%=ViewEndEntityHelper.columnwidth%>"> 
        <%= ejbcawebbean.getText("KEYRECOVERABLE") %> 
      </td>
      <td><% if(viewendentityhelper.userdata.getKeyRecoverable())
                  out.write(ejbcawebbean.getText("YES"));
             else out.write(ejbcawebbean.getText("NO"));%>
      </td>
    </tr>
      <% } %>

        <% int revstatus = RevokedCertInfo.NOT_REVOKED;
           ExtendedInformation revei = viewendentityhelper.userdata.getExtendedInformation();
		   if ( revei != null ) {
 		       String value = revei.getCustomData(ExtendedInformation.CUSTOM_REVOCATIONREASON);
	           if((value != null) && (((String) value).length() > 0)) {
	               revstatus = (Integer.valueOf(value).intValue());
	           }
		   }
        %>
      <% if(viewendentityhelper.profile.getUse(EndEntityProfile.ISSUANCEREVOCATIONREASON,0)){ %>
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
      <% } %>

      <% if(viewendentityhelper.profile.getUse(EndEntityProfile.SENDNOTIFICATION,0)){ %>
    <tr  id="Row<%=(viewendentityhelper.row++)%2%>"> 
      <td  align="right" width="<%=ViewEndEntityHelper.columnwidth%>"> 
        <%= ejbcawebbean.getText("SENDNOTIFICATION") %>
      </td>
      <td><% if(viewendentityhelper.userdata.getSendNotification())
                  out.write(ejbcawebbean.getText("YES"));
             else out.write(ejbcawebbean.getText("NO"));%>
      </td>
    </tr>
      <% } %>

      <% if(viewendentityhelper.profile.getUsePrinting()){ %>
    <tr  id="Row<%=(viewendentityhelper.row++)%2%>"> 
      <td  align="right" width="<%=ViewEndEntityHelper.columnwidth%>"> 
        <%= ejbcawebbean.getText("PRINTUSERDATA") %>
      </td>
      <td><% if(viewendentityhelper.userdata.getPrintUserData())
                  out.write(ejbcawebbean.getText("YES"));
             else out.write(ejbcawebbean.getText("NO"));%>
      </td>
    </tr>
      <% } %>


    <!-- ---------- Actions -------------------- -->

       <tr id="Row<%=(viewendentityhelper.row++)%2%>">
     <td align="right">&nbsp;</td>
	 <td>
             <input type="reset" name="<%= ViewEndEntityHelper.BUTTON_CLOSE %>" value="<%= ejbcawebbean.getText("CLOSE") %>" tabindex="3"
                    onClick='self.close()'>
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
