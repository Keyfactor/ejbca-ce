<%               
  CertificateProfile certificateprofiledata = cabean.getCertificateProfile(certprofile.trim());
 
  String[] TYPE_NAMES = {"ENDENTITY", "CA", "ROOTCA"};
  int[] TYPE_IDS = {SecConst.CERTTYPE_ENDENTITY,SecConst.CERTTYPE_CA , SecConst.CERTTYPE_ROOTCA};
%>
<SCRIPT language="JavaScript">
<!--  

function checkusefield(usefield, criticalfield){
  var usebox = eval("document.editcertificateprofile." + usefield);
  var cribox = eval("document.editcertificateprofile." + criticalfield);
  if(usebox.checked){
    cribox.disabled = false;
  }
  else{
    cribox.checked=false;
    cribox.disabled = true;
  }
}

function checkusecrldisturifield(){
  if(document.editcertificateprofile.<%=CHECKBOX_CRLDISTRIBUTIONPOINT %>.checked){
    document.editcertificateprofile.<%= CHECKBOX_CRLDISTRIBUTIONPOINTCRITICAL %>.disabled = false;
    document.editcertificateprofile.<%= TEXTFIELD_CRLDISTURI %>.disabled = false;
    document.editcertificateprofile.<%= TEXTFIELD_CRLDISTURI %>.value = "<%= globalconfiguration.getStandardCRLDistributionPointURI() %>";
  }
  else{
    document.editcertificateprofile.<%= CHECKBOX_CRLDISTRIBUTIONPOINTCRITICAL %>.disabled = true;
    document.editcertificateprofile.<%= CHECKBOX_CRLDISTRIBUTIONPOINTCRITICAL %>.checked = false;
    document.editcertificateprofile.<%= TEXTFIELD_CRLDISTURI %>.disabled = true;
    document.editcertificateprofile.<%= TEXTFIELD_CRLDISTURI %>.value = "";
  }

}

function checkusecertificatepoliciesfield(){
  if(document.editcertificateprofile.<%=CHECKBOX_USECERTIFICATEPOLICIES %>.checked){
    document.editcertificateprofile.<%= CHECKBOX_CERTIFICATEPOLICIESCRITICAL %>.disabled = false;
    document.editcertificateprofile.<%= TEXTFIELD_CERTIFICATEPOLICYID %>.disabled = false;
    document.editcertificateprofile.<%= TEXTFIELD_CERTIFICATEPOLICYID %>.value = "";
  }
  else{
    document.editcertificateprofile.<%= CHECKBOX_CERTIFICATEPOLICIESCRITICAL %>.disabled = true;
    document.editcertificateprofile.<%= CHECKBOX_CERTIFICATEPOLICIESCRITICAL %>.checked = false;
    document.editcertificateprofile.<%= TEXTFIELD_CERTIFICATEPOLICYID %>.disabled = true;
    document.editcertificateprofile.<%= TEXTFIELD_CERTIFICATEPOLICYID %>.value = "";
  }
}

function checkuseextendedkeyusagefield(){
  if(document.editcertificateprofile.<%=CHECKBOX_USEEXTENDEDKEYUSAGE %>.checked){
    document.editcertificateprofile.<%= SELECT_EXTENDEDKEYUSAGE %>.disabled = false;
  }
  else{
    document.editcertificateprofile.<%= SELECT_EXTENDEDKEYUSAGE %>.disabled = true;
  }
}


function checkallfields(){
    var illegalfields = 0;

    if(!checkfieldfordecimalnumbers("document.editcertificateprofile.<%=TEXTFIELD_VALIDITY%>","<%= ejbcawebbean.getText("ONLYDECNUMBERSINVALIDITY") %>"))
      illegalfields++;
    
    var availablebitlengths = document.editcertificateprofile.<%= SELECT_AVAILABLEBITLENGTHS%>.options;
    var selected = 0;
    for(var i=0; i < availablebitlengths.length; i++){
      if(availablebitlengths[i].selected==true)
        selected++; 
    }

    if(selected == 0){
      alert("<%=  ejbcawebbean.getText("ONEAVAILABLEBITLENGTH") %>");
      illegalfields++; 
    }
   
     return illegalfields == 0;  
   } 
-->

</SCRIPT>
<div align="center"> 
  <h2><%= ejbcawebbean.getText("EDITCERTIFICATEPROFILE") %><br>
  </h2>
  <h3><%= ejbcawebbean.getText("CERTIFICATEPROFILE")+ " : " + certprofile %> </h3>
</div>
<form name="editcertificateprofile" method="post" action="<%=THIS_FILENAME %>">
  <input type="hidden" name='<%= ACTION %>' value='<%=ACTION_EDIT_CERTIFICATEPROFILE %>'>
  <input type="hidden" name='<%= HIDDEN_CERTIFICATEPROFILENAME %>' value='<%=certprofile %>'>
  <table width="100%" border="0" cellspacing="3" cellpadding="3">
    <tr id="Row0"> 
      <td width="50%" valign="top"> 
        <div align="left"> 
          <h3>&nbsp;</h3>
        </div>
      </td>
      <td width="50%" valign="top"> 
        <div align="right">
        <A href="<%=THIS_FILENAME %>"><u><%= ejbcawebbean.getText("BACKTOCERTIFICATEPROFILES") %></u></A>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
        <A  onclick='displayHelpWindow("<%= ejbcawebbean.getHelpfileInfix("ca_help.html") + "#certificateprofiles"%>")'>
        <u><%= ejbcawebbean.getText("HELP") %></u> </A></div>
      </td>
    </tr>
    <tr  id="Row0"> 
      <td width="50%"  align="right"> 
        <%= ejbcawebbean.getText("VALIDITY") %> <br>&nbsp;
      </td>
      <td width="50%"> 
        <input type="text" name="<%=TEXTFIELD_VALIDITY%>" size="5" maxlength="255" 
           value="<%= certificateprofiledata.getValidity()  %>"><br>
      </td>
    <tr  id="Row1"> 
      <td width="50%"  align="right"> 
        <%= ejbcawebbean.getText("USEBASICCONSTRAINTS") %> <br>  <%= ejbcawebbean.getText("BASICCONSTRAINTSCRITICAL") %>

      </td>
      <td width="50%">
           <input type="checkbox" name="<%=CHECKBOX_BASICCONSTRAINTS %>"   onClick="checkusefield('<%=CHECKBOX_BASICCONSTRAINTS %>', '<%=CHECKBOX_BASICCONSTRAINTSCRITICAL %>')" value="<%=CHECKBOX_VALUE %>" 
           <% if(certificateprofiledata.getUseBasicConstraints()) 
                 out.write("CHECKED");
           %>> <br> 
          <input type="checkbox" name="<%=CHECKBOX_BASICCONSTRAINTSCRITICAL %>" value="<%=CHECKBOX_VALUE %>" 
           <%
               if(!certificateprofiledata.getUseBasicConstraints())
                 out.write(" disabled ");  
               else
               if(certificateprofiledata.getBasicConstraintsCritical())
                 out.write("CHECKED");
           %>> 
      </td>
    <tr  id="Row0"> 
      <td width="50%"  align="right"> 
        <%= ejbcawebbean.getText("USEKEYUSAGE") %> <br>  <%= ejbcawebbean.getText("KEYUSAGECRITICAL") %>

      </td>
      <td width="50%">
           <input type="checkbox" name="<%=CHECKBOX_KEYUSAGE %>" onClick="checkusefield('<%=CHECKBOX_KEYUSAGE %>', '<%=CHECKBOX_KEYUSAGECRITICAL %>')" value="<%=CHECKBOX_VALUE %>" 
           <% if(certificateprofiledata.getUseKeyUsage())
                 out.write("CHECKED");
           %>> <br> 
          <input type="checkbox" name="<%=CHECKBOX_KEYUSAGECRITICAL %>" value="<%=CHECKBOX_VALUE %>" 
           <%
               if(!certificateprofiledata.getUseKeyUsage())
                 out.write(" disabled ");  
               else
               if(certificateprofiledata.getKeyUsageCritical())
                 out.write("CHECKED");
           %>> 
      </td>
    <tr  id="Row1"> 
      <td width="50%"  align="right"> 
        <%= ejbcawebbean.getText("SUBJECTKEYID") %> <br>  <%= ejbcawebbean.getText("SUBJECTKEYIDCRITICAL") %>

      </td>
      <td width="50%">
           <input type="checkbox" name="<%=CHECKBOX_SUBJECTKEYIDENTIFIER %>" onClick="checkusefield('<%=CHECKBOX_SUBJECTKEYIDENTIFIER %>', '<%=CHECKBOX_SUBJECTKEYIDENTIFIERCRITICAL %>')" value="<%=CHECKBOX_VALUE %>" 
           <% if(certificateprofiledata.getUseSubjectKeyIdentifier())
                 out.write("CHECKED");
           %>> <br> 
          <input type="checkbox" name="<%=CHECKBOX_SUBJECTKEYIDENTIFIERCRITICAL %>" value="<%=CHECKBOX_VALUE %>" 
           <%
             if(!certificateprofiledata.getUseSubjectKeyIdentifier())
                 out.write(" disabled "); 
              else
              if(certificateprofiledata.getSubjectKeyIdentifierCritical())
                 out.write("CHECKED");
           %>> 
      </td>
    </tr>
    <tr  id="Row0"> 
      <td width="50%"  align="right"> 
         <%= ejbcawebbean.getText("AUTHORITYKEYID") %> <br> <%= ejbcawebbean.getText("AUTHORITYKEYIDCRITICAL") %> 
      </td>
      <td width="50%">
           <input type="checkbox" name="<%=CHECKBOX_AUTHORITYKEYIDENTIFIER %>" onClick="checkusefield('<%=CHECKBOX_AUTHORITYKEYIDENTIFIER %>', '<%=CHECKBOX_AUTHORITYKEYIDENTIFIERCRITICAL %>')" value="<%=CHECKBOX_VALUE %>" 
           <% if(certificateprofiledata.getUseAuthorityKeyIdentifier())
                 out.write("CHECKED");
           %>> <br> 
          <input type="checkbox" name="<%=CHECKBOX_AUTHORITYKEYIDENTIFIERCRITICAL %>" value="<%=CHECKBOX_VALUE %>" 
           <%
             if(!certificateprofiledata.getUseAuthorityKeyIdentifier())
                 out.write(" disabled ");  
             else
             if(certificateprofiledata.getAuthorityKeyIdentifierCritical())
                 out.write("CHECKED");
           %>> 
      </td>
    </tr>
    <tr  id="Row1"> 
      <td width="50%"  align="right"> 
        <%= ejbcawebbean.getText("SUBJECTALTNAME") %> <br>  <%= ejbcawebbean.getText("SUBJECTALTNAMECRITICAL") %>

      </td>
      <td width="50%">
           <input type="checkbox" name="<%=CHECKBOX_SUBJECTALTERNATIVENAME %>" onClick="checkusefield('<%=CHECKBOX_SUBJECTALTERNATIVENAME %>', '<%=CHECKBOX_SUBJECTALTERNATIVENAMECRITICAL %>')" value="<%=CHECKBOX_VALUE %>" 
           <% if(certificateprofiledata.getUseSubjectAlternativeName())
                 out.write("CHECKED");
           %>> <br> 
          <input type="checkbox" name="<%=CHECKBOX_SUBJECTALTERNATIVENAMECRITICAL %>" value="<%=CHECKBOX_VALUE %>" 
           <% 
             if(!certificateprofiledata.getUseSubjectAlternativeName())
                 out.write(" disabled "); 
              else
              if(certificateprofiledata.getSubjectAlternativeNameCritical())
                 out.write("CHECKED");
           %>> 
      </td>
    </tr>
    <tr  id="Row0"> 
      <td width="50%"  align="right"> 
        <%= ejbcawebbean.getText("CRLDISTPOINT") %> <br>  <%= ejbcawebbean.getText("CRLDISTPOINTCRITICAL") %> <br> <%= ejbcawebbean.getText("CRLDISTPOINTURI") %>

      </td>
      <td width="50%">
           <input type="checkbox" name="<%=CHECKBOX_CRLDISTRIBUTIONPOINT %>" onClick="checkusecrldisturifield()" value="<%=CHECKBOX_VALUE %>" 
           <% if(certificateprofiledata.getUseCRLDistributionPoint())
                 out.write("CHECKED");
           %>> <br> 
          <input type="checkbox" name="<%=CHECKBOX_CRLDISTRIBUTIONPOINTCRITICAL %>" value="<%=CHECKBOX_VALUE %>" 
           <%
               if(!certificateprofiledata.getUseCRLDistributionPoint())
                 out.write(" disabled "); 
               else
                 if(certificateprofiledata.getCRLDistributionPointCritical())
                 out.write("CHECKED");
           %>> <br> 
           <input type="text" name="<%=TEXTFIELD_CRLDISTURI%>" size="60" maxlength="255" 
           <%       if(!certificateprofiledata.getUseCRLDistributionPoint())
                      out.write(" disabled "); 
                    else 
                      if(!certificateprofiledata.getCRLDistributionPointURI().equals(""))
                       out.write(" value=\"" + certificateprofiledata.getCRLDistributionPointURI() + "\""); 
                      else
                       out.write(" value=\"" + globalconfiguration.getStandardCRLDistributionPointURI()+ "\"");%>>
      </td>
    </tr>
    <tr  id="Row1"> 
      <td width="50%"  align="right"> 
        <%= ejbcawebbean.getText("CERTIFICATEPOLICIES") %> <br>  <%= ejbcawebbean.getText("CERTIFICATEPOLICIESCRIT") %> <br> <%= ejbcawebbean.getText("CERTIFICATEPOLICYID") %>

      </td>
      <td width="50%">
           <input type="checkbox" name="<%=CHECKBOX_USECERTIFICATEPOLICIES %>" onClick="checkusecertificatepoliciesfield()" value="<%=CHECKBOX_VALUE %>" 
           <% if(certificateprofiledata.getUseCertificatePolicies())
                 out.write("CHECKED");
           %>> <br> 
          <input type="checkbox" name="<%=CHECKBOX_CERTIFICATEPOLICIESCRITICAL %>" value="<%=CHECKBOX_VALUE %>" 
           <%
               if(!certificateprofiledata.getUseCertificatePolicies())
                 out.write(" disabled "); 
               else
                 if(certificateprofiledata.getCertificatePoliciesCritical())
                 out.write("CHECKED");
           %>> <br> 
           <input type="text" name="<%=TEXTFIELD_CERTIFICATEPOLICYID%>" size="60" maxlength="255" 
           <%       if(!certificateprofiledata.getUseCertificatePolicies())
                      out.write(" disabled "); 
                    else 
                      out.write(" value=\"" + certificateprofiledata.getCertificatePolicyId() + "\""); %>
      </td>
    </tr>
    <tr  id="Row0"> 
      <td width="50%" valign="top" align="right">&nbsp;</td>
      <td width="50%" valign="top" align="right">&nbsp;</td>
    </tr>
    <tr  id="Row1"> 
      <td width="50%" align="right"> 
        <%= ejbcawebbean.getText("KEYUSAGE") %> <br>&nbsp;
      </td>
      <td width="50%"> 
        <select name="<%=SELECT_KEYUSAGE%>" size="9" multiple >
           <%  boolean[] ku = certificateprofiledata.getKeyUsage();
                for(int i=0; i<keyusagetexts.length;i++){ %>
           <option  value="<%= i %>" 
              <% if(ku[i]) out.write(" selected "); %>> 
              <%= ejbcawebbean.getText(keyusagetexts[i]) %>
           </option>
           <%   } %> 
        </select>
      </td>
    </tr>
    <tr  id="Row0"> 
      <td width="50%"  align="right"> 
        <%= ejbcawebbean.getText("ALLOWKEYUSAGEOVERRIDE") %>
      </td>
      <td width="50%">
           <input type="checkbox" name="<%=CHECKBOX_ALLOWKEYUSAGEOVERRIDE %>"  value="<%=CHECKBOX_VALUE %>" 
           <% if(certificateprofiledata.getAllowKeyUsageOverride())
                 out.write("CHECKED");
           %>> 
      </td>
    </tr>
    <tr  id="Row1"> 
      <td width="50%"  align="right"> 
        <%= ejbcawebbean.getText("USEEXTENDEDKEYUSAGE") %>
      </td>
      <td width="50%">
           <input type="checkbox" name="<%=CHECKBOX_USEEXTENDEDKEYUSAGE %>"  onclick="checkuseextendedkeyusagefield()" value="<%=CHECKBOX_VALUE %>" 
           <% if(certificateprofiledata.getUseExtendedKeyUsage())
                 out.write("CHECKED");
           %>> 
      </td>
    </tr>
    <tr  id="Row0"> 
      <td width="50%" align="right"> 
        <%= ejbcawebbean.getText("EXTENDEDKEYUSAGE") %> <br>&nbsp;
      </td>
      <td width="50%"> 
        <select name="<%=SELECT_EXTENDEDKEYUSAGE%>" size="9" multiple <% if(!certificateprofiledata.getUseExtendedKeyUsage()) out.write(" disabled "); %>>
           <%  ArrayList eku = certificateprofiledata.getExtendedKeyUsage();
                for(int i=0; i<extendedkeyusagetexts.length;i++){ %>
           <option  value="<%= i %>" 
              <% for(int j=0; j < eku.size(); j++) 
                   if(((Integer) eku.get(j)).intValue() == i ) out.write(" selected "); %>> 
              <%= ejbcawebbean.getText(extendedkeyusagetexts[i]) %>
           </option>
           <%   } %> 
        </select>
      </td>
    </tr>
    <tr  id="Row1"> 
      <td width="50%" align="right"> 
        <%= ejbcawebbean.getText("AVAILABLEBITLENGTHS") %> <br>&nbsp;
      </td>
      <td width="50%"> 
        <select name="<%=SELECT_AVAILABLEBITLENGTHS%>" size="5" multiple >
           <%  int[] availablebits = certificateprofiledata.getAvailableBitLengths();
                for(int i=0; i<defaultavailablebitlengths.length;i++){ %>
           <option  value="<%= defaultavailablebitlengths[i] %>" 
              <% for(int j=0; j<availablebits.length;j++){
                   if(availablebits[j] == defaultavailablebitlengths[i])
                      out.write(" selected ");
                  }%>>
              <%= defaultavailablebitlengths[i] + " " + ejbcawebbean.getText("BITS") %>         
           </option>  
              <% } %>
        </select>
      </td>
    </tr>
    <tr  id="Row0"> 
      <td width="50%" align="right"> 
        <%= ejbcawebbean.getText("TYPE") %> <br>&nbsp;
      </td>
      <td width="50%"> 
        <select name="<%=SELECT_TYPE%>" size="1" >
           <%  int type = certificateprofiledata.getType();
                for(int i=0; i<certificateprofiledata.NUMBER_OF_TYPES;i++){ %>
           <option  value="<%= TYPE_IDS[i] %>" 
              <%  if(TYPE_IDS[i] == type)
                    out.write(" selected ");
                  %>>
              <%= ejbcawebbean.getText(TYPE_NAMES[i]) %>         
           </option>  
              <% } %>
        </select>
      </td>
    </tr>
    <tr  id="Row1"> 
      <td width="49%" valign="top">&nbsp;</td>
      <td width="51%" valign="top"> 
        <input type="submit" name="<%= BUTTON_SAVE %>" onClick='return checkallfields()' value="<%= ejbcawebbean.getText("SAVE") %>">
        <input type="submit" name="<%= BUTTON_CANCEL %>" value="<%= ejbcawebbean.getText("CANCEL") %>">
      </td>
    </tr>
  </table>
 </form>