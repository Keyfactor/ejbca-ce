<% CertificateType certificatetypedata = cabean.getCertificateType(certificatetype);
 
%>
<SCRIPT language="JavaScript">
<!--  

function checkusefield(usefield, criticalfield){
  var usebox = eval("document.editcertificatetype." + usefield);
  var cribox = eval("document.editcertificatetype." + criticalfield);
  if(usebox.checked){
    cribox.disabled = false;
  }
  else{
    cribox.checked=false;
    cribox.disabled = true;
  }
}

function checkusecrldisturifield(){
  if(document.editcertificatetype.<%=CHECKBOX_CRLDISTRIBUTIONPOINT %>.checked){
    document.editcertificatetype.<%= CHECKBOX_CRLDISTRIBUTIONPOINTCRITICAL %>.disabled = false;
    document.editcertificatetype.<%= TEXTFIELD_CRLDISTURI %>.disabled = false;
    document.editcertificatetype.<%= TEXTFIELD_CRLDISTURI %>.value = "<%= globalconfiguration.getStandardCRLDistributionPointURI() %>";
  }
  else{
    document.editcertificatetype.<%= CHECKBOX_CRLDISTRIBUTIONPOINTCRITICAL %>.disabled = true;
    document.editcertificatetype.<%= CHECKBOX_CRLDISTRIBUTIONPOINTCRITICAL %>.checked = false;
    document.editcertificatetype.<%= TEXTFIELD_CRLDISTURI %>.disabled = true;
    document.editcertificatetype.<%= TEXTFIELD_CRLDISTURI %>.value = "";
  }

}

function checkallfields(){
    var illegalfields = 0;

    if(!checkfieldfordecimalnumbers("document.editcertificatetype.<%=TEXTFIELD_VALIDITY%>","<%= ejbcawebbean.getText("ONLYDECNUMBERSINVALIDITY") %>"))
      illegalfields++;

    if(!checkfieldfordecimalnumbers("document.editcertificatetype.<%=TEXTFIELD_CRLPERIOD%>","<%= ejbcawebbean.getText("ONLYDECNUMBERSINCRLPERIOD") %>"))
      illegalfields++;
    
    var availablebitlengths = document.editcertificatetype.<%= SELECT_AVAILABLEBITLENGTHS%>.options;
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
  <h2><%= ejbcawebbean.getText("EDITCERTIFICATETYPE") %><br>
  </h2>
  <h3><%= ejbcawebbean.getText("CERTIFICATETYPE")+ " : " + certificatetype %> </h3>
</div>
<form name="editcertificatetype" method="post" action="<%=THIS_FILENAME %>">
  <input type="hidden" name='<%= ACTION %>' value='<%=ACTION_EDIT_CERTIFICATETYPE %>'>
  <input type="hidden" name='<%= HIDDEN_CERTIFICATETYPENAME %>' value='<%=certificatetype %>'>
  <table width="100%" border="0" cellspacing="3" cellpadding="3">
    <tr id="Row0"> 
      <td width="50%" valign="top"> 
        <div align="left"> 
          <h3>&nbsp;</h3>
        </div>
      </td>
      <td width="50%" valign="top"> 
        <div align="right">
        <A href="<%=THIS_FILENAME %>"><u><%= ejbcawebbean.getText("BACKTOCERTIFICATETYPES") %></u></A>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
        <A  onclick='displayHelpWindow("<%= ejbcawebbean.getHelpfileInfix("ca_help.html") + "#certificatetypes"%>")'>
        <u><%= ejbcawebbean.getText("HELP") %></u> </A></div>
      </td>
    </tr>
    <tr  id="Row0"> 
      <td width="50%"  align="right"> 
        <%= ejbcawebbean.getText("VALIDITY") %> <br>&nbsp;
      </td>
      <td width="50%"> 
        <input type="text" name="<%=TEXTFIELD_VALIDITY%>" size="5" maxlength="255" 
           value="<%= certificatetypedata.getValidity().longValue()  %>"><br>
      </td>
    <tr  id="Row1"> 
      <td width="50%"  align="right"> 
        <%= ejbcawebbean.getText("USEBASICCONSTRAINTS") %> <br>  <%= ejbcawebbean.getText("BASICCONSTRAINTSCRITICAL") %>

      </td>
      <td width="50%">
           <input type="checkbox" name="<%=CHECKBOX_BASICCONSTRAINTS %>"   onClick="checkusefield('<%=CHECKBOX_BASICCONSTRAINTS %>', '<%=CHECKBOX_BASICCONSTRAINTSCRITICAL %>')" value="<%=CHECKBOX_VALUE %>" 
           <% if(certificatetypedata.getUseBasicConstraints().booleanValue()) 
                 out.write("CHECKED");
           %>> <br> 
          <input type="checkbox" name="<%=CHECKBOX_BASICCONSTRAINTSCRITICAL %>" value="<%=CHECKBOX_VALUE %>" 
           <%
               if(!certificatetypedata.getUseBasicConstraints().booleanValue())
                 out.write(" disabled ");  
               else
               if(certificatetypedata.getBasicConstraintsCritical().booleanValue())
                 out.write("CHECKED");
           %>> 
      </td>
    <tr  id="Row0"> 
      <td width="50%"  align="right"> 
        <%= ejbcawebbean.getText("USEKEYUSAGE") %> <br>  <%= ejbcawebbean.getText("KEYUSAGECRITICAL") %>

      </td>
      <td width="50%">
           <input type="checkbox" name="<%=CHECKBOX_KEYUSAGE %>" onClick="checkusefield('<%=CHECKBOX_KEYUSAGE %>', '<%=CHECKBOX_KEYUSAGECRITICAL %>')" value="<%=CHECKBOX_VALUE %>" 
           <% if(certificatetypedata.getUseKeyUsage().booleanValue())
                 out.write("CHECKED");
           %>> <br> 
          <input type="checkbox" name="<%=CHECKBOX_KEYUSAGECRITICAL %>" value="<%=CHECKBOX_VALUE %>" 
           <%
               if(!certificatetypedata.getUseKeyUsage().booleanValue())
                 out.write(" disabled ");  
               else
               if(certificatetypedata.getKeyUsageCritical().booleanValue())
                 out.write("CHECKED");
           %>> 
      </td>
    <tr  id="Row1"> 
      <td width="50%"  align="right"> 
        <%= ejbcawebbean.getText("SUBJECTKEYID") %> <br>  <%= ejbcawebbean.getText("SUBJECTKEYIDCRITICAL") %>

      </td>
      <td width="50%">
           <input type="checkbox" name="<%=CHECKBOX_SUBJECTKEYIDENTIFIER %>" onClick="checkusefield('<%=CHECKBOX_SUBJECTKEYIDENTIFIER %>', '<%=CHECKBOX_SUBJECTKEYIDENTIFIERCRITICAL %>')" value="<%=CHECKBOX_VALUE %>" 
           <% if(certificatetypedata.getUseSubjectKeyIdentifier().booleanValue())
                 out.write("CHECKED");
           %>> <br> 
          <input type="checkbox" name="<%=CHECKBOX_SUBJECTKEYIDENTIFIERCRITICAL %>" value="<%=CHECKBOX_VALUE %>" 
           <%
             if(!certificatetypedata.getUseSubjectKeyIdentifier().booleanValue())
                 out.write(" disabled "); 
              else
              if(certificatetypedata.getSubjectKeyIdentifierCritical().booleanValue())
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
           <% if(certificatetypedata.getUseAuthorityKeyIdentifier().booleanValue())
                 out.write("CHECKED");
           %>> <br> 
          <input type="checkbox" name="<%=CHECKBOX_AUTHORITYKEYIDENTIFIERCRITICAL %>" value="<%=CHECKBOX_VALUE %>" 
           <%
             if(!certificatetypedata.getUseAuthorityKeyIdentifier().booleanValue())
                 out.write(" disabled ");  
             else
             if(certificatetypedata.getAuthorityKeyIdentifierCritical().booleanValue())
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
           <% if(certificatetypedata.getUseSubjectAlternativeName().booleanValue())
                 out.write("CHECKED");
           %>> <br> 
          <input type="checkbox" name="<%=CHECKBOX_SUBJECTALTERNATIVENAMECRITICAL %>" value="<%=CHECKBOX_VALUE %>" 
           <% 
             if(!certificatetypedata.getUseSubjectAlternativeName().booleanValue())
                 out.write(" disabled "); 
              else
              if(certificatetypedata.getSubjectAlternativeNameCritical().booleanValue())
                 out.write("CHECKED");
           %>> 
      </td>
    </tr>
    <tr  id="Row0"> 
      <td width="50%"  align="right"> 
        <%= ejbcawebbean.getText("CRLNUMBER") %> <br>  <%= ejbcawebbean.getText("CRLNUMBERCRITICAL") %>

      </td>
      <td width="50%">
           <input type="checkbox" name="<%=CHECKBOX_CRLNUMBER %>" onClick="checkusefield('<%=CHECKBOX_CRLNUMBER %>', '<%=CHECKBOX_CRLNUMBERCRITICAL %>')" value="<%=CHECKBOX_VALUE %>" 
           <% if(certificatetypedata.getUseCRLNumber().booleanValue())
                 out.write("CHECKED");
           %>> <br> 
          <input type="checkbox" name="<%=CHECKBOX_CRLNUMBERCRITICAL %>" value="<%=CHECKBOX_VALUE %>" 
           <% 
               if(!certificatetypedata.getUseCRLNumber().booleanValue())
                 out.write(" disabled "); 
               else
               if(certificatetypedata.getCRLNumberCritical().booleanValue())
                 out.write("CHECKED");
           %>> 
      </td>
    </tr>
    <tr  id="Row1"> 
      <td width="50%"  align="right"> 
        <%= ejbcawebbean.getText("CRLDISTPOINT") %> <br>  <%= ejbcawebbean.getText("CRLDISTPOINTCRITICAL") %> <br> <%= ejbcawebbean.getText("CRLDISTPOINTURI") %>

      </td>
      <td width="50%">
           <input type="checkbox" name="<%=CHECKBOX_CRLDISTRIBUTIONPOINT %>" onClick="checkusecrldisturifield()" value="<%=CHECKBOX_VALUE %>" 
           <% if(certificatetypedata.getUseCRLDistributionPoint().booleanValue())
                 out.write("CHECKED");
           %>> <br> 
          <input type="checkbox" name="<%=CHECKBOX_CRLDISTRIBUTIONPOINTCRITICAL %>" value="<%=CHECKBOX_VALUE %>" 
           <%
               if(!certificatetypedata.getUseCRLDistributionPoint().booleanValue())
                 out.write(" disabled "); 
               else
                 if(certificatetypedata.getCRLDistributionPointCritical().booleanValue())
                 out.write("CHECKED");
           %>> <br> 
           <input type="text" name="<%=TEXTFIELD_CRLDISTURI%>" size="60" maxlength="255" 
           <%       if(!certificatetypedata.getUseCRLDistributionPoint().booleanValue())
                      out.write(" disabled "); 
                    else 
                      if(!certificatetypedata.getCRLDistributionPointURI().equals(""))
                       out.write(" value=\"" + certificatetypedata.getCRLDistributionPointURI() + "\""); 
                      else
                       out.write(" value=\"" + globalconfiguration.getStandardCRLDistributionPointURI()+ "\"");%>>
      </td>
    </tr>
    <tr  id="Row0"> 
      <td width="50%"  align="right"> 
        <%= ejbcawebbean.getText("CRLPERIOD") %> <br>&nbsp;
      </td>
      <td width="50%">
           <input type="text" name="<%=TEXTFIELD_CRLPERIOD%>" size="5" maxlength="255" value="<%= certificatetypedata.getCRLPeriod().longValue()%>"> 
      </td>
    </tr>
    <tr  id="Row1"> 
      <td width="50%"  align="right"> 
        <%= ejbcawebbean.getText("EMAILINDN") %> <br>&nbsp;
      </td>
      <td width="50%">
           <input type="checkbox" name="<%=CHECKBOX_EMAILINDN %>"  value="<%=CHECKBOX_VALUE %>" 
           <% if(certificatetypedata.getEmailInDN().booleanValue())
                 out.write("CHECKED");
           %>> <br> &nbsp;
      </td>
    </tr>
    <tr  id="Row0"> 
      <td width="50%"  align="right"> 
        <%= ejbcawebbean.getText("FINISHUSER") %> <br>&nbsp;
      </td>
      <td width="50%">
           <input type="checkbox" name="<%=CHECKBOX_FINISHUSER%>"  value="<%=CHECKBOX_VALUE %>" 
           <% if(certificatetypedata.getFinishUser().booleanValue())
                 out.write("CHECKED");
           %>> <br> &nbsp;
      </td>
    </tr>
    <tr  id="Row1"> 
      <td width="50%" valign="top" align="right">&nbsp;</td>
      <td width="50%" valign="top" align="right">&nbsp;</td>
    </tr>
    <tr  id="Row0"> 
      <td width="50%" align="right"> 
        <%= ejbcawebbean.getText("KEYUSAGE") %> <br>&nbsp;
      </td>
      <td width="50%"> 
        <select name="<%=SELECT_KEYUSAGE%>" size="9" multiple >
           <%  boolean[] ku = certificatetypedata.getKeyUsage();
                for(int i=0; i<keyusagetexts.length;i++){ %>
           <option  value="<%= i %>" 
              <% if(ku[i]) out.write(" selected "); %>> 
              <%= ejbcawebbean.getText(keyusagetexts[i]) %>
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
           <%  int[] availablebits = certificatetypedata.getAvailableBitLengths();
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
      <td width="49%" valign="top">&nbsp;</td>
      <td width="51%" valign="top"> 
        <input type="submit" name="<%= BUTTON_SAVE %>" onClick='return checkallfields()' value="<%= ejbcawebbean.getText("SAVE") %>">
        <input type="submit" name="<%= BUTTON_CANCEL %>" value="<%= ejbcawebbean.getText("CANCEL") %>">
      </td>
    </tr>
  </table>
 </form>