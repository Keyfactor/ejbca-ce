
<% 
  TreeMap issuerdatas   = ejbcawebbean.getInformationMemory().getHardTokenIssuers();
%>
  <script language=javascript>
<!--
function checkfields(){
   var returnval;
   returnval = !((document.editissuers.<%=TEXTFIELD_ALIAS %>.value=="") || (document.editissuers.<%=TEXTFIELD_CERTSN %>.value==""))  
 
   if(!returnval)
     alert("<%= ejbcawebbean.getText("BOTHFIELDMUSTBEFILLED")%>");

   return returnval;
}

function checkselected(){
   var returnval;
   returnval = document.editissuers.<%= SELECT_ISSUER %>.options.selectedIndex != -1
 
   if(!returnval)
     alert("<%= ejbcawebbean.getText("ONECURRENTISSUERMUSTBESEL")%>");

   return returnval;
}
-->
</script>

<div align="center">
  <p><H1><%= ejbcawebbean.getText("EDITHARDTOKENISSUERS") %></H1></p>
 <!-- <div align="right"><A  onclick='displayHelpWindow("<%= ejbcawebbean.getHelpfileInfix("hardtoken_help.html") + "#edithardtokenissuers"%>")'>
    <u><%= ejbcawebbean.getText("HELP") %></u> </A> -->
  </div>
  <form name="editissuers" method="post"  action="<%= THIS_FILENAME%>">
    <input type="hidden" name='<%= ACTION %>' value='<%=ACTION_EDIT_ISSUERS %>'>
    <table width="100%" border="0" cellspacing="0" cellpadding="0">
    <% if(issuerexists){ %> 
      <tr> 
        <td width="5%"></td>
        <td width="60%"><div align="center"><H4 id="alert"><%= ejbcawebbean.getText("ISSUERALREADYEXISTS") %></H4></div></td>
        <td width="35%"></td>
      </tr>
    <% } %>
    <% if(issuerdeletefailed){ %> 
      <tr> 
        <td width="5%"></td>
        <td width="60%"><div align="center"><H4 id="alert"><%= ejbcawebbean.getText("COULDNTDELETEISSUER") %></H4></div></td>
        <td width="35%"></td>
      </tr>
    <% } %>
      <tr> 
        <td width="5%"></td>
        <td width="60%"><H3><%= ejbcawebbean.getText("CURRENTHARDTOKENISSUERS") %></H3></td>
        <td width="35%"></td>
      </tr>
      <tr> 
        <td width="5%"></td>
        <td width="60%">
          <select name="<%=SELECT_ISSUER%>" size="15"  >
            <% Iterator i = issuerdatas.keySet().iterator();
               while(i.hasNext()){  
                 String curalias = (String) i.next();
                 HardTokenIssuerData data = (HardTokenIssuerData) issuerdatas.get(curalias);                 
                  %>
              <option value="<%=curalias%>"> 
                  <%= curalias %>, <%=  ejbcawebbean.getText("SHORTSERIALNUMBER") %> : <%= data.getCertificateSN().toString(16) + ", " + caidtonamemap.get(new Integer(data.getIssuerDN().hashCode()))%>  
               </option>
            <%}%>
              <option value="">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</option>
          </select>
          </td>
      </tr>
      <tr> 
        <td width="5%"></td>
        <td width="40%"> 
          <table width="100%" border="0" cellspacing="0" cellpadding="0">
            <tr>
              <td>
                <input type="submit" name="<%= BUTTON_EDIT_ISSUER %>" value="<%= ejbcawebbean.getText("EDITHARDTOKENISSUER") %>">
              </td>
              <td>
             &nbsp; 
              </td>
              <td>
                <input class=buttonstyle type="submit" onClick="return confirm('<%= ejbcawebbean.getText("AREYOUSURE") %>');" name="<%= BUTTON_DELETE_ISSUER %>" value="<%= ejbcawebbean.getText("DELETEISSUER") %>">
              </td>
            </tr>
          </table> 
        </td>
        <td width="55%"> </td>
      </tr>
    </table>
   
  <p align="left"> </p>
    <table width="100%" border="0" cellspacing="0" cellpadding="0">
      <tr> 
        <td width="130"></td>
        <td width="*"><H3><%= ejbcawebbean.getText("ADDISSUER") %></H3></td>
      </tr>
      <tr> 
        <td width="130">
             <%= ejbcawebbean.getText("ALIAS") %>
        </td>
        <td width="*"> 
         <input type="text" name="<%=TEXTFIELD_ALIAS%>" size="40" maxlength="255">
        </td>
      </tr> 
      <tr>
        <td width="130">
             <%= ejbcawebbean.getText("CERTIFICATESN") %>
        </td>
        <td width="*"> 
         <input type="text" name="<%=TEXTFIELD_CERTSN%>" size="40" maxlength="255">
          &nbsp;
          <select name="<%=SELECT_CA%>" >
            <%Iterator iter = ejbcawebbean.getInformationMemory().getAuthorizedCAIds().iterator(); 
              while(iter.hasNext()){
                Integer authorizedcaid = (Integer) iter.next();%>
              <option value="<%= authorizedcaid%>">
                 <%= caidtonamemap.get(authorizedcaid)%>
              </option>
            <%}%>
          </select>
        </td>
      </tr> 
       <tr>
        <td width="130">
            &nbsp;&nbsp;
        </td>
        <td width="*">            
          <input type="submit" name="<%= BUTTON_ADD_ISSUER%>" onClick='return (checkfieldforlegalchars("document.editissuers.<%=TEXTFIELD_ALIAS%>","<%= ejbcawebbean.getText("ONLYCHARACTERSINALIAS") %>") && checkfieldforhexadecimalnumbers("document.editissuers.<%=TEXTFIELD_CERTSN%>","<%= ejbcawebbean.getText("ONLYHEXINCERTSN") %>") && checkfields())' value="<%= ejbcawebbean.getText("ADDISSUER") %>">&nbsp;&nbsp;&nbsp;
          <input type="submit" name="<%= BUTTON_RENAME_ISSUER%>" onClick='return (checkfieldforlegalchars("document.editissuers.<%=TEXTFIELD_ALIAS%>","<%= ejbcawebbean.getText("ONLYCHARACTERSINALIAS") %>") && checkfieldforhexadecimalnumbers("document.editissuers.<%=TEXTFIELD_CERTSN%>","<%= ejbcawebbean.getText("ONLYHEXINCERTSN") %>") && checkfields() && checkselected())'  value="<%= ejbcawebbean.getText("RENAMESELECTED") %>">&nbsp;&nbsp;&nbsp;
          <input type="submit" name="<%= BUTTON_CLONE_ISSUER%>" onClick='return (checkfieldforlegalchars("document.editissuers.<%=TEXTFIELD_ALIAS%>","<%= ejbcawebbean.getText("ONLYCHARACTERSINALIAS") %>") && checkfieldforhexadecimalnumbers("document.editissuers.<%=TEXTFIELD_CERTSN%>","<%= ejbcawebbean.getText("ONLYHEXINCERTSN") %>") && checkfields() && checkselected())'  value="<%= ejbcawebbean.getText("USESELECTEDASTEMPLATE") %>">
        </td>
      <tr> 
        <td width="130">&nbsp; </td>
        <td width="*">&nbsp;</td>
      </tr>
    </table>
  </form>
  <p align="center">&nbsp;</p>
  <p>&nbsp;</p>
</div>

