<% HardTokenIssuerData issuerdata = tokenbean.getHardTokenIssuerData(alias);
   AvailableHardToken[] availabletokens = tokenbean.getAvailableHardTokens();
   boolean used = false;

   int row=0;
%>
<SCRIPT language="JavaScript">

  <!-- // Method to check all textfields for valid input -->
<!--
function checkallfields(){
    var illegalfields = 0;

    if(document.editissuer.<%=SELECT_AVAILABLEHARDTOKENS%>.options.selectedIndex == -1){
      alert("<%=  ejbcawebbean.getText("ATLEASTONTTOKENMUST") %>");
      illegalfields++;
    }

    return illegalfields;
}
-->
</SCRIPT>
<div align="center"> 
  <h2><%= ejbcawebbean.getText("EDITHARDTOKENISSUER") %><br></h2>
</div>
<form name="editissuer" method="post" action="<%=THIS_FILENAME %>">
  <input type="hidden" name='<%= ACTION %>' value='<%=ACTION_EDIT_ISSUER %>'>
  <input type="hidden" name='<%= HIDDEN_ALIAS %>' value='<%=alias %>'>
  <table width="100%" border="0" cellspacing="3" cellpadding="3">
    <tr id="Row<%=row++%2%>"> 
      <td width="15%" valign="top">
         &nbsp;
      </td>
      <td width="35%" valign="top"> 
        <div align="left"> 
          <h3>&nbsp;</h3>
        </div>
      </td>
      <td width="50%" valign="top"> 
        <div align="right">
        <A href="<%=THIS_FILENAME %>"><u><%= ejbcawebbean.getText("BACKTOHARDTOKENISSUERS") %></u></A>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
     <!--   <A  onclick='displayHelpWindow("<%= ejbcawebbean.getHelpfileInfix("hardtoken_help.html") + "#edithardtokenissuers"%>")'>
        <u><%= ejbcawebbean.getText("HELP") %></u> </A></div> -->
      </td>
    </tr>
    <tr id="Row<%=row++%2%>"> 
      <td width="5%" valign="top">
         &nbsp;
      </td>
      <td width="25%"  align="right"> 
        <%= ejbcawebbean.getText("ALIAS") %> 
      </td>
      <td width="70%"> 
         <%=  issuerdata.getAlias() %>
      </td>
    <tr  id="Row<%=row++%2%>"> 
      <td width="5%" valign="top">
        &nbsp;
      </td>
      <td width="25%"  align="right"> 
        <%= ejbcawebbean.getText("CERTIFICATESN") %> 
      </td>
      <td width="70%"> 
        <%= issuerdata.getCertificateSN().toString(16) %> 
      </td>
    <tr  id="Row<%=row++%2%>"> 
      <td width="5%" valign="top">
        &nbsp;
      </td>
      <td width="25%"  align="right"> 
        <%= ejbcawebbean.getText("CA") %> 
      </td>
      <td width="70%"> 
        <%=caidtonamemap.get(new Integer(issuerdata.getIssuerDN().hashCode()))%> 
      </td>
    <tr  id="Row<%=row++%2%>"> 
      <td width="5%" valign="top">
         &nbsp;
      </td>
      <td width="25%"  align="right"> 
          &nbsp;
      </td>
      <td width="70%"> 
         &nbsp;&nbsp; 
      </td>
    <tr  id="Row<%=row++%2%>"> 
      <td width="5%" valign="top">
        &nbsp;
      </td>
      <td width="25%"  align="right"> 
        <%= ejbcawebbean.getText("AVAILABLEHARDTOKENTYPES") %> 
      </td>
      <td width="70%"> 
        <select name="<%=SELECT_AVAILABLEHARDTOKENS %>" size="10" multiple >
            <% 
               for(int i=0; i < availabletokens.length; i++){ %>
           <option  value='<%= availabletokens[i].getId()%>'
           <% ArrayList currenttokens = issuerdata.getHardTokenIssuer().getAvailableHardTokens();
              if(currenttokens != null){   
                Iterator iter = currenttokens.iterator();
                while(iter.hasNext())
                  if(((Integer) iter.next()).toString().equals(availabletokens[i].getId()))
                    out.write(" selected "); 
              }%>><%= availabletokens[i].getName() %>
           </option>
            <% } %>
        </select>  
      </td> 
    </tr>
    <tr  id="Row<%=row++%2%>"> 
      <td width="5%" valign="top">
         &nbsp;
      </td>
      <td width="25%" align="right"> </td>
      <td width="70%" valign="top"> 
        <input type="submit" name="<%= BUTTON_SAVE %>" onClick='return checkallfields()' value="<%= ejbcawebbean.getText("SAVE") %>" >
        <input type="submit" name="<%= BUTTON_CANCEL %>" value="<%= ejbcawebbean.getText("CANCEL") %>">
      </td>
    </tr>
  </table>
 </form>