<%
  String[] certificatetypes     = cabean.getCertificateTypeNames(); 
%>


<div align="center">
  <p><H1><%= ejbcawebbean.getText("EDITCERTIFICATETYPES") %></H1></p>
  <div align="right"><A  onclick='displayHelpWindow("<%= ejbcawebbean.getHelpfileInfix("ca_help.html") + "#certificatetypes"%>")'>
    <u><%= ejbcawebbean.getText("HELP") %></u> </A>
  </div>
  <form name="editcertificatetypes" method="post"  action="<%= THIS_FILENAME%>">
    <input type="hidden" name='<%= ACTION %>' value='<%=ACTION_EDIT_CERTIFICATETYPES %>'>
    <table width="100%" border="0" cellspacing="0" cellpadding="0">
    <% if(triedtoeditfixedcertificatetype){ %> 
      <tr> 
        <td width="5%"></td>
        <td width="60%"><H4 id="alert"><%= ejbcawebbean.getText("YOUCANTEDITFIXEDCERTTYPES") %></H4></td>
        <td width="35%"></td>
      </tr>
    <% } %>
    <% if(triedtodeletefixedcertificatetype){ %> 
      <tr> 
        <td width="5%"></td>
        <td width="60%"><H4 id="alert"><%= ejbcawebbean.getText("YOUCANTDELETEFIXEDCERT") %></H4></td>
        <td width="35%"></td>
      </tr>
    <% } %>
    <% if(triedtoaddfixedcertificatetype){ %> 
      <tr> 
        <td width="5%"></td>
        <td width="60%"><H4 id="alert"><%= ejbcawebbean.getText("YOUCANTADDFIXEDCERT") %></H4></td>
        <td width="35%"></td>
      </tr>
    <% } %>
    <% if(certificatetypeexists){ %> 
      <tr> 
        <td width="5%"></td>
        <td width="60%"><H4 id="alert"><%= ejbcawebbean.getText("CERTIFICATETYPEALREADY") %></H4></td>
        <td width="35%"></td>
      </tr>
    <% } %>

      <tr> 
        <td width="5%"></td>
        <td width="60%"><H3><%= ejbcawebbean.getText("CURRENTCERTIFICATETYPES") %></H3></td>
        <td width="35%"></td>
      </tr>
      <tr> 
        <td width="5%"></td>
        <td width="60%">
          <select name="<%=SELECT_CERTIFICATETYPE%>" size="15"  >
            <% String certtypename;
               for(int i=0; i < certificatetypes.length ;i++){
                 certtypename=certificatetypes[i];
                 if( cabean.getCertificateTypeId(certificatetypes[i]) <= CertificateTypeDataHandler.FIXED_CERTIFICATETYPE_BOUNDRY){ 
                   certtypename += " (FIXED)";
                 }
  
              %>
              <option value="<%=certtypename%>"> 
                  <%= certtypename %>                 
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
        <td width="60%"> 
          <table width="100%" border="0" cellspacing="0" cellpadding="0">
            <tr>
              <td>
                <input type="submit" name="<%= BUTTON_EDIT_CERTIFICATETYPE %>" value="<%= ejbcawebbean.getText("EDITCERTTYPE") %>">
              </td>
              <td>
             &nbsp; 
              </td>
              <td>
                <input class=buttonstyle type="submit" onClick="return confirm('<%= ejbcawebbean.getText("AREYOUSURE") %>');" name="<%= BUTTON_DELETE_CERTIFICATETYPE %>" value="<%= ejbcawebbean.getText("DELETECERTTYPE") %>">
              </td>
            </tr>
          </table> 
        </td>
        <td width="35%"> </td>
      </tr>
    </table>
   
  <p align="left"> </p>
    <table width="100%" border="0" cellspacing="0" cellpadding="0">
      <tr> 
        <td width="5%"></td>
        <td width="95%"><H3><%= ejbcawebbean.getText("ADD") %></H3></td>
      </tr>
      <tr> 
        <td width="5%"></td>
        <td width="95%"> 
          <input type="text" name="<%=TEXTFIELD_CERTIFICATETYPENAME%>" size="40" maxlength="255">   
          <input type="submit" name="<%= BUTTON_ADD_CERTIFICATETYPE%>" onClick='return checkfieldforlegalchars("document.editcertificatetypes.<%=TEXTFIELD_CERTIFICATETYPENAME%>","<%= ejbcawebbean.getText("ONLYCHARACTERS") %>")' value="<%= ejbcawebbean.getText("ADD") %>">&nbsp;&nbsp;&nbsp;
          <input type="submit" name="<%= BUTTON_RENAME_CERTIFICATETYPE%>" onClick='return checkfieldforlegalchars("document.editcertificatetypes.<%=TEXTFIELD_CERTIFICATETYPENAME%>","<%= ejbcawebbean.getText("ONLYCHARACTERS") %>")' value="<%= ejbcawebbean.getText("RENAMESELECTED") %>">&nbsp;&nbsp;&nbsp;
          <input type="submit" name="<%= BUTTON_CLONE_CERTIFICATETYPE%>" onClick='return checkfieldforlegalchars("document.editcertificatetypes.<%=TEXTFIELD_CERTIFICATETYPENAME%>","<%= ejbcawebbean.getText("ONLYCHARACTERS") %>")' value="<%= ejbcawebbean.getText("USESELECTEDASTEMPLATE") %>">
        </td>
      </tr>
      <tr> 
        <td width="5%">&nbsp; </td>
        <td width="95%">&nbsp;</td>
      </tr>
    </table>
  </form>
  <p align="center">&nbsp;</p>
  <p>&nbsp;</p>
</div>

