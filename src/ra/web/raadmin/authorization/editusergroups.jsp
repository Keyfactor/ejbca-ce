<% /* editusergroups.jsp
    *
    * Main user group editing page, included from ejbcaathorization.jsp 
    * 
    * Created on  14 mars 2002, 11:56
    *
    * author  Philip Vendil */ %>

<% 
  String[] usergroups = ejbcaauthorization.getUserGroupnames(); 
%>


<div align="center">
  <p><H1><%= ejbcawebbean.getText("ACCESSCONTROLLISTS") %></H1></p>
  <div align="right"><A  onclick='displayHelpWindow("<%= ejbcawebbean.getHelpfileInfix("authorization_help.html") + "#usergroups" %>")'>
    <u><%= ejbcawebbean.getText("INFORMATIONANDHELP") %></u> </A>
  </div>
  <form name="editgroup" method="post"  action="<%= THIS_FILENAME%>">
    <input type="hidden" name='<%= ACTION %>' value='<%=ACTION_EDIT_GROUPS %>'>
    <table width="100%" border="0" cellspacing="0" cellpadding="0">
    <% if(usergroupexists){ %> 
      <tr> 
        <td width="5%"></td>
        <td width="60%"><H4 id="alert"><%= ejbcawebbean.getText("USERGROUPEXISTS") %></H4></td>
        <td width="35%"></td>
      </tr>
    <% } %> 
      <tr> 
        <td width="5%"></td>
        <td width="60%"><H3><%= ejbcawebbean.getText("CURRENTUSERGROUPS") %></H3></td>
        <td width="35%"></td>
      </tr>
      <tr> 
        <td width="5%"></td>
        <td width="60%">
          <select name="<%=SELECT_USERGROUPS%>" size="15"  >
            <% for(int i=0; i < usergroups.length ;i++){ %>
              <option value="<%=usergroups[i]%>"><%=usergroups[i]%></option>
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
                <input type="submit" name="<%= BUTTON_EDIT_USERS %>" value="<%= ejbcawebbean.getText("EDITUSERS") %>">
              </td>
              <td>
                <input type="submit" name="<%= BUTTON_EDIT_ACCESSRULES %>" value="<%= ejbcawebbean.getText("EDITACCESSRULES") %>">
              </td>
              <td>
                <input class=buttonstyle type="submit" onClick="return confirm('<%= ejbcawebbean.getText("AREYOUSURE") %>');" name="<%= BUTTON_DELETE_USERGROUP %>" value="<%= ejbcawebbean.getText("DELETEGROUP") %>">
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
        <td width="95%"><H3><%= ejbcawebbean.getText("ADDUSERGROUP") %></H3></td>
      </tr>
      <tr> 
        <td width="5%"></td>
        <td width="95%"> 
          <input type="text" name="<%=TEXTFIELD_GROUPNAME%>" size="40" maxlength="255">   
          <input type="submit" name="<%= BUTTON_ADD_USERGROUP%>" onClick='return checkfieldforlegalchars("document.editgroup.<%=TEXTFIELD_GROUPNAME%>","<%= ejbcawebbean.getText("ONLYCHARACTERS") %>")' value="<%= ejbcawebbean.getText("ADDUSERGROUP") %>">&nbsp;&nbsp;&nbsp;
          <input type="submit" name="<%= BUTTON_RENAME_SELECTED%>" onClick='return checkfieldforlegalchars("document.editgroup.<%=TEXTFIELD_GROUPNAME%>","<%= ejbcawebbean.getText("ONLYCHARACTERS") %>")' value="<%= ejbcawebbean.getText("RENAMESELECTEDUSERGROUP") %>">
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

