<% String[][] profiledata = ejbcarabean.getProfileAsString(profile);
   
%>
<SCRIPT language="JavaScript">
  <!-- // Method to check all textfields for valid input -->
<!--  
function checkallfields(){
    var illegalfields = 0;

    if(!checkfieldforlegalchars("document.editprofile.<%=TEXTFIELD_USERNAME%>","<%= ejbcawebbean.getText("ONLYCHARACTERS2") %>"))
      illegalfields++;

    if(!checkfieldforlegalchars("document.editprofile.<%=TEXTFIELD_PASSWORD%>","<%= ejbcawebbean.getText("ONLYCHARACTERS2") %>"))
      illegalfields++;
 
    if(!checkfieldforlegalchars("document.editprofile.<%=TEXTFIELD_COMMONNAME%>","<%= ejbcawebbean.getText("ONLYCHARACTERS2") %>"))
      illegalfields++;
  
    if(!checkfieldforlegalchars("document.editprofile.<%=TEXTFIELD_ORGANIZATIONUNIT%>","<%= ejbcawebbean.getText("ONLYCHARACTERS2") %>"))
      illegalfields++;
  
    if(!checkfieldforlegalchars("document.editprofile.<%=TEXTFIELD_ORGANIZATION%>","<%= ejbcawebbean.getText("ONLYCHARACTERS2") %>"))
      illegalfields++;

    if(!checkfieldforlegalchars("document.editprofile.<%=TEXTFIELD_LOCALE%>","<%= ejbcawebbean.getText("ONLYCHARACTERS2") %>"))
      illegalfields++;
  
    if(!checkfieldforlegalchars("document.editprofile.<%=TEXTFIELD_STATE%>","<%= ejbcawebbean.getText("ONLYCHARACTERS2") %>"))
      illegalfields++;

    if(!checkfieldforlegalchars("document.editprofile.<%=TEXTFIELD_COUNTRY%>","<%= ejbcawebbean.getText("ONLYCHARACTERS2") %>"))
      illegalfields++;

    if(!checkfieldforlegalemailchars("document.editprofile.<%=TEXTFIELD_EMAIL%>","<%= ejbcawebbean.getText("ONLYEMAILCHARS") %>"))
      illegalfields++;
   
     return illegalfields == 0;  
   } 
-->

</SCRIPT>
<div align="center"> 
  <h2><%= ejbcawebbean.getText("EDITPROFILE") %><br>
  </h2>
  <h3><%= ejbcawebbean.getText("PROFILE") + profile %> </h3>
</div>
<form name="editprofile" method="post" action="<%=THIS_FILENAME %>">
  <input type="hidden" name='<%= ACTION %>' value='<%=ACTION_EDIT_PROFILE %>'>
  <input type="hidden" name='<%= HIDDEN_PROFILENAME %>' value='<%=profile %>'>
  <table width="100%" border="0" cellspacing="3" cellpadding="3">
    <tr id="Row0"> 
      <td width="50%" valign="top"> 
        <div align="left"> 
          <h3>&nbsp;</h3>
        </div>
      </td>
      <td width="50%" valign="top"> 
        <div align="right">
        <A href="<%=THIS_FILENAME %>"><u><%= ejbcawebbean.getText("BACKTOPROFILES") %></u></A>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
        <A  onclick='displayHelpWindow("<%= ejbcawebbean.getHelpfileInfix("ra_help.html") + "#profiles"%>")'>
        <u><%= ejbcawebbean.getText("INFORMATIONANDHELP") %></u> </A></div>
      </td>
    </tr>
    <tr  id="Row0"> 
      <td width="50%"  align="right"> 
        <%= ejbcawebbean.getText("USERNAME") %> <br>
        <%= ejbcawebbean.getText("REQUIRED") %>
      </td>
      <td width="50%"> 
        <input type="text" name="<%=TEXTFIELD_USERNAME%>" size="40" maxlength="255" 
           value="<% if(profiledata[Profile.USERNAME][Profile.VALUE]!= null) out.write(profiledata[Profile.USERNAME][Profile.VALUE]); %>"><br>
        <input type="checkbox" name="<%=CHECKBOX_REQUIRED_USERNAME %>" value="<%=CHECKBOX_VALUE %>" 
           <% if(profiledata[Profile.USERNAME][Profile.ISREQUIRED]!= null)
               if(profiledata[Profile.USERNAME][Profile.ISREQUIRED].equals(Profile.TRUE))
                 out.write("CHECKED");
           %>> 
      </td>
    <tr  id="Row1"> 
      <td width="50%"  align="right"> 
        <%= ejbcawebbean.getText("PASSWORD") %> <br>
        <%= ejbcawebbean.getText("REQUIRED") %>
      </td>
      <td width="50%"> 
        <input type="text" name="<%=TEXTFIELD_PASSWORD%>" size="40" maxlength="255" 
           value="<% if(profiledata[Profile.PASSWORD][Profile.VALUE]!= null) out.write(profiledata[Profile.PASSWORD][Profile.VALUE]); %>"><br>
        <input type="checkbox" name="<%=CHECKBOX_REQUIRED_PASSWORD %>" value="<%=CHECKBOX_VALUE %>" 
           <% if(profiledata[Profile.PASSWORD][Profile.ISREQUIRED]!= null)
               if(profiledata[Profile.PASSWORD][Profile.ISREQUIRED].equals(Profile.TRUE))
                 out.write("CHECKED");
           %>> 
      </td>
    <tr  id="Row0"> 
      <td width="50%"  align="right"> 
        <%= ejbcawebbean.getText("CLEARTEXTPASSWORD") %> <br>
        <%= ejbcawebbean.getText("REQUIRED") %>
      </td>
      <td width="50%"> 
        <input type="checkbox" name="<%=CHECKBOX_CLEARTEXTPASSWORD%>"  value="<%=CHECKBOX_VALUE %>" 
           <% if(profiledata[Profile.CLEARTEXTPASSWORD][Profile.VALUE]!= null)
               if(profiledata[Profile.CLEARTEXTPASSWORD][Profile.VALUE].equals(Profile.TRUE))
                 out.write("CHECKED");
           %>> <br>
        <input type="checkbox" name="<%=CHECKBOX_REQUIRED_CLEARTEXTPASSWORD %>" value="<%=CHECKBOX_VALUE %>" 
           <% if(profiledata[Profile.CLEARTEXTPASSWORD][Profile.ISREQUIRED]!= null)
               if(profiledata[Profile.CLEARTEXTPASSWORD][Profile.ISREQUIRED].equals(Profile.TRUE))
                 out.write("CHECKED");
           %>> 
      </td>
    <tr  id="Row1"> 
      <td width="50%"  align="right"> 
        <%= ejbcawebbean.getText("COMMONNAME") %> <br>
        <%= ejbcawebbean.getText("REQUIRED") %>
      </td>
      <td width="50%"> 
        <input type="text" name="<%=TEXTFIELD_COMMONNAME%>" size="40" maxlength="255" 
           value="<% if(profiledata[Profile.COMMONNAME][Profile.VALUE]!= null) out.write(profiledata[Profile.COMMONNAME][Profile.VALUE]); %>"><br>
        <input type="checkbox" name="<%=CHECKBOX_REQUIRED_COMMONNAME %>" value="<%=CHECKBOX_VALUE %>" 
           <% if(profiledata[Profile.COMMONNAME][Profile.ISREQUIRED]!= null)
               if(profiledata[Profile.COMMONNAME][Profile.ISREQUIRED].equals(Profile.TRUE))
                 out.write("CHECKED");
           %>> 
      </td>
    </tr>
    <tr  id="Row0"> 
      <td width="50%" align="right"> 
        <%= ejbcawebbean.getText("ORGANIZATIONUNIT") %> <br>
        <%= ejbcawebbean.getText("REQUIRED") %>
      </td>
      <td width="50%"> 
        <input type="text" name="<%=TEXTFIELD_ORGANIZATIONUNIT%>" size="40" maxlength="255" 
           value="<% if(profiledata[Profile.ORGANIZATIONUNIT][Profile.VALUE]!= null) out.write(profiledata[Profile.ORGANIZATIONUNIT][Profile.VALUE]); %>"><br>
        <input type="checkbox" name="<%=CHECKBOX_REQUIRED_ORGANIZATIONUNIT %>" value="<%=CHECKBOX_VALUE %>" 
           <% if(profiledata[Profile.ORGANIZATIONUNIT][Profile.ISREQUIRED]!= null)
               if(profiledata[Profile.ORGANIZATIONUNIT][Profile.ISREQUIRED].equals(Profile.TRUE))
                 out.write("CHECKED");
           %>> 
      </td>
    </tr>
    <tr  id="Row1"> 
      <td width="50%" align="right"> 
        <%= ejbcawebbean.getText("ORGANIZATION") %> <br>
        <%= ejbcawebbean.getText("REQUIRED") %>
      </td>
      <td width="50%"> 
        <input type="text" name="<%=TEXTFIELD_ORGANIZATION%>" size="40" maxlength="255" 
           value="<% if(profiledata[Profile.ORGANIZATION][Profile.VALUE]!= null) out.write(profiledata[Profile.ORGANIZATION][Profile.VALUE]); %>"><br>
        <input type="checkbox" name="<%=CHECKBOX_REQUIRED_ORGANIZATION %>" value="<%=CHECKBOX_VALUE %>" 
           <% if(profiledata[Profile.ORGANIZATION][Profile.ISREQUIRED]!= null)
               if(profiledata[Profile.ORGANIZATION][Profile.ISREQUIRED].equals(Profile.TRUE))
                 out.write("CHECKED");
           %>> 
      </td>
    </tr>
    <tr  id="Row0"> 
      <td width="50%" align="right"> 
        <%= ejbcawebbean.getText("LOCALE") %> <br>
        <%= ejbcawebbean.getText("REQUIRED") %>
      </td>
      <td width="50%"> 
        <input type="text" name="<%=TEXTFIELD_LOCALE%>" size="40" maxlength="255" 
           value="<% if(profiledata[Profile.LOCALE][Profile.VALUE]!= null) out.write(profiledata[Profile.LOCALE][Profile.VALUE]); %>"><br>
        <input type="checkbox" name="<%=CHECKBOX_REQUIRED_LOCALE %>" value="<%=CHECKBOX_VALUE %>" 
           <% if(profiledata[Profile.LOCALE][Profile.ISREQUIRED]!= null)
               if(profiledata[Profile.LOCALE][Profile.ISREQUIRED].equals(Profile.TRUE))
                 out.write("CHECKED");
           %>> 
      </td>
    </tr>
    <tr  id="Row1"> 
      <td width="50%" align="right"> 
        <%= ejbcawebbean.getText("STATE") %> <br>
        <%= ejbcawebbean.getText("REQUIRED") %>
      </td>
      <td width="50%"> 
        <input type="text" name="<%=TEXTFIELD_STATE%>" size="40" maxlength="255" 
           value="<% if(profiledata[Profile.STATE][Profile.VALUE]!= null) out.write(profiledata[Profile.STATE][Profile.VALUE]); %>"><br>
        <input type="checkbox" name="<%=CHECKBOX_REQUIRED_STATE %>" value="<%=CHECKBOX_VALUE %>" 
           <% if(profiledata[Profile.STATE][Profile.ISREQUIRED]!= null)
               if(profiledata[Profile.STATE][Profile.ISREQUIRED].equals(Profile.TRUE))
                 out.write("CHECKED");
           %>> 
      </td>
    </tr>
    <tr  id="Row0"> 
      <td width="50%" align="right"> 
        <%= ejbcawebbean.getText("COUNTRY") %> <br>
        <%= ejbcawebbean.getText("REQUIRED") %>
      </td>
      <td width="50%"> 
        <input type="text" name="<%=TEXTFIELD_COUNTRY%>" size="2" maxlength="2" 
           value="<% if(profiledata[Profile.COUNTRY][Profile.VALUE]!= null) out.write(profiledata[Profile.COUNTRY][Profile.VALUE]); %>"><br>
        <input type="checkbox" name="<%=CHECKBOX_REQUIRED_COUNTRY%>" value="<%=CHECKBOX_VALUE %>" 
           <% if(profiledata[Profile.COUNTRY][Profile.ISREQUIRED]!= null)
               if(profiledata[Profile.COUNTRY][Profile.ISREQUIRED].equals(Profile.TRUE))
                 out.write("CHECKED");
           %>> 
      </td>
    </tr>
    <tr  id="Row1"> 
      <td width="50%" align="right"> 
        <%= ejbcawebbean.getText("EMAIL") %> <br>
        <%= ejbcawebbean.getText("REQUIRED") %>
      </td>
      <td width="50%"> 
        <input type="text" name="<%=TEXTFIELD_EMAIL%>" size="40" maxlength="255" 
           value="<% if(profiledata[Profile.EMAIL][Profile.VALUE]!= null) out.write(profiledata[Profile.EMAIL][Profile.VALUE]); %>"><br>
        <input type="checkbox" name="<%=CHECKBOX_REQUIRED_EMAIL%>" value="<%=CHECKBOX_VALUE %>" 
           <% if(profiledata[Profile.EMAIL][Profile.ISREQUIRED]!= null)
               if(profiledata[Profile.EMAIL][Profile.ISREQUIRED].equals(Profile.TRUE))
                 out.write("CHECKED");
           %>> 
      </td>
    </tr>
    <tr  id="Row0"> 
      <td width="50%" valign="top" align="right"><%= ejbcawebbean.getText("TYPES") %></td>
      <td width="50%" valign="top" align="right">&nbsp;</td>
    </tr>
    <tr  id="Row1"> 
      <td width="50%" align="right"> 
        <%= ejbcawebbean.getText("TYPEENDUSER") %> <br>
        <%= ejbcawebbean.getText("REQUIRED") %>
      </td>
      <td width="50%"> 
        <input type="checkbox" name="<%=CHECKBOX_TYPEENDUSER%>" value="<%=CHECKBOX_VALUE %>" 
           <% if(profiledata[Profile.TYPE_ENDUSER][Profile.VALUE]!= null)
               if(profiledata[Profile.TYPE_ENDUSER][Profile.VALUE].equals(Profile.TRUE))
                 out.write("CHECKED");
           %>> <br>

        <input type="checkbox" name="<%=CHECKBOX_REQUIRED_TYPEENDUSER%>" value="<%=CHECKBOX_VALUE %>" 
           <% if(profiledata[Profile.TYPE_ENDUSER][Profile.ISREQUIRED]!= null)
               if(profiledata[Profile.TYPE_ENDUSER][Profile.ISREQUIRED].equals(Profile.TRUE))
                 out.write("CHECKED");
           %>> 
      </td>
    </tr>
    <tr  id="Row0"> 
      <td width="50%" align="right"> 
        <%= ejbcawebbean.getText("TYPERA") %> <br>
        <%= ejbcawebbean.getText("REQUIRED") %>
      </td>
      <td width="50%"> 
        <input type="checkbox" name="<%=CHECKBOX_TYPERA%>" value="<%=CHECKBOX_VALUE %>" 
           <% if(profiledata[Profile.TYPE_RA][Profile.VALUE]!= null)
               if(profiledata[Profile.TYPE_RA][Profile.VALUE].equals(Profile.TRUE))
                 out.write("CHECKED");
           %>> <br>

        <input type="checkbox" name="<%=CHECKBOX_REQUIRED_TYPERA%>" value="<%=CHECKBOX_VALUE %>" 
           <% if(profiledata[Profile.TYPE_RA][Profile.ISREQUIRED]!= null)
               if(profiledata[Profile.TYPE_RA][Profile.ISREQUIRED].equals(Profile.TRUE))
                 out.write("CHECKED");
           %>> 
      </td>
    </tr>
    <tr  id="Row1"> 
      <td width="50%" align="right"> 
        <%= ejbcawebbean.getText("TYPERAADMIN") %> <br>
        <%= ejbcawebbean.getText("REQUIRED") %>
      </td>
      <td width="50%"> 
        <input type="checkbox" name="<%=CHECKBOX_TYPERAADMIN%>" value="<%=CHECKBOX_VALUE %>" 
           <% if(profiledata[Profile.TYPE_RAADMIN][Profile.VALUE]!= null)
               if(profiledata[Profile.TYPE_RAADMIN][Profile.VALUE].equals(Profile.TRUE))
                 out.write("CHECKED");
           %>> <br>

        <input type="checkbox" name="<%=CHECKBOX_REQUIRED_TYPERAADMIN%>" value="<%=CHECKBOX_VALUE %>" 
           <% if(profiledata[Profile.TYPE_RAADMIN][Profile.ISREQUIRED]!= null)
               if(profiledata[Profile.TYPE_RAADMIN][Profile.ISREQUIRED].equals(Profile.TRUE))
                 out.write("CHECKED");
           %>> 
      </td>
    </tr>
    <tr  id="Row0"> 
      <td width="50%" align="right"> 
        <%= ejbcawebbean.getText("TYPECA") %> <br>
        <%= ejbcawebbean.getText("REQUIRED") %>
      </td>
      <td width="50%"> 
        <input type="checkbox" name="<%=CHECKBOX_TYPECA%>" value="<%=CHECKBOX_VALUE %>" 
           <% if(profiledata[Profile.TYPE_CA][Profile.VALUE]!= null)
               if(profiledata[Profile.TYPE_CA][Profile.VALUE].equals(Profile.TRUE))
                 out.write("CHECKED");
           %>> <br>

        <input type="checkbox" name="<%=CHECKBOX_REQUIRED_TYPECA%>" value="<%=CHECKBOX_VALUE %>" 
           <% if(profiledata[Profile.TYPE_CA][Profile.ISREQUIRED]!= null)
               if(profiledata[Profile.TYPE_CA][Profile.ISREQUIRED].equals(Profile.TRUE))
                 out.write("CHECKED");
           %>> 
      </td>
    </tr>
    <tr  id="Row1"> 
      <td width="50%" align="right"> 
        <%= ejbcawebbean.getText("TYPECAADMIN") %> <br>
        <%= ejbcawebbean.getText("REQUIRED") %>
      </td>
      <td width="50%"> 
        <input type="checkbox" name="<%=CHECKBOX_TYPECAADMIN%>" value="<%=CHECKBOX_VALUE %>" 
           <% if(profiledata[Profile.TYPE_CAADMIN][Profile.VALUE]!= null)
               if(profiledata[Profile.TYPE_CAADMIN][Profile.VALUE].equals(Profile.TRUE))
                 out.write("CHECKED");
           %>> <br>

        <input type="checkbox" name="<%=CHECKBOX_REQUIRED_TYPECAADMIN%>" value="<%=CHECKBOX_VALUE %>" 
           <% if(profiledata[Profile.TYPE_CAADMIN][Profile.ISREQUIRED]!= null)
               if(profiledata[Profile.TYPE_CAADMIN][Profile.ISREQUIRED].equals(Profile.TRUE))
                 out.write("CHECKED");
           %>> 
      </td>
    </tr>
    <tr  id="Row0"> 
      <td width="50%" align="right"> 
        <%= ejbcawebbean.getText("TYPEROOTCA") %> <br>
        <%= ejbcawebbean.getText("REQUIRED") %>
      </td>
      <td width="50%"> 
        <input type="checkbox" name="<%=CHECKBOX_TYPEROOTCA%>" value="<%=CHECKBOX_VALUE %>" 
           <% if(profiledata[Profile.TYPE_ROOTCA][Profile.VALUE]!= null)
               if(profiledata[Profile.TYPE_ROOTCA][Profile.VALUE].equals(Profile.TRUE))
                 out.write("CHECKED");
           %>> <br>

        <input type="checkbox" name="<%=CHECKBOX_REQUIRED_TYPEROOTCA%>" value="<%=CHECKBOX_VALUE %>" 
           <% if(profiledata[Profile.TYPE_ROOTCA][Profile.ISREQUIRED]!= null)
               if(profiledata[Profile.TYPE_ROOTCA][Profile.ISREQUIRED].equals(Profile.TRUE))
                 out.write("CHECKED");
           %>> 
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