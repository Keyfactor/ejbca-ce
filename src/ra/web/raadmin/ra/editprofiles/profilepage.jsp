<% String[][] profiledata = ejbcarabean.getProfileAsString(profile);
   String[] certificatetypenames = ejbcarabean.getCertificateTypeNames();
   boolean used = false;
%>
<SCRIPT language="JavaScript">

  <!-- // Method to check all textfields for valid input -->
<!--  
function checkallfields(){
    var illegalfields = 0;

    if(!checkfieldforlegalcharswithchangeable("document.editprofile.<%=TEXTFIELD_USERNAME%>","<%= ejbcawebbean.getText("ONLYCHARACTERS2") %>"))
      illegalfields++;
 
    if(!checkfieldforlegaldncharswithchangeable("document.editprofile.<%=TEXTFIELD_COMMONNAME%>","<%= ejbcawebbean.getText("ONLYDNCHARACTERS") %>"))
      illegalfields++;
  
    if(!checkfieldforlegaldncharswithchangeable("document.editprofile.<%=TEXTFIELD_ORGANIZATIONUNIT%>","<%= ejbcawebbean.getText("ONLYDNCHARACTERS") %>"))
      illegalfields++;
  
    if(!checkfieldforlegaldncharswithchangeable("document.editprofile.<%=TEXTFIELD_ORGANIZATION%>","<%= ejbcawebbean.getText("ONLYDNCHARACTERS") %>"))
      illegalfields++;

    if(!checkfieldforlegaldncharswithchangeable("document.editprofile.<%=TEXTFIELD_LOCALE%>","<%= ejbcawebbean.getText("ONLYDNCHARACTERS") %>"))
      illegalfields++;
  
    if(!checkfieldforlegaldncharswithchangeable("document.editprofile.<%=TEXTFIELD_STATE%>","<%= ejbcawebbean.getText("ONLYDNCHARACTERS") %>"))
      illegalfields++;

    if(!checkfieldforlegaldncharswithchangeable("document.editprofile.<%=TEXTFIELD_COUNTRY%>","<%= ejbcawebbean.getText("ONLYDNCHARACTER") %>"))
      illegalfields++;

    if(!checkfieldforlegalemailcharswithchangeable("document.editprofile.<%=TEXTFIELD_EMAIL%>","<%= ejbcawebbean.getText("ONLYEMAILCHARS") %>"))
      illegalfields++;
 
    if(document.editprofile.<%= SELECT_DEFAULTCERTTYPE %>.options.selectedIndex == -1){
      alert("<%=  ejbcawebbean.getText("ADEFAULTCERTTYPE") %>");
      illegalfields++;
    }

    if(illegalfields == 0){
      document.editprofile.<%= CHECKBOX_CLEARTEXTPASSWORD %>.disabled = false;
      document.editprofile.<%= CHECKBOX_REQUIRED_CLEARTEXTPASSWORD %>.disabled = false;
      document.editprofile.<%= CHECKBOX_REQUIRED_COMMONNAME %>.disabled = false;
      document.editprofile.<%= CHECKBOX_CHANGEABLE_COMMONNAME %>.disabled = false;
      document.editprofile.<%= TEXTFIELD_COMMONNAME %>.disabled = false;
      document.editprofile.<%= CHECKBOX_REQUIRED_ORGANIZATIONUNIT %>.disabled = false;
      document.editprofile.<%= CHECKBOX_CHANGEABLE_ORGANIZATIONUNIT %>.disabled = false;
      document.editprofile.<%= TEXTFIELD_ORGANIZATIONUNIT %>.disabled = false;
      document.editprofile.<%= CHECKBOX_REQUIRED_ORGANIZATION %>.disabled = false;
      document.editprofile.<%= CHECKBOX_CHANGEABLE_ORGANIZATION %>.disabled = false;
      document.editprofile.<%= TEXTFIELD_ORGANIZATION %>.disabled = false;
      document.editprofile.<%= CHECKBOX_REQUIRED_LOCALE %>.disabled = false;
      document.editprofile.<%= CHECKBOX_CHANGEABLE_LOCALE %>.disabled = false;
      document.editprofile.<%= TEXTFIELD_LOCALE %>.disabled = false;
      document.editprofile.<%= CHECKBOX_REQUIRED_STATE %>.disabled = false;
      document.editprofile.<%= CHECKBOX_CHANGEABLE_STATE %>.disabled = false;
      document.editprofile.<%= TEXTFIELD_STATE %>.disabled = false;
      document.editprofile.<%= CHECKBOX_REQUIRED_COUNTRY %>.disabled = false;
      document.editprofile.<%= CHECKBOX_CHANGEABLE_COUNTRY %>.disabled = false;
      document.editprofile.<%= TEXTFIELD_COUNTRY %>.disabled = false;
      document.editprofile.<%= CHECKBOX_REQUIRED_EMAIL %>.disabled = false;
      document.editprofile.<%= CHECKBOX_CHANGEABLE_EMAIL %>.disabled = false;
      document.editprofile.<%= TEXTFIELD_EMAIL %>.disabled = false;
      document.editprofile.<%= CHECKBOX_REQUIRED_TYPEENDUSER %>.disabled = false;
      document.editprofile.<%= CHECKBOX_TYPEENDUSER %>.disabled = false;
      document.editprofile.<%= CHECKBOX_REQUIRED_TYPERA %>.disabled = false;
      document.editprofile.<%= CHECKBOX_TYPERA %>.disabled = false;
      document.editprofile.<%= CHECKBOX_REQUIRED_TYPECA %>.disabled = false;
      document.editprofile.<%= CHECKBOX_TYPECA %>.disabled = false;
      document.editprofile.<%= CHECKBOX_REQUIRED_TYPERAADMIN %>.disabled = false;
      document.editprofile.<%= CHECKBOX_TYPERAADMIN %>.disabled = false;
      document.editprofile.<%= CHECKBOX_REQUIRED_TYPECAADMIN %>.disabled = false;
      document.editprofile.<%= CHECKBOX_TYPECAADMIN %>.disabled = false;
      document.editprofile.<%= CHECKBOX_REQUIRED_TYPEROOTCA %>.disabled = false;
      document.editprofile.<%= CHECKBOX_TYPEROOTCA %>.disabled = false;
    }


     return illegalfields == 0;  
} 

function checkusecheckbox(usefield, value, required){
  var usebox = eval("document.editprofile." + usefield);
  var valuefield = eval("document.editprofile." + value);
  var reqbox = eval("document.editprofile." + required);
  if(usebox.checked){
    valuefield.disabled = false;
    reqbox.disabled = false;
  }
  else{
    valuefield.checked=false;
    valuefield.disabled = true;
    reqbox.checked = false;
    reqbox.disabled = true;
  }
}

function checkusetextfield(usefield, value, required, change){
  var usebox = eval("document.editprofile." + usefield);
  var valuefield = eval("document.editprofile." + value);
  var reqbox = eval("document.editprofile." + required);
  var changebox = eval("document.editprofile." + change);

  if(usebox.checked){
    valuefield.disabled = false;
    reqbox.disabled = false;
    changebox.disabled = false;
  }
  else{
    valuefield.value = "";
    valuefield.disabled = true;
    reqbox.checked = false;
    reqbox.disabled = true;
    changebox.checked = false;
    changebox.disabled = true;
  }
}
-->

</SCRIPT>
<div align="center"> 
  <h2><%= ejbcawebbean.getText("EDITPROFILE") %><br>
  </h2>
  <h3><%= ejbcawebbean.getText("PROFILE") + " " + profile %> </h3>
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
        <u><%= ejbcawebbean.getText("HELP") %></u> </A></div>
      </td>
    </tr>
    <tr  id="Row0"> 
      <td width="50%"  align="right"> 
        <%= ejbcawebbean.getText("USERNAME") %> <br>&nbsp;
      </td>
      <td width="50%"> 
        <input type="text" name="<%=TEXTFIELD_USERNAME%>" size="40" maxlength="1024" 
           value="<% if(profiledata[Profile.USERNAME][Profile.VALUE]!= null) out.write(profiledata[Profile.USERNAME][Profile.VALUE]); %>"><br>
           <%= ejbcawebbean.getText("REQUIRED") %>
           <input type="checkbox" name="<%=CHECKBOX_REQUIRED_USERNAME %>" value="<%=CHECKBOX_VALUE %>" 
           <% if(profiledata[Profile.USERNAME][Profile.ISREQUIRED]!= null)
               if(profiledata[Profile.USERNAME][Profile.ISREQUIRED].equals(Profile.TRUE))
                 out.write("CHECKED");
           %>> 
        &nbsp;&nbsp;<%= ejbcawebbean.getText("CHANGEABLE") %> 
        <input type="checkbox" name="<%=CHECKBOX_CHANGEABLE_USERNAME %>" value="<%=CHECKBOX_VALUE %>" 
           <% if(profiledata[Profile.USERNAME][Profile.CHANGEABLE]!= null)
               if(profiledata[Profile.USERNAME][Profile.CHANGEABLE].equals(Profile.TRUE))
                 out.write("CHECKED");
           %>> 
      </td>
    <tr  id="Row1"> 
      <td width="50%"  align="right"> 
        <%= ejbcawebbean.getText("PASSWORD") %> <br> &nbsp;
      </td>
      <td width="50%"> 
        <input type="text" name="<%=TEXTFIELD_PASSWORD%>" size="40" maxlength="1024" 
           value="<% if(profiledata[Profile.PASSWORD][Profile.VALUE]!= null) out.write(profiledata[Profile.PASSWORD][Profile.VALUE]); %>"><br>
           <%= ejbcawebbean.getText("REQUIRED") %>
           <input type="checkbox" name="<%=CHECKBOX_REQUIRED_PASSWORD %>" value="<%=CHECKBOX_VALUE %>" 
           <% if(profiledata[Profile.PASSWORD][Profile.ISREQUIRED]!= null)
               if(profiledata[Profile.PASSWORD][Profile.ISREQUIRED].equals(Profile.TRUE))
                 out.write("CHECKED");
           %>> 
        &nbsp;&nbsp;<%= ejbcawebbean.getText("CHANGEABLE") %> 
        <input type="checkbox" name="<%=CHECKBOX_CHANGEABLE_PASSWORD %>" value="<%=CHECKBOX_VALUE %>" 
           <% if(profiledata[Profile.PASSWORD][Profile.CHANGEABLE]!= null)
               if(profiledata[Profile.PASSWORD][Profile.CHANGEABLE].equals(Profile.TRUE))
                 out.write("CHECKED");
           %>> 
      </td>
    <tr  id="Row0"> 
      <td width="50%"  align="right"> 
        <%= ejbcawebbean.getText("CLEARTEXTPASSWORD") %> <br>&nbsp;
      </td>
      <td width="50%"> 
        <% used = false;
            if(profiledata[Profile.CLEARTEXTPASSWORD][Profile.USE]!= null)
               if(profiledata[Profile.CLEARTEXTPASSWORD][Profile.USE].equals(Profile.TRUE)) 
                 used=true; %>
        <input type="checkbox" name="<%=CHECKBOX_CLEARTEXTPASSWORD%>"  value="<%=CHECKBOX_VALUE %>" <% if(!used) out.write(" disabled "); %>
           <% if(profiledata[Profile.CLEARTEXTPASSWORD][Profile.VALUE]!= null && used)
               if(profiledata[Profile.CLEARTEXTPASSWORD][Profile.VALUE].equals(Profile.TRUE))
                 out.write("CHECKED");
           %>> <br>
        <%= ejbcawebbean.getText("USE") %> 
        <input type="checkbox" name="<%=CHECKBOX_USE_CLEARTEXTPASSWORD %>" value="<%=CHECKBOX_VALUE %>" onclick="checkusecheckbox('<%=CHECKBOX_USE_CLEARTEXTPASSWORD %>', '<%=CHECKBOX_CLEARTEXTPASSWORD%>', '<%=CHECKBOX_REQUIRED_CLEARTEXTPASSWORD %>')"
           <%  if(used)
                 out.write(" CHECKED ");
           %>> &nbsp;&nbsp; 
        <%= ejbcawebbean.getText("REQUIRED") %>
        <input type="checkbox" name="<%=CHECKBOX_REQUIRED_CLEARTEXTPASSWORD %>" value="<%=CHECKBOX_VALUE %>" <% if(!used) out.write(" disabled "); %>
           <% if(profiledata[Profile.CLEARTEXTPASSWORD][Profile.ISREQUIRED]!= null && used)
               if(profiledata[Profile.CLEARTEXTPASSWORD][Profile.ISREQUIRED].equals(Profile.TRUE))
                 out.write("CHECKED");
           %>> 

      </td>
    <tr  id="Row1"> 
      <td width="50%"  align="right"> 
        <%= ejbcawebbean.getText("COMMONNAME") %> <br>&nbsp;

      </td>
      <td width="50%"> 
        <% used = false;
            if(profiledata[Profile.COMMONNAME][Profile.USE]!= null)
               if(profiledata[Profile.COMMONNAME][Profile.USE].equals(Profile.TRUE)) 
                 used=true; %>
        <input type="text" name="<%=TEXTFIELD_COMMONNAME%>" size="40" maxlength="1024" <% if(!used) out.write(" disabled "); %>
           value="<% if(profiledata[Profile.COMMONNAME][Profile.VALUE]!= null && used) out.write(profiledata[Profile.COMMONNAME][Profile.VALUE]); %>"><br>
        <%= ejbcawebbean.getText("USE") %> 
        <input type="checkbox" name="<%=CHECKBOX_USE_COMMONNAME %>" value="<%=CHECKBOX_VALUE %>" onclick="checkusetextfield('<%=CHECKBOX_USE_COMMONNAME %>', '<%=TEXTFIELD_COMMONNAME%>', '<%=CHECKBOX_REQUIRED_COMMONNAME %>', '<%=CHECKBOX_CHANGEABLE_COMMONNAME %>')"
           <%if(used)
                 out.write("CHECKED");
           %>>&nbsp;&nbsp;
            <%= ejbcawebbean.getText("REQUIRED") %>
            <input type="checkbox" name="<%=CHECKBOX_REQUIRED_COMMONNAME %>" value="<%=CHECKBOX_VALUE %>" <% if(!used) out.write(" disabled "); %>
           <% if(profiledata[Profile.COMMONNAME][Profile.ISREQUIRED]!= null && used)
               if(profiledata[Profile.COMMONNAME][Profile.ISREQUIRED].equals(Profile.TRUE))
                 out.write("CHECKED");
           %>> 
        &nbsp;&nbsp;<%= ejbcawebbean.getText("CHANGEABLE") %> 
        <input type="checkbox" name="<%=CHECKBOX_CHANGEABLE_COMMONNAME %>" value="<%=CHECKBOX_VALUE %>" <% if(!used) out.write(" disabled "); %>
           <% if(profiledata[Profile.COMMONNAME][Profile.CHANGEABLE]!= null && used)
               if(profiledata[Profile.COMMONNAME][Profile.CHANGEABLE].equals(Profile.TRUE))
                 out.write("CHECKED");
           %>> 
      </td>
    </tr>
    <tr  id="Row0"> 
      <td width="50%" align="right"> 
        <%= ejbcawebbean.getText("ORGANIZATIONUNIT") %> <br>&nbsp;
      </td>
      <td width="50%"> 
        <% used = false;
            if(profiledata[Profile.ORGANIZATIONUNIT][Profile.USE]!= null)
               if(profiledata[Profile.ORGANIZATIONUNIT][Profile.USE].equals(Profile.TRUE)) 
                 used=true; %>
        <input type="text" name="<%=TEXTFIELD_ORGANIZATIONUNIT%>" size="40" maxlength="1024" <% if(!used) out.write(" disabled "); %>
           value="<% if(profiledata[Profile.ORGANIZATIONUNIT][Profile.VALUE]!= null && used) out.write(profiledata[Profile.ORGANIZATIONUNIT][Profile.VALUE]); %>"><br>
        <%= ejbcawebbean.getText("USE") %> 
        <input type="checkbox" name="<%=CHECKBOX_USE_ORGANIZATIONUNIT %>" value="<%=CHECKBOX_VALUE %>" onclick="checkusetextfield('<%=CHECKBOX_USE_ORGANIZATIONUNIT %>', '<%=TEXTFIELD_ORGANIZATIONUNIT%>', '<%=CHECKBOX_REQUIRED_ORGANIZATIONUNIT %>', '<%=CHECKBOX_CHANGEABLE_ORGANIZATIONUNIT %>')"
           <% if(used)
                 out.write("CHECKED");
           %>>&nbsp;&nbsp;
        <%= ejbcawebbean.getText("REQUIRED") %>
        <input type="checkbox" name="<%=CHECKBOX_REQUIRED_ORGANIZATIONUNIT %>" value="<%=CHECKBOX_VALUE %>" <% if(!used) out.write(" disabled "); %>
           <% if(profiledata[Profile.ORGANIZATIONUNIT][Profile.ISREQUIRED]!= null && used)
               if(profiledata[Profile.ORGANIZATIONUNIT][Profile.ISREQUIRED].equals(Profile.TRUE))
                 out.write("CHECKED");
           %>> 
        &nbsp;&nbsp;<%= ejbcawebbean.getText("CHANGEABLE") %> 
        <input type="checkbox" name="<%=CHECKBOX_CHANGEABLE_ORGANIZATIONUNIT  %>" value="<%=CHECKBOX_VALUE %>" <% if(!used) out.write(" disabled "); %>
           <% if(profiledata[Profile.ORGANIZATIONUNIT][Profile.CHANGEABLE]!= null && used)
               if(profiledata[Profile.ORGANIZATIONUNIT][Profile.CHANGEABLE].equals(Profile.TRUE))
                 out.write("CHECKED");
           %>> 
      </td>
    </tr>
    <tr  id="Row1"> 
      <td width="50%" align="right"> 
        <%= ejbcawebbean.getText("ORGANIZATION") %> <br>&nbsp;
      </td>
      <td width="50%"> 
        <% used = false;
            if(profiledata[Profile.ORGANIZATION][Profile.USE]!= null)
               if(profiledata[Profile.ORGANIZATION][Profile.USE].equals(Profile.TRUE)) 
                 used=true; %>
        <input type="text" name="<%=TEXTFIELD_ORGANIZATION%>" size="40" maxlength="1024" <% if(!used) out.write(" disabled "); %>
           value="<% if(profiledata[Profile.ORGANIZATION][Profile.VALUE]!= null && used) out.write(profiledata[Profile.ORGANIZATION][Profile.VALUE]); %>"><br>
        <%= ejbcawebbean.getText("USE") %> 
        <input type="checkbox" name="<%=CHECKBOX_USE_ORGANIZATION %>" value="<%=CHECKBOX_VALUE %>" onclick="checkusetextfield('<%=CHECKBOX_USE_ORGANIZATION %>', '<%=TEXTFIELD_ORGANIZATION%>', '<%=CHECKBOX_REQUIRED_ORGANIZATION %>','<%=CHECKBOX_CHANGEABLE_ORGANIZATION %>')"
           <% if(used)
                 out.write("CHECKED");
           %>>&nbsp;&nbsp;
           <%= ejbcawebbean.getText("REQUIRED") %>
        <input type="checkbox" name="<%=CHECKBOX_REQUIRED_ORGANIZATION %>" value="<%=CHECKBOX_VALUE %>" <% if(!used) out.write(" disabled "); %>
           <% if(profiledata[Profile.ORGANIZATION][Profile.ISREQUIRED]!= null && used)
               if(profiledata[Profile.ORGANIZATION][Profile.ISREQUIRED].equals(Profile.TRUE))
                 out.write("CHECKED");
           %>> 
        &nbsp;&nbsp;<%= ejbcawebbean.getText("CHANGEABLE") %> 
        <input type="checkbox" name="<%=CHECKBOX_CHANGEABLE_ORGANIZATION  %>" value="<%=CHECKBOX_VALUE %>" <% if(!used) out.write(" disabled "); %>
           <% if(profiledata[Profile.ORGANIZATION][Profile.CHANGEABLE]!= null && used)
               if(profiledata[Profile.ORGANIZATION][Profile.CHANGEABLE].equals(Profile.TRUE))
                 out.write("CHECKED");
           %>> 
      </td>
    </tr>
    <tr  id="Row0"> 
      <td width="50%" align="right"> 
        <%= ejbcawebbean.getText("LOCALE") %> <br>&nbsp;
      </td>
      <td width="50%"> 
        <% used = false;
            if(profiledata[Profile.LOCALE][Profile.USE]!= null)
               if(profiledata[Profile.LOCALE][Profile.USE].equals(Profile.TRUE)) 
                 used=true; %>
        <input type="text" name="<%=TEXTFIELD_LOCALE%>" size="40" maxlength="1024" <% if(!used) out.write(" disabled "); %>
           value="<% if(profiledata[Profile.LOCALE][Profile.VALUE]!= null && used) out.write(profiledata[Profile.LOCALE][Profile.VALUE]); %>"><br>
        <%= ejbcawebbean.getText("USE") %> 
        <input type="checkbox" name="<%=CHECKBOX_USE_LOCALE %>" value="<%=CHECKBOX_VALUE %>" onclick="checkusetextfield('<%=CHECKBOX_USE_LOCALE %>', '<%=TEXTFIELD_LOCALE%>', '<%=CHECKBOX_REQUIRED_LOCALE %>', '<%=CHECKBOX_CHANGEABLE_LOCALE %>')"
           <% if(used)
                 out.write("CHECKED");
           %>>&nbsp;&nbsp;
                <%= ejbcawebbean.getText("REQUIRED") %>
        <input type="checkbox" name="<%=CHECKBOX_REQUIRED_LOCALE %>" value="<%=CHECKBOX_VALUE %>"  <% if(!used) out.write(" disabled "); %>
           <% if(profiledata[Profile.LOCALE][Profile.ISREQUIRED]!= null && used)
               if(profiledata[Profile.LOCALE][Profile.ISREQUIRED].equals(Profile.TRUE))
                 out.write("CHECKED");
           %>> 
        &nbsp;&nbsp;<%= ejbcawebbean.getText("CHANGEABLE") %> 
        <input type="checkbox" name="<%=CHECKBOX_CHANGEABLE_LOCALE  %>" value="<%=CHECKBOX_VALUE %>"  <% if(!used) out.write(" disabled "); %>
           <% if(profiledata[Profile.LOCALE][Profile.CHANGEABLE]!= null && used)
               if(profiledata[Profile.LOCALE][Profile.CHANGEABLE].equals(Profile.TRUE))
                 out.write("CHECKED");
           %>> 
      </td>
    </tr>
    <tr  id="Row1"> 
      <td width="50%" align="right"> 
        <%= ejbcawebbean.getText("STATE") %> <br>&nbsp;
      </td>
      <td width="50%"> 
        <% used = false;
            if(profiledata[Profile.STATE][Profile.USE]!= null)
               if(profiledata[Profile.STATE][Profile.USE].equals(Profile.TRUE)) 
                 used=true; %>
        <input type="text" name="<%=TEXTFIELD_STATE%>" size="40" maxlength="1024" <% if(!used) out.write(" disabled "); %>
           value="<% if(profiledata[Profile.STATE][Profile.VALUE]!= null && used) out.write(profiledata[Profile.STATE][Profile.VALUE]); %>"><br>
        <%= ejbcawebbean.getText("USE") %> 
        <input type="checkbox" name="<%=CHECKBOX_USE_STATE %>" value="<%=CHECKBOX_VALUE %>" onclick="checkusetextfield('<%=CHECKBOX_USE_STATE %>', '<%=TEXTFIELD_STATE%>', '<%=CHECKBOX_REQUIRED_STATE %>', '<%=CHECKBOX_CHANGEABLE_STATE %>')"
           <% if(used)
                 out.write("CHECKED");
           %>>&nbsp;&nbsp;
               <%= ejbcawebbean.getText("REQUIRED") %>
        <input type="checkbox" name="<%=CHECKBOX_REQUIRED_STATE %>" value="<%=CHECKBOX_VALUE %>" <% if(!used) out.write(" disabled "); %>
           <% if(profiledata[Profile.STATE][Profile.ISREQUIRED]!= null && used)
               if(profiledata[Profile.STATE][Profile.ISREQUIRED].equals(Profile.TRUE))
                 out.write("CHECKED");
           %>> 
        &nbsp;&nbsp;<%= ejbcawebbean.getText("CHANGEABLE") %> 
        <input type="checkbox" name="<%=CHECKBOX_CHANGEABLE_STATE  %>" value="<%=CHECKBOX_VALUE %>" <% if(!used) out.write(" disabled "); %>
           <% if(profiledata[Profile.STATE][Profile.CHANGEABLE]!= null && used)
               if(profiledata[Profile.STATE][Profile.CHANGEABLE].equals(Profile.TRUE))
                 out.write("CHECKED");
           %>> 
      </td>
    </tr>
    <tr  id="Row0"> 
      <td width="50%" align="right"> 
        <%= ejbcawebbean.getText("COUNTRY") %> <br>&nbsp;
      </td>
      <td width="50%"> 
        <% used = false;
            if(profiledata[Profile.COUNTRY][Profile.USE]!= null)
               if(profiledata[Profile.COUNTRY][Profile.USE].equals(Profile.TRUE)) 
                 used=true; %>
        <input type="text" name="<%=TEXTFIELD_COUNTRY%>" size="2" maxlength="1024" <% if(!used) out.write(" disabled "); %>
           value="<% if(profiledata[Profile.COUNTRY][Profile.VALUE]!= null && used) out.write(profiledata[Profile.COUNTRY][Profile.VALUE]); %>"><br>
        <%= ejbcawebbean.getText("USE") %> 
        <input type="checkbox" name="<%=CHECKBOX_USE_COUNTRY %>" value="<%=CHECKBOX_VALUE %>" onclick="checkusetextfield('<%=CHECKBOX_USE_COUNTRY %>', '<%=TEXTFIELD_COUNTRY%>', '<%=CHECKBOX_REQUIRED_COUNTRY %>', '<%=CHECKBOX_CHANGEABLE_COUNTRY %>')"
           <% if(used)
                 out.write("CHECKED");
           %>>&nbsp;&nbsp;
                <%= ejbcawebbean.getText("REQUIRED") %>
        <input type="checkbox" name="<%=CHECKBOX_REQUIRED_COUNTRY%>" value="<%=CHECKBOX_VALUE %>" <% if(!used) out.write(" disabled "); %>
           <% if(profiledata[Profile.COUNTRY][Profile.ISREQUIRED]!= null && used)
               if(profiledata[Profile.COUNTRY][Profile.ISREQUIRED].equals(Profile.TRUE))
                 out.write("CHECKED");
           %>> 
        &nbsp;&nbsp;<%= ejbcawebbean.getText("CHANGEABLE") %> 
        <input type="checkbox" name="<%=CHECKBOX_CHANGEABLE_COUNTRY  %>" value="<%=CHECKBOX_VALUE %>" <% if(!used) out.write(" disabled "); %>
           <% if(profiledata[Profile.COUNTRY][Profile.CHANGEABLE]!= null && used)
               if(profiledata[Profile.COUNTRY][Profile.CHANGEABLE].equals(Profile.TRUE))
                 out.write("CHECKED");
           %>> 
      </td>
    </tr>
    <tr  id="Row1"> 
      <td width="50%" align="right"> 
        <%= ejbcawebbean.getText("EMAIL") %> <br>&nbsp;
      </td>
      <td width="50%"> 
        <% used = false;
            if(profiledata[Profile.EMAIL][Profile.USE]!= null)
               if(profiledata[Profile.EMAIL][Profile.USE].equals(Profile.TRUE)) 
                 used=true; %>
        <input type="text" name="<%=TEXTFIELD_EMAIL%>" size="40" maxlength="1024"  <% if(!used) out.write(" disabled "); %>
           value="<% if(profiledata[Profile.EMAIL][Profile.VALUE]!= null && used) out.write(profiledata[Profile.EMAIL][Profile.VALUE]); %>"><br>
        <%= ejbcawebbean.getText("USE") %> 
        <input type="checkbox" name="<%=CHECKBOX_USE_EMAIL %>" value="<%=CHECKBOX_VALUE %>" onclick="checkusetextfield('<%=CHECKBOX_USE_EMAIL %>', '<%=TEXTFIELD_EMAIL%>', '<%=CHECKBOX_REQUIRED_EMAIL %>', '<%=CHECKBOX_CHANGEABLE_EMAIL %>')"
           <% if(used)
                 out.write("CHECKED");
           %>>&nbsp;&nbsp;
               <%= ejbcawebbean.getText("REQUIRED") %>
        <input type="checkbox" name="<%=CHECKBOX_REQUIRED_EMAIL%>" value="<%=CHECKBOX_VALUE %>"  <% if(!used) out.write(" disabled "); %>
           <% if(profiledata[Profile.EMAIL][Profile.ISREQUIRED]!= null && used)
               if(profiledata[Profile.EMAIL][Profile.ISREQUIRED].equals(Profile.TRUE))
                 out.write("CHECKED");
           %>> 
        &nbsp;&nbsp;<%= ejbcawebbean.getText("CHANGEABLE") %> 
        <input type="checkbox" name="<%=CHECKBOX_CHANGEABLE_EMAIL  %>" value="<%=CHECKBOX_VALUE %>"  <% if(!used) out.write(" disabled "); %>
           <% if(profiledata[Profile.EMAIL][Profile.CHANGEABLE]!= null && used)
               if(profiledata[Profile.EMAIL][Profile.CHANGEABLE].equals(Profile.TRUE))
                 out.write("CHECKED");
           %>> 
      </td>
    </tr>
    <tr  id="Row0"> 
      <td width="50%" align="right"> 
        <%= ejbcawebbean.getText("DEFAULTCERTIFICATETYPE") %> <br>&nbsp;
      </td>
      <td width="50%"> 
        <select name="<%=SELECT_DEFAULTCERTTYPE %>" size="1" >
            <% for(int i=0; i < certificatetypenames.length;i++){
               int certtypeid = ejbcarabean.getCertificateTypeId(certificatetypenames[i]); %>
           <option <%  if(profiledata[Profile.DEFAULTCERTTYPE][Profile.VALUE] != null)
                          if(profiledata[Profile.DEFAULTCERTTYPE][Profile.VALUE].equals(Integer.toString(certtypeid)))
                            out.write(" selected "); %>
                    value='<%= certtypeid %>'><%= certificatetypenames[i] %>
           </option>
            <% } %>
        </select>
      </td>
    <tr  id="Row1"> 
      <td width="50%" align="right"> 
        <%= ejbcawebbean.getText("AVAILABLECERTIFICATETYPES") %> <br>&nbsp;
      </td>
      <td width="50%"> 
        <select name="<%=SELECT_AVAILABLECERTTYPES %>" size="7" multiple >
            <% String[] availablecerttypes = new RE(Profile.SPLITCHAR, false).split(profiledata[Profile.AVAILABLECERTTYPES][Profile.VALUE]); 
               for(int i=0; i < certificatetypenames.length;i++){
               int certtypeid = ejbcarabean.getCertificateTypeId(certificatetypenames[i]); %>
           <option <% for(int j=0;j< availablecerttypes.length;j++){
                         if(availablecerttypes[j].equals(Integer.toString(certtypeid)))
                            out.write(" selected "); 
                      }%>
                    value='<%= certtypeid%>'><%= certificatetypenames[i] %>
           </option>
            <% } %>
        </select>
      </td>
    </tr>
    <tr  id="Row0"> 
      <td width="50%" valign="top" align="right"><%= ejbcawebbean.getText("TYPES") %></td>
      <td width="50%" valign="top" align="right">&nbsp;</td>
    </tr>
    <tr  id="Row1"> 
      <td width="50%" align="right"> 
        <%= ejbcawebbean.getText("TYPEENDUSER") %> <br>&nbsp;
      </td>
      <td width="50%"> 
        <% used = false;
            if(profiledata[Profile.TYPE_ENDUSER][Profile.USE]!= null)
               if(profiledata[Profile.TYPE_ENDUSER][Profile.USE].equals(Profile.TRUE)) 
                 used=true; %>
        <input type="checkbox" name="<%=CHECKBOX_TYPEENDUSER%>" value="<%=CHECKBOX_VALUE %>" <% if(!used) out.write(" disabled "); %>
           <% if(profiledata[Profile.TYPE_ENDUSER][Profile.VALUE]!= null && used)
               if(profiledata[Profile.TYPE_ENDUSER][Profile.VALUE].equals(Profile.TRUE))
                 out.write("CHECKED");
           %>> <br>    
         <%= ejbcawebbean.getText("USE") %> 
        <input type="checkbox" name="<%=CHECKBOX_USE_TYPEENDUSER %>" value="<%=CHECKBOX_VALUE %>" onclick="checkusecheckbox('<%=CHECKBOX_USE_TYPEENDUSER %>', '<%=CHECKBOX_TYPEENDUSER%>', '<%=CHECKBOX_REQUIRED_TYPEENDUSER %>')"
           <% if(used)
                 out.write("CHECKED");
           %>>&nbsp;&nbsp;
        <%= ejbcawebbean.getText("REQUIRED") %>
        <input type="checkbox" name="<%=CHECKBOX_REQUIRED_TYPEENDUSER%>" value="<%=CHECKBOX_VALUE %>" <% if(!used) out.write(" disabled "); %>
           <% if(profiledata[Profile.TYPE_ENDUSER][Profile.ISREQUIRED]!= null && used)
               if(profiledata[Profile.TYPE_ENDUSER][Profile.ISREQUIRED].equals(Profile.TRUE))
                 out.write("CHECKED");
           %>> 
      </td>
    </tr>
    <tr  id="Row0"> 
      <td width="50%" align="right"> 
        <%= ejbcawebbean.getText("TYPERA") %> <br>&nbsp;
      </td>
      <td width="50%"> 
        <% used = false;
            if(profiledata[Profile.TYPE_RA][Profile.USE]!= null)
               if(profiledata[Profile.TYPE_RA][Profile.USE].equals(Profile.TRUE)) 
                 used=true; %>
        <input type="checkbox" name="<%=CHECKBOX_TYPERA%>" value="<%=CHECKBOX_VALUE %>"  <% if(!used) out.write(" disabled "); %>
           <% if(profiledata[Profile.TYPE_RA][Profile.VALUE]!= null && used)
               if(profiledata[Profile.TYPE_RA][Profile.VALUE].equals(Profile.TRUE))
                 out.write("CHECKED");
           %>> <br> 
        <%= ejbcawebbean.getText("USE") %> 
        <input type="checkbox" name="<%=CHECKBOX_USE_TYPERA %>" value="<%=CHECKBOX_VALUE %>" onclick="checkusecheckbox('<%=CHECKBOX_USE_TYPERA %>', '<%=CHECKBOX_TYPERA%>', '<%=CHECKBOX_REQUIRED_TYPERA %>')"
           <% if(used)
                 out.write("CHECKED");
           %>>&nbsp;&nbsp;
       <%= ejbcawebbean.getText("REQUIRED") %>
        <input type="checkbox" name="<%=CHECKBOX_REQUIRED_TYPERA%>" value="<%=CHECKBOX_VALUE %>"  <% if(!used) out.write(" disabled "); %>
           <% if(profiledata[Profile.TYPE_RA][Profile.ISREQUIRED]!= null && used)
               if(profiledata[Profile.TYPE_RA][Profile.ISREQUIRED].equals(Profile.TRUE))
                 out.write("CHECKED");
           %>> 
      </td>
    </tr>
    <tr  id="Row1"> 
      <td width="50%" align="right"> 
        <%= ejbcawebbean.getText("TYPERAADMIN") %> <br>&nbsp;
      </td>
      <td width="50%"> 
        <% used = false;
            if(profiledata[Profile.TYPE_RAADMIN][Profile.USE]!= null)
               if(profiledata[Profile.TYPE_RAADMIN][Profile.USE].equals(Profile.TRUE)) 
                 used=true; %>
        <input type="checkbox" name="<%=CHECKBOX_TYPERAADMIN%>" value="<%=CHECKBOX_VALUE %>"  <% if(!used) out.write(" disabled "); %>
           <% if(profiledata[Profile.TYPE_RAADMIN][Profile.VALUE]!= null && used)
               if(profiledata[Profile.TYPE_RAADMIN][Profile.VALUE].equals(Profile.TRUE))
                 out.write("CHECKED");
           %>> <br>
        <%= ejbcawebbean.getText("USE") %> 
        <input type="checkbox" name="<%=CHECKBOX_USE_TYPERAADMIN %>" value="<%=CHECKBOX_VALUE %>" onclick="checkusecheckbox('<%=CHECKBOX_USE_TYPERAADMIN %>', '<%=CHECKBOX_TYPERAADMIN%>', '<%=CHECKBOX_REQUIRED_TYPERAADMIN %>')"
           <% if(used)
                 out.write("CHECKED");
           %>>&nbsp;&nbsp;
         <%= ejbcawebbean.getText("REQUIRED") %>
        <input type="checkbox" name="<%=CHECKBOX_REQUIRED_TYPERAADMIN%>" value="<%=CHECKBOX_VALUE %>"  <% if(!used) out.write(" disabled "); %>
           <% if(profiledata[Profile.TYPE_RAADMIN][Profile.ISREQUIRED]!= null && used)
               if(profiledata[Profile.TYPE_RAADMIN][Profile.ISREQUIRED].equals(Profile.TRUE))
                 out.write("CHECKED");
           %>> 
      </td>
    </tr>
    <tr  id="Row0"> 
      <td width="50%" align="right"> 
        <%= ejbcawebbean.getText("TYPECA") %> <br>&nbsp;
      </td>
      <td width="50%"> 
        <% used = false;
            if(profiledata[Profile.TYPE_CA][Profile.USE]!= null)
               if(profiledata[Profile.TYPE_CA][Profile.USE].equals(Profile.TRUE)) 
                 used=true; %>
        <input type="checkbox" name="<%=CHECKBOX_TYPECA%>" value="<%=CHECKBOX_VALUE %>" <% if(!used) out.write(" disabled "); %>
           <% if(profiledata[Profile.TYPE_CA][Profile.VALUE]!= null && used)
               if(profiledata[Profile.TYPE_CA][Profile.VALUE].equals(Profile.TRUE))
                 out.write("CHECKED");
           %>> <br>
        <%= ejbcawebbean.getText("USE") %> 
        <input type="checkbox" name="<%=CHECKBOX_USE_TYPECA %>" value="<%=CHECKBOX_VALUE %>" onclick="checkusecheckbox('<%=CHECKBOX_USE_TYPECA %>', '<%=CHECKBOX_TYPECA%>', '<%=CHECKBOX_REQUIRED_TYPECA %>')"
           <%  if(used)
                 out.write("CHECKED");
           %>>&nbsp;&nbsp;
        <%= ejbcawebbean.getText("REQUIRED") %>
        <input type="checkbox" name="<%=CHECKBOX_REQUIRED_TYPECA%>" value="<%=CHECKBOX_VALUE %>" <% if(!used) out.write(" disabled "); %>
           <% if(profiledata[Profile.TYPE_CA][Profile.ISREQUIRED]!= null && used)
               if(profiledata[Profile.TYPE_CA][Profile.ISREQUIRED].equals(Profile.TRUE))
                 out.write("CHECKED");
           %>> 
      </td>
    </tr>
    <tr  id="Row1"> 
      <td width="50%" align="right"> 
        <%= ejbcawebbean.getText("TYPECAADMIN") %> <br>&nbsp;
      </td>
      <td width="50%"> 
        <% used = false;
            if(profiledata[Profile.TYPE_CAADMIN][Profile.USE]!= null)
               if(profiledata[Profile.TYPE_CAADMIN][Profile.USE].equals(Profile.TRUE)) 
                 used=true; %>
        <input type="checkbox" name="<%=CHECKBOX_TYPECAADMIN%>" value="<%=CHECKBOX_VALUE %>"  <% if(!used) out.write(" disabled "); %>
           <% if(profiledata[Profile.TYPE_CAADMIN][Profile.VALUE]!= null && used)
               if(profiledata[Profile.TYPE_CAADMIN][Profile.VALUE].equals(Profile.TRUE))
                 out.write("CHECKED");
           %>> <br>
        <%= ejbcawebbean.getText("USE") %> 
        <input type="checkbox" name="<%=CHECKBOX_USE_TYPECAADMIN %>" value="<%=CHECKBOX_VALUE %>" onclick="checkusecheckbox('<%=CHECKBOX_USE_TYPECAADMIN %>', '<%=CHECKBOX_TYPECAADMIN%>', '<%=CHECKBOX_REQUIRED_TYPECAADMIN %>')"
           <%  if(used)
                 out.write("CHECKED");
           %>>&nbsp;&nbsp;
        <%= ejbcawebbean.getText("REQUIRED") %>
        <input type="checkbox" name="<%=CHECKBOX_REQUIRED_TYPECAADMIN%>" value="<%=CHECKBOX_VALUE %>" <% if(!used) out.write(" disabled "); %>
           <% if(profiledata[Profile.TYPE_CAADMIN][Profile.ISREQUIRED]!= null && used)
               if(profiledata[Profile.TYPE_CAADMIN][Profile.ISREQUIRED].equals(Profile.TRUE))
                 out.write("CHECKED");
           %>> 
      </td>
    </tr>
    <tr  id="Row0"> 
      <td width="50%" align="right"> 
        <%= ejbcawebbean.getText("TYPEROOTCA") %> <br>&nbsp;
      </td>
      <td width="50%"> 
        <% used = false;
            if(profiledata[Profile.TYPE_ROOTCA][Profile.USE]!= null)
               if(profiledata[Profile.TYPE_ROOTCA][Profile.USE].equals(Profile.TRUE)) 
                 used=true; %>
        <input type="checkbox" name="<%=CHECKBOX_TYPEROOTCA%>" value="<%=CHECKBOX_VALUE %>"  <% if(!used) out.write(" disabled "); %>
           <% if(profiledata[Profile.TYPE_ROOTCA][Profile.VALUE]!= null && used)
               if(profiledata[Profile.TYPE_ROOTCA][Profile.VALUE].equals(Profile.TRUE))
                 out.write("CHECKED");
           %>> <br>
        <%= ejbcawebbean.getText("USE") %> 
        <input type="checkbox" name="<%=CHECKBOX_USE_TYPEROOTCA %>" value="<%=CHECKBOX_VALUE %>" onclick="checkusecheckbox('<%=CHECKBOX_USE_TYPEROOTCA %>', '<%=CHECKBOX_TYPEROOTCA%>', '<%=CHECKBOX_REQUIRED_TYPEROOTCA %>')"
           <%   if(used)
                 out.write("CHECKED");
           %>>&nbsp;&nbsp;
        <%= ejbcawebbean.getText("REQUIRED") %>
        <input type="checkbox" name="<%=CHECKBOX_REQUIRED_TYPEROOTCA%>" value="<%=CHECKBOX_VALUE %>" <% if(!used) out.write(" disabled "); %>
           <% if(profiledata[Profile.TYPE_ROOTCA][Profile.ISREQUIRED]!= null && used)
               if(profiledata[Profile.TYPE_ROOTCA][Profile.ISREQUIRED].equals(Profile.TRUE))
                 out.write("CHECKED");
           %>> 
      </td>
    </tr>
    <tr  id="Row0"> 
      <td width="49%" valign="top">&nbsp;</td>
      <td width="51%" valign="top"> 
        <input type="submit" name="<%= BUTTON_SAVE %>" onClick='return checkallfields()' value="<%= ejbcawebbean.getText("SAVE") %>" >
        <input type="submit" name="<%= BUTTON_CANCEL %>" value="<%= ejbcawebbean.getText("CANCEL") %>">
      </td>
    </tr>
  </table>
 </form>