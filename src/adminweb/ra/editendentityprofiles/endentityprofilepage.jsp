<% profiledata = ejbcarabean.getEndEntityProfile(profile);
   String[] certificateprofilenames = ejbcarabean.getCertificateProfileNames();
   boolean used = false;

   String[] subjectfieldtexts = {"","","","OLDEMAILDN","COMMONNAME","SERIALNUMBER","TITLE","ORGANIZATIONUNIT","ORGANIZATION","LOCALE","STATE","DOMAINCOMPONENT","COUNTRY"
                                , "RFC822NAME", "DNSNAME", "IPADDRESS", "OTHERNAME", "UNIFORMRESOURCEID", "X400ADDRESS", "DIRECTORYNAME"
                                ,"EDIPARTNAME", "REGISTEREDID"};

   String[] tokentexts = RAInterfaceBean.tokentexts;
   int[] tokenids = RAInterfaceBean.tokenids;
   boolean emailfieldexists = false;
%>
<SCRIPT language="JavaScript">

  <!-- // Method to check all textfields for valid input -->
<!--  
    var numbersubjectdnfields = <%= profiledata.getSubjectDNFieldOrderLength()%>
    var dnfieldtypes = new Array(<%= profiledata.getSubjectDNFieldOrderLength()%>);
    <% for(int i=0; i < profiledata.getSubjectDNFieldOrderLength(); i++){ %>
    dnfieldtypes[<%=i %>] = <%= profiledata.getSubjectDNFieldsInOrder(i)[EndEntityProfile.FIELDTYPE]%>
    <%}%>

    var numbersubjectaltnamesfields = <%= profiledata.getSubjectAltNameFieldOrderLength()%>
    var altnamesfieldtypes = new Array(<%= profiledata.getSubjectAltNameFieldOrderLength()%>);
    <% for(int i=0; i < profiledata.getSubjectAltNameFieldOrderLength(); i++){ %>
    altnamesfieldtypes[<%=i %>] = <%=profiledata.getSubjectAltNameFieldsInOrder(i)[EndEntityProfile.FIELDTYPE]%>
    <%}%>

function checkallfields(){
    var illegalfields = 0;
    var fieldname;

    if(!checkfieldforlegalcharswithchangeable("document.editprofile.<%=TEXTFIELD_USERNAME%>","<%= ejbcawebbean.getText("ONLYCHARACTERS2") %>"))
      illegalfields++;
 


    for(var i=0; i < numbersubjectdnfields; i++){
      if(dnfieldtypes[i] != <%= EndEntityProfile.OLDEMAILDN %>){
        fieldname = "document.editprofile.<%=TEXTFIELD_SUBJECTDN%>" + i;
        if(!checkfieldforlegaldncharswithchangeable(fieldname,"<%= ejbcawebbean.getText("ONLYDNCHARACTERS") %>"))
          illegalfields++;
      }    
    } 

    for(var i=0; i < numbersubjectaltnamesfields; i++){
      if(altnamesfieldtypes[i] != <%= EndEntityProfile.RFC822NAME%>){
        fieldname = "document.editprofile.<%=TEXTFIELD_SUBJECTALTNAME%>"+i;
        if(!checkfieldforlegaldncharswithchangeable(fieldname,"<%= ejbcawebbean.getText("ONLYDNCHARACTERS") %>"))
          illegalfields++;
      }    
    } 
  

    if(!checkfieldforlegalemailcharswithchangeable("document.editprofile.<%=TEXTFIELD_EMAIL%>","<%= ejbcawebbean.getText("ONLYEMAILCHARS") %>"))
      illegalfields++;
 
    if(document.editprofile.<%= SELECT_DEFAULTCERTPROFILE %>.options.selectedIndex == -1){
      alert("<%=  ejbcawebbean.getText("ADEFAULTCERTPROFILE") %>");
      illegalfields++;
    }

    if(illegalfields == 0){
      document.editprofile.<%= CHECKBOX_CLEARTEXTPASSWORD %>.disabled = false;
      document.editprofile.<%= CHECKBOX_REQUIRED_CLEARTEXTPASSWORD %>.disabled = false; 
      document.editprofile.<%= TEXTFIELD_EMAIL %>.disabled = false;
      document.editprofile.<%= CHECKBOX_USE_EMAIL %>.disabled = false;
      document.editprofile.<%= CHECKBOX_REQUIRED_ADMINISTRATOR %>.disabled = false;
      document.editprofile.<%= CHECKBOX_ADMINISTRATOR %>.disabled = false;
      document.editprofile.<%= CHECKBOX_REQUIRED_KEYRECOVERABLE %>.disabled = false;
      <% if(globalconfiguration.getEnableKeyRecovery()){ %>
      document.editprofile.<%= CHECKBOX_KEYRECOVERABLE %>.disabled = false;
      <% } %>
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
  <h3><%= ejbcawebbean.getText("PROFILE") + " : " + profile %> </h3>
</div>
<form name="editprofile" method="post" action="<%=THIS_FILENAME %>">
  <input type="hidden" name='<%= ACTION %>' value='<%=ACTION_EDIT_PROFILE %>'>
  <input type="hidden" name='<%= HIDDEN_PROFILENAME %>' value='<%=profile %>'>
  <table width="100%" border="0" cellspacing="3" cellpadding="3">
    <tr id="Row0"> 
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
        <A href="<%=THIS_FILENAME %>"><u><%= ejbcawebbean.getText("BACKTOPROFILES") %></u></A>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
        <A  onclick='displayHelpWindow("<%= ejbcawebbean.getHelpfileInfix("ra_help.html") + "#profiles"%>")'>
        <u><%= ejbcawebbean.getText("HELP") %></u> </A></div>
      </td>
    </tr>
    <tr id="Row0"> 
      <td width="5%" valign="top">
         &nbsp;
      </td>
      <td width="25%"  align="right"> 
        <%= ejbcawebbean.getText("USERNAME") %> <br>&nbsp;
      </td>
      <td width="70%"> 
        <input type="text" name="<%=TEXTFIELD_USERNAME%>" size="40" maxlength="1024" 
           value="<%= profiledata.getValue(EndEntityProfile.USERNAME,0)%>"><br>
           <%= ejbcawebbean.getText("REQUIRED") %>
           <input type="checkbox" name="<%=CHECKBOX_REQUIRED_USERNAME %>" value="<%=CHECKBOX_VALUE %>" 
           <%  if(profiledata.isRequired(EndEntityProfile.USERNAME,0))
                 out.write(" CHECKED ");
           %>> 
        &nbsp;&nbsp;<%= ejbcawebbean.getText("MODIFYABLE") %> 
        <input type="checkbox" name="<%=CHECKBOX_MODIFYABLE_USERNAME %>" value="<%=CHECKBOX_VALUE %>" 
           <%if(profiledata.isModifyable(EndEntityProfile.USERNAME,0))
                 out.write("CHECKED");
           %>> 
      </td>
    <tr  id="Row1"> 
      <td width="5%" valign="top">
         &nbsp;
      </td>
      <td width="25%"  align="right"> 
        <%= ejbcawebbean.getText("PASSWORD") %> <br> &nbsp;
      </td>
      <td width="70%"> 
        <input type="text" name="<%=TEXTFIELD_PASSWORD%>" size="40" maxlength="1024" 
           value="<%= profiledata.getValue(EndEntityProfile.PASSWORD,0)%>"><br>
           <%= ejbcawebbean.getText("REQUIRED") %>
           <input type="checkbox" name="<%=CHECKBOX_REQUIRED_PASSWORD %>" value="<%=CHECKBOX_VALUE %>" 
           <% if(profiledata.isRequired(EndEntityProfile.PASSWORD,0))
                 out.write("CHECKED");
           %>> 
        &nbsp;&nbsp;<%= ejbcawebbean.getText("MODIFYABLE") %> 
        <input type="checkbox" name="<%=CHECKBOX_MODIFYABLE_PASSWORD %>" value="<%=CHECKBOX_VALUE %>" 
           <% if(profiledata.isModifyable(EndEntityProfile.PASSWORD,0))
                 out.write("CHECKED");
           %>> 
      </td>
    <tr  id="Row0"> 
      <td width="5%" valign="top">
         &nbsp;
      </td>
      <td width="25%"  align="right"> 
        <%= ejbcawebbean.getText("USEINBATCH") %> <br>&nbsp;
      </td>
      <td width="70%"> 
        <% used = false;
             if(profiledata.getUse(EndEntityProfile.CLEARTEXTPASSWORD,0)) 
                 used=true; %>
        <input type="checkbox" name="<%=CHECKBOX_CLEARTEXTPASSWORD%>"  value="<%=CHECKBOX_VALUE %>" <% if(!used) out.write(" disabled "); %>
           <% if(profiledata.getValue(EndEntityProfile.CLEARTEXTPASSWORD,0).equals(EndEntityProfile.TRUE) && used)
                 out.write(" CHECKED ");
           %>> <br>
        <%= ejbcawebbean.getText("USE") %> 
        <input type="checkbox" name="<%=CHECKBOX_USE_CLEARTEXTPASSWORD %>" value="<%=CHECKBOX_VALUE %>" onclick="checkusecheckbox('<%=CHECKBOX_USE_CLEARTEXTPASSWORD %>', '<%=CHECKBOX_CLEARTEXTPASSWORD%>', '<%=CHECKBOX_REQUIRED_CLEARTEXTPASSWORD %>')"
           <%  if(used)
                 out.write(" CHECKED ");
           %>> &nbsp;&nbsp; 
        <%= ejbcawebbean.getText("REQUIRED") %>
        <input type="checkbox" name="<%=CHECKBOX_REQUIRED_CLEARTEXTPASSWORD %>" value="<%=CHECKBOX_VALUE %>" <% if(!used) out.write(" disabled "); %>
           <% if(profiledata.isRequired(EndEntityProfile.CLEARTEXTPASSWORD,0) && used)
                 out.write("CHECKED");
           %>> 

      </td>
    <tr  id="Row1"> 
      <td width="5%" valign="top">
        <%= ejbcawebbean.getText("SELECTFORREMOVAL") %>
      </td>
      <td width="25%"  align="right"> 
        <%= ejbcawebbean.getText("SUBJECTDNFIELDS") %> <br>&nbsp;
      </td>
      <td width="70%"> 
        <select name="<%=SELECT_ADDSUBJECTDN %>" size="1" >
            <% 
               for(int i=3; i < 13; i++){ %>
           <option  value='<%= i%>'><%= ejbcawebbean.getText(subjectfieldtexts[i]) %>
           </option>
            <% } %>
        </select>
        &nbsp;<input type="submit" name="<%= BUTTON_ADDSUBJECTDN %>" value="<%= ejbcawebbean.getText("ADD") %>">   
      </td> 
    </tr>
    <% numberofsubjectdnfields = profiledata.getSubjectDNFieldOrderLength();
       for(int i=0; i < numberofsubjectdnfields; i++){
         fielddata =  profiledata.getSubjectDNFieldsInOrder(i);
    %>
    <tr  id="Row<%=i%2%>"> 
      <td width="5%" valign="top">
        <input type="checkbox" name="<%=CHECKBOX_SELECTSUBJECTDN + i%>" value="<%=CHECKBOX_VALUE %>">      
      </td>
      <td width="25%" align="right"> 
        <%= ejbcawebbean.getText(subjectfieldtexts[fielddata[EndEntityProfile.FIELDTYPE]]) %> <br>&nbsp;
      </td>
      <td width="70%"> 
        <% if(fielddata[EndEntityProfile.FIELDTYPE] != EndEntityProfile.OLDEMAILDN ){ %>
        <input type="text" name="<%=TEXTFIELD_SUBJECTDN + i%>" size="40" maxlength="1024"
           value="<% if(profiledata.getValue(fielddata[EndEntityProfile.FIELDTYPE], fielddata[EndEntityProfile.NUMBER]) != null) out.write(profiledata.getValue(fielddata[EndEntityProfile.FIELDTYPE], fielddata[EndEntityProfile.NUMBER])); %>"><br> 
        <%= ejbcawebbean.getText("REQUIRED") %>
        <input type="checkbox" name="<%=CHECKBOX_REQUIRED_SUBJECTDN + i %>" value="<%=CHECKBOX_VALUE %>"
           <% if(profiledata.isRequired(fielddata[EndEntityProfile.FIELDTYPE], fielddata[EndEntityProfile.NUMBER]))
                 out.write("CHECKED");
           %>> 
        &nbsp;&nbsp;<%= ejbcawebbean.getText("MODIFYABLE") %> 
        <input type="checkbox" name="<%=CHECKBOX_MODIFYABLE_SUBJECTDN + i %>" value="<%=CHECKBOX_VALUE %>" 
           <% if(profiledata.isModifyable(fielddata[EndEntityProfile.FIELDTYPE], fielddata[EndEntityProfile.NUMBER]))
                 out.write("CHECKED");
           %>> 
        <% }
           else{ 
             emailfieldexists=true; 
              %>
           <%= ejbcawebbean.getText("REQUIRED") %>
        <input type="checkbox" name="<%=CHECKBOX_REQUIRED_SUBJECTDN + i %>" value="<%=CHECKBOX_VALUE %>"
           <% if(profiledata.isRequired(fielddata[EndEntityProfile.FIELDTYPE], fielddata[EndEntityProfile.NUMBER]))
                 out.write("CHECKED");
           %>>&nbsp;<%=ejbcawebbean.getText("SEEEMAILCONFIGURATION") %>
        <% }%>
      </td>
    </tr>
   <% } %>
    <tr  id="Row0"> 
      <td width="5%" valign="top">
        <input type="submit" name="<%= BUTTON_DELETESUBJECTDN %>" value="<%= ejbcawebbean.getText("REMOVE") %>">
      </td>
      <td width="25%"  align="right"> 
           &nbsp;&nbsp;
      </td>
      <td width="70%"> 
        &nbsp;&nbsp;
      </td> 
    </tr>
    <tr  id="Row1"> 
      <td width="5%" valign="top">
        <%= ejbcawebbean.getText("SELECTFORREMOVAL") %>
      </td>
      <td width="25%"  align="right"> 
        <%= ejbcawebbean.getText("SUBJECTALTNAMEFIELDS") %> <br>&nbsp;
      </td>
      <td width="70%"> 
        <select name="<%=SELECT_ADDSUBJECTALTNAME %>" size="1" >
            <% 
               for(int i=13; i < subjectfieldtexts.length; i++){ %>
           <option  value='<%= i%>'><%= ejbcawebbean.getText(subjectfieldtexts[i]) %>
           </option>
            <% } %>
        </select>
        &nbsp;<input type="submit" name="<%= BUTTON_ADDSUBJECTALTNAME %>" value="<%= ejbcawebbean.getText("ADD") %>"> 
      </td> 
    </tr>
    <% numberofsubjectdnfields = profiledata.getSubjectAltNameFieldOrderLength();
       for(int i=0; i < numberofsubjectdnfields; i++){
         fielddata =  profiledata.getSubjectAltNameFieldsInOrder(i);
    %>
    <tr  id="Row<%=i%2%>"> 
      <td width="5%" valign="top">
        <input type="checkbox" name="<%=CHECKBOX_SELECTSUBJECTALTNAME + i %>" value="<%=CHECKBOX_VALUE %>">      
      </td>
      <td width="25%" align="right"> 
        <%= ejbcawebbean.getText(subjectfieldtexts[fielddata[EndEntityProfile.FIELDTYPE]]) %> <br>&nbsp;
      </td>
      <td width="70%"> 
        <% if(fielddata[EndEntityProfile.FIELDTYPE] != EndEntityProfile.RFC822NAME ){ %>
        <input type="text" name="<%=TEXTFIELD_SUBJECTALTNAME + i%>" size="40" maxlength="1024" 
           value="<% if(profiledata.getValue(fielddata[EndEntityProfile.FIELDTYPE], fielddata[EndEntityProfile.NUMBER]) != null) out.write(profiledata.getValue(fielddata[EndEntityProfile.FIELDTYPE], fielddata[EndEntityProfile.NUMBER])); %>"><br>

        <%= ejbcawebbean.getText("REQUIRED") %>
        <input type="checkbox" name="<%=CHECKBOX_REQUIRED_SUBJECTALTNAME + i %>" value="<%=CHECKBOX_VALUE %>"
           <% if(profiledata.isRequired(fielddata[EndEntityProfile.FIELDTYPE], fielddata[EndEntityProfile.NUMBER]))
                 out.write("CHECKED");
           %>> 
        &nbsp;&nbsp;<%= ejbcawebbean.getText("MODIFYABLE") %> 
        <input type="checkbox" name="<%=CHECKBOX_MODIFYABLE_SUBJECTALTNAME + i %>" value="<%=CHECKBOX_VALUE %>" 
           <% if(profiledata.isModifyable(fielddata[EndEntityProfile.FIELDTYPE], fielddata[EndEntityProfile.NUMBER]))
                 out.write("CHECKED");
           %>> 
        <% }
           else{ 
             emailfieldexists=true; 
              %>
             <%= ejbcawebbean.getText("REQUIRED") %>
        <input type="checkbox" name="<%=CHECKBOX_REQUIRED_SUBJECTALTNAME + i %>" value="<%=CHECKBOX_VALUE %>"
           <% if(profiledata.isRequired(fielddata[EndEntityProfile.FIELDTYPE], fielddata[EndEntityProfile.NUMBER]))
                 out.write("CHECKED");
           %>>&nbsp;<%=ejbcawebbean.getText("SEEEMAILCONFIGURATION") %>
        <% }%>
      </td>
    </tr>
   <% } %>
    <tr  id="Row0"> 
      <td width="5%" valign="top">
        <input type="submit" name="<%= BUTTON_DELETESUBJECTALTNAME %>" value="<%= ejbcawebbean.getText("REMOVE") %>">
      </td>
      <td width="25%"  align="right"> 
           &nbsp;&nbsp;
      </td>
      <td width="70%"> 
        &nbsp;&nbsp;
      </td> 
    </tr>
    <tr  id="Row1"> 
      <td width="5%" valign="top">
         &nbsp;
      </td>
      <td width="25%" align="right"> 
        <%= ejbcawebbean.getText("EMAIL") %> <br>&nbsp;
      </td>
      <td width="70%"> 
        <% used = false;
           if(profiledata.getUse(EndEntityProfile.EMAIL,0) || emailfieldexists) 
             used=true; %>
        <input type="text" name="<%=TEXTFIELD_EMAIL%>" size="40" maxlength="1024"  <% if(!used) out.write(" disabled "); %>
           value="<% if(profiledata.getValue(EndEntityProfile.EMAIL,0) != null && used) out.write(profiledata.getValue(EndEntityProfile.EMAIL,0)); %>"><br>
        <%= ejbcawebbean.getText("USE") %> 
        <input type="checkbox" name="<%=CHECKBOX_USE_EMAIL %>" value="<%=CHECKBOX_VALUE %>" onclick="checkusetextfield('<%=CHECKBOX_USE_EMAIL %>', '<%=TEXTFIELD_EMAIL%>', '<%=CHECKBOX_REQUIRED_EMAIL %>', '<%=CHECKBOX_MODIFYABLE_EMAIL %>')"
           <% if(used)
                 out.write(" CHECKED ");
              if(emailfieldexists)
                 out.write(" disabled "); %>
           >&nbsp;&nbsp;
               <%= ejbcawebbean.getText("REQUIRED") %>
        <input type="checkbox" name="<%=CHECKBOX_REQUIRED_EMAIL%>" value="<%=CHECKBOX_VALUE %>"  <% if(!used) out.write(" disabled "); %>
           <% if(profiledata.isRequired(EndEntityProfile.EMAIL,0) && used)
                 out.write("CHECKED");
           %>> 
        &nbsp;&nbsp;<%= ejbcawebbean.getText("MODIFYABLE") %> 
        <input type="checkbox" name="<%=CHECKBOX_MODIFYABLE_EMAIL  %>" value="<%=CHECKBOX_VALUE %>"  <% if(!used) out.write(" disabled "); %>
           <% if(profiledata.isModifyable(EndEntityProfile.EMAIL,0) && used)
                 out.write("CHECKED");
           %>> 
      </td>
    </tr>
    <tr  id="Row0"> 
      <td width="5%" valign="top">
         &nbsp;
      </td>
      <td width="25%" align="right"> 
        <%= ejbcawebbean.getText("DEFAULTCERTIFICATEPROFILE") %> <br>&nbsp;
      </td>
      <td width="70%"> 
        <select name="<%=SELECT_DEFAULTCERTPROFILE %>" size="1" >
            <% for(int i=0; i < certificateprofilenames.length;i++){
               int certprofid = ejbcarabean.getCertificateProfileId(certificateprofilenames[i]); %>
           <option <%  if(profiledata.getValue(EndEntityProfile.DEFAULTCERTPROFILE ,0) != null)
                          if(profiledata.getValue(EndEntityProfile.DEFAULTCERTPROFILE ,0).equals(Integer.toString(certprofid)))
                            out.write(" selected "); %>
                    value='<%= certprofid %>'><%= certificateprofilenames[i] %>
           </option>
            <% } %>
        </select>
      </td>
    <tr  id="Row1"> 
      <td width="5%" valign="top">
         &nbsp;
      </td>
      <td width="25%" align="right"> 
        <%= ejbcawebbean.getText("AVAILABLECERTIFICATEPROF") %> <br>&nbsp;
      </td>
      <td width="70%"> 
        <select name="<%=SELECT_AVAILABLECERTPROFILES %>" size="7" multiple >
            <% String[] availablecertprofs = new RE(EndEntityProfile.SPLITCHAR, false).split(profiledata.getValue(EndEntityProfile.AVAILCERTPROFILES ,0)); 
               for(int i=0; i < certificateprofilenames.length;i++){
               int certprofid = ejbcarabean.getCertificateProfileId(certificateprofilenames[i]); %>
           <option <% for(int j=0;j< availablecertprofs.length;j++){
                         if(availablecertprofs[j].equals(Integer.toString(certprofid)))
                            out.write(" selected "); 
                      }%>
                    value='<%= certprofid%>'><%= certificateprofilenames[i] %>
           </option>
            <% } %>
        </select>
      </td>
    </tr>
    <tr  id="Row0"> 
      <td width="5%" valign="top">
         &nbsp;
      </td>
      <td width="25%" align="right"> 
        <%= ejbcawebbean.getText("DEFAULTTOKEN") %> <br>&nbsp;
      </td>
      <td width="70%"> 
        <select name="<%=SELECT_DEFAULTTOKENTYPE %>" size="1" >
            <% for(int i=0; i < tokentexts.length;i++){ %>
           <option <%  if(profiledata.getValue(EndEntityProfile.DEFKEYSTORE  ,0) != null)
                          if(profiledata.getValue(EndEntityProfile.DEFKEYSTORE  ,0).equals(Integer.toString(tokenids[i])))
                            out.write(" selected "); %>
                    value='<%= tokenids[i] %>'><%= ejbcawebbean.getText(tokentexts[i]) %>
           </option>
            <% } %>
        </select>
      </td>
    <tr  id="Row1"> 
      <td width="5%" valign="top">
         &nbsp;
      </td>
      <td width="25%" align="right"> 
        <%= ejbcawebbean.getText("AVAILABLETOKENS") %> <br>&nbsp;
      </td>
      <td width="70%"> 
        <select name="<%=SELECT_AVAILABLETOKENTYPES %>" size="7" multiple >
            <% String[] availabletokens = new RE(EndEntityProfile.SPLITCHAR, false).split(profiledata.getValue(EndEntityProfile.AVAILKEYSTORE, 0 )); 
               for(int i=0; i < tokentexts.length;i++){ %>
           <option <% for(int j=0;j< availabletokens.length;j++){
                         if(availabletokens[j].equals(Integer.toString(tokenids[i])))
                            out.write(" selected "); 
                      }%>
                    value='<%= tokenids[i]%>'><%= ejbcawebbean.getText(tokentexts[i])%>
           </option>
            <% } %>
        </select>
      </td>
    </tr>
    <tr  id="Row0">       
      <td width="5%" valign="top">
         &nbsp;
      </td>
      <td width="25%" valign="top" align="right"><%= ejbcawebbean.getText("TYPES") %></td>
      <td width="70%" valign="top" align="right">&nbsp;</td>
    </tr>
    <tr  id="Row1"> 
      <td width="5%" valign="top">
         &nbsp;
      </td>
      <td width="25%" align="right"> 
        <%= ejbcawebbean.getText("ADMINISTRATOR") %> <br>&nbsp;
      </td>
      <td width="70%"> 
        <% used = profiledata.getUse(EndEntityProfile.ADMINISTRATOR,0); %>
        <input type="checkbox" name="<%=CHECKBOX_ADMINISTRATOR%>" value="<%=CHECKBOX_VALUE %>" <% if(!used) out.write(" disabled "); %>
           <% if(profiledata.getValue(EndEntityProfile.ADMINISTRATOR,0) != null && used)
                 if(profiledata.getValue(EndEntityProfile.ADMINISTRATOR,0).equals(EndEntityProfile.TRUE))
                   out.write("CHECKED");
           %>> <br>    
         <%= ejbcawebbean.getText("USE") %> 
        <input type="checkbox" name="<%=CHECKBOX_USE_ADMINISTRATOR %>" value="<%=CHECKBOX_VALUE %>" onclick="checkusecheckbox('<%=CHECKBOX_USE_ADMINISTRATOR %>', '<%=CHECKBOX_ADMINISTRATOR%>', '<%=CHECKBOX_REQUIRED_ADMINISTRATOR %>')"
           <% if(used)
                 out.write("CHECKED");
           %>>&nbsp;&nbsp;
        <%= ejbcawebbean.getText("REQUIRED") %>
        <input type="checkbox" name="<%=CHECKBOX_REQUIRED_ADMINISTRATOR%>" value="<%=CHECKBOX_VALUE %>" <% if(!used) out.write(" disabled "); %>
           <% if(profiledata.isRequired(EndEntityProfile.ADMINISTRATOR,0) && used)
                out.write("CHECKED");
           %>> 
      </td>
    </tr>
<% if(globalconfiguration.getEnableKeyRecovery()){ %> 
    <tr  id="Row0"> 
      <td width="5%" valign="top">
         &nbsp;
      </td>
      <td width="25%" align="right"> 
        <%= ejbcawebbean.getText("KEYRECOVERABLE") %> <br>&nbsp;
      </td>
      <td width="70%"> 
        <% used = profiledata.getUse(EndEntityProfile.KEYRECOVERABLE,0); %>
        <input type="checkbox" name="<%=CHECKBOX_KEYRECOVERABLE%>" value="<%=CHECKBOX_VALUE %>" <% if(!used) out.write(" disabled "); %>
           <% if(profiledata.getValue(EndEntityProfile.KEYRECOVERABLE,0) != null && used)
                 if(profiledata.getValue(EndEntityProfile.KEYRECOVERABLE,0).equals(EndEntityProfile.TRUE))
                   out.write("CHECKED");
           %>> <br>    
         <%= ejbcawebbean.getText("USE") %> 
        <input type="checkbox" name="<%=CHECKBOX_USE_KEYRECOVERABLE %>" value="<%=CHECKBOX_VALUE %>" onclick="checkusecheckbox('<%=CHECKBOX_USE_KEYRECOVERABLE %>', '<%=CHECKBOX_KEYRECOVERABLE%>', '<%=CHECKBOX_REQUIRED_KEYRECOVERABLE %>')"
           <% if(used)
                 out.write("CHECKED");
           %>>&nbsp;&nbsp;
        <%= ejbcawebbean.getText("REQUIRED") %>
        <input type="checkbox" name="<%=CHECKBOX_REQUIRED_KEYRECOVERABLE%>" value="<%=CHECKBOX_VALUE %>" <% if(!used) out.write(" disabled "); %>
           <% if(profiledata.isRequired(EndEntityProfile.KEYRECOVERABLE,0) && used)
                out.write("CHECKED");
           %>> 
      </td>
    </tr>
   <% } %>
    <tr  id="Row1"> 
      <td width="5%" valign="top">
         &nbsp;
      </td>
      <td width="25%" align="right"> 
      <td width="70%" valign="top"> 
        <input type="submit" name="<%= BUTTON_SAVE %>" onClick='return checkallfields()' value="<%= ejbcawebbean.getText("SAVE") %>" >
        <input type="submit" name="<%= BUTTON_CANCEL %>" value="<%= ejbcawebbean.getText("CANCEL") %>">
      </td>
    </tr>
  </table>
 </form>