<head>
  <title><%= globalconfiguration.getEjbcaTitle() %></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>">
  <link rel=STYLESHEET href="<%= ejbcawebbean.getCssFile() %>">
  <script language=javascript src="<%= globalconfiguration.getRaAdminPath() %>ejbcajslib.js"></script>
  <script language=javascript>
<!--
function viewuser(){
  var returnval = onlyoneselected("document.form.<%= CHECKBOX_SELECT_USER %>", <%= numcheckboxes %>,"<%= ejbcawebbean.getText("YOUCANONLYVIEWONE") %>");
  var index = 0;

  if(returnval){
    for (var i = 0; i < <%= numcheckboxes %>; i++) {
      box = eval("document.form.<%= CHECKBOX_SELECT_USER %>" + i ); 
      if (box.checked == true){ 
        index =i;
        break;
      }
    }
    var hiddenusernamefield = eval("document.form.<%= HIDDEN_USERNAME %>" + i);
    var username = hiddenusernamefield.value;
    var hiddenusernamefield = eval("document.form.<%= HIDDEN_USERDN %>" + i);
    var userdn = hiddenusernamefield.value;
    var link = "<%= VIEWUSER_LINK %>?<%= USER_PARAMETER %>="+username;
    window.open(link, 'view_cert',config='height=600,width=500,scrollbars=yes,toolbar=no,resizable=1');
  }          
  
  return returnval;
}

function edituser(){
  var returnval = onlyoneselected("document.form.<%= CHECKBOX_SELECT_USER %>", <%= numcheckboxes %>,"<%= ejbcawebbean.getText("YOUCANONLYVIEWONE") %>");
  var index = 0;

  if(returnval){
    for (var i = 0; i < <%= numcheckboxes %>; i++) {
      box = eval("document.form.<%= CHECKBOX_SELECT_USER %>" + i ); 
      if (box.checked == true){ 
        index =i;
        break;
      }
    }
    var hiddenusernamefield = eval("document.form.<%= HIDDEN_USERNAME %>" + i);
    var username = hiddenusernamefield.value;
    var link = "<%= EDITUSER_LINK %>?<%= USER_PARAMETER %>="+username;
    window.open(link, 'edit_user',config='height=600,width=500,scrollbars=yes,toolbar=no,resizable=1');
  }         
  
  return returnval;
}

function viewcert(){
  var returnval = onlyoneselected("document.form.<%= CHECKBOX_SELECT_USER %>", <%= numcheckboxes %>,"<%= ejbcawebbean.getText("YOUCANONLYVIEWCERT") %>");
  var index = 0;

  if(returnval){
    for (var i = 0; i < <%= numcheckboxes %>; i++) {
      box = eval("document.form.<%= CHECKBOX_SELECT_USER %>" + i ); 
      if (box.checked == true){ 
        index =i;
        break;
      }
    }
    var hiddenusernamefield = eval("document.form.<%= HIDDEN_USERNAME %>" + i);
    var username = hiddenusernamefield.value;
    var hiddenuserdnfield = eval("document.form.<%= HIDDEN_USERDN %>" + i);
    var userdn = hiddenuserdnfield.value;
    var link = "<%= VIEWCERT_LINK %>?<%= SUBJECTDN_PARAMETER %>="+userdn+"&<%= USER_PARAMETER %>="+username;
    window.open(link, 'view_cert',config='height=600,width=500,scrollbars=yes,toolbar=no,resizable=1');
  }         
  
  return returnval;
}

-->
</script>
</head>

<body>
<h2 align="center"><%= ejbcawebbean.getText("LISTUSERS") %></h2>
  <div align="right"><A  onclick='displayHelpWindow("<%= ejbcawebbean.getHelpfileInfix("ra_help.html") +"#listusers" %>")'>
    <u><%= ejbcawebbean.getText("INFORMATIONANDHELP") %></u> </A>
  </div>
<form name="form" method="post" action="<%=THIS_FILENAME %>">
  <input type="hidden" name='<%= ACTION %>' value='<%=ACTION_LISTUSERS %>'>
  <input type="hidden" name='<%= OLD_ACTION %>' value='<%=oldaction %>'>
  <input type="hidden" name='<%= OLD_ACTION_VALUE %>' value='<%=oldactionvalue %>'>
  <input type="hidden" name='<%= HIDDEN_RECORDNUMBER %>' value='<%=String.valueOf(record) %>'>
  <input type="hidden" name='<%= HIDDEN_SORTBY  %>' value='<%=sortby %>'>
  <p><%= ejbcawebbean.getText("FINDUSERWITHUSERNAME") %>
    <input type="text" name="<%=TEXTFIELD_USERNAME %>" size="40" maxlength="255" 
     <% if(oldaction != null && oldactionvalue!= null && oldaction.equals(OLD_ACTION_FINDUSER))
          out.write("value='"+oldactionvalue+"'"); %>
     >
    <input type="submit" name="<%=BUTTON_FIND %>" value="<%= ejbcawebbean.getText("FIND") %>">
  </p>
  <p><%= ejbcawebbean.getText("ORWITHSTATUS") %>
    <select name="<%=SELECT_LIST_STATUS %>">
      <option value=''>--</option> 
      <option <% if(oldaction != null && oldactionvalue!= null && oldaction.equals(OLD_ACTION_LISTUSERS))
                   if(oldactionvalue.equals(Integer.toString(UserData.STATUS_NEW)))
                     out.write("selected"); %>
              value='<%= Integer.toString(UserData.STATUS_NEW) %>'><%= ejbcawebbean.getText("STATUSNEW") %></option>
      <option <% if(oldaction != null && oldactionvalue!= null && oldaction.equals(OLD_ACTION_LISTUSERS))
                   if(oldactionvalue.equals(Integer.toString(UserData.STATUS_FAILED)))
                     out.write("selected"); %>
              value='<%= Integer.toString(UserData.STATUS_FAILED) %>'><%= ejbcawebbean.getText("STATUSFAILED") %></option>
      <option <% if(oldaction != null && oldactionvalue!= null && oldaction.equals(OLD_ACTION_LISTUSERS))
                   if(oldactionvalue.equals(Integer.toString(UserData.STATUS_INITIALIZED)))
                     out.write("selected"); %>
              value='<%= Integer.toString(UserData.STATUS_INITIALIZED) %>'><%= ejbcawebbean.getText("STATUSINITIALIZED") %></option>
      <option <% if(oldaction != null && oldactionvalue!= null && oldaction.equals(OLD_ACTION_LISTUSERS))
                   if(oldactionvalue.equals(Integer.toString(UserData.STATUS_INPROCESS)))
                     out.write("selected"); %>
              value='<%= Integer.toString(UserData.STATUS_INPROCESS) %>'><%= ejbcawebbean.getText("STATUSINPROCESS") %></option>
      <option <% if(oldaction != null && oldactionvalue!= null && oldaction.equals(OLD_ACTION_LISTUSERS))
                   if(oldactionvalue.equals(Integer.toString(UserData.STATUS_GENERATED)))
                     out.write("selected"); %>
              value='<%= Integer.toString(UserData.STATUS_GENERATED) %>'><%= ejbcawebbean.getText("STATUSGENERATED") %></option>
      <option <% if(oldaction != null && oldactionvalue!= null && oldaction.equals(OLD_ACTION_LISTUSERS))
                   if(oldactionvalue.equals(Integer.toString(UserData.STATUS_REVOKED)))
                     out.write("selected"); %>
              value='<%= Integer.toString(UserData.STATUS_REVOKED) %>'><%= ejbcawebbean.getText("STATUSREVOKED") %></option>
      <option <% if(oldaction != null && oldactionvalue!= null && oldaction.equals(OLD_ACTION_LISTUSERS))
                   if(oldactionvalue.equals(Integer.toString(UserData.STATUS_HISTORICAL)))
                     out.write("selected"); %>
              value='<%= Integer.toString(UserData.STATUS_HISTORICAL) %>'><%= ejbcawebbean.getText("STATUSHISTORICAL") %></option>
    </select>
    <input type="submit" name="<%=BUTTON_LIST %>" value="<%= ejbcawebbean.getText("LIST") %>">
  </p>
  <p><%= ejbcawebbean.getText("ORIFCERTIFICATSERIAL") %>
    <input type="text" name="<%=TEXTFIELD_SERIALNUMBER %>" size="40" maxlength="255" 
     <% if(oldaction != null && oldactionvalue!= null && oldaction.equals(OLD_ACTION_ISREVOKED))
          out.write("value='"+oldactionvalue+"'"); %>
     >
    <input type="submit" name="<%=BUTTON_ISREVOKED %>" value="<%= ejbcawebbean.getText("ISREVOKED") %>" 
           onclick='return checkfieldforhexadecimalnumbers("document.form.<%=TEXTFIELD_SERIALNUMBER %>","<%= ejbcawebbean.getText("ONLYHEXNUMBERS") %>")'>
  </p>
  <p><%= ejbcawebbean.getText("ORLISTEXPIRING") %>
    <input type="text" name="<%=TEXTFIELD_DAYS %>" size="3" maxlength="5" 
     <% if(oldaction != null && oldactionvalue!= null && oldaction.equals(OLD_ACTION_LISTEXPIRED))
          out.write("value='"+oldactionvalue+"'"); %>
     > <%= ejbcawebbean.getText("DAYS") %>
    <input type="submit" name="<%=BUTTON_LISTEXPIRED %>" value="<%= ejbcawebbean.getText("LIST") %>"
           onclick='return checkfieldfordecimalnumbers("document.form.<%=TEXTFIELD_DAYS %>","<%= ejbcawebbean.getText("ONLYDECNUMBERS") %>")'>
  </p>
  <br>
  <table width="100%" border="0" cellspacing="1" cellpadding="0">
    <tr> 
      <td width="14%"> 
        <% if(rabean.previousButton(record,size)){ %>
          <input type="submit" name="<%=BUTTON_PREVIOUS %>" value="<%= ejbcawebbean.getText("PREVIOUS") %>">
        <% } %>
      </td>
      <td width="76%">&nbsp; </td>
      <td width="10%"> 
        <div align="right">
        <% if(rabean.nextButton(record,size)){ %>
          <input type="submit" name="<%=BUTTON_NEXT %>" value="<%= ejbcawebbean.getText("NEXT") %>">
        <% } %>
        </div>
      </td>
    </tr>
  </table>
  <table width="100%" border="0" cellspacing="1" cellpadding="0">
  <tr> 
    <td width="8%"><%= ejbcawebbean.getText("SELECT") %>
     </td>
    <td width="14%"><% if(sortby.equals(SORTBY_USERNAME_ACC)){ %>
                          <input type="image" src='<%= ejbcawebbean.getImagefileInfix("downarrow.gif") %>' border="0" name="<%=SORTBY_USERNAME_DEC %>" value="submit" ><%= ejbcawebbean.getText("USERNAME") %>              
                   <% }else{
                         if(sortby.equals(SORTBY_USERNAME_DEC)){ %>
                          <input type="image" src='<%= ejbcawebbean.getImagefileInfix("uparrow.gif") %>' border="0" name="<%=SORTBY_USERNAME_ACC %>" value="submit" ><%= ejbcawebbean.getText("USERNAME") %>                     
                   <%    }else{ %> 
                          <input type="image" src='<%= ejbcawebbean.getImagefileInfix("noarrow.gif") %>' border="0" name="<%=SORTBY_USERNAME_ACC %>" value="submit" ><%= ejbcawebbean.getText("USERNAME") %>
                   <%    }
                       } %>
    </td>
    <td width="22%">
                   <% if(sortby.equals(SORTBY_COMMONNAME_ACC)){ %>
                          <input type="image" src='<%= ejbcawebbean.getImagefileInfix("downarrow.gif") %>' border="0" name="<%=SORTBY_COMMONNAME_DEC %>" value="submit" ><%= ejbcawebbean.getText("COMMONNAME") %>              
                   <% }else{
                         if(sortby.equals(SORTBY_COMMONNAME_DEC)){ %>
                          <input type="image" src='<%= ejbcawebbean.getImagefileInfix("uparrow.gif") %>' border="0" name="<%=SORTBY_COMMONNAME_ACC %>" value="submit" ><%= ejbcawebbean.getText("COMMONNAME") %>                     
                   <%    }else{ %> 
                          <input type="image" src='<%= ejbcawebbean.getImagefileInfix("noarrow.gif") %>' border="0" name="<%=SORTBY_COMMONNAME_ACC %>" value="submit" ><%= ejbcawebbean.getText("COMMONNAME") %>
                   <%    }
                       } %>
    </td>
    <td width="20%">
                   <% if(sortby.equals(SORTBY_ORGANIZATIONUNIT_ACC)){ %>
                          <input type="image" src='<%= ejbcawebbean.getImagefileInfix("downarrow.gif") %>' border="0" name="<%=SORTBY_ORGANIZATIONUNIT_DEC %>" value="submit" ><%= ejbcawebbean.getText("ORGANIZATIONUNIT") %>              
                   <% }else{
                         if(sortby.equals(SORTBY_ORGANIZATIONUNIT_DEC)){ %>
                          <input type="image" src='<%= ejbcawebbean.getImagefileInfix("uparrow.gif") %>' border="0" name="<%=SORTBY_ORGANIZATIONUNIT_ACC %>" value="submit" ><%= ejbcawebbean.getText("ORGANIZATIONUNIT") %>                     
                   <%    }else{ %> 
                          <input type="image" src='<%= ejbcawebbean.getImagefileInfix("noarrow.gif") %>' border="0" name="<%=SORTBY_ORGANIZATIONUNIT_ACC %>" value="submit" ><%= ejbcawebbean.getText("ORGANIZATIONUNIT") %>
                   <%    }
                       } %>
    </td>
    <td width="21%"><% if(sortby.equals(SORTBY_ORGANIZATION_ACC)){ %>
                          <input type="image" src='<%= ejbcawebbean.getImagefileInfix("downarrow.gif") %>' border="0" name="<%=SORTBY_ORGANIZATION_DEC %>" value="submit" ><%= ejbcawebbean.getText("ORGANIZATION") %>                        
                   <% }else{ 
                         if(sortby.equals(SORTBY_ORGANIZATION_DEC)){ %>
                          <input type="image" src='<%= ejbcawebbean.getImagefileInfix("uparrow.gif") %>' border="0" name="<%=SORTBY_ORGANIZATION_ACC %>" value="submit" ><%= ejbcawebbean.getText("ORGANIZATION") %>                 
                   <%    }else{ %> 
                          <input type="image" src='<%= ejbcawebbean.getImagefileInfix("noarrow.gif") %>' border="0" name="<%=SORTBY_ORGANIZATION_ACC %>" value="submit" ><%= ejbcawebbean.getText("ORGANIZATION") %>
                   <%    }
                       } %>
    </td>
    <td width="15%"><% if(sortby.equals(SORTBY_STATUS_ACC)){ %>
                          <input type="image" src='<%= ejbcawebbean.getImagefileInfix("downarrow.gif") %>' border="0" name="<%=SORTBY_STATUS_DEC %>" value="submit" ><%= ejbcawebbean.getText("STATUS") %>              
                   <% }else{
                         if(sortby.equals(SORTBY_STATUS_DEC)){ %>
                          <input type="image" src='<%= ejbcawebbean.getImagefileInfix("uparrow.gif") %>' border="0" name="<%=SORTBY_STATUS_ACC %>" value="submit" ><%= ejbcawebbean.getText("STATUS") %>                     
                   <%    }else{ %> 
                          <input type="image" src='<%= ejbcawebbean.getImagefileInfix("noarrow.gif") %>' border="0" name="<%=SORTBY_STATUS_ACC %>" value="submit" ><%= ejbcawebbean.getText("STATUS") %>
                   <%    }
                       } %>
    </td>
  </tr>
  <% if(blank){ %>
 <tr id="Row0"> 
   <td width="8%"> 
   </td>
    <td width="14%">&nbsp;</td>
    <td width="22%">&nbsp;</td>
    <td width="20%">&nbsp;</td>
    <td width="21%">&nbsp;</td>
    <td width="15%">&nbsp;</td>
  </tr> 
  <% }else{
       if(users == null || users.length == 0){     %>
  <tr id="Row0"> 
   <td width="8%"> 
   </td>
    <td width="14%">&nbsp;</td>
    <td width="22%"><%= ejbcawebbean.getText("NOUSERSFOUND") %></td>
    <td width="20%">&nbsp;</td>
    <td width="21%">&nbsp;</td>
    <td width="15%">&nbsp;</td>
  </tr>
  <% } else{
         for(int i=0; i < users.length; i++){%>
  <tr id="Row<%= i%2 %>"> 
      <td width="8%"> 
        <div align="center">
          <input type="checkbox" name="<%= CHECKBOX_SELECT_USER + i %>" value="<%= CHECKBOX_VALUE %>">
        </div>
      </td>
    <td width="14%"><%= users[i][UserView.USERNAME] %>
       <input type="hidden" name='<%= HIDDEN_USERNAME + i %>' value='<%= users[i][UserView.USERNAME] %>'>
       <input type="hidden" name='<%= HIDDEN_USERDN + i %>' value='<%= java.net.URLEncoder.encode(users[i][UserView.USERDN],"UTF-8") %>'>
    </td>
    <td width="22%"><%= users[i][UserView.COMMONNAME] %></td>
    <td width="20%"><%= users[i][UserView.ORGANIZATIONUNIT] %></td>
    <td width="21%"><%= users[i][UserView.ORGANIZATION] %></td>
    <td width="15%"><%
                       if(users[i][UserView.STATUS] != null){
                        switch(Integer.parseInt(users[i][UserView.STATUS])){
                          case UserData.STATUS_NEW :
                            out.write(ejbcawebbean.getText("STATUSNEW"));
                            break;
                          case UserData.STATUS_INITIALIZED :
                            out.write(ejbcawebbean.getText("STATUSINITIALIZED"));
                            break;
                          case UserData.STATUS_INPROCESS :
                            out.write(ejbcawebbean.getText("STATUSINPROCESS"));
                            break;
                          case UserData.STATUS_GENERATED :
                            out.write(ejbcawebbean.getText("STATUSGENERATED"));
                            break;
                          case UserData.STATUS_REVOKED :
                            out.write(ejbcawebbean.getText("STATUSREVOKED"));
                            break;
                          case UserData.STATUS_HISTORICAL :
                            out.write(ejbcawebbean.getText("STATUSHISTORICAL"));
                            break;
                        }
                      }%></td>
  </tr>
 <%      }
       }
     } %>
</table>
  <table width="100%" border="0" cellspacing="1" cellpadding="0">
    <tr>
      <td width="14%">
        <% if(rabean.previousButton(record,size)){ %>
          <input type="submit" name="<%=BUTTON_PREVIOUS %>" value="<%= ejbcawebbean.getText("PREVIOUS") %>">
        <% } %>
      </td>
      <td width="76%"> 
        <div align="center">
          <input type="button" name="<%=BUTTON_SELECTALL %>" value="<%= ejbcawebbean.getText("SELECTALL") %>"
                onClick='checkAll("document.form.<%= CHECKBOX_SELECT_USER %>", <%= numcheckboxes %>)'>
          <input type="button" name="<%=BUTTON_DESELECTALL %>" value="<%= ejbcawebbean.getText("UNSELECTALL") %>"
                onClick='uncheckAll("document.form.<%= CHECKBOX_SELECT_USER %>", <%= numcheckboxes %>)'>
          <input type="button" name="<%=BUTTON_INVERTSELECTION %>" value="<%= ejbcawebbean.getText("INVERTSELECTION") %>"           
                 onClick='switchAll("document.form.<%= CHECKBOX_SELECT_USER %>", <%= numcheckboxes %>)'>
        </div>
      </td>
      <td width="10%"> 
        <div align="right">
        <% if(rabean.nextButton(record,size)){ %>
          <input type="submit" name="<%=BUTTON_NEXT %>" value="<%= ejbcawebbean.getText("NEXT") %>">
        <% } %>
        </div>
      </td>
    </tr>
  </table>
  <table width="100%" border="0" cellspacing="1" cellpadding="0">
    <tr>
      <td>
        <input type="submit" name="<%=BUTTON_VIEW_USER %>" value="<%= ejbcawebbean.getText("VIEWUSER") %>"
               onClick='return viewuser()'> 
        &nbsp;&nbsp;&nbsp;
        <input type="submit" name="<%=BUTTON_EDIT_USER %>" value="<%= ejbcawebbean.getText("EDITUSER") %>"
               onClick='return edituser()'>
        &nbsp;&nbsp;&nbsp;
        <input type="submit" name="<%=BUTTON_VIEW_CERTIFICATE %>" value="<%= ejbcawebbean.getText("VIEWCERTIFICATE") %>"
               onClick='return viewcert()'>
        &nbsp;&nbsp;&nbsp;
        <input type="submit" name="<%=BUTTON_DELETE_USERS %>" value="<%= ejbcawebbean.getText("DELETESELECTED") %>"
               onClick='return confirm("<%= ejbcawebbean.getText("AREYOUSUREDELETE") %>")'>
        &nbsp;&nbsp;&nbsp;
        <input type="submit" name="<%=BUTTON_REVOKE_USERS %>" value="<%= ejbcawebbean.getText("REVOKESELECTED") %>"
               onClick='return confirm("<%= ejbcawebbean.getText("AREYOUSUREREVOKE") %>")'>
        &nbsp;&nbsp;&nbsp;
        <input type="submit" name="<%=BUTTON_CHANGESTATUS %>" value="<%= ejbcawebbean.getText("CHANGESTATUSTO") %>"
               onClick='return confirm("<%= ejbcawebbean.getText("AREYOUSURECHANGE") %>")'>
        <select name="<%=SELECT_CHANGE_STATUS %>">
         <option selected value='<%= Integer.toString(UserData.STATUS_NEW) %>'><%= ejbcawebbean.getText("STATUSNEW") %></option>
         <option value='<%= Integer.toString(UserData.STATUS_FAILED) %>'><%= ejbcawebbean.getText("STATUSFAILED") %></option>
         <option value='<%= Integer.toString(UserData.STATUS_INITIALIZED) %>'><%= ejbcawebbean.getText("STATUSINITIALIZED") %></option>
         <option value='<%= Integer.toString(UserData.STATUS_INPROCESS) %>'><%= ejbcawebbean.getText("STATUSINPROCESS") %></option>
         <option value='<%= Integer.toString(UserData.STATUS_GENERATED) %>'><%= ejbcawebbean.getText("STATUSGENERATED") %></option>
         <option value='<%= Integer.toString(UserData.STATUS_REVOKED) %>'><%= ejbcawebbean.getText("STATUSREVOKED") %></option>
         <option value='<%= Integer.toString(UserData.STATUS_HISTORICAL) %>'><%= ejbcawebbean.getText("STATUSHISTORICAL") %></option>
        </select>
      </td>
      <td>&nbsp;</td>
    </tr>
  </table>
  </form>
  <%// Include Footer 
   String footurl =   globalconfiguration.getFootBanner(); %>
   
  <jsp:include page="<%= footurl %>" />
</body>
</html>
