<% /* edituserentities.jsp
    *
    * Page for editing a usergroupsuser entities, included from ejbcaathorization.jsp 
    * 
    * Created on  14 mars 2002, 20:49
    *
    * author  Philip Vendil */ %>

<% // Check actions submitted

    if( request.getParameter(BUTTON_ADD_USERENTITY) != null ){
         // Add given user entity.
         
         String[][] userentity = new String[1][3];
         userentity[0][EjbcaAthorization.USER_ENTITY_MATCHWITH]  = request.getParameter(SELECT_MATCHWITH);
         userentity[0][EjbcaAthorization.USER_ENTITY_MATCHTYPE]  = request.getParameter(SELECT_MATCHTYPE);
         userentity[0][EjbcaAthorization.USER_ENTITY_MATCHVALUE] = request.getParameter(TEXTFIELD_MATCHVALUE);
         if(userentity[0][EjbcaAthorization.USER_ENTITY_MATCHVALUE] != null){
           userentity[0][EjbcaAthorization.USER_ENTITY_MATCHVALUE]=
             userentity[0][EjbcaAthorization.USER_ENTITY_MATCHVALUE].trim();
           if(!userentity[0][EjbcaAthorization.USER_ENTITY_MATCHVALUE].equals("")){
             ejbcaauthorization.addUserEntities(usergroup,userentity);
           }
         }
    }
    if( request.getParameter(BUTTON_DELETE_USERENTITIES) != null ){
         // Delete selected user entities.
       java.util.Enumeration parameters = request.getParameterNames();
       java.util.Vector indexes = new  java.util.Vector();
       int index;
       while(parameters.hasMoreElements()) {
         String parameter = (String) parameters.nextElement();
         if(parameter.startsWith(CHECKBOX_DELETE_USERENTITY) && request.getParameter(parameter).equals(CHECKBOX_VALUE)){ 
           index = java.lang.Integer.parseInt(parameter.substring(CHECKBOX_DELETE_USERENTITY.length())); //Without []     
           indexes.addElement(new Integer(index)); 
          }
       }
       
       if(indexes.size() > 0){
         String[][] userentities = new String[indexes.size()][3];
         for(int i = 0; i < indexes.size(); i++){
           index = ((java.lang.Integer) indexes.elementAt(i)).intValue();
           userentities[i][EjbcaAthorization.USER_ENTITY_MATCHWITH] = request.getParameter(HIDDEN_MATCHWITH+index);
           userentities[i][EjbcaAthorization.USER_ENTITY_MATCHTYPE] = request.getParameter(HIDDEN_MATCHTYPE+index);
           userentities[i][EjbcaAthorization.USER_ENTITY_MATCHVALUE] = request.getParameter(HIDDEN_MATCHVALUE+index);
         }
         ejbcaauthorization.removeUserEntities(usergroup,userentities);   
      }
    }


%>

<%
   // Generate Html file.
   String[][] userentities = ejbcaauthorization.getUserEntities(usergroup);

   int numdeletecheckboxes=userentities.length;
%>

<div align="center">
  <p><H1><%= ejbcawebbean.getText("EDITUSERS") %></H1></p>
  <p><H2><%= ejbcawebbean.getText("FORUSERGROUP") + " " + usergroup %></H2></p>
  <form name="toaccessrules" method="post" action="<%=THIS_FILENAME %>">
  <div align="right"><A href="<%=THIS_FILENAME %>"><u><%= ejbcawebbean.getText("BACKTOUSERGROUPS") %></u></A>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
    <input type="hidden" name='<%= HIDDEN_GROUPNAME %>' value='<%= usergroup %>'>
    <input type="hidden" name='<%= ACTION %>' value='<%=ACTION_EDIT_ACCESSRULES %>'>
    <A href='javascript:document.toaccessrules.submit();'><u><%= ejbcawebbean.getText("EDITACCESSRULES") %></u></A>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
    <A  onclick='displayHelpWindow("<%= ejbcawebbean.getHelpfileInfix("authorization_help.html") + "#users"%>")'>
    <u><%= ejbcawebbean.getText("INFORMATIONANDHELP") %></u> </A>
  </div>
  </form>
  <p align="center"></p>
  <form name="addusers" method="post" action="<%=THIS_FILENAME %>">
    <input type="hidden" name='<%= ACTION %>' value='<%=ACTION_EDIT_USERENTITIES %>'>
    <input type="hidden" name='<%= HIDDEN_GROUPNAME %>' value='<%= usergroup %>'>
    <table width="100%" border="0" cellspacing="0" cellpadding="0">
      <tr> 
        <td width="6%"></td>
        <td width="20%"><H3><%= ejbcawebbean.getText("ADDUSER") %></H3></td>
        <td width="15%"></td>
        <td width="33%"></td>
        <td width="26%">&nbsp;</td>
      </tr>
      <tr> 
        <td width="6%"><b></b></td>
        <td width="20%"><H3><%= ejbcawebbean.getText("MATCHWITH") %></H3></td>
        <td width="15%"><H3><%= ejbcawebbean.getText("MATCHTYPE") %></H3></td>
        <td width="33%"><H3><%= ejbcawebbean.getText("USER") %></H3></td>
        <td width="26%"><b></b></td>
      </tr>
      <tr> 
        <td width="6%"></td>
        <td width="20%"> 
          <select name="<%=SELECT_MATCHWITH %>" size="1">
            <option selected value='<%= UserEntity.WITH_SERIALNUMBER %>'><%= ejbcawebbean.getText("WITHSERIALNUMBER") %></option>
            <option value='<%= UserEntity.WITH_COMMONNAME %>'><%= ejbcawebbean.getText("WITHCOMMONNAME") %></option>
            <option value='<%= UserEntity.WITH_ORGANIZATIONUNIT %>'><%= ejbcawebbean.getText("WITHORGANIZATIONUNIT") %></option>
            <option value='<%= UserEntity.WITH_ORGANIZATION %>'><%= ejbcawebbean.getText("WITHORGANIZATION") %></option>
            <option value='<%= UserEntity.WITH_LOCALE %>'><%= ejbcawebbean.getText("WITHLOCATION") %></option>
            <option value='<%= UserEntity.WITH_STATE %>'><%= ejbcawebbean.getText("WITHSTATE") %></option>
            <option value='<%= UserEntity.WITH_COUNTRY %>'><%= ejbcawebbean.getText("WITHCOUNTRY") %></option>
          </select>
        </td>
        <td width="15%"> 
          <select name="<%=SELECT_MATCHTYPE %>" size="1">
            <option selected value='<%= UserEntity.TYPE_EQUALCASE %>' ><%= ejbcawebbean.getText("EQUALCASE") %> </option>
            <option value='<%= UserEntity.TYPE_EQUALCASEINS %>' ><%= ejbcawebbean.getText("EQUALCASEINS") %> </option>
            <option value='<%= UserEntity.TYPE_NOT_EQUALCASE %>' ><%= ejbcawebbean.getText("NOTEQUALCASE") %> </option>
            <option value='<%= UserEntity.TYPE_NOT_EQUALCASEINS %>' ><%= ejbcawebbean.getText("NOTEQUALCASEINS") %> </option>
          </select>
          </td>
        <td width="33%"> 
          <input type="text" name="<%= TEXTFIELD_MATCHVALUE %>" size="60">
        </td>
        <td width="26%"> 
          <input type="submit" name="<%= BUTTON_ADD_USERENTITY %>" 
                 onClick='return checkfieldforlegalchars("document.addusers.<%=TEXTFIELD_MATCHVALUE%>","<%= ejbcawebbean.getText("ONLYCHARACTERS") %>")'
                 value="<%= ejbcawebbean.getText("ADD") %>">
        </td>
      </tr>
    </table>
    <table width="100%" border="0" cellspacing="0" cellpadding="0">
      <tr> 
        <td width="66%" valign="middle">&nbsp;</td>
        <td width="16%">&nbsp;</td>
        <td width="18%" valign="middle">&nbsp; </td>
      </tr>
    </table>
  </form>
  <p align="left"> </p>
  <form name="deleteusers" method="post" action="<%=THIS_FILENAME %>">
    <input type="hidden" name='<%= ACTION %>' value='<%=ACTION_EDIT_USERENTITIES %>'>
    <input type="hidden" name='<%= HIDDEN_GROUPNAME %>' value='<%= usergroup %>'>
    <table width="100%" border="0" cellspacing="0" cellpadding="0">
      <tr> 
        <td width="6%"></td>
        <td width="20%"><H3><%= ejbcawebbean.getText("CURRENTUSERS") %></H3></td>
        <td width="15%">&nbsp;</td>
        <td width="57%">&nbsp;</td>
        <td width="2%">&nbsp;</td>
      </tr>
      <tr> 
        <td width="10%"><H3><%= ejbcawebbean.getText("DELETE") %></H3></td>
        <td width="20%"><H3><%= ejbcawebbean.getText("MATCHWITH") %></H3></td>
        <td width="15%"><H3><%= ejbcawebbean.getText("MATCHTYPE") %></H3></td>
        <td width="53%"><H3><%= ejbcawebbean.getText("USER") %></H3></td>
        <td width="2%"><b></b></td>
      </tr>
   <% if(userentities == null || userentities.length == 0){ %>
      <tr id="Row0"> 
        <td width="10%">&nbsp;</td>
        <td width="20%">&nbsp;</td>
        <td width="15%">&nbsp;</td>
        <td width="53%"><%= ejbcawebbean.getText("NOUSERSDEFINED") %></td>
        <td width="2%">&nbsp;</td>
      </tr>
   <% }
      else{
        for(int i = 0; i < userentities.length ; i++){ %> 
      <tr id="Row<%= i%2 %>"> 
        <td width="10%"> 
          <input type="checkbox" name="<%= CHECKBOX_DELETE_USERENTITY + i %>" value="<%= CHECKBOX_VALUE %>">
        </td>
        <td width="20%">
          <input type="hidden" name='<%= HIDDEN_MATCHWITH + i %>' value='<%= userentities[i][EjbcaAthorization.USER_ENTITY_MATCHWITH] %>'>
        <% if(userentities[i][EjbcaAthorization.USER_ENTITY_MATCHWITH].equals(String.valueOf(UserEntity.WITH_COUNTRY))){
             out.write(ejbcawebbean.getText("WITHCOUNTRY"));
           }
           if(userentities[i][EjbcaAthorization.USER_ENTITY_MATCHWITH].equals(String.valueOf(UserEntity.WITH_ORGANIZATION))){
             out.write(ejbcawebbean.getText("WITHORGANIZATION"));
           }
           if(userentities[i][EjbcaAthorization.USER_ENTITY_MATCHWITH].equals(String.valueOf(UserEntity.WITH_ORGANIZATIONUNIT))){
             out.write(ejbcawebbean.getText("WITHORGANIZATIONUNIT"));
           }
           if(userentities[i][EjbcaAthorization.USER_ENTITY_MATCHWITH].equals(String.valueOf(UserEntity.WITH_COMMONNAME))){
             out.write(ejbcawebbean.getText("WITHCOMMONNAME"));
           }
%>
        </td>
        <td width="15%">
          <input type="hidden" name='<%= HIDDEN_MATCHTYPE + i %>' value='<%= userentities[i][EjbcaAthorization.USER_ENTITY_MATCHTYPE] %>'>
<%      if(userentities[i][EjbcaAthorization.USER_ENTITY_MATCHTYPE].equals(String.valueOf(UserEntity.TYPE_EQUALCASE))){
             out.write(ejbcawebbean.getText("EQUALCASE"));
        }
        if(userentities[i][EjbcaAthorization.USER_ENTITY_MATCHTYPE].equals(String.valueOf(UserEntity.TYPE_EQUALCASEINS))){
             out.write(ejbcawebbean.getText("EQUALCASEINS"));
        }
        if(userentities[i][EjbcaAthorization.USER_ENTITY_MATCHTYPE].equals(String.valueOf(UserEntity.TYPE_NOT_EQUALCASE))){
             out.write(ejbcawebbean.getText("NOTEQUALCASE"));
        }
        if(userentities[i][EjbcaAthorization.USER_ENTITY_MATCHTYPE].equals(String.valueOf(UserEntity.TYPE_NOT_EQUALCASEINS))){
             out.write(ejbcawebbean.getText("NOTEQUALCASEINS"));
        }
%>

        </td>
        <td width="53%">
          <input type="hidden" name='<%= HIDDEN_MATCHVALUE + i %>' value='<%= userentities[i][EjbcaAthorization.USER_ENTITY_MATCHVALUE] %>'>
           <%= userentities[i][EjbcaAthorization.USER_ENTITY_MATCHVALUE] %>
        </td>
        <td width="2%">&nbsp;</td>
      </tr>
<%    }
    } %>  
    </table>
  <table width="100%" border="0" cellspacing="0" cellpadding="0">
    <tr>
       <td width="66%" valign="middle">
           <input type="button" value="<%= ejbcawebbean.getText("SELECTALL") %>" 
           onClick='checkAll("document.deleteusers.<%= CHECKBOX_DELETE_USERENTITY %>", <%= numdeletecheckboxes %>)'>
           <input type="button" value="<%= ejbcawebbean.getText("UNSELECTALL") %>" 
           onClick='uncheckAll("document.deleteusers.<%= CHECKBOX_DELETE_USERENTITY %>", <%= numdeletecheckboxes %>)'>
           <input type="button" value="<%=ejbcawebbean.getText("INVERTSELECTION") %>" 
           onClick='switchAll("document.deleteusers.<%= CHECKBOX_DELETE_USERENTITY %>", <%= numdeletecheckboxes %>)'>
        <td width="32%">&nbsp;</td>
        <td width="2%" valign="middle">&nbsp; </td>
    </tr>
    <tr> 
        <td width="66%" valign="middle"><H3><%= ejbcawebbean.getText("DELETESELECTED") %></H3>
          <input type="submit" onClick="return confirm('<%= ejbcawebbean.getText("AREYOUSURE") %>');"  name="<%= BUTTON_DELETE_USERENTITIES %>" value="<%= ejbcawebbean.getText("DELETE") %>">
        </td>  
        <td width="32%">&nbsp;</td>
        <td width="2%" valign="middle">&nbsp; </td>
    </tr>
  </table>
  </form>
  <p align="center">&nbsp;</p>
  <p>&nbsp;</p>
</div>
