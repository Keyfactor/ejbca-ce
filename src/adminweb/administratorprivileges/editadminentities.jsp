<% /* editadminentities.jsp
    *
    * Page for editing a admingroups admin entities, included from administratorprivileges.jsp 
    * 
    * Created on  14 mars 2002, 20:49
    *
    * author  Philip Vendil */ %>

<% // Check actions submitted

    if( request.getParameter(BUTTON_ADD_ADMINENTITY) != null ){
         // Add given admin entity.
         
         String[][] adminentity = new String[1][3];
         adminentity[0][AuthorizationDataHandler.ADMIN_ENTITY_MATCHWITH]  = request.getParameter(SELECT_MATCHWITH);
         adminentity[0][AuthorizationDataHandler.ADMIN_ENTITY_MATCHTYPE]  = request.getParameter(SELECT_MATCHTYPE);
         adminentity[0][AuthorizationDataHandler.ADMIN_ENTITY_MATCHVALUE] = request.getParameter(TEXTFIELD_MATCHVALUE);
         if(adminentity[0][AuthorizationDataHandler.ADMIN_ENTITY_MATCHVALUE] != null){
           adminentity[0][AuthorizationDataHandler.ADMIN_ENTITY_MATCHVALUE]=
             adminentity[0][AuthorizationDataHandler.ADMIN_ENTITY_MATCHVALUE].trim();
           if(!adminentity[0][AuthorizationDataHandler.ADMIN_ENTITY_MATCHVALUE].equals("")){
             adh.addAdminEntities(admingroup,adminentity);
           }
         }
    }
    if( request.getParameter(BUTTON_DELETE_ADMINENTITIES) != null ){
         // Delete selected admin entities.
       java.util.Enumeration parameters = request.getParameterNames();
       java.util.Vector indexes = new  java.util.Vector();
       int index;
       while(parameters.hasMoreElements()) {
         String parameter = (String) parameters.nextElement();
         if(parameter.startsWith(CHECKBOX_DELETE_ADMINENTITY) && request.getParameter(parameter).equals(CHECKBOX_VALUE)){ 
           index = java.lang.Integer.parseInt(parameter.substring(CHECKBOX_DELETE_ADMINENTITY.length())); //Without []     
           indexes.addElement(new Integer(index)); 
          }
       }
       
       if(indexes.size() > 0){
         String[][] adminentities = new String[indexes.size()][3];
         for(int i = 0; i < indexes.size(); i++){
           index = ((java.lang.Integer) indexes.elementAt(i)).intValue();
           adminentities[i][AuthorizationDataHandler.ADMIN_ENTITY_MATCHWITH] = request.getParameter(HIDDEN_MATCHWITH+index);
           adminentities[i][AuthorizationDataHandler.ADMIN_ENTITY_MATCHTYPE] = request.getParameter(HIDDEN_MATCHTYPE+index);
           adminentities[i][AuthorizationDataHandler.ADMIN_ENTITY_MATCHVALUE] = request.getParameter(HIDDEN_MATCHVALUE+index);
         }
         adh.removeAdminEntities(admingroup,adminentities);   
      }
    }


%>

<%
   // Generate Html file.
   String[][] adminentities = adh.getAdminEntities(admingroup);

   int numdeletecheckboxes=adminentities.length;
%>

<div align="center">
  <p><H1><%= ejbcawebbean.getText("EDITADMINS") %></H1></p>
  <p><H2><%= ejbcawebbean.getText("FORADMINGROUP") + " " + admingroup %></H2></p>
  <form name="toaccessrules" method="post" action="<%=THIS_FILENAME %>">
  <div align="right"><A href="<%=THIS_FILENAME %>"><u><%= ejbcawebbean.getText("BACKTOADMINGROUPS") %></u></A>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
    <input type="hidden" name='<%= HIDDEN_GROUPNAME %>' value='<%= admingroup %>'>
    <input type="hidden" name='<%= ACTION %>' value='<%=ACTION_EDIT_ACCESSRULES %>'>
    <A href='javascript:document.toaccessrules.submit();'><u><%= ejbcawebbean.getText("EDITACCESSRULES") %></u></A>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
    <A  onclick='displayHelpWindow("<%= ejbcawebbean.getHelpfileInfix("authorization_help.html") + "#admins"%>")'>
    <u><%= ejbcawebbean.getText("HELP") %></u> </A>
  </div>
  </form>
  <p align="center"></p>
  <form name="addadmins" method="post" action="<%=THIS_FILENAME %>">
    <input type="hidden" name='<%= ACTION %>' value='<%=ACTION_EDIT_ADMINENTITIES %>'>
    <input type="hidden" name='<%= HIDDEN_GROUPNAME %>' value='<%= admingroup %>'>
    <table width="100%" border="0" cellspacing="0" cellpadding="0">
      <tr> 
        <td width="6%"></td>
        <td width="20%"><H3><%= ejbcawebbean.getText("ADDADMIN") %></H3></td>
        <td width="15%"></td>
        <td width="33%"></td>
        <td width="26%">&nbsp;</td>
      </tr>
      <tr> 
        <td width="6%"><b></b></td>
        <td width="20%"><H3><%= ejbcawebbean.getText("MATCHWITH") %></H3></td>
        <td width="15%"><H3><%= ejbcawebbean.getText("MATCHTYPE") %></H3></td>
        <td width="33%"><H3><%= ejbcawebbean.getText("ADMIN") %></H3></td>
        <td width="26%"><b></b></td>
      </tr>
      <tr> 
        <td width="6%"></td>
        <td width="20%"> 
          <select name="<%=SELECT_MATCHWITH %>" size="1">
            <option selected value='<%= AdminEntity.WITH_SERIALNUMBER %>'><%= ejbcawebbean.getText("WITHSERIALNUMBER") %></option>
            <option value='<%= AdminEntity.WITH_DNSERIALNUMBER %>'><%= ejbcawebbean.getText("WITHDNSERIALNUMBER") %></option>
            <option value='<%= AdminEntity.WITH_UID %>'><%= ejbcawebbean.getText("WITHUID") %></option>
            <option value='<%= AdminEntity.WITH_COMMONNAME %>'><%= ejbcawebbean.getText("WITHCOMMONNAME") %></option>
            <option value='<%= AdminEntity.WITH_TITLE %>'><%= ejbcawebbean.getText("WITHTITLE") %></option>
            <option value='<%= AdminEntity.WITH_ORGANIZATIONUNIT %>'><%= ejbcawebbean.getText("WITHORGANIZATIONUNIT") %></option>
            <option value='<%= AdminEntity.WITH_ORGANIZATION %>'><%= ejbcawebbean.getText("WITHORGANIZATION") %></option>
            <option value='<%= AdminEntity.WITH_LOCALE %>'><%= ejbcawebbean.getText("WITHLOCATION") %></option>
            <option value='<%= AdminEntity.WITH_STATE %>'><%= ejbcawebbean.getText("WITHSTATE") %></option>
            <option value='<%= AdminEntity.WITH_DOMAINCOMPONENT %>'><%= ejbcawebbean.getText("WITHDOMAINCOMPONENT") %></option>
            <option value='<%= AdminEntity.WITH_COUNTRY %>'><%= ejbcawebbean.getText("WITHCOUNTRY") %></option>
          </select>
        </td>
        <td width="15%"> 
          <select name="<%=SELECT_MATCHTYPE %>" size="1">
            <option selected value='<%= AdminEntity.TYPE_EQUALCASE %>' ><%= ejbcawebbean.getText("EQUALCASE") %> </option>
            <option value='<%= AdminEntity.TYPE_EQUALCASEINS %>' ><%= ejbcawebbean.getText("EQUALCASEINS") %> </option>
            <option value='<%= AdminEntity.TYPE_NOT_EQUALCASE %>' ><%= ejbcawebbean.getText("NOTEQUALCASE") %> </option>
            <option value='<%= AdminEntity.TYPE_NOT_EQUALCASEINS %>' ><%= ejbcawebbean.getText("NOTEQUALCASEINS") %> </option>
          </select>
          </td>
        <td width="33%"> 
          <input type="text" name="<%= TEXTFIELD_MATCHVALUE %>" size="40">
        </td>
        <td width="26%"> 
          <input type="submit" name="<%= BUTTON_ADD_ADMINENTITY %>" 
                 onClick='return checkfieldforlegalchars("document.addadmins.<%=TEXTFIELD_MATCHVALUE%>","<%= ejbcawebbean.getText("ONLYCHARACTERS") %>")'
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
  <form name="deleteadmins" method="post" action="<%=THIS_FILENAME %>">
    <input type="hidden" name='<%= ACTION %>' value='<%=ACTION_EDIT_ADMINENTITIES %>'>
    <input type="hidden" name='<%= HIDDEN_GROUPNAME %>' value='<%= admingroup %>'>
    <table width="100%" border="0" cellspacing="0" cellpadding="0">
      <tr> 
        <td width="6%"></td>
        <td width="20%"><H3><%= ejbcawebbean.getText("CURRENTADMINS") %></H3></td>
        <td width="15%">&nbsp;</td>
        <td width="57%">&nbsp;</td>
        <td width="2%">&nbsp;</td>
      </tr>
      <tr> 
        <td width="10%"><H3><%= ejbcawebbean.getText("DELETE") %></H3></td>
        <td width="20%"><H3><%= ejbcawebbean.getText("MATCHWITH") %></H3></td>
        <td width="15%"><H3><%= ejbcawebbean.getText("MATCHTYPE") %></H3></td>
        <td width="53%"><H3><%= ejbcawebbean.getText("ADMIN") %></H3></td>
        <td width="2%"><b></b></td>
      </tr>
   <% if(adminentities == null || adminentities.length == 0){ %>
      <tr id="Row0"> 
        <td width="10%">&nbsp;</td>
        <td width="20%">&nbsp;</td>
        <td width="15%">&nbsp;</td>
        <td width="53%"><%= ejbcawebbean.getText("NOADMINSDEFINED") %></td>
        <td width="2%">&nbsp;</td>
      </tr>
   <% }
      else{
        for(int i = 0; i < adminentities.length ; i++){ %> 
      <tr id="Row<%= i%2 %>"> 
        <td width="10%"> 
          <input type="checkbox" name="<%= CHECKBOX_DELETE_ADMINENTITY + i %>" value="<%= CHECKBOX_VALUE %>">
        </td>
        <td width="20%">
          <input type="hidden" name='<%= HIDDEN_MATCHWITH + i %>' value='<%= adminentities[i][AuthorizationDataHandler.ADMIN_ENTITY_MATCHWITH] %>'>
        <% if(adminentities[i][AuthorizationDataHandler.ADMIN_ENTITY_MATCHWITH].equals(String.valueOf(AdminEntity.WITH_COUNTRY))){
             out.write(ejbcawebbean.getText("WITHCOUNTRY"));
           }
           if(adminentities[i][AuthorizationDataHandler.ADMIN_ENTITY_MATCHWITH].equals(String.valueOf(AdminEntity.WITH_DOMAINCOMPONENT))){
             out.write(ejbcawebbean.getText("WITHDOMAINCOMPONENT"));
           }
           if(adminentities[i][AuthorizationDataHandler.ADMIN_ENTITY_MATCHWITH].equals(String.valueOf(AdminEntity.WITH_STATE))){
             out.write(ejbcawebbean.getText("WITHSTATE"));
           }
           if(adminentities[i][AuthorizationDataHandler.ADMIN_ENTITY_MATCHWITH].equals(String.valueOf(AdminEntity.WITH_LOCALE))){
             out.write(ejbcawebbean.getText("WITHLOCATION"));
           }
           if(adminentities[i][AuthorizationDataHandler.ADMIN_ENTITY_MATCHWITH].equals(String.valueOf(AdminEntity.WITH_ORGANIZATION))){
             out.write(ejbcawebbean.getText("WITHORGANIZATION"));
           }
           if(adminentities[i][AuthorizationDataHandler.ADMIN_ENTITY_MATCHWITH].equals(String.valueOf(AdminEntity.WITH_ORGANIZATIONUNIT))){
             out.write(ejbcawebbean.getText("WITHORGANIZATIONUNIT"));
           }
           if(adminentities[i][AuthorizationDataHandler.ADMIN_ENTITY_MATCHWITH].equals(String.valueOf(AdminEntity.WITH_TITLE))){
             out.write(ejbcawebbean.getText("WITHTITLE"));
           }
           if(adminentities[i][AuthorizationDataHandler.ADMIN_ENTITY_MATCHWITH].equals(String.valueOf(AdminEntity.WITH_COMMONNAME))){
             out.write(ejbcawebbean.getText("WITHCOMMONNAME"));
           }
           if(adminentities[i][AuthorizationDataHandler.ADMIN_ENTITY_MATCHWITH].equals(String.valueOf(AdminEntity.WITH_UID))){
             out.write(ejbcawebbean.getText("WITHUID"));
           }
           if(adminentities[i][AuthorizationDataHandler.ADMIN_ENTITY_MATCHWITH].equals(String.valueOf(AdminEntity.WITH_DNSERIALNUMBER))){
             out.write(ejbcawebbean.getText("WITHDNSERIALNUMBER"));
           }
           if(adminentities[i][AuthorizationDataHandler.ADMIN_ENTITY_MATCHWITH].equals(String.valueOf(AdminEntity.WITH_SERIALNUMBER))){
             out.write(ejbcawebbean.getText("WITHSERIALNUMBER"));
           }
%>
        </td>
        <td width="15%">
          <input type="hidden" name='<%= HIDDEN_MATCHTYPE + i %>' value='<%= adminentities[i][AuthorizationDataHandler.ADMIN_ENTITY_MATCHTYPE] %>'>
<%      if(adminentities[i][AuthorizationDataHandler.ADMIN_ENTITY_MATCHTYPE].equals(String.valueOf(AdminEntity.TYPE_EQUALCASE))){
             out.write(ejbcawebbean.getText("EQUALCASE"));
        }
        if(adminentities[i][AuthorizationDataHandler.ADMIN_ENTITY_MATCHTYPE].equals(String.valueOf(AdminEntity.TYPE_EQUALCASEINS))){
             out.write(ejbcawebbean.getText("EQUALCASEINS"));
        }
        if(adminentities[i][AuthorizationDataHandler.ADMIN_ENTITY_MATCHTYPE].equals(String.valueOf(AdminEntity.TYPE_NOT_EQUALCASE))){
             out.write(ejbcawebbean.getText("NOTEQUALCASE"));
        }
        if(adminentities[i][AuthorizationDataHandler.ADMIN_ENTITY_MATCHTYPE].equals(String.valueOf(AdminEntity.TYPE_NOT_EQUALCASEINS))){
             out.write(ejbcawebbean.getText("NOTEQUALCASEINS"));
        }
%>

        </td>
        <td width="53%">
          <input type="hidden" name='<%= HIDDEN_MATCHVALUE + i %>' value='<%= adminentities[i][AuthorizationDataHandler.ADMIN_ENTITY_MATCHVALUE] %>'>
           <%= adminentities[i][AuthorizationDataHandler.ADMIN_ENTITY_MATCHVALUE] %>
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
           onClick='checkAll("document.deleteadmins.<%= CHECKBOX_DELETE_ADMINENTITY %>", <%= numdeletecheckboxes %>)'>
           <input type="button" value="<%= ejbcawebbean.getText("UNSELECTALL") %>" 
           onClick='uncheckAll("document.deleteadmins.<%= CHECKBOX_DELETE_ADMINENTITY %>", <%= numdeletecheckboxes %>)'>
           <input type="button" value="<%=ejbcawebbean.getText("INVERTSELECTION") %>" 
           onClick='switchAll("document.deleteadmins.<%= CHECKBOX_DELETE_ADMINENTITY %>", <%= numdeletecheckboxes %>)'>
        <td width="32%">&nbsp;</td>
        <td width="2%" valign="middle">&nbsp; </td>
    </tr>
    <tr> 
        <td width="66%" valign="middle"><H3><%= ejbcawebbean.getText("DELETESELECTED") %></H3>
          <input type="submit" onClick="return confirm('<%= ejbcawebbean.getText("AREYOUSURE") %>');"  name="<%= BUTTON_DELETE_ADMINENTITIES %>" value="<%= ejbcawebbean.getText("DELETE") %>">
        </td>  
        <td width="32%">&nbsp;</td>
        <td width="2%" valign="middle">&nbsp; </td>
    </tr>
  </table>
  </form>
  <p align="center">&nbsp;</p>
  <p>&nbsp;</p>
</div>
