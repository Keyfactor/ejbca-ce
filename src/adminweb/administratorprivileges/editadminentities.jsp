<% /* editadminentities.jsp
    *
    * Page for editing a admingroups admin entities, included from administratorprivileges.jsp 
    * 
    * Created on  14 mars 2002, 20:49
    *
    * author  Philip Vendil */ %>

<% // Check actions submitted
    AdminEntity adminentity = null;
    int matchwith, matchtype;
    String matchvalue = null;


    if( request.getParameter(BUTTON_ADD_ADMINENTITY) != null ){
         // Add given admin entity.
         
         matchwith  = Integer.parseInt(request.getParameter(SELECT_MATCHWITH));
         matchtype  = Integer.parseInt(request.getParameter(SELECT_MATCHTYPE));
         matchvalue = request.getParameter(TEXTFIELD_MATCHVALUE);
         if(matchvalue != null && !matchvalue.trim().equals("")){
             ArrayList adminentities = new ArrayList();
             adminentities.add(new AdminEntity(matchwith, matchtype, matchvalue, caid));
             adh.addAdminEntities(admingroup[ADMINGROUPNAME],caid,adminentities);
         }
    }
    if( request.getParameter(BUTTON_DELETE_ADMINENTITIES) != null ){
         // Delete selected admin entities.
       java.util.Enumeration parameters = request.getParameterNames();
       java.util.ArrayList indexes = new  java.util.ArrayList();
       int index;
       while(parameters.hasMoreElements()) {
         String parameter = (String) parameters.nextElement();
         if(parameter.startsWith(CHECKBOX_DELETE_ADMINENTITY) && request.getParameter(parameter).equals(CHECKBOX_VALUE)){ 
           index = java.lang.Integer.parseInt(parameter.substring(CHECKBOX_DELETE_ADMINENTITY.length())); //Without []     
           indexes.add(new Integer(index)); 
          }
       }
       
       if(indexes.size() > 0){
         ArrayList adminentities = new ArrayList();
         Iterator iter = indexes.iterator();
         while(iter.hasNext()){
           index = ((java.lang.Integer) iter.next()).intValue();
           adminentities.add(new AdminEntity(Integer.parseInt(request.getParameter(HIDDEN_MATCHWITH+index)),
                                             Integer.parseInt(request.getParameter(HIDDEN_MATCHTYPE+index)),
                                             request.getParameter(HIDDEN_MATCHVALUE+index), caid));
         }
         adh.removeAdminEntities(admingroup[ADMINGROUPNAME],caid,adminentities);
      }
    }


%>

<%
   // Generate Html file.
     System.out.println("admingroupname '" + admingroup[ADMINGROUPNAME] + "', caid :" + caid);
   if(adh == null)
     System.out.println(" adh is null");

   if(admingroup == null)
     System.out.println(" admingroup is null");
   if(adh.getAdminGroup(admingroup[ADMINGROUPNAME],caid) == null)
     System.out.println(" AdminGroup is null");

   Collection adminentities = adh.getAdminGroup(admingroup[ADMINGROUPNAME],caid).getAdminEntities();

   int numdeletecheckboxes=adminentities.size();
   String[] MATCHWITHTEXTS = {"","WITHCOUNTRY", "WITHDOMAINCOMPONENT", "WITHSTATE", "WITHLOCATION", 
                              "WITHORGANIZATION", "WITHORGANIZATIONUNIT", "WITHTITLE", 
                              "WITHCOMMONNAME", "WITHUID", "WITHDNSERIALNUMBER", "WITHSERIALNUMBER"}; 

   String[] MATCHTYPETEXTS = {"EQUALCASE", "EQUALCASEINS", "NOTEQUALCASE", "NOTEQUALCASEINS"};
%>

<div align="center">
  <p><H1><%= ejbcawebbean.getText("EDITADMINS") %></H1></p>
  <p><H2><%= ejbcawebbean.getText("FORADMINGROUP") + " " + admingroup[ADMINGROUPNAME] + ", " + ejbcawebbean.getText("CA") + ": " + caidtonamemap.get(new Integer(caid)) %></H2></p>
  <form name="toaccessrules" method="post" action="<%=THIS_FILENAME %>">
  <div align="right"><A href="<%=THIS_FILENAME %>"><u><%= ejbcawebbean.getText("BACKTOADMINGROUPS") %></u></A>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
    <input type="hidden" name='<%= HIDDEN_GROUPNAME %>' value='<%= admingroup[ADMINGROUPNAME] + ";" + caid %>'>
    <input type="hidden" name='<%= ACTION %>' value='<%=ACTION_EDIT_ACCESSRULES %>'>
    <A href='javascript:document.toaccessrules.submit();'><u><%= ejbcawebbean.getText("EDITACCESSRULES") %></u></A>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
<!--    <A  onclick='displayHelpWindow("<%= ejbcawebbean.getHelpfileInfix("authorization_help.html") + "#admins"%>")'>
    <u><%= ejbcawebbean.getText("HELP") %></u> </A> -->
  </div>
  </form>
  <p align="center"></p>
  <form name="addadmins" method="post" action="<%=THIS_FILENAME %>">
    <input type="hidden" name='<%= ACTION %>' value='<%=ACTION_EDIT_ADMINENTITIES %>'>
    <input type="hidden" name='<%= HIDDEN_GROUPNAME %>' value='<%= admingroup[ADMINGROUPNAME] + ";" + caid %>'>
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
          <input type="text" name="<%= TEXTFIELD_MATCHVALUE %>" size="30">
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
    <input type="hidden" name='<%= HIDDEN_GROUPNAME %>' value='<%= admingroup[ADMINGROUPNAME] + ";" + caid %>'>
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
   <% if(adminentities == null || adminentities.size() == 0){ %>
      <tr id="Row0"> 
        <td width="10%">&nbsp;</td>
        <td width="20%">&nbsp;</td>
        <td width="15%">&nbsp;</td>
        <td width="53%"><%= ejbcawebbean.getText("NOADMINSDEFINED") %></td>
        <td width="2%">&nbsp;</td>
      </tr>
   <% }
      else{
        Iterator iter = adminentities.iterator();
        int i = 0;
        while(iter.hasNext()){ 
          adminentity = (AdminEntity) iter.next();%> 
      <tr id="Row<%= i%2 %>"> 
        <td width="10%"> 
          <input type="checkbox" name="<%= CHECKBOX_DELETE_ADMINENTITY + i %>" value="<%= CHECKBOX_VALUE %>">
        </td>
        <td width="20%">
          <input type="hidden" name='<%= HIDDEN_MATCHWITH + i %>' value='<%= adminentity.getMatchWith() %>'>
        <%=  ejbcawebbean.getText(MATCHWITHTEXTS[adminentity.getMatchWith()]) %>
        </td>
        <td width="15%">
          <input type="hidden" name='<%= HIDDEN_MATCHTYPE + i %>' value='<%= adminentity.getMatchType() %>'>
        <%=  ejbcawebbean.getText(MATCHTYPETEXTS[adminentity.getMatchType() - 1000]) %>    

        </td>
        <td width="53%">
          <input type="hidden" name='<%= HIDDEN_MATCHVALUE + i %>' value='<%= adminentity.getMatchValue() %>'>
           <%= adminentity.getMatchValue() %>
        </td>
        <td width="2%">&nbsp;</td>
      </tr>
<%    i++;
      }
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
