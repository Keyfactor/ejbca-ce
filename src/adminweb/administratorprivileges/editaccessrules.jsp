<% /* editacccessrules.jsp
    *
    * page for editing a admingroups access rules, included from Aadministratorprivileges.jsp 
    * 
    * Created on  14 mars 2002, 20:49
    *
    * author  Philip Vendil */ %>

<% // Check actions submitted

    // init record variables


    if( request.getParameter(BUTTON_ADD_ACCESSRULES) != null ){
         // Add selected access rules.
       java.util.Enumeration parameters = request.getParameterNames();
       java.util.Vector indexes = new  java.util.Vector();
       int index;
       while(parameters.hasMoreElements()){
         String parameter = (String) parameters.nextElement();
         if(parameter.startsWith(CHECKBOX_ADDROW) && request.getParameter(parameter).equals(CHECKBOX_VALUE)) {
           index = java.lang.Integer.parseInt(parameter.substring(CHECKBOX_ADDROW.length())); //Without []
           indexes.addElement(new Integer(index));
         }
       }
       
       if(indexes.size() > 0){
         String[][] accessrules = new String[indexes.size()][3];
         for(int i = 0; i < indexes.size(); i++){
           index = ((java.lang.Integer) indexes.elementAt(i)).intValue();
           accessrules[i][AuthorizationDataHandler.ACCESS_RULE_RESOURCE] = request.getParameter(HIDDEN_ADDRESOURCE+index);
           accessrules[i][AuthorizationDataHandler.ACCESS_RULE_RULE] = request.getParameter(SELECT_ADDRULE+index);
           if(request.getParameter(CHECKBOX_RECURSIVEROW+index)!= null){
             accessrules[i][AuthorizationDataHandler.ACCESS_RULE_RECURSIVE] = "true";
           }
           else{
             accessrules[i][AuthorizationDataHandler.ACCESS_RULE_RECURSIVE] = "false";
           }
         }
         adh.addAccessRules(admingroup,accessrules);
       }
    }
    if( request.getParameter(BUTTON_DELETE_ACCESSRULES) != null ){
         // Delete selected access rules
       java.util.Enumeration parameters = request.getParameterNames();
       java.util.Vector indexes = new  java.util.Vector();
       int index;
       while(parameters.hasMoreElements()) {
         String parameter = (String) parameters.nextElement();
         if(parameter.startsWith(CHECKBOX_DELETEROW) && request.getParameter(parameter).equals(CHECKBOX_VALUE)){
           index = java.lang.Integer.parseInt(parameter.substring(CHECKBOX_DELETEROW.length())); //Without []   
           indexes.addElement(new Integer(index)); 
          }
       }
       
       if(indexes.size() > 0){
         String[][] accessrules = new String[indexes.size()][3];
         for(int i = 0; i < indexes.size(); i++){
           index = ((java.lang.Integer) indexes.elementAt(i)).intValue();
           accessrules[i][AuthorizationDataHandler.ACCESS_RULE_RESOURCE] = request.getParameter(HIDDEN_DELETEROW+index);  
         }
         adh.removeAccessRules(admingroup,accessrules);   
      }
    }

    int recordnumber = ejbcawebbean.getEntriesPerPage();
    int oldrecordnumber = 0;
    if (request.getParameter(HIDDEN_RECORDNUMBER) != null ){
      recordnumber =  Integer.parseInt(request.getParameter(HIDDEN_RECORDNUMBER)); 
      oldrecordnumber = recordnumber - ejbcawebbean.getEntriesPerPage();
      if(oldrecordnumber < 0) oldrecordnumber=0;
    }   

    if( request.getParameter(BUTTON_PREVIOUS_ACCESSRULES) != null ){
      recordnumber = Integer.parseInt(request.getParameter(HIDDEN_RECORDNUMBER));
      oldrecordnumber = recordnumber;
      recordnumber -= ejbcawebbean.getEntriesPerPage();
      oldrecordnumber -= 2 * ejbcawebbean.getEntriesPerPage();  
      if(recordnumber < ejbcawebbean.getEntriesPerPage()) recordnumber=ejbcawebbean.getEntriesPerPage();
      if(oldrecordnumber < 0 ) oldrecordnumber = 0;
    }
    if( request.getParameter(BUTTON_NEXT_ACCESSRULES) != null ){
      recordnumber = Integer.parseInt(request.getParameter(HIDDEN_RECORDNUMBER));
      oldrecordnumber = recordnumber;
      recordnumber += ejbcawebbean.getEntriesPerPage();
    }




   // Generate Html file.
   String[][] accessrules = adh.getAccessRules(admingroup);
   String[] availableaccessrules = adh.getAvailableRules(admingroup);
   if(recordnumber > availableaccessrules.length){
     recordnumber = availableaccessrules.length;
     oldrecordnumber = recordnumber - ejbcawebbean.getEntriesPerPage();
     if(oldrecordnumber < 0) oldrecordnumber =0;
   }
   int numdeletecheckboxes=0;
%>

<div align="center">
  <p><H1><%= ejbcawebbean.getText("ACCESSRULES") %></H1></p>
  <p><H2><%= ejbcawebbean.getText("FORADMINGROUP")%> <%= admingroup %></H2></p>
  <form name="toadminentities" method="post" action="<%=THIS_FILENAME %>">
  <div align="right"><A href="<%=THIS_FILENAME %>"><u><%= ejbcawebbean.getText("BACKTOADMINGROUPS") %></u></A>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
    <input type="hidden" name='<%= HIDDEN_GROUPNAME %>' value='<%= admingroup %>'>
    <input type="hidden" name='<%= ACTION %>' value='<%=ACTION_EDIT_ADMINENTITIES%>'>
    <% if(!admingroup.equals(AdminGroup.SPECIALADMINGROUP_PUBLICWEBADMIN) && !admingroup.equals(AdminGroup.SPECIALADMINGROUP_CACOMMANDLINEADMIN)
          && !admingroup.equals(AdminGroup.SPECIALADMINGROUP_RACOMMANDLINEADMIN)){ %>
    <A href='javascript:document.toadminentities.submit();'><u><%= ejbcawebbean.getText("EDITADMINS") %></u></A>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
    <% } %>
    <A  onclick='displayHelpWindow("<%= ejbcawebbean.getHelpfileInfix("authorization_help.html") + "#accessrules" %>")'>
    <u><%= ejbcawebbean.getText("HELP") %></u> </A>
  </div>
  </form>
  <form name="deleteaccessrules" method="post" action="<%=THIS_FILENAME %>">
    <input type="hidden" name='<%= ACTION %>' value='<%=ACTION_EDIT_ACCESSRULES %>'>
    <input type="hidden" name='<%= HIDDEN_GROUPNAME %>' value='<%= admingroup %>'>
    <table width="100%" border="0" cellspacing="0" cellpadding="0">
      <tr> 
        <td width="17%"><H2><%= ejbcawebbean.getText("ACCESSRULES") %></H2></td>
        <td width="37%">&nbsp;</td>
        <td width="12%">&nbsp;</td>
        <td width="16%">&nbsp;</td>
        <td width="18%">&nbsp;</td>
      </tr>
      <tr id="Header"> 
        <td width="17%"><H3><%= ejbcawebbean.getText("DELETE") %></H3></td>
        <td width="37%"><H3><%= ejbcawebbean.getText("RESOURCE") %></H3></td>
        <td width="12%"><H3><%= ejbcawebbean.getText("RULE") %></H3></td>
        <td width="16%"><H3><%= ejbcawebbean.getText("RECURSIVE") %></H3></td>
        <td width="18%"><H3></H3></td>
      </tr>
      <% if(accessrules == null || accessrules.length == 0){ %>
      <tr id="Row0"> 
        <td width="17%">&nbsp;</td>
        <td width="37%"><%= ejbcawebbean.getText("NOACCESSRULESDEFINED") %></td>
        <td width="12%">&nbsp;</td>
        <td width="16%">&nbsp;</td>    
        <td width="18%">&nbsp;</td>  
      </tr>
      <%}
        else{
          numdeletecheckboxes= accessrules.length;
          for(int i = 0; i < accessrules.length; i++){ %>
      <tr id="Row<%= i%2 %>"> <!-- User entries in css to make lines in table --> 
        <td width="17%">
          <input type="checkbox" name="<%=CHECKBOX_DELETEROW  + i  %>" value="<%= CHECKBOX_VALUE %>">

          <input type="hidden" name='<%= HIDDEN_DELETEROW + i %>' value='<%= accessrules[i][AuthorizationDataHandler.ACCESS_RULE_RESOURCE] %>'>
        </td>
           <% 
           // Check if it is a profile rule, then replace profile id with profile name.

           if(accessrules[i][AuthorizationDataHandler.ACCESS_RULE_RESOURCE].startsWith(globalconfiguration.ENDENTITYPROFILEPREFIX)){
              if(accessrules[i][AuthorizationDataHandler.ACCESS_RULE_RESOURCE].lastIndexOf('/') < globalconfiguration.ENDENTITYPROFILEPREFIX.length())
                accessrules[i][AuthorizationDataHandler.ACCESS_RULE_RESOURCE] = globalconfiguration.ENDENTITYPROFILEPREFIX  
                                                                               + rabean.getEndEntityProfileName(Integer.parseInt(accessrules[i][AuthorizationDataHandler.ACCESS_RULE_RESOURCE].substring(globalconfiguration.ENDENTITYPROFILEPREFIX.length())));
              
              else
                accessrules[i][AuthorizationDataHandler.ACCESS_RULE_RESOURCE] = globalconfiguration.ENDENTITYPROFILEPREFIX  
                                                                               + rabean.getEndEntityProfileName(Integer.parseInt(accessrules[i][AuthorizationDataHandler.ACCESS_RULE_RESOURCE].substring(globalconfiguration.ENDENTITYPROFILEPREFIX.length(),
                                                                                                                                                                              accessrules[i][AuthorizationDataHandler.ACCESS_RULE_RESOURCE].lastIndexOf('/'))))
                                                                               + accessrules[i][AuthorizationDataHandler.ACCESS_RULE_RESOURCE].substring(accessrules[i][AuthorizationDataHandler.ACCESS_RULE_RESOURCE].lastIndexOf('/'));
           } %>
        <td width="37%"><%= accessrules[i][AuthorizationDataHandler.ACCESS_RULE_RESOURCE] %></td>
        <td width="12%"><% if(accessrules[i][AuthorizationDataHandler.ACCESS_RULE_RULE].equals(String.valueOf(AccessRule.RULE_ACCEPT))){
                             out.write(ejbcawebbean.getText("ACCEPT"));
                           }
                           if(accessrules[i][AuthorizationDataHandler.ACCESS_RULE_RULE].equals(String.valueOf(AccessRule.RULE_DECLINE))){
                              out.write(ejbcawebbean.getText("DECLINE"));
                           }%></td>
        <td width="16%"><% if(accessrules[i][AuthorizationDataHandler.ACCESS_RULE_RECURSIVE].equals("true")){
                             out.write(ejbcawebbean.getText("YES"));
                           }
                           else{
                             out.write(ejbcawebbean.getText("NO"));
                           }
    %> </td>
        <td width="18%">&nbsp;</td>
      </tr>
      <% }
      }  %>
    </table>
  <table width="100%" border="0" cellspacing="0" cellpadding="0">
    <tr>
       <td width="66%" valign="middle">
           <input type="button" value="<%= ejbcawebbean.getText("SELECTALL") %>" 
           onClick='checkAll("document.deleteaccessrules.<%= CHECKBOX_DELETEROW %>", <%= numdeletecheckboxes %>)'>
           <input type="button" value="<%= ejbcawebbean.getText("UNSELECTALL") %>" 
           onClick='uncheckAll("document.deleteaccessrules.<%= CHECKBOX_DELETEROW %>", <%= numdeletecheckboxes %>)'>
           <input type="button" value="<%=ejbcawebbean.getText("INVERTSELECTION") %>" 
           onClick='switchAll("document.deleteaccessrules.<%= CHECKBOX_DELETEROW %>", <%= numdeletecheckboxes %>)'>
        <td width="16%">&nbsp;</td>
        <td width="18%" valign="middle">&nbsp; </td>
    </tr>
    <tr> 
        <td width="66%" valign="middle"><H2><%= ejbcawebbean.getText("DELETESELECTED") %></H2>
          <input type="submit" onClick="return confirm('<%= ejbcawebbean.getText("AREYOUSURE") %>');" name="<%=BUTTON_DELETE_ACCESSRULES %>" value="<%= ejbcawebbean.getText("DELETE") %>">
        </td>  <td width="16%">&nbsp;</td>
        <td width="18%" valign="middle">&nbsp; </td>
    </tr>
  </table>
  </form>
  <p align="center"><H1><%= ejbcawebbean.getText("AVAILABLERULES") %></H1></p>
  <form name="addaccessrules" method="post" action="<%=THIS_FILENAME %>">
    <input type="hidden" name='<%= ACTION %>' value='<%=ACTION_EDIT_ACCESSRULES %>'>
    <input type="hidden" name='<%= HIDDEN_GROUPNAME %>' value='<%= admingroup %>'>
    <input type="hidden" name='<%= HIDDEN_RECORDNUMBER %>' value='<%= String.valueOf(recordnumber) %>'>
    <table width="100%" border="0" cellspacing="0" cellpadding="0">
      <tr> 
        <td width="17%"><H2><%= ejbcawebbean.getText("AVAILABLEACCESSRULES") %></H2></td>
        <td width="37%">&nbsp;</td>
        <td width="12%">&nbsp;</td>
        <td width="16%">&nbsp;</td>
        <td width="18%">&nbsp;</td>
      </tr>
      <tr> 
        <td width="17%">&nbsp;</td>
        <td width="37%"><H3><%= ejbcawebbean.getText("ROW") %>&nbsp;<%=oldrecordnumber %>&nbsp;
                         <%= ejbcawebbean.getText("TO") %>&nbsp; <%=recordnumber %>&nbsp; 
                         <%= ejbcawebbean.getText("OF") %>&nbsp;<%= availableaccessrules.length %></H3>
        </td>
        <td width="12%">&nbsp;</td>
        <td width="16%">&nbsp;</td>
        <td width="18%">&nbsp;</td>
     </tr>
      <tr id="Header"> 
        <td width="17%"><H3><%= ejbcawebbean.getText("ADD") %></H3></td>
        <td width="37%"><H3><%= ejbcawebbean.getText("RESOURCE") %></H3></td>
        <td width="12%"><H3><%= ejbcawebbean.getText("RULE") %></H3></td>
        <td width="16%"><H3><%= ejbcawebbean.getText("RECURSIVE") %></H3></td>
        <td width="18%"><H3></H3></td>
      </tr>
    <% if(availableaccessrules == null || availableaccessrules.length == 0){ %>
      <tr id="Row0">
        <td width="17%">&nbsp; </td> 
        <td width="37%"><%= ejbcawebbean.getText("NOAVAILABLEACCESSRULES") %></td>
        <td width="12%">&nbsp;</td>
        <td width="16%">&nbsp;</td>
      </tr>
      <%}
        else{ 
          for(int i =  oldrecordnumber ; i < recordnumber; i++){ %>
      <tr id="Row<%= i%2 %>"> 
        <td width="17%"> 
          <input type="checkbox" name="<%= CHECKBOX_ADDROW  + i %>" value="<%= CHECKBOX_VALUE %>">
          </td>
        <td width="37%">
          <input type="hidden" name='<%= HIDDEN_ADDRESOURCE  + i %>' value='<%= availableaccessrules[i] %>'>  
              <% 
           // Check if it is a profile rule, then replace profile id with profile name.
           if(availableaccessrules[i].startsWith(globalconfiguration.ENDENTITYPROFILEPREFIX)){
              if(availableaccessrules[i].lastIndexOf('/') < globalconfiguration.ENDENTITYPROFILEPREFIX.length())
                availableaccessrules[i] = globalconfiguration.ENDENTITYPROFILEPREFIX  
                                          + rabean.getEndEntityProfileName(Integer.parseInt(availableaccessrules[i].substring(globalconfiguration.ENDENTITYPROFILEPREFIX.length())));
              else
                availableaccessrules[i] = globalconfiguration.ENDENTITYPROFILEPREFIX 
                                          + rabean.getEndEntityProfileName(Integer.parseInt(availableaccessrules[i].substring(globalconfiguration.ENDENTITYPROFILEPREFIX.length(),
                                                                                   availableaccessrules[i].lastIndexOf('/'))))
                                          + availableaccessrules[i].substring(availableaccessrules[i].lastIndexOf('/'));
           }
           out.print(availableaccessrules[i]); %>
                
          </td>
        <td width="12%"> 
          <select name="<%=SELECT_ADDRULE  + i  %>" size="1">
            <option selected value='<%= AccessRule.RULE_ACCEPT %>'><%= ejbcawebbean.getText("ACCEPT") %></option>
            <option value='<%= AccessRule.RULE_DECLINE %>'><%= ejbcawebbean.getText("DECLINE") %></option>
          </select>
          </td>
        <td width="16%"> 
          <input type="checkbox" name="<%=CHECKBOX_RECURSIVEROW  + i  %>" value="<%= CHECKBOX_VALUE %>">
        </td>
        <td width="18%">&nbsp;</td>
      </tr>
     <%  }
      } %>
    </table>
  <table width="100%" border="0" cellspacing="0" cellpadding="0">
    <tr>
       <td width="50%" valign="left">
         <% if(recordnumber >  ejbcawebbean.getEntriesPerPage()){ %>
           <input type="submit" name="<%= BUTTON_PREVIOUS_ACCESSRULES %>"
              value="<%= ejbcawebbean.getText("PREVIOUS") + " " + ejbcawebbean.getEntriesPerPage() %>">
         <% } %>
       </td>
       <td width="50%" valign="right">
         <% if(recordnumber < availableaccessrules.length ){ %>
           <input type="submit" name="<%= BUTTON_NEXT_ACCESSRULES %>"
              value="<%= ejbcawebbean.getText("NEXT") + " " + ejbcawebbean.getEntriesPerPage() %>">
         <% } %>
       </td>
     </tr> 
     <tr> 
        <td width="66%" valign="middle"><H2><%= ejbcawebbean.getText("ADDSELECTED") %></H2>
          <input type="submit" name="<%=BUTTON_ADD_ACCESSRULES %>" value="<%= ejbcawebbean.getText("ADD") %>">
        </td>  <td width="16%">&nbsp;</td>
        <td width="18%" valign="middle">&nbsp; </td>
    </tr>
  </table>
  </form>
  <p align="left">&nbsp; </p>
  <p>&nbsp;</p>
</div>