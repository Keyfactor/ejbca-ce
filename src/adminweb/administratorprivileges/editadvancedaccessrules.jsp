<% /* editadvancedacccessrules.js   p
    *
    * 
    * Created on  17 feb 2004, 20:49
    *
    * author  Philip Vendil */ %>

<% // Check actions submitted
     
     // Generate Html file.

     Collection[] accessrules = {admingroupaccessrules.getRoleBasedAccessRules(),
                                 admingroupaccessrules.getRegularAccessRules(),
                                 admingroupaccessrules.getEndEntityProfileAccessRules(),
                                 admingroupaccessrules.getCAAccessRules()};
     Collection[] availableaccessrules = 
                                {nonusedavailableaccessrule.getRoleBasedAccessRules(),
                                 nonusedavailableaccessrule.getRegularAccessRules(),
                                 nonusedavailableaccessrule.getEndEntityProfileAccessRules(),
                                 nonusedavailableaccessrule.getCAAccessRules()};
     String[] accessruletexts = {"ROLEBASEDACCESSRULES", "REGULARACCESSRULES",
                                 "ENDENTITYPROFILEACCESSR", "CAACCESSRULES"};

     int numdeletecheckboxes=0;
%>

<div align="center">
  <form name="deleteaccessrules" method="post" action="<%=THIS_FILENAME %>">
    <input type="hidden" name='<%= ACTION %>' value='<%=ACTION_EDIT_ACCESSRULES %>'>
    <input type="hidden" name='<%= HIDDEN_GROUPNAME %>' value='<%= admingroup[ADMINGROUPNAME] + ";" + caid %>'>
    <input type="hidden" name='<%= MODE %>' value='<%=MODE_ADVANCED%>'>
    <table width="100%" border="0" cellspacing="0" cellpadding="0">
      <% int i=0;  
         for(int j=0; j < accessruletexts.length; j++){ %>
      <tr id="Header"> 
        <td width="17%"><H3>&nbsp;</H3></td>
        <td width="37%"><H3>&nbsp;</H3></td>
        <td width="12%"><H3>&nbsp;</H3></td>
        <td width="16%"><H3>&nbsp;</H3></td>
        <td width="18%"><H3>&nbsp;</H3></td>
      </tr>
      <tr id="Header"> 
        <td width="17%"><H3> &nbsp;</H3></td>
        <td width="37%"><H3><%= ejbcawebbean.getText(accessruletexts[j]) %></H3></td>
        <td width="12%"><H3> &nbsp;</H3></td>
        <td width="16%"><H3> &nbsp;</H3></td>
        <td width="18%"><H3></H3></td>
      </tr>
      <tr id="Header"> 
        <td width="17%"><H3><%= ejbcawebbean.getText("DELETE") %></H3></td>
        <td width="37%"><H3><%= ejbcawebbean.getText("RESOURCE") %></H3></td>
        <td width="12%"><H3><%= ejbcawebbean.getText("RULE") %></H3></td>
        <td width="16%"><H3><%= ejbcawebbean.getText("RECURSIVE") %></H3></td>
        <td width="18%"><H3></H3></td>
      </tr>
      <% if(accessrules[j] == null || accessrules[j].size() == 0){ %>
      <tr id="Row0"> 
        <td width="17%">&nbsp;</td>
        <td width="37%"><%= ejbcawebbean.getText("NOACCESSRULESDEFINED") %></td>
        <td width="12%">&nbsp;</td>
        <td width="16%">&nbsp;</td>    
        <td width="18%">&nbsp;</td>  
      </tr>
      <%}
        else{
          numdeletecheckboxes+= accessrules[j].size();
          Iterator iter = accessrules[j].iterator();
          while(iter.hasNext()){ 
            accessrule = (AccessRule) iter.next();%>
      <tr id="Row<%= i%2 %>"> <!-- User entries in css to make lines in table --> 
        <td width="17%">
          <input type="checkbox" name="<%=CHECKBOX_DELETEROW  + i  %>" value="<%= CHECKBOX_VALUE %>">

          <input type="hidden" name='<%= HIDDEN_DELETEROW + i %>' value='<%= accessrule.getAccessRule() %>'>
        </td>
           <% 
           // Check if it is a profile rule, then replace profile id with profile name.
           accessrulesstring = accessrule.getAccessRule(); 
           if(j==2){
           // Check if it is a profile rule, then replace profile id with profile name.
             if(accessrulesstring.startsWith(AvailableAccessRules.ENDENTITYPROFILEPREFIX)){
               if(accessrulesstring.lastIndexOf('/') < AvailableAccessRules.ENDENTITYPROFILEPREFIX.length())
                 accessrulesstring = AvailableAccessRules.ENDENTITYPROFILEPREFIX  
                                   + rabean.getEndEntityProfileName(Integer.parseInt(accessrulesstring.substring(AvailableAccessRules.ENDENTITYPROFILEPREFIX.length())));
              
               else
                 accessrulesstring =AvailableAccessRules.ENDENTITYPROFILEPREFIX  
                                    + rabean.getEndEntityProfileName(Integer.parseInt(accessrulesstring.substring(AvailableAccessRules.ENDENTITYPROFILEPREFIX.length(), accessrulesstring.lastIndexOf('/'))))
                                    + accessrulesstring.substring(accessrulesstring.lastIndexOf('/'));
             }
           }
           if(j==3){
           // Check if it is a CA rule, then replace CA id with CA name.
             if(accessrulesstring.startsWith(AvailableAccessRules.CAPREFIX)){
               if(accessrulesstring.lastIndexOf('/') < AvailableAccessRules.CAPREFIX.length())
                 accessrulesstring = AvailableAccessRules.CAPREFIX  
                                   + caidtonamemap.get(new Integer(accessrulesstring.substring(AvailableAccessRules.CAPREFIX.length())));
              
               else
                 accessrulesstring =AvailableAccessRules.CAPREFIX  
                                    + caidtonamemap.get(new Integer(accessrulesstring.substring(AvailableAccessRules.CAPREFIX.length(), accessrulesstring.lastIndexOf('/'))))
                                    + accessrulesstring.substring(accessrulesstring.lastIndexOf('/'));
             }
           }%>
        <td width="37%"><%= accessrulesstring %></td>
        <td width="12%"><% if(accessrule.getRule() ==  AccessRule.RULE_ACCEPT){
                             out.write(ejbcawebbean.getText("ACCEPT"));
                           }
                           if(accessrule.getRule() == AccessRule.RULE_DECLINE){
                              out.write(ejbcawebbean.getText("DECLINE"));
                           }%></td>
        <td width="16%"><% if(accessrule.isRecursive()){
                             out.write(ejbcawebbean.getText("YES"));
                           }
                           else{
                             out.write(ejbcawebbean.getText("NO"));
                           }
    %> </td>
        <td width="18%">&nbsp;</td>
      </tr>
      <%  i++;
          } 
        } 
      }%>
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
    <input type="hidden" name='<%= HIDDEN_GROUPNAME %>' value='<%= admingroup[ADMINGROUPNAME] + ";" + caid %>'>
    <input type="hidden" name='<%= MODE %>' value='<%=MODE_ADVANCED%>'>

    <table width="100%" border="0" cellspacing="0" cellpadding="0">
      <tr> 
        <td width="17%">&nbsp;</td>
        <td width="37%">&nbsp;</td>
        <td width="12%">&nbsp;</td>
        <td width="16%">&nbsp;</td>
        <td width="18%">&nbsp;</td>
     </tr>
      <% i=0;  
         for(int j=0; j < accessruletexts.length; j++){ %>
      <tr id="Header"> 
        <td width="17%"><H3>&nbsp;</H3></td>
        <td width="37%"><H3>&nbsp;</H3></td>
        <td width="12%"><H3>&nbsp;</H3></td>
        <td width="16%"><H3>&nbsp;</H3></td>
        <td width="18%"><H3>&nbsp;</H3></td>
      </tr>
      <tr id="Header"> 
        <td width="17%"><H3>&nbsp;</H3></td>
        <td width="37%"><H3><%= ejbcawebbean.getText(accessruletexts[j]) %></H3></td>
        <td width="12%"><H3>&nbsp;</H3></td>
        <td width="16%"><H3>&nbsp;</H3></td>
        <td width="18%"><H3>&nbsp;</H3></td>
      </tr>
      <tr id="Header"> 
        <td width="17%"><H3><%= ejbcawebbean.getText("ADD") %></H3></td>
        <td width="37%"><H3><%= ejbcawebbean.getText("RESOURCE") %></H3></td>
        <td width="12%"><H3><%= ejbcawebbean.getText("RULE") %></H3></td>
        <td width="16%"><H3><%= ejbcawebbean.getText("RECURSIVE") %></H3></td>
        <td width="18%"><H3></H3></td>
      </tr>
    <% if(availableaccessrules[j] == null || availableaccessrules[j].size() == 0){ %>
      <tr id="Row0">
        <td width="17%">&nbsp; </td> 
        <td width="37%"><%= ejbcawebbean.getText("NOAVAILABLEACCESSRULES") %></td>
        <td width="12%">&nbsp;</td>
        <td width="16%">&nbsp;</td>
      </tr>
      <%}
        else{ 
          Iterator iter = availableaccessrules[j].iterator();
          while(iter.hasNext()){ 
            accessrule = (AccessRule) iter.next();%>
      <tr id="Row<%= i%2 %>"> 
        <td width="17%"> 
          <input type="checkbox" name="<%= CHECKBOX_ADDROW  + i %>" value="<%= CHECKBOX_VALUE %>">
          </td>
        <td width="37%">
          <input type="hidden" name='<%= HIDDEN_ADDRESOURCE  + i %>' value='<%= accessrule.getAccessRule() %>'>  
           <% 
           // Check if it is a profile rule, then replace profile id with profile name.
           accessrulesstring = accessrule.getAccessRule(); 
           if(j==2){
           // Check if it is a profile rule, then replace profile id with profile name.
             if(accessrulesstring.startsWith(AvailableAccessRules.ENDENTITYPROFILEPREFIX)){
               if(accessrulesstring.lastIndexOf('/') < AvailableAccessRules.ENDENTITYPROFILEPREFIX.length())
                 accessrulesstring = AvailableAccessRules.ENDENTITYPROFILEPREFIX  
                                   + rabean.getEndEntityProfileName(Integer.parseInt(accessrulesstring.substring(AvailableAccessRules.ENDENTITYPROFILEPREFIX.length())));
              
               else
                 accessrulesstring =AvailableAccessRules.ENDENTITYPROFILEPREFIX  
                                    + rabean.getEndEntityProfileName(Integer.parseInt(accessrulesstring.substring(AvailableAccessRules.ENDENTITYPROFILEPREFIX.length(), accessrulesstring.lastIndexOf('/'))))
                                    + accessrulesstring.substring(accessrulesstring.lastIndexOf('/'));
             }
           }
           if(j==3){
           // Check if it is a CA rule, then replace CA id with CA name.
             if(accessrulesstring.startsWith(AvailableAccessRules.CAPREFIX)){ 
               if(accessrulesstring.lastIndexOf('/') < AvailableAccessRules.CAPREFIX.length())
                 accessrulesstring = AvailableAccessRules.CAPREFIX  
                                   + caidtonamemap.get(new Integer(accessrulesstring.substring(AvailableAccessRules.CAPREFIX.length())));
              
               else
                 accessrulesstring =AvailableAccessRules.CAPREFIX  
                                    + caidtonamemap.get(new Integer(accessrulesstring.substring(AvailableAccessRules.CAPREFIX.length(), accessrulesstring.lastIndexOf('/'))))
                                    + accessrulesstring.substring(accessrulesstring.lastIndexOf('/'));
             }
           }
           out.write(accessrulesstring); %>
    
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
     <%   i++; 
          } 
        }
      }%>
    </table>
  <table width="100%" border="0" cellspacing="0" cellpadding="0">
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