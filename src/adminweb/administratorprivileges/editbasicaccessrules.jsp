<% /* editbasicacccessrules.jsp
    *
    * page for editing a admingroups access rules, included from Administratorprivileges.jsp 
    * 
    * Created on  14 mars 2002, 20:49
    *
    * author  Philip Vendil */ %>

<% 

  int row = 0;

  

%>

<SCRIPT language="JavaScript">
<!--  

function roleupdated(){
  var currentrole = document.basicrules.<%=SELECT_ROLE%>.options[document.basicrules.<%=SELECT_ROLE%>.options.selectedIndex].value;  

  if(currentrole == <%=BasicAccessRuleSet.ROLE_NONE %>){
    document.basicrules.<%=SELECT_CAS %>.disabled = true;
    document.basicrules.<%=SELECT_ENDENTITYRULES%>.disabled = true;
    document.basicrules.<%=SELECT_ENDENTITYPROFILES %>.disabled = true;
    document.basicrules.<%=SELECT_OTHER %>.disabled = true;


    numofcas = document.basicrules.<%=SELECT_CAS %>.length;
    for( i=numofcas-1; i >= 0; i-- ){          
         document.basicrules.<%=SELECT_CAS%>.options[i].selected=false;
    }

    numofendentity = document.basicrules.<%=SELECT_ENDENTITYRULES %>.length;
    for( i=numofendentity-1; i >= 0; i-- ){          
         document.basicrules.<%=SELECT_ENDENTITYRULES%>.options[i].selected=false;
    }

    numofprofiles = document.basicrules.<%=SELECT_ENDENTITYPROFILES %>.length;
    for( i=numofprofiles-1; i >= 0; i-- ){          
         document.basicrules.<%=SELECT_ENDENTITYPROFILES%>.options[i].selected=false;
    }

    numofother = document.basicrules.<%=SELECT_OTHER %>.length;
    for( i=numofother-1; i >= 0; i-- ){
       document.basicrules.<%=SELECT_OTHER %>.options[i]=null;
    }


  }
 
  if(currentrole == <%=BasicAccessRuleSet.ROLE_SUPERADMINISTRATOR %>){
    document.basicrules.<%=SELECT_CAS %>.disabled = true;
    document.basicrules.<%=SELECT_ENDENTITYRULES%>.disabled = true;
    document.basicrules.<%=SELECT_ENDENTITYPROFILES %>.disabled = true;
    document.basicrules.<%=SELECT_OTHER %>.disabled = true;

    numofcas = document.basicrules.<%=SELECT_CAS %>.length;
    for( i=numofcas-1; i >= 0; i-- ){          
         document.basicrules.<%=SELECT_CAS%>.options[i].selected=false;
    }

    numofendentity = document.basicrules.<%=SELECT_ENDENTITYRULES %>.length;
    for( i=numofendentity-1; i >= 0; i-- ){          
         document.basicrules.<%=SELECT_ENDENTITYRULES%>.options[i].selected=false;
    }

    numofprofiles = document.basicrules.<%=SELECT_ENDENTITYPROFILES %>.length;
    for( i=numofprofiles-1; i >= 0; i-- ){          
         document.basicrules.<%=SELECT_ENDENTITYPROFILES%>.options[i].selected=false;
    }

    numofother = document.basicrules.<%=SELECT_OTHER %>.length;
    for( i=numofother-1; i >= 0; i-- ){
       document.basicrules.<%=SELECT_OTHER %>.options[i]=null;
    }

  }
  if(currentrole == <%= BasicAccessRuleSet.ROLE_CAADMINISTRATOR%>){
    document.basicrules.<%=SELECT_CAS %>.disabled = false;
    document.basicrules.<%=SELECT_ENDENTITYRULES%>.disabled = true;
    document.basicrules.<%=SELECT_ENDENTITYPROFILES %>.disabled = true;
    document.basicrules.<%=SELECT_OTHER %>.disabled = false;

    numofendentity = document.basicrules.<%=SELECT_ENDENTITYRULES %>.length;
    for( i=numofendentity-1; i >= 0; i-- ){          
         document.basicrules.<%=SELECT_ENDENTITYRULES%>.options[i].selected=false;
    }

    numofprofiles = document.basicrules.<%=SELECT_ENDENTITYPROFILES %>.length;
    for( i=numofprofiles-1; i >= 0; i-- ){          
         document.basicrules.<%=SELECT_ENDENTITYPROFILES%>.options[i].selected=false;
    }

    numofother = document.basicrules.<%=SELECT_OTHER %>.length;
    for( i=numofother-1; i >= 0; i-- ){
       document.basicrules.<%=SELECT_OTHER %>.options[i]=null;
    }
    <% if(globalconfiguration.getIssueHardwareTokens()){ %>
    document.basicrules.<%=SELECT_OTHER %>.options[0]=new Option("<%= ejbcawebbean.getText(BasicAccessRuleSet.OTHERTEXTS[BasicAccessRuleSet.OTHER_ISSUEHARDTOKENS]) %>",<%= BasicAccessRuleSet.OTHER_ISSUEHARDTOKENS %>);
    <% } %>
  }
  if(currentrole == <%= BasicAccessRuleSet.ROLE_RAADMINISTRATOR%>){
    document.basicrules.<%=SELECT_CAS %>.disabled = false;
    document.basicrules.<%=SELECT_ENDENTITYRULES%>.disabled = false;
    document.basicrules.<%=SELECT_ENDENTITYPROFILES %>.disabled = false;
    document.basicrules.<%=SELECT_OTHER %>.disabled = false;

    numofendentity = document.basicrules.<%=SELECT_ENDENTITYRULES %>.length;
    for( i=numofendentity-1; i >= 0; i-- ){
       if(document.basicrules.<%=SELECT_ENDENTITYRULES%>.options[i].value == <%=BasicAccessRuleSet.ENDENTITY_VIEW %> ||
          document.basicrules.<%=SELECT_ENDENTITYRULES%>.options[i].value == <%=BasicAccessRuleSet.ENDENTITY_VIEWHISTORY %> ||
          document.basicrules.<%=SELECT_ENDENTITYRULES%>.options[i].value == <%=BasicAccessRuleSet.ENDENTITY_CREATE %> ||
          document.basicrules.<%=SELECT_ENDENTITYRULES%>.options[i].value == <%=BasicAccessRuleSet.ENDENTITY_EDIT %> ||
          document.basicrules.<%=SELECT_ENDENTITYRULES%>.options[i].value == <%=BasicAccessRuleSet.ENDENTITY_DELETE %> ||
          document.basicrules.<%=SELECT_ENDENTITYRULES%>.options[i].value == <%=BasicAccessRuleSet.ENDENTITY_REVOKE %>)
         document.basicrules.<%=SELECT_ENDENTITYRULES%>.options[i].selected=true;
       else
         document.basicrules.<%=SELECT_ENDENTITYRULES%>.options[i].selected=false;
    }

    numofother = document.basicrules.<%=SELECT_OTHER %>.length;
    for( i=numofother-1; i >= 0; i-- ){
       document.basicrules.<%=SELECT_OTHER %>.options[i]=null;
    }
    document.basicrules.<%=SELECT_OTHER %>.options[0]=new Option("<%= ejbcawebbean.getText(BasicAccessRuleSet.OTHERTEXTS[BasicAccessRuleSet.OTHER_VIEWLOG]) %>",<%= BasicAccessRuleSet.OTHER_VIEWLOG %>);
    <% if(globalconfiguration.getIssueHardwareTokens()){ %>
      document.basicrules.<%=SELECT_OTHER %>.options[1]=new Option("<%= ejbcawebbean.getText(BasicAccessRuleSet.OTHERTEXTS[BasicAccessRuleSet.OTHER_ISSUEHARDTOKENS]) %>",<%= BasicAccessRuleSet.OTHER_ISSUEHARDTOKENS %>);
    <% } %>
  }  
  if(currentrole == <%= BasicAccessRuleSet.ROLE_SUPERVISOR%>){
    document.basicrules.<%=SELECT_CAS %>.disabled = false;
    document.basicrules.<%=SELECT_ENDENTITYRULES%>.disabled = false;
    document.basicrules.<%=SELECT_ENDENTITYPROFILES %>.disabled = false;
    document.basicrules.<%=SELECT_OTHER %>.disabled = true;

    numofendentity = document.basicrules.<%=SELECT_ENDENTITYRULES %>.length;
    for( i=numofendentity-1; i >= 0; i-- ){
       if(document.basicrules.<%=SELECT_ENDENTITYRULES%>.options[i].value == <%=BasicAccessRuleSet.ENDENTITY_VIEW %> ||
          document.basicrules.<%=SELECT_ENDENTITYRULES%>.options[i].value == <%=BasicAccessRuleSet.ENDENTITY_VIEWHISTORY %>)
         document.basicrules.<%=SELECT_ENDENTITYRULES%>.options[i].selected=true;
       else
         document.basicrules.<%=SELECT_ENDENTITYRULES%>.options[i].selected=false;
    }
  }

}

function checkallfields(){ 
    var illegalfields = 0;
    var illegalselection = false;

    document.basicrules.<%=SELECT_CAS %>.disabled = false;
    document.basicrules.<%=SELECT_ENDENTITYRULES%>.disabled = false;
    document.basicrules.<%=SELECT_ENDENTITYPROFILES %>.disabled = false;
    document.basicrules.<%=SELECT_OTHER %>.disabled = false;

    var currentrole = document.basicrules.<%=SELECT_ROLE%>.options[document.basicrules.<%=SELECT_ROLE%>.options.selectedIndex].value;        

    if(currentrole == <%= BasicAccessRuleSet.ROLE_NONE%>){
      alert("<%= ejbcawebbean.getText("SELECTAROLE") %>");
      illegalfields++;       
    }

    if(currentrole == <%= BasicAccessRuleSet.ROLE_SUPERVISOR%>){
      var numofendentity = document.basicrules.<%=SELECT_ENDENTITYRULES %>.length;
      for( i=numofendentity-1; i >= 0; i-- ){
       if(document.basicrules.<%=SELECT_ENDENTITYRULES%>.options[i].selected){
         if(!(document.basicrules.<%=SELECT_ENDENTITYRULES%>.options[i].value==<%= BasicAccessRuleSet.ENDENTITY_VIEW%> ||
              document.basicrules.<%=SELECT_ENDENTITYRULES%>.options[i].value==<%= BasicAccessRuleSet.ENDENTITY_VIEWHISTORY%> ||
              document.basicrules.<%=SELECT_ENDENTITYRULES%>.options[i].value==<%= BasicAccessRuleSet.ENDENTITY_VIEWHARDTOKENS%>)){
            illegalselection = true;
         }
       }         
      }
      if(illegalselection){
           alert("<%= ejbcawebbean.getText("SUPERVISORISONLYALLOWED") %>");
           illegalfields++;       
      }        
    }

  return illegalfields == 0;  
} 
-->

</SCRIPT>
  <table width="100%" border="0" cellspacing="3" cellpadding="3" >
    <form name="basicrules" method="post" action="<%=THIS_FILENAME %>">
    <input type="hidden" name='<%= ACTION %>' value='<%=ACTION_EDIT_ACCESSRULES %>'>
    <input type="hidden" name='<%= HIDDEN_GROUPNAME %>' value='<%= admingroup[ADMINGROUPNAME] + ";" + caid %>'>
    <input type="hidden" name='<%= MODE %>' value='<%=MODE_BASIC%>'>
    <tr  id="Row<%=row++%2%>">  
      <td width="50%"  align="right"> 
        <%= ejbcawebbean.getText("ROLE") %>
      </td>
      <td width="50%">
        <select name="<%=SELECT_ROLE%>" size="1" onchange='roleupdated()'>
           <%  int currentrole = basicruleset.getCurrentRole();
               Iterator iter = basicruleset.getAvailableRoles().iterator();  
               while(iter.hasNext()){
                 int nextrole = ((Integer) iter.next()).intValue();%>
           <option  value="<%= nextrole %>" 
              <% if(nextrole == currentrole) out.write(" selected "); %>> 
              <%= ejbcawebbean.getText(BasicAccessRuleSet.ROLETEXTS[nextrole]) %>
           </option>
           <%   } %> 
        </select>
      </td>
    </tr>
    <tr id="Row<%=row++%2%>"> 
      <td width="50%" valign="top"> 
        <div align="right"> 
          <%= ejbcawebbean.getText("AUTHORIZEDCAS") %>
        </div>
      </td>
      <td width="50%" valign="top"> 
        <select name="<%=SELECT_CAS%>" size="7" multiple <% if(currentrole == BasicAccessRuleSet.ROLE_SUPERADMINISTRATOR) out.write(" disabled ");%> >
           <%  iter = basicruleset.getAvailableCAs().iterator();  
               boolean allexists = false;
               TreeMap canames = new TreeMap();
               while(iter.hasNext()){
                 Integer nextca = (Integer) iter.next();

                 if(nextca.intValue() == BasicAccessRuleSet.CA_ALL){
                   allexists=true;
                   continue;
                 }
                 canames.put(caidtonamemap.get(nextca),nextca);
               }
               
               
               iter = canames.keySet().iterator();
               while(iter.hasNext()){
                 Object next = iter.next();%>
               <option  value="<%= canames.get(next) %>" 
                  <% if(basicruleset.getCurrentCAs().contains(canames.get(next))) out.write(" selected "); %>> 
                  <%= next %>
               </option>
           <%  }
                if(allexists){%>
           <option  value="<%= BasicAccessRuleSet.CA_ALL %>" 
              <% if(basicruleset.getCurrentCAs().contains(new Integer(BasicAccessRuleSet.CA_ALL))) out.write(" selected "); %>> 
              <%=  ejbcawebbean.getText("ALL")%>
           </option>
           <% } %>   
        </select>
      </td>
    </tr>
    <tr  id="Row<%=row++%2%>"> 
      <td width="50%" valign="top"> 
        <div align="right"> 
          <%= ejbcawebbean.getText("ENDENTITYRULES") %>
        </div>
      </td>
      <td width="50%" valign="top"> 
        <select name="<%=SELECT_ENDENTITYRULES%>" size="8" multiple <% if(currentrole == BasicAccessRuleSet.ROLE_SUPERADMINISTRATOR ||
                                                                          currentrole == BasicAccessRuleSet.ROLE_CAADMINISTRATOR) out.write(" disabled ");%>>
           <%  iter = basicruleset.getAvailableEndEntityRules().iterator();                 
               while(iter.hasNext()){
                 Integer next = (Integer) iter.next(); %>
           <option  value="<%= next %>" 
              <% if(basicruleset.getCurrentEndEntityRules().contains(next)) out.write(" selected "); %>> 
                <%= ejbcawebbean.getText(BasicAccessRuleSet.getEndEntityRuleText(next.intValue()))%>
           </option>
           <%   } %> 
        </select>
      </td>
    </tr>
    <tr  id="Row<%=row++%2%>"> 
      <td width="50%" valign="top"> 
        <div align="right"> 
          <%= ejbcawebbean.getText("ENDENTITYPROFILES") %>
        </div>
      </td>
      <td width="50%" valign="top"> 
        <select name="<%=SELECT_ENDENTITYPROFILES%>" size="7" multiple <% if(currentrole == BasicAccessRuleSet.ROLE_SUPERADMINISTRATOR ||
                                                                             currentrole == BasicAccessRuleSet.ROLE_CAADMINISTRATOR) out.write(" disabled ");%>>
           <%  iter = basicruleset.getAvailableEndEntityProfiles().iterator();  
               allexists=false;
               TreeMap profilemap = new TreeMap();
               while(iter.hasNext()){
                 Integer next = (Integer) iter.next();
                 if(next.intValue() == BasicAccessRuleSet.ENDENTITYPROFILE_ALL){
                   allexists = true;
                   continue;
                 }
                 profilemap.put(rabean.getEndEntityProfileName(next.intValue()),next);  
               } 

               
               iter = profilemap.keySet().iterator();
               while(iter.hasNext()){
                 Object next = iter.next();%>                     
           <option  value="<%= profilemap.get(next) %>" 
              <% if(basicruleset.getCurrentEndEntityProfiles().contains(profilemap.get(next))) out.write(" selected "); %>> 
              <%= next%>
           </option>
           <%   }
                if(allexists){%>
           <option  value="<%= BasicAccessRuleSet.ENDENTITYPROFILE_ALL %>" 
              <% if(basicruleset.getCurrentEndEntityProfiles().contains(new Integer(BasicAccessRuleSet.ENDENTITYPROFILE_ALL))) out.write(" selected "); %>> 
              <%=  ejbcawebbean.getText("ALL")%>
           </option>
             <% } %>
        </select>
      </td>
    </tr>   
    <tr  id="Row<%=row++%2%>"> 
      <td width="50%" valign="top"> 
        <div align="right"> 
          <%= ejbcawebbean.getText("OTHERRULES") %>
        </div>
      </td>
      <td width="50%" valign="top"> 
        <select name="<%=SELECT_OTHER%>" size="3" multiple <% if(currentrole == BasicAccessRuleSet.ROLE_SUPERADMINISTRATOR || currentrole == BasicAccessRuleSet.ROLE_SUPERVISOR) out.write(" disabled ");%>>
           <%  iter = basicruleset.getAvailableOtherRules().iterator();                 
               while(iter.hasNext()){
                 Integer next = (Integer) iter.next();
                 if(!(next.intValue() == BasicAccessRuleSet.OTHER_ISSUEHARDTOKENS && !globalconfiguration.getIssueHardwareTokens()) 
                    && !(currentrole == BasicAccessRuleSet.ROLE_CAADMINISTRATOR && next.intValue() == BasicAccessRuleSet.OTHER_VIEWLOG)){ %>
           <option  value="<%= next %>" 
              <% if(basicruleset.getCurrentOtherRules().contains(next)) out.write(" selected "); %>> 
              <%= ejbcawebbean.getText(BasicAccessRuleSet.OTHERTEXTS[next.intValue()])%>
           </option>
           <%   }  
              } %> 
        </select>
      </td>
    </tr>
    <tr  id="Row<%=row++%2%>"> 
      <td width="49%" valign="top">&nbsp;</td>
      <td width="51%" valign="top"> 
        <input type="submit" name="<%= BUTTON_SAVE %>" onClick='return checkallfields()' value="<%= ejbcawebbean.getText("SAVE") %>">
        <input type="submit" name="<%= BUTTON_CANCEL %>" value="<%= ejbcawebbean.getText("CANCEL") %>">
      </td>
    </tr>
  </table>
 </form>