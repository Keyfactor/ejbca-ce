  <p><%= ejbcawebbean.getText("FINDUSERWITHUSERNAME") %>
    <input type="text" name="<%=TEXTFIELD_USERNAME %>" size="40" maxlength="255" 
     <% if(oldaction != null && oldactionvalue!= null && oldaction.equals(OLD_ACTION_FINDUSER))
          out.write("value='"+oldactionvalue+"'"); %>
     >
    <input type="submit" name="<%=BUTTON_FIND %>" value="<%= ejbcawebbean.getText("FIND") %>">
  </p>
  <p><%= ejbcawebbean.getText("ORIFCERTIFICATSERIAL") %>
    <input type="text" name="<%=TEXTFIELD_SERIALNUMBER %>" size="33" maxlength="255" 
     <% if(oldaction != null && oldactionvalue!= null && oldaction.equals(OLD_ACTION_ISREVOKED))
          out.write("value='"+oldactionvalue+"'"); %>
     >
    <input type="submit" name="<%=BUTTON_ISREVOKED %>" value="<%= ejbcawebbean.getText("FIND") %>" 
           onclick='return checkfieldforhexadecimalnumbers("document.form.<%=TEXTFIELD_SERIALNUMBER %>","<%= ejbcawebbean.getText("ONLYHEXNUMBERS") %>")'>
  </p>
  <p><%= ejbcawebbean.getText("ORWITHSTATUS") %>
    <select name="<%=SELECT_LIST_STATUS %>">
      <option value=''>--</option> 
      <option <% if(oldaction != null && oldactionvalue!= null && oldaction.equals(OLD_ACTION_LISTUSERS))
                   if(oldactionvalue.equals(ALL_STATUS))
                     out.write("selected"); %>
              value='<%= ALL_STATUS %>'><%= ejbcawebbean.getText("ALL") %></option>
      <option <% if(oldaction != null && oldactionvalue!= null && oldaction.equals(OLD_ACTION_LISTUSERS))
                   if(oldactionvalue.equals(Integer.toString(UserDataRemote.STATUS_NEW)))
                     out.write("selected"); %>
              value='<%= Integer.toString(UserDataRemote.STATUS_NEW) %>'><%= ejbcawebbean.getText("STATUSNEW") %></option>
      <option <% if(oldaction != null && oldactionvalue!= null && oldaction.equals(OLD_ACTION_LISTUSERS))
                   if(oldactionvalue.equals(Integer.toString(UserDataRemote.STATUS_FAILED)))
                     out.write("selected"); %>
              value='<%= Integer.toString(UserDataRemote.STATUS_FAILED) %>'><%= ejbcawebbean.getText("STATUSFAILED") %></option>
      <option <% if(oldaction != null && oldactionvalue!= null && oldaction.equals(OLD_ACTION_LISTUSERS))
                   if(oldactionvalue.equals(Integer.toString(UserDataRemote.STATUS_INITIALIZED)))
                     out.write("selected"); %>
              value='<%= Integer.toString(UserDataRemote.STATUS_INITIALIZED) %>'><%= ejbcawebbean.getText("STATUSINITIALIZED") %></option>
      <option <% if(oldaction != null && oldactionvalue!= null && oldaction.equals(OLD_ACTION_LISTUSERS))
                   if(oldactionvalue.equals(Integer.toString(UserDataRemote.STATUS_INPROCESS)))
                     out.write("selected"); %>
              value='<%= Integer.toString(UserDataRemote.STATUS_INPROCESS) %>'><%= ejbcawebbean.getText("STATUSINPROCESS") %></option>
      <option <% if(oldaction != null && oldactionvalue!= null && oldaction.equals(OLD_ACTION_LISTUSERS))
                   if(oldactionvalue.equals(Integer.toString(UserDataRemote.STATUS_GENERATED)))
                     out.write("selected"); %>
              value='<%= Integer.toString(UserDataRemote.STATUS_GENERATED) %>'><%= ejbcawebbean.getText("STATUSGENERATED") %></option>
      <option <% if(oldaction != null && oldactionvalue!= null && oldaction.equals(OLD_ACTION_LISTUSERS))
                   if(oldactionvalue.equals(Integer.toString(UserDataRemote.STATUS_REVOKED)))
                     out.write("selected"); %>
              value='<%= Integer.toString(UserDataRemote.STATUS_REVOKED) %>'><%= ejbcawebbean.getText("STATUSREVOKED") %></option>
      <option <% if(oldaction != null && oldactionvalue!= null && oldaction.equals(OLD_ACTION_LISTUSERS))
                   if(oldactionvalue.equals(Integer.toString(UserDataRemote.STATUS_HISTORICAL)))
                     out.write("selected"); %>
              value='<%= Integer.toString(UserDataRemote.STATUS_HISTORICAL) %>'><%= ejbcawebbean.getText("STATUSHISTORICAL") %></option>
    </select>
    <input type="submit" name="<%=BUTTON_LIST %>" value="<%= ejbcawebbean.getText("LIST") %>">
  </p>
  <p><%= ejbcawebbean.getText("ORLISTEXPIRING") %>
    <input type="text" name="<%=TEXTFIELD_DAYS %>" size="3" maxlength="5" 
     <% if(oldaction != null && oldactionvalue!= null && oldaction.equals(OLD_ACTION_LISTEXPIRED))
          out.write("value='"+oldactionvalue+"'"); %>
     > <%= ejbcawebbean.getText("DAYS") %>
    <input type="submit" name="<%=BUTTON_LISTEXPIRED %>" value="<%= ejbcawebbean.getText("LIST") %>"
           onclick='return checkfieldfordecimalnumbers("document.form.<%=TEXTFIELD_DAYS %>","<%= ejbcawebbean.getText("ONLYDECNUMBERS") %>")'>
  </p>
