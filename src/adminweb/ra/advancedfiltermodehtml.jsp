<% String[] profilenames = rabean.getEndEntityProfileNames(); 
   String[] certificateprofilenames = rabean.getCertificateProfileNames();
 
   String[] connectorreferences = {"AND","OR","ANDNOT","ORNOT"};
   String[] monthreferences     = {"MONTHJAN","MONTHFEB","MONTHMAR","MONTHAPR","MONTHMAY","MONTHJUN","MONTHJUL","MONTHAUG","MONTHSEP"
                                  ,"MONTHOCT","MONTHNOV","MONTHDEC"};
   int[] matchwithfields        = {UserMatch.MATCH_WITH_USERNAME, UserMatch.MATCH_WITH_UID, UserMatch.MATCH_WITH_COMMONNAME, UserMatch.MATCH_WITH_DNSERIALNUMBER, 
                                   UserMatch.MATCH_WITH_GIVENNAME,UserMatch.MATCH_WITH_INITIALS, UserMatch.MATCH_WITH_SURNAME, UserMatch.MATCH_WITH_TITLE, 
                                   UserMatch.MATCH_WITH_ORGANIZATIONUNIT, UserMatch.MATCH_WITH_ORGANIZATION , UserMatch.MATCH_WITH_LOCALE, UserMatch.MATCH_WITH_STATE,
                                   UserMatch.MATCH_WITH_DOMAINCOMPONENT, UserMatch.MATCH_WITH_COUNTRY, UserMatch.MATCH_WITH_EMAIL, 
                                   UserMatch.MATCH_WITH_STATUS, UserMatch.MATCH_WITH_ENDENTITYPROFILE, UserMatch.MATCH_WITH_CERTIFICATEPROFILE};
                                   
   String[] matchwithtexts      = {"MATCHUSERNAME", "MATCHUID", "MATCHCOMMONNAME", "MATCHDNSERIALNUMBER", "MATCHGIVENNAME", "MATCHINITIALS", "MATCHSURNAME",
                                   "MATCHTITLE", "MATCHORGANIZATIONUNIT", "MATCHORGANIZATION", "MATCHLOCALE", "MATCHSTATE", "MATCHDOMAINCOMPONENT",
                                   "MATCHCOUNTRY", "MATCHEMAIL", "MATCHSTATUS", "MATCHENDENTITYPROFILE", "MATCHCERTIFICATEPROFILE"};

   Calendar calendar = Calendar.getInstance();
   int dayofmonth    = calendar.get(Calendar.DAY_OF_MONTH);
   int month         = calendar.get(Calendar.MONTH);
   int year          = calendar.get(Calendar.YEAR);
   int hour          = calendar.get(Calendar.HOUR_OF_DAY);
   hour++;
   if(hour >= 24) hour =0;

%> 

<script language=javascript>
<!--
   var profilenames = new Array(<%= profilenames.length %>);
   <% for(int i = 0; i < profilenames.length; i++){ %>
      profilenames[<%=i %>] = "<%=profilenames[i] %>";

    <% } %>
   var certificateprofilenames = new Array(<%= certificateprofilenames.length %>);
   <% for(int i = 0; i < certificateprofilenames.length; i++){ %>
      certificateprofilenames[<%=i %>] = "<%=certificateprofilenames[i] %>";

    <% } %>
   
   var ID    = 0;
   var NAME  = 1;

   var matchtypefields = new Array(2)
   matchtypefields[ID] = new Array(2);
   matchtypefields[ID][0]= <%= BasicMatch.MATCH_TYPE_EQUALS %>;
   matchtypefields[ID][1] = <%= BasicMatch.MATCH_TYPE_BEGINSWITH %>;

   matchtypefields[NAME] = new Array(2);
   matchtypefields[NAME][0] = "<%= ejbcawebbean.getText("EQUALS") %>";
   matchtypefields[NAME][1] = "<%= ejbcawebbean.getText("BEGINSWITH") %>";

   statusfields = new Array(2);
   statusfields[ID] = new Array(7);
   statusfields[ID][0] = <%= UserDataRemote.STATUS_NEW %>;
   statusfields[ID][1] = <%= UserDataRemote.STATUS_FAILED %>;
   statusfields[ID][2] = <%= UserDataRemote.STATUS_INITIALIZED %>;
   statusfields[ID][3] = <%= UserDataRemote.STATUS_INPROCESS %>;
   statusfields[ID][4] = <%= UserDataRemote.STATUS_GENERATED %>;
   statusfields[ID][5] = <%= UserDataRemote.STATUS_REVOKED %>;
   statusfields[ID][6] = <%= UserDataRemote.STATUS_HISTORICAL %>;

   statusfields[NAME] = new Array(7);
   statusfields[NAME][0] ="<%= ejbcawebbean.getText("STATUSNEW") %>";
   statusfields[NAME][1] = "<%= ejbcawebbean.getText("STATUSFAILED") %>";
   statusfields[NAME][2] = "<%= ejbcawebbean.getText("STATUSINITIALIZED") %>";
   statusfields[NAME][3] = "<%= ejbcawebbean.getText("STATUSINPROCESS") %>";
   statusfields[NAME][4] = "<%= ejbcawebbean.getText("STATUSGENERATED") %>";
   statusfields[NAME][5] = "<%= ejbcawebbean.getText("STATUSREVOKED") %>";
   statusfields[NAME][6] = "<%= ejbcawebbean.getText("STATUSHISTORICAL") %>";


function changematchfields(row){

 // check value on matchwith
  matchwith = eval("document.form.selectmatchwithrow" + row);
  matchtype = eval("document.form.selectmatchtyperow" + row);
  textmatchvalue = eval("document.form.textfieldmatchvaluerow" + row);
  menumatchvalue = eval("document.form.selectmatchvaluerow" + row);
  var index = matchwith.selectedIndex;
  var numofvalues;
  matchwithvalue = matchwith[index].value;  
  var i;

 // if dn field remove equals and a textfield
  if(matchwithvalue >=  100){
     var numoftypes = matchtype.length;
     for( i=numoftypes-1; i >= 0; i-- ){
       matchtype.options[i]=null;
     }
     matchtype.options[0]= new Option(matchtypefields[NAME][1],matchtypefields[ID][1]);

     numofvalues = menumatchvalue.length;
     for(i=numofvalues-1; i >= 0; i--){
       menumatchvalue.options[i]=null;
     }     
     menumatchvalue.disabled = true;
     textmatchvalue.disabled = false;
     textmatchvalue.size=40;
  }
   // if profile remove beginswith and menu
  else{
    if(matchwithvalue == <%= UserMatch.MATCH_WITH_ENDENTITYPROFILE %> ){

      menumatchvalue.disabled = false;
      textmatchvalue.disabled = true;
      textmatchvalue.value= "";
      textmatchvalue.size=1;

      var numoftypes = matchtype.length;
      for( i=numoftypes-1; i >= 0; i-- ){
        matchtype.options[i]=null;
      }
      matchtype.options[0]= new Option(matchtypefields[NAME][0],matchtypefields[ID][0]);

     numofvalues = menumatchvalue.length;
     for(i=numofvalues-1; i >= 0; i--){
       menumatchvalue.options[i]=null;
     }  
     for( i = 0; i < profilenames.length; i++){
       menumatchvalue.options[i]= new Option(profilenames[i],profilenames[i]);       
     }
    }
    else{
      if(matchwithvalue == <%= UserMatch.MATCH_WITH_CERTIFICATEPROFILE %> ){
  
        menumatchvalue.disabled = false;
        textmatchvalue.disabled = true;
        textmatchvalue.value= "";
        textmatchvalue.size=1;

        var numoftypes = matchtype.length;
        for( i=numoftypes-1; i >= 0; i-- ){
          matchtype.options[i]=null;
        }
        matchtype.options[0]= new Option(matchtypefields[NAME][0],matchtypefields[ID][0]);

        numofvalues = menumatchvalue.length;
        for(i=numofvalues-1; i >= 0; i--){
         menumatchvalue.options[i]=null;
        }  
        for( i = 0; i < certificateprofilenames.length; i++){
          menumatchvalue.options[i]= new Option(certificateprofilenames[i],certificateprofilenames[i]);       
        }
      
     }
     else{      
        // if status remove beginswith and menu
        if(matchwithvalue == <%= UserMatch.MATCH_WITH_STATUS %> ){
          menumatchvalue.disabled = false;
          textmatchvalue.disabled = true;
          textmatchvalue.value= "";
          textmatchvalue.size=1;

          numoftypes = matchtype.length;
          for( i=numoftypes-1; i >= 0; i-- ){
            matchtype.options[i]=null;
          }
          matchtype.options[0]= new Option(matchtypefields[NAME][0],matchtypefields[ID][0]);

          numofvalues = menumatchvalue.length;
          for( i=numofvalues-1; i >= 0; i--){
            menumatchvalue.options[i]=null;
          }  
          for( i = 0; i < statusfields[ID].length ; i++){
            menumatchvalue.options[i]= new Option(statusfields[NAME][i],statusfields[ID][i]);       
          }
        }
   // else equals and beginswith and textfield.
        else{
          var numoftypes = matchtype.length;
          for(i=numoftypes-1; i >= 0; i-- ){
            matchtype.options[i]=null;
          }
          matchtype.options[0]= new Option(matchtypefields[NAME][0],matchtypefields[ID][0]);
          matchtype.options[1]= new Option(matchtypefields[NAME][1],matchtypefields[ID][1]);

          numofvalues = menumatchvalue.length;
          for(i=numofvalues-1; i >= 0; i--){
            menumatchvalue.options[i]=null;
          }     
          menumatchvalue.disabled = true;
          textmatchvalue.disabled = false;
          textmatchvalue.size=40;
        }
      }
    }
  }
}

 -->
</script>
<table width="100%" border="0" cellspacing="1" cellpadding="0">
  <tr> 
    <td width="2%">&nbsp;</td>
    <td width="5%" align="left">&nbsp;
    </td>
    <td width="93%" align="left"> 
        <% int tempval = -1;
           if(oldmatchwithrow1!= null)
             tempval= Integer.parseInt(oldmatchwithrow1); %>
        <select name="<%=SELECT_MATCHWITH_ROW1 %>" onchange='changematchfields(1)' >
           <option  value='<%= VALUE_NONE %>'><%= ejbcawebbean.getText("NONE") %>
           </option>
           <% for(int i =0; i < matchwithfields.length;i++){ %>
  
           <option <%  if(tempval == matchwithfields[i])
                         out.write(" selected ");
                    %> value='<%= matchwithfields[i] %>'><%= ejbcawebbean.getText(matchwithtexts[i]) %>
           </option>
           <% } %>
        </select> &nbsp;&nbsp;
          <%
           tempval = -1;
           if(oldmatchtyperow1!= null)
             tempval= Integer.parseInt(oldmatchtyperow1);
          %>
        <select name="<%=SELECT_MATCHTYPE_ROW1 %>">
          <% if(oldmatchwithrow1 != null){
               if(Integer.parseInt(oldmatchwithrow1) < 100){ %>
          <option <%  if(tempval == BasicMatch.MATCH_TYPE_EQUALS){
                         out.write(" selected ");
                    } %> value='<%= Integer.toString(BasicMatch.MATCH_TYPE_EQUALS) %>'><%= ejbcawebbean.getText("EQUALS") %>
          </option>
             <%  }
               }else{ %>
          <option <% if(tempval == BasicMatch.MATCH_TYPE_EQUALS){
                         out.write(" selected ");
                    } %> value='<%= Integer.toString(BasicMatch.MATCH_TYPE_EQUALS) %>'><%= ejbcawebbean.getText("EQUALS") %>
          </option> 
            <% }%>
          <% if(oldmatchwithrow1 != null){
               if(Integer.parseInt(oldmatchwithrow1) != UserMatch.MATCH_WITH_STATUS && Integer.parseInt(oldmatchwithrow1) != UserMatch.MATCH_WITH_ENDENTITYPROFILE){ %>
          <option <%  if(tempval == BasicMatch.MATCH_TYPE_BEGINSWITH){
                         out.write(" selected ");
                    } %> value='<%= Integer.toString(BasicMatch.MATCH_TYPE_BEGINSWITH) %>'><%= ejbcawebbean.getText("BEGINSWITH") %>
          </option>
               <% }
             }else{ %>
          <option <%  if(tempval == BasicMatch.MATCH_TYPE_BEGINSWITH){
                         out.write(" selected ");
                    } %> value='<%= Integer.toString(BasicMatch.MATCH_TYPE_BEGINSWITH) %>'><%= ejbcawebbean.getText("BEGINSWITH") %>
          </option> 
           <% } %>
        </select> &nbsp;&nbsp; 

        <select name="<%=SELECT_MATCHVALUE_ROW1 %>"
           <% if(oldmatchwithrow1 != null){
                 if(oldmatchwithrow1.equals(Integer.toString(UserMatch.MATCH_WITH_ENDENTITYPROFILE))){ %>
              >
                <% for(int i=0; i < profilenames.length; i++){ %>
          <option <% if(oldmatchvaluerow1!= null){
                       if(oldmatchvaluerow1.equals(profilenames[i]))
                         out.write(" selected ");
                    } %> value='<%= profilenames[i] %>'><%= profilenames[i] %>
          </option>                   
                <%  }
                  }
                  else{
                   if(oldmatchwithrow1.equals(Integer.toString(UserMatch.MATCH_WITH_CERTIFICATEPROFILE))){ %>
              >
                <% for(int i=0; i < certificateprofilenames.length; i++){ %>
          <option <% if(oldmatchvaluerow1!= null){
                       if(oldmatchvaluerow1.equals(certificateprofilenames[i]))
                         out.write(" selected ");
                    } %> value='<%= certificateprofilenames[i] %>'><%= certificateprofilenames[i] %>
          </option>                   
                <%  }
                  }
                  else{
                    if(oldmatchwithrow1.equals(Integer.toString(UserMatch.MATCH_WITH_STATUS))){ %> 
              >
              <%
                tempval = -1;
                if(oldmatchtyperow1!= null)
                  tempval= Integer.parseInt(oldmatchvaluerow1);
            %>
      <option <% if( tempval == UserDataRemote.STATUS_NEW)
                     out.write("selected"); %>
              value='<%= Integer.toString(UserDataRemote.STATUS_NEW) %>'><%= ejbcawebbean.getText("STATUSNEW") %></option>
      <option <%  if( tempval == UserDataRemote.STATUS_FAILED)
                     out.write("selected"); %>
              value='<%= Integer.toString(UserDataRemote.STATUS_FAILED) %>'><%= ejbcawebbean.getText("STATUSFAILED") %></option>
      <option <% if( tempval == UserDataRemote.STATUS_INITIALIZED)
                     out.write("selected"); %>
              value='<%= Integer.toString(UserDataRemote.STATUS_INITIALIZED) %>'><%= ejbcawebbean.getText("STATUSINITIALIZED") %></option>
      <option <%  if( tempval == UserDataRemote.STATUS_INPROCESS)
                     out.write("selected"); %>
              value='<%= Integer.toString(UserDataRemote.STATUS_INPROCESS) %>'><%= ejbcawebbean.getText("STATUSINPROCESS") %></option>
      <option <%  if( tempval == UserDataRemote.STATUS_GENERATED)
                     out.write("selected"); %>
              value='<%= Integer.toString(UserDataRemote.STATUS_GENERATED) %>'><%= ejbcawebbean.getText("STATUSGENERATED") %></option>
      <option <%  if( tempval == UserDataRemote.STATUS_REVOKED)
                     out.write("selected"); %>
              value='<%= Integer.toString(UserDataRemote.STATUS_REVOKED) %>'><%= ejbcawebbean.getText("STATUSREVOKED") %></option>
      <option <% if( tempval == UserDataRemote.STATUS_HISTORICAL)
                     out.write("selected"); %>
              value='<%= Integer.toString(UserDataRemote.STATUS_HISTORICAL) %>'><%= ejbcawebbean.getText("STATUSHISTORICAL") %></option> 
       <% } else{ %>
          disabled >
       <%  }
         }}
        }else{ %>
          disabled > 
     <% } %>
       </select>
       <% if( oldmatchwithrow1!= null){
           if( oldmatchwithrow1.equals(Integer.toString(UserMatch.MATCH_WITH_STATUS))  || oldmatchwithrow1.equals(Integer.toString(UserMatch.MATCH_WITH_ENDENTITYPROFILE)) || oldmatchwithrow1.equals(Integer.toString(UserMatch.MATCH_WITH_CERTIFICATEPROFILE))){ %>
       <input type="text" name="<%=TEXTFIELD_MATCHVALUE_ROW1 %>"  size="1" maxlength="255" value='' disabled >    
           <% }else{ %>
              <input type="text" name="<%=TEXTFIELD_MATCHVALUE_ROW1 %>" size="40" maxlength="255" value='<%=oldmatchvaluerow1 %>' >
           <% }
           }else{ %>
              <input type="text" name="<%=TEXTFIELD_MATCHVALUE_ROW1 %>" size="40" maxlength="255" value='' >
        <% } %>
    </td>
  </tr>

  <tr> 
    <td width="2%">&nbsp;</td>
    <td width="5%" align="left">
       <select name='<%= SELECT_CONNECTOR_ROW2  %>'>  
         <option  value='<%= VALUE_NONE %>'><%= ejbcawebbean.getText("NONE") %>
         </option>
         <% for(int i=0; i<  connectorreferences.length; i++) { %> 
         <option <% if(oldconnectorrow2 != null)
                      if(oldconnectorrow2.equals(Integer.toString(i))) 
                        out.print(" selected ");
                      %> value='<%= i %>'> 
           <%= ejbcawebbean.getText(connectorreferences[i]) %>
         </option> 
         <% } %> 
       </select>
    </td>
    <td width="93%" align="left"> 
        <% tempval = -1;
           if(oldmatchwithrow2!= null)
             tempval= Integer.parseInt(oldmatchwithrow2); %>
        <select name="<%=SELECT_MATCHWITH_ROW2 %>" onchange='changematchfields(2)' >
           <option  value='<%= VALUE_NONE %>'><%= ejbcawebbean.getText("NONE") %>
           </option>
           <% for(int i =0; i < matchwithfields.length;i++){ %>
  
           <option <%  if(tempval == matchwithfields[i])
                         out.write(" selected ");
                    %> value='<%= matchwithfields[i] %>'><%= ejbcawebbean.getText(matchwithtexts[i]) %>
           </option>
           <% } %>
        </select> &nbsp;&nbsp;
          <%
           tempval = -1;
           if(oldmatchtyperow2!= null)
             tempval= Integer.parseInt(oldmatchtyperow2);
          %>
        <select name="<%=SELECT_MATCHTYPE_ROW2 %>">
          <% if(oldmatchwithrow2 != null){
               if(Integer.parseInt(oldmatchwithrow2) < 100){ %>
          <option <%  if(tempval == BasicMatch.MATCH_TYPE_EQUALS){
                         out.write(" selected ");
                    } %> value='<%= Integer.toString(BasicMatch.MATCH_TYPE_EQUALS) %>'><%= ejbcawebbean.getText("EQUALS") %>
          </option>
             <%  }
               }else{ %>
          <option <% if(tempval == BasicMatch.MATCH_TYPE_EQUALS){
                         out.write(" selected ");
                    } %> value='<%= Integer.toString(BasicMatch.MATCH_TYPE_EQUALS) %>'><%= ejbcawebbean.getText("EQUALS") %>
          </option> 
            <% }%>
          <option <%  if(tempval == BasicMatch.MATCH_TYPE_BEGINSWITH){
                         out.write(" selected ");
                    } %> value='<%= Integer.toString(BasicMatch.MATCH_TYPE_BEGINSWITH) %>'><%= ejbcawebbean.getText("BEGINSWITH") %>
          </option>
        </select> &nbsp;&nbsp; 

        <select name="<%=SELECT_MATCHVALUE_ROW2 %>"
           <% if(oldmatchwithrow2 != null){
                 if(oldmatchwithrow2.equals(Integer.toString(UserMatch.MATCH_WITH_ENDENTITYPROFILE))){ %>
              >
                <% for(int i=0; i < profilenames.length; i++){ %>
          <option <% if(oldmatchvaluerow2!= null){
                       if(oldmatchvaluerow2.equals(profilenames[i]))
                         out.write(" selected ");
                    } %> value='<%= profilenames[i] %>'><%= profilenames[i] %>
          </option>                   
                <%  }
                  }
                  else{
                   if(oldmatchwithrow2.equals(Integer.toString(UserMatch.MATCH_WITH_CERTIFICATEPROFILE))){ %>
              >
                <% for(int i=0; i < certificateprofilenames.length; i++){ %>
          <option <% if(oldmatchvaluerow2!= null){
                       if(oldmatchvaluerow2.equals(certificateprofilenames[i]))
                         out.write(" selected ");
                    } %> value='<%= certificateprofilenames[i] %>'><%= certificateprofilenames[i] %>
          </option>                   
                <%  }
                  }
                  else{
                    if(oldmatchwithrow2.equals(Integer.toString(UserMatch.MATCH_WITH_STATUS))){ %> 
              >
              <%
                tempval = -1;
                if(oldmatchtyperow2!= null)
                  tempval= Integer.parseInt(oldmatchvaluerow2);
            %>
      <option <% if( tempval == UserDataRemote.STATUS_NEW)
                     out.write("selected"); %>
              value='<%= Integer.toString(UserDataRemote.STATUS_NEW) %>'><%= ejbcawebbean.getText("STATUSNEW") %></option>
      <option <%  if( tempval == UserDataRemote.STATUS_FAILED)
                     out.write("selected"); %>
              value='<%= Integer.toString(UserDataRemote.STATUS_FAILED) %>'><%= ejbcawebbean.getText("STATUSFAILED") %></option>
      <option <% if( tempval == UserDataRemote.STATUS_INITIALIZED)
                     out.write("selected"); %>
              value='<%= Integer.toString(UserDataRemote.STATUS_INITIALIZED) %>'><%= ejbcawebbean.getText("STATUSINITIALIZED") %></option>
      <option <%  if( tempval == UserDataRemote.STATUS_INPROCESS)
                     out.write("selected"); %>
              value='<%= Integer.toString(UserDataRemote.STATUS_INPROCESS) %>'><%= ejbcawebbean.getText("STATUSINPROCESS") %></option>
      <option <%  if( tempval == UserDataRemote.STATUS_GENERATED)
                     out.write("selected"); %>
              value='<%= Integer.toString(UserDataRemote.STATUS_GENERATED) %>'><%= ejbcawebbean.getText("STATUSGENERATED") %></option>
      <option <%  if( tempval == UserDataRemote.STATUS_REVOKED)
                     out.write("selected"); %>
              value='<%= Integer.toString(UserDataRemote.STATUS_REVOKED) %>'><%= ejbcawebbean.getText("STATUSREVOKED") %></option>
      <option <% if( tempval == UserDataRemote.STATUS_HISTORICAL)
                     out.write("selected"); %>
              value='<%= Integer.toString(UserDataRemote.STATUS_HISTORICAL) %>'><%= ejbcawebbean.getText("STATUSHISTORICAL") %></option> 
       <% } else{ %>
          disabled >
       <%  }
         }}
        }else{ %>
          disabled > 
     <% } %>
       </select>
       <% if( oldmatchwithrow2!= null){
           if( oldmatchwithrow2.equals(Integer.toString(UserMatch.MATCH_WITH_STATUS))  || oldmatchwithrow2.equals(Integer.toString(UserMatch.MATCH_WITH_ENDENTITYPROFILE)) || oldmatchwithrow2.equals(Integer.toString(UserMatch.MATCH_WITH_CERTIFICATEPROFILE))){ %>
       <input type="text" name="<%=TEXTFIELD_MATCHVALUE_ROW2 %>"  size="1" maxlength="255" value='' disabled >    
           <% }else{ %>
              <input type="text" name="<%=TEXTFIELD_MATCHVALUE_ROW2 %>" size="40" maxlength="255" value='<%=oldmatchvaluerow2 %>' >
           <% }
           }else{ %>
              <input type="text" name="<%=TEXTFIELD_MATCHVALUE_ROW2 %>" size="40" maxlength="255" value='' >
        <% } %>
    </td>
  </tr>

  <tr> 
    <td width="2%">&nbsp;</td>
    <td width="5%" align="left">
       <select name='<%= SELECT_CONNECTOR_ROW3  %>'>  
         <option  value='<%= VALUE_NONE %>'><%= ejbcawebbean.getText("NONE") %>
         </option>
         <% for(int i=0; i<  connectorreferences.length; i++) { %> 
         <option <% if(oldconnectorrow3 != null)
                      if(oldconnectorrow3.equals(Integer.toString(i))) 
                        out.print(" selected ");
                      %> value='<%= i %>'> 
           <%= ejbcawebbean.getText(connectorreferences[i]) %>
         </option> 
         <% } %> 
       </select>
    </td>
    <td width="93%" align="left"> 
        <% tempval = -1;
           if(oldmatchwithrow3!= null)
             tempval= Integer.parseInt(oldmatchwithrow3); %>
        <select name="<%=SELECT_MATCHWITH_ROW3 %>" onchange='changematchfields(3)' >
           <option  value='<%= VALUE_NONE %>'><%= ejbcawebbean.getText("NONE") %>
           </option>
           <% for(int i =0; i < matchwithfields.length;i++){ %>
           <option <%  if(tempval == matchwithfields[i])
                         out.write(" selected ");
                    %> value='<%= matchwithfields[i] %>'><%= ejbcawebbean.getText(matchwithtexts[i]) %>
           </option>
           <% } %>
        </select> &nbsp;&nbsp;
          <%
           tempval = -1;
           if(oldmatchtyperow3!= null)
             tempval= Integer.parseInt(oldmatchtyperow3);
          %>
        <select name="<%=SELECT_MATCHTYPE_ROW3 %>">
          <% if(oldmatchwithrow3 != null){
               if(Integer.parseInt(oldmatchwithrow3) < 100){ %>
          <option <%  if(tempval == BasicMatch.MATCH_TYPE_EQUALS){
                         out.write(" selected ");
                    } %> value='<%= Integer.toString(BasicMatch.MATCH_TYPE_EQUALS) %>'><%= ejbcawebbean.getText("EQUALS") %>
          </option>
             <%  }
               }else{ %>
          <option <% if(tempval == BasicMatch.MATCH_TYPE_EQUALS){
                         out.write(" selected ");
                    } %> value='<%= Integer.toString(BasicMatch.MATCH_TYPE_EQUALS) %>'><%= ejbcawebbean.getText("EQUALS") %>
          </option> 
            <% }%>
          <option <%  if(tempval == BasicMatch.MATCH_TYPE_BEGINSWITH){
                         out.write(" selected ");
                    } %> value='<%= Integer.toString(BasicMatch.MATCH_TYPE_BEGINSWITH) %>'><%= ejbcawebbean.getText("BEGINSWITH") %>
          </option>
        </select> &nbsp;&nbsp; 

        <select name="<%=SELECT_MATCHVALUE_ROW3 %>"
           <% if(oldmatchwithrow3 != null){
                 if(oldmatchwithrow3.equals(Integer.toString(UserMatch.MATCH_WITH_ENDENTITYPROFILE))){ %>
              >
                <% for(int i=0; i < profilenames.length; i++){ %>
          <option <% if(oldmatchvaluerow3!= null){
                       if(oldmatchvaluerow3.equals(profilenames[i]))
                         out.write(" selected ");
                    } %> value='<%= profilenames[i] %>'><%= profilenames[i] %>
          </option>                   
                <%  }
                  }
                  else{
                   if(oldmatchwithrow3.equals(Integer.toString(UserMatch.MATCH_WITH_CERTIFICATEPROFILE))){ %>
              >
                <% for(int i=0; i < certificateprofilenames.length; i++){ %>
          <option <% if(oldmatchvaluerow3!= null){
                       if(oldmatchvaluerow3.equals(certificateprofilenames[i]))
                         out.write(" selected ");
                    } %> value='<%= certificateprofilenames[i] %>'><%= certificateprofilenames[i] %>
          </option>                   
                <%  }
                  }
                  else{
                    if(oldmatchwithrow3.equals(Integer.toString(UserMatch.MATCH_WITH_STATUS))){ %> 
              >
              <%
                tempval = -1;
                if(oldmatchtyperow3!= null)
                  tempval= Integer.parseInt(oldmatchvaluerow3);
            %>
      <option <% if( tempval == UserDataRemote.STATUS_NEW)
                     out.write("selected"); %>
              value='<%= Integer.toString(UserDataRemote.STATUS_NEW) %>'><%= ejbcawebbean.getText("STATUSNEW") %></option>
      <option <%  if( tempval == UserDataRemote.STATUS_FAILED)
                     out.write("selected"); %>
              value='<%= Integer.toString(UserDataRemote.STATUS_FAILED) %>'><%= ejbcawebbean.getText("STATUSFAILED") %></option>
      <option <% if( tempval == UserDataRemote.STATUS_INITIALIZED)
                     out.write("selected"); %>
              value='<%= Integer.toString(UserDataRemote.STATUS_INITIALIZED) %>'><%= ejbcawebbean.getText("STATUSINITIALIZED") %></option>
      <option <%  if( tempval == UserDataRemote.STATUS_INPROCESS)
                     out.write("selected"); %>
              value='<%= Integer.toString(UserDataRemote.STATUS_INPROCESS) %>'><%= ejbcawebbean.getText("STATUSINPROCESS") %></option>
      <option <%  if( tempval == UserDataRemote.STATUS_GENERATED)
                     out.write("selected"); %>
              value='<%= Integer.toString(UserDataRemote.STATUS_GENERATED) %>'><%= ejbcawebbean.getText("STATUSGENERATED") %></option>
      <option <%  if( tempval == UserDataRemote.STATUS_REVOKED)
                     out.write("selected"); %>
              value='<%= Integer.toString(UserDataRemote.STATUS_REVOKED) %>'><%= ejbcawebbean.getText("STATUSREVOKED") %></option>
      <option <% if( tempval == UserDataRemote.STATUS_HISTORICAL)
                     out.write("selected"); %>
              value='<%= Integer.toString(UserDataRemote.STATUS_HISTORICAL) %>'><%= ejbcawebbean.getText("STATUSHISTORICAL") %></option> 
       <% } else{ %>
          disabled >
       <%  }
         }}
        }else{ %>
          disabled > 
     <% } %>
       </select>
       <% if( oldmatchwithrow3!= null){
           if( oldmatchwithrow3.equals(Integer.toString(UserMatch.MATCH_WITH_STATUS))  || oldmatchwithrow3.equals(Integer.toString(UserMatch.MATCH_WITH_ENDENTITYPROFILE)) || oldmatchwithrow3.equals(Integer.toString(UserMatch.MATCH_WITH_CERTIFICATEPROFILE))){ %>
       <input type="text" name="<%=TEXTFIELD_MATCHVALUE_ROW3 %>"  size="1" maxlength="255" value='' disabled >    
           <% }else{ %>
              <input type="text" name="<%=TEXTFIELD_MATCHVALUE_ROW3 %>" size="40" maxlength="255" value='<%=oldmatchvaluerow3 %>' >
           <% }
           }else{ %>
              <input type="text" name="<%=TEXTFIELD_MATCHVALUE_ROW3 %>" size="40" maxlength="255" value='' >
        <% } %>
    </td>
  </tr>

  <tr> 
    <td width="2%">&nbsp;</td>
    <td width="5%" align="left">
      <select name='<%= SELECT_CONNECTOR_ROW4  %>'>  
         <option  value='<%= VALUE_NONE %>'><%= ejbcawebbean.getText("NONE") %>
         </option>
         <% for(int i=0; i<  connectorreferences.length; i++) { %> 
         <option <% if(oldconnectorrow4 != null)
                      if(oldconnectorrow4.equals(Integer.toString(i))) 
                        out.print(" selected ");
                      %> value='<%= i %>'> 
           <%= ejbcawebbean.getText(connectorreferences[i]) %>
         </option> 
         <% } %> 
      </select>
    </td>
    <td width="93%" align="left"> 
      <select name='<%= SELECT_MATCHWITH_ROW4  %>'>  
         <option  value='<%= VALUE_NONE %>'><%= ejbcawebbean.getText("NONE") %>
         </option>
         <option <% if(oldmatchwithrow4!= null)
                   if(oldmatchwithrow4.equals(Integer.toString(TimeMatch.MATCH_WITH_TIMECREATED)))
                     out.write("selected"); %>
              value='<%= Integer.toString(TimeMatch.MATCH_WITH_TIMECREATED) %>'><%= ejbcawebbean.getText("CREATED") %>
         </option>   
         <option <% if(oldmatchwithrow4!= null)
                   if(oldmatchwithrow4.equals(Integer.toString(TimeMatch.MATCH_WITH_TIMEMODIFIED)))
                     out.write("selected"); %>
              value='<%= Integer.toString(TimeMatch.MATCH_WITH_TIMEMODIFIED) %>'><%= ejbcawebbean.getText("MODIFIED") %>
         </option>          
      </select>  
      &nbsp;<%= ejbcawebbean.getText("ONORAFTER") %>&nbsp;
      <select name='<%= SELECT_DAY_ROW4  %>'>  
         <% for(int i=0; i <  31; i++) { %> 
         <option <% if(olddayrow4 != null)
                      if(olddayrow4.equals(Integer.toString(i))) 
                        out.print(" selected ");
                      %> value='<%= i %>'> 
           <%= i+1 %>
         </option> 
         <% } %> 
      </select>&nbsp;
      <select name='<%= SELECT_MONTH_ROW4  %>'>  
         <% for(int i=0; i < monthreferences.length; i++) { %> 
         <option <% if(oldmonthrow4 != null)
                      if(oldmonthrow4.equals(Integer.toString(i))) 
                        out.print(" selected ");
                      %> value='<%= i %>'> 
          <%= ejbcawebbean.getText(monthreferences[i]) %>
         </option> 
         <% } %> 
      </select>&nbsp;
      <select name='<%= SELECT_YEAR_ROW4  %>'>  
         <% for(int i=2000; i <  2020; i++) { %> 
         <option <% if(oldyearrow4 != null)
                      if(oldyearrow4.equals(Integer.toString(i))) 
                        out.print(" selected ");
                      %> value='<%= i %>'> 
          <%= i %>
         </option> 
         <% } %> 
      </select>&nbsp;
      <select name='<%= SELECT_TIME_ROW4  %>'>  
          <% Calendar time = Calendar.getInstance();
             DateFormat dateformat = DateFormat.getTimeInstance(DateFormat.SHORT);%>

         <% for(int i=0; i <  24; i++) { %> 
         <option <% if(oldtimerow4 != null)
                      if(oldtimerow4.equals(Integer.toString(i))) 
                        out.print(" selected ");
                      %> value='<%= i %>'> 
          <% time.set(0,0,0,i,0); 
             out.print(dateformat.format(time.getTime()));%>
         </option> 
         <% } %> 
      </select>
    </td>
  </tr>

  <tr> 
    <td width="2%">&nbsp;</td>
    <td width="5%" align="left">
     &nbsp;
    </td>
    <td width="93%" align="left"> 
      &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
      &nbsp;<%= ejbcawebbean.getText("ONORBEFORE") %>&nbsp;
      <select name='<%= SELECT_DAY_ROW5  %>'> 
         <%  tempval =0;
             if(olddayrow5 != null){
               tempval = Integer.parseInt(olddayrow5);  
             }else{ 
                tempval = dayofmonth;
             }  
            for(int i=0; i <  31; i++) { %> 
         <option  <%   if(tempval == i) 
                        out.print(" selected ");
                      %> value='<%= i %>'> 
           <%= i+1 %>
         </option> 
         <% } %> 
      </select>&nbsp;
      <select name='<%= SELECT_MONTH_ROW5  %>'>  
         <%  tempval =0;
             if(oldmonthrow5 != null){
               tempval = Integer.parseInt(oldmonthrow5);  
             }else{ 
                tempval = month;
             } 

             for(int i=0; i < monthreferences.length; i++) { %> 
         <option <%   if(tempval == i) 
                        out.print(" selected ");
                      %> value='<%= i %>'> 
          <%= ejbcawebbean.getText(monthreferences[i]) %>
         </option> 
         <% } %> 
      </select>&nbsp;
      <select name='<%= SELECT_YEAR_ROW5  %>'>  
         <%  tempval =0;
             if(oldyearrow5 != null){
               tempval = Integer.parseInt(oldyearrow5);  
             }else{ 
                tempval = year;
             } 
            for(int i=2000; i <  2020; i++) { %> 
         <option  <%   if(tempval == i) 
                        out.print(" selected ");
                      %>value='<%= i %>'> 
          <%= i %>
         </option> 
         <% } %> 
      </select>&nbsp;
      <select name='<%= SELECT_TIME_ROW5  %>'>  
          <% time = Calendar.getInstance();
             dateformat = DateFormat.getTimeInstance(DateFormat.SHORT);%>
         <%  tempval =0;
             if(oldtimerow5 != null){
               tempval = Integer.parseInt(oldtimerow5);  
             }else{ 
                tempval = hour;
             } 

           for(int i=0; i <  24; i++) { %> 
         <option  <%   if(tempval == i) 
                        out.print(" selected ");
                      %> value='<%= i %>'> 
          <% time.set(0,0,0,i,0); 
             out.print(dateformat.format(time.getTime()));%>
         </option> 
         <% } %> 
      </select>
    </td>
  </tr>
    <td width="2%">&nbsp;</td>
    <td width="5%" align="left">
    </td>
    <td width="93%" align="left"> <input type="submit" name="<%=BUTTON_ADVANCEDLIST %>" value="<%= ejbcawebbean.getText("LIST") %>">
    </td>        
</table>