
<head>
  <title><%= globalconfiguration.getEjbcaTitle() %></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>">
  <link rel=STYLESHEET href="<%= ejbcawebbean.getCssFile() %>">
  <script language=javascript src="<%= globalconfiguration.getAdminWebPath() %>ejbcajslib.js"></script>
  <script language=javascript>
<!--
function viewuser(row){
    var hiddenusernamefield = eval("document.form.<%= HIDDEN_USERNAME %>" + row);
    var username = hiddenusernamefield.value;
    var link = "<%= VIEWUSER_LINK %>?<%= USER_PARAMETER %>="+username;
    window.open(link, 'view_cert',config='height=600,width=500,scrollbars=yes,toolbar=no,resizable=1');
}

function viewadmincert(row){
    var username = "";
    var hiddenuserdnfield = eval("document.form.<%= HIDDEN_ADMINDN %>" + row);
    var userdn = hiddenuserdnfield.value;
    var link = "<%= VIEWCERT_LINK %>?<%= SUBJECTDN_PARAMETER %>="+userdn+"&<%= USER_PARAMETER %>="+username;
    window.open(link, 'view_cert',config='height=600,width=500,scrollbars=yes,toolbar=no,resizable=1');
}

function viewcert(row){
    var hiddenusernamefield = eval("document.form.<%= HIDDEN_USERNAME %>" + row);
    var username = hiddenusernamefield.value;
    var hiddenuserdnfield = eval("document.form.<%= HIDDEN_CERTDN %>" + row);
    var userdn = hiddenuserdnfield.value;
    var link = "<%= VIEWCERT_LINK %>?<%= SUBJECTDN_PARAMETER %>="+userdn+"&<%= USER_PARAMETER %>="+username;
    window.open(link, 'view_cert',config='height=600,width=500,scrollbars=yes,toolbar=no,resizable=1');
}


-->
</script>
</head>

<body>
<h2 align="center"><%= ejbcawebbean.getText("VIEWLOG") %></h2>
  <form name="changefiltermode" method="post" action="<%=THIS_FILENAME %>">
    <div align="right">
     <% if(filtermode == AdminPreference.FILTERMODE_BASIC){ %>
      <input type="hidden" name='<%= ACTION %>' value='<%=ACTION_CHANGEFILTERMODETO_ADVANCED %>'>
      <A href='javascript:document.changefiltermode.submit();'><u><%= ejbcawebbean.getText("ADVANCEDMODE") %></u></A>
     <% }
        if(filtermode == AdminPreference.FILTERMODE_ADVANCED){ %>
        <input type="hidden" name='<%= ACTION %>' value='<%=ACTION_CHANGEFILTERMODETO_BASIC %>'>
        <A href='javascript:document.changefiltermode.submit();'><u><%= ejbcawebbean.getText("BASICMODE") %></u></A>
     <% } %>
     &nbsp;&nbsp;&nbsp;
     <A  onclick='displayHelpWindow("<%= ejbcawebbean.getHelpfileInfix("log_help.html") +"#viewlog" %>")'>
     <u><%= ejbcawebbean.getText("HELP") %></u> </A>
  </div>
  </form> 
<form name="form" method="post" action="<%=THIS_FILENAME %>">
  <input type="hidden" name='<%= ACTION %>' value='<%=ACTION_LISTLOG %>'>
  <input type="hidden" name='<%= OLD_ACTION %>' value='<%=oldaction %>'>
  <% if( oldactionvalue != null){ %>
  <input type="hidden" name='<%= OLD_ACTION_VALUE %>' value='<%=oldactionvalue %>'>
  <% }if(oldmatchwithrow1 != null){ %>
  <input type="hidden" name='<%= OLD_MATCHWITHROW1 %>' value='<%=oldmatchwithrow1 %>'>
  <% } %>
  <% if(oldmatchwithrow2 != null){ %>
  <input type="hidden" name='<%= OLD_MATCHWITHROW2 %>' value='<%=oldmatchwithrow2 %>'>
  <% } %>
  <% if(oldmatchwithrow3 != null){ %>
  <input type="hidden" name='<%= OLD_MATCHWITHROW3 %>' value='<%=oldmatchwithrow3 %>'>
  <% } %>
  <% if(oldmatchwithrow4 != null){ %>
  <input type="hidden" name='<%= OLD_MATCHWITHROW4 %>' value='<%=oldmatchwithrow4 %>'>
  <% } %>
  <% if(oldmatchtyperow1 != null){ %>
  <input type="hidden" name='<%= OLD_MATCHTYPEROW1 %>' value='<%=oldmatchtyperow1 %>'>
  <% } %>
  <% if(oldmatchtyperow2 != null){ %>
  <input type="hidden" name='<%= OLD_MATCHTYPEROW2 %>' value='<%=oldmatchtyperow2 %>'>
  <% } %>
  <% if(oldmatchtyperow3 != null){ %>
  <input type="hidden" name='<%= OLD_MATCHTYPEROW2 %>' value='<%=oldmatchtyperow3 %>'>
  <% } %>
  <% if(oldmatchvaluerow1 != null){ %>
  <input type="hidden" name='<%= OLD_MATCHVALUEROW1 %>' value='<%=oldmatchvaluerow1%>'>
  <% } %>
  <% if(oldmatchvaluerow2 != null){ %>
  <input type="hidden" name='<%= OLD_MATCHVALUEROW2 %>' value='<%=oldmatchvaluerow2 %>'>
  <% } %>
  <% if(oldmatchvaluerow3 != null){ %>
  <input type="hidden" name='<%= OLD_MATCHVALUEROW3 %>' value='<%=oldmatchvaluerow3%>'>
  <% } %>
  <% if(oldconnectorrow2 != null){ %>
  <input type="hidden" name='<%= OLD_CONNECTORROW2 %>' value='<%=oldconnectorrow2%>'>
  <% } %>
  <% if(oldconnectorrow3 != null){ %>
  <input type="hidden" name='<%= OLD_CONNECTORROW3 %>' value='<%=oldconnectorrow3%>'>
  <% } %>
  <% if(oldconnectorrow4 != null){ %>
  <input type="hidden" name='<%= OLD_CONNECTORROW4 %>' value='<%=oldconnectorrow4%>'>
  <% } %>
  <% if(olddayrow4 != null){ %>
  <input type="hidden" name='<%= OLD_DAY_ROW4 %>' value='<%=olddayrow4%>'>
  <% } %>
  <% if(olddayrow5 != null){ %>
  <input type="hidden" name='<%= OLD_DAY_ROW5 %>' value='<%=olddayrow5%>'>
  <% } %>
  <% if(oldmonthrow4 != null){ %>
  <input type="hidden" name='<%= OLD_MONTH_ROW4 %>' value='<%=oldmonthrow4%>'>
  <% } %>
  <% if(oldmonthrow5 != null){ %>
  <input type="hidden" name='<%= OLD_MONTH_ROW5 %>' value='<%=oldmonthrow5%>'>
  <% } %>
  <% if(oldyearrow4 != null){ %>
  <input type="hidden" name='<%= OLD_YEAR_ROW4 %>' value='<%=oldyearrow4%>'>
  <% } %>
  <% if(oldyearrow5 != null){ %>
  <input type="hidden" name='<%= OLD_YEAR_ROW5 %>' value='<%=oldyearrow5%>'>
  <% } %>
  <% if(oldtimerow4 != null){ %>
  <input type="hidden" name='<%= OLD_TIME_ROW4 %>' value='<%=oldtimerow4%>'>
  <% } %>
  <% if(oldtimerow5 != null){ %>
  <input type="hidden" name='<%= OLD_TIME_ROW5 %>' value='<%=oldtimerow5%>'>
  <% } %>

  <input type="hidden" name='<%= HIDDEN_RECORDNUMBER %>' value='<%=String.valueOf(record) %>'>
  <input type="hidden" name='<%= HIDDEN_SORTBY  %>' value='<%=sortby %>'>
     <% if(filtermode == AdminPreference.FILTERMODE_BASIC){ %>
      <p><%= ejbcawebbean.getText("VIEWEVENTSOCCURED") %>
      <select name="<%=SELECT_VIEWLASTENTRIES %>" >
        <option  value='' > -- </option>
      <% 
         for(int i=0; i < VIEWLASTTIMES.length; i++){ %>
        <option  value='<%=i%>' <% if( oldactionvalue != null )
                                        if(Integer.parseInt(oldactionvalue) ==i)
                                           out.write(" selected ");
                                   %>><%=ejbcawebbean.getText(VIEWLASTTIMESTEXTS[i]) %></option>
      <% } %>
     </select>  
    <input type="submit" name="<%=BUTTON_VIEWLAST %>" value="<%= ejbcawebbean.getText("VIEW") %>">
  </p>
     <% }
        if(filtermode == AdminPreference.FILTERMODE_ADVANCED){ %>
        <%@ include file="advancedlogfiltermodehtml.jsp" %>
     <%   } %>

  <% if(illegalquery){ %>
      <H4 id="alert"><div align="center"><%= ejbcawebbean.getText("INVALIDQUERY") %></div></H4>
  <% } %>

  <% if(largeresult){ %>
     <H4 id="alert"><div align="center" ><%= ejbcawebbean.getText("TOLARGERESULT")  + " " + LogInterfaceBean.MAXIMUM_QUERY_ROWCOUNT
                                             + " " + ejbcawebbean.getText("ROWSWILLBEDISPLAYED") %> </div> </H4>  
  <% } %>
  <p>
    <input type="submit" name="<%=BUTTON_RELOAD %>" value="<%= ejbcawebbean.getText("RELOAD") %>">
  </p>
  <br>
  <table width="100%" border="0" cellspacing="1" cellpadding="0">
    <tr> 
      <td width="14%"> 
        <% if(logbean.previousButton(record,size)){ %>
          <input type="submit" name="<%=BUTTON_PREVIOUS %>" value="<%= ejbcawebbean.getText("PREVIOUS") %>">
        <% } %>
      </td>
      <td width="76%">&nbsp; </td>
      <td width="10%"> 
        <div align="right">
        <% if(logbean.nextButton(record,size)){ %>
          <input type="submit" name="<%=BUTTON_NEXT %>" value="<%= ejbcawebbean.getText("NEXT") %>">
        <% } %>
        </div>
      </td>
    </tr>
  </table>
  <table width="1100" border="0" cellspacing="1" cellpadding="0">
  <tr> 
    <td width="9%"><% if(sortby.equals(SORTBY_TIME_ACC)){ %>
                          <input type="image" src='<%= ejbcawebbean.getImagefileInfix("downarrow.gif") %>' border="0" name="<%=SORTBY_TIME_DEC %>" value="submit" ><%= ejbcawebbean.getText("TIME") %>              
                   <% }else{
                         if(sortby.equals(SORTBY_TIME_DEC)){ %>
                          <input type="image" src='<%= ejbcawebbean.getImagefileInfix("uparrow.gif") %>' border="0" name="<%=SORTBY_TIME_ACC %>" value="submit" ><%= ejbcawebbean.getText("TIME") %>                     
                   <%    }else{ %> 
                          <input type="image" src='<%= ejbcawebbean.getImagefileInfix("noarrow.gif") %>' border="0" name="<%=SORTBY_TIME_ACC %>" value="submit" ><%= ejbcawebbean.getText("TIME") %>
                   <%    }
                       } %>
    </td>
    <td width="9%">
                   <% if(sortby.equals(SORTBY_ADMINTYPE_ACC)){ %>
                          <input type="image" src='<%= ejbcawebbean.getImagefileInfix("downarrow.gif") %>' border="0" name="<%=SORTBY_ADMINTYPE_DEC %>" value="submit" ><%= ejbcawebbean.getText("ADMINTYPE") %>              
                   <% }else{
                         if(sortby.equals(SORTBY_ADMINTYPE_DEC)){ %>
                          <input type="image" src='<%= ejbcawebbean.getImagefileInfix("uparrow.gif") %>' border="0" name="<%=SORTBY_ADMINTYPE_ACC %>" value="submit" ><%= ejbcawebbean.getText("ADMINTYPE") %>                     
                   <%    }else{ %> 
                          <input type="image" src='<%= ejbcawebbean.getImagefileInfix("noarrow.gif") %>' border="0" name="<%=SORTBY_ADMINTYPE_ACC %>" value="submit" ><%= ejbcawebbean.getText("ADMINTYPE") %>
                   <%    }
                       } %>
    </td>
    <td width="19%">
                   <% if(sortby.equals(SORTBY_ADMINDATA_ACC)){ %>
                          <input type="image" src='<%= ejbcawebbean.getImagefileInfix("downarrow.gif") %>' border="0" name="<%=SORTBY_ADMINDATA_DEC %>" value="submit" ><%= ejbcawebbean.getText("ADMINISTRATOR") %>              
                   <% }else{
                         if(sortby.equals(SORTBY_ADMINDATA_DEC)){ %>
                          <input type="image" src='<%= ejbcawebbean.getImagefileInfix("uparrow.gif") %>' border="0" name="<%=SORTBY_ADMINDATA_ACC %>" value="submit" ><%= ejbcawebbean.getText("ADMINISTRATOR") %>                     
                   <%    }else{ %> 
                          <input type="image" src='<%= ejbcawebbean.getImagefileInfix("noarrow.gif") %>' border="0" name="<%=SORTBY_ADMINDATA_ACC %>" value="submit" ><%= ejbcawebbean.getText("ADMINISTRATOR") %>
                   <%    }
                       } %>
    </td>
    <td width="5%">
                   <% if(sortby.equals(SORTBY_MODULE_ACC)){ %>
                          <input type="image" src='<%= ejbcawebbean.getImagefileInfix("downarrow.gif") %>' border="0" name="<%=SORTBY_MODULE_DEC %>" value="submit" ><%= ejbcawebbean.getText("MODULE") %>              
                   <% }else{
                         if(sortby.equals(SORTBY_MODULE_DEC)){ %>
                          <input type="image" src='<%= ejbcawebbean.getImagefileInfix("uparrow.gif") %>' border="0" name="<%=SORTBY_MODULE_ACC %>" value="submit" ><%= ejbcawebbean.getText("MODULE") %>                     
                   <%    }else{ %> 
                          <input type="image" src='<%= ejbcawebbean.getImagefileInfix("noarrow.gif") %>' border="0" name="<%=SORTBY_MODULE_ACC %>" value="submit" ><%= ejbcawebbean.getText("MODULE") %>
                   <%    }
                       } %>
    </td>
    <td width="9%"><% if(sortby.equals(SORTBY_EVENT_ACC)){ %>
                          <input type="image" src='<%= ejbcawebbean.getImagefileInfix("downarrow.gif") %>' border="0" name="<%=SORTBY_EVENT_DEC %>" value="submit" ><%= ejbcawebbean.getText("EVENT") %>                        
                   <% }else{ 
                         if(sortby.equals(SORTBY_EVENT_DEC)){ %>
                          <input type="image" src='<%= ejbcawebbean.getImagefileInfix("uparrow.gif") %>' border="0" name="<%=SORTBY_EVENT_ACC %>" value="submit" ><%= ejbcawebbean.getText("EVENT") %>                 
                   <%    }else{ %> 
                          <input type="image" src='<%= ejbcawebbean.getImagefileInfix("noarrow.gif") %>' border="0" name="<%=SORTBY_EVENT_ACC %>" value="submit" ><%= ejbcawebbean.getText("EVENT") %>
                   <%    }
                       } %>
    </td>
    <td width="9%"><% if(sortby.equals(SORTBY_USERNAME_ACC)){ %>
                          <input type="image" src='<%= ejbcawebbean.getImagefileInfix("downarrow.gif") %>' border="0" name="<%=SORTBY_USERNAME_DEC %>" value="submit" ><%= ejbcawebbean.getText("USERNAME") %>              
                   <% }else{
                         if(sortby.equals(SORTBY_USERNAME_DEC)){ %>
                          <input type="image" src='<%= ejbcawebbean.getImagefileInfix("uparrow.gif") %>' border="0" name="<%=SORTBY_USERNAME_ACC %>" value="submit" ><%= ejbcawebbean.getText("USERNAME") %>                     
                   <%    }else{ %> 
                          <input type="image" src='<%= ejbcawebbean.getImagefileInfix("noarrow.gif") %>' border="0" name="<%=SORTBY_USERNAME_ACC %>" value="submit" ><%= ejbcawebbean.getText("USERNAME") %>
                   <%    }
                       } %>
    </td>
    <td width="20%"><% if(sortby.equals(SORTBY_CERTIFICATE_ACC)){ %>
                          <input type="image" src='<%= ejbcawebbean.getImagefileInfix("downarrow.gif") %>' border="0" name="<%=SORTBY_CERTIFICATE_DEC %>" value="submit" ><%= ejbcawebbean.getText("CERTIFICATE") %>              
                   <% }else{
                         if(sortby.equals(SORTBY_CERTIFICATE_DEC)){ %>
                          <input type="image" src='<%= ejbcawebbean.getImagefileInfix("uparrow.gif") %>' border="0" name="<%=SORTBY_CERTIFICATE_ACC %>" value="submit" ><%= ejbcawebbean.getText("CERTIFICATE") %>                     
                   <%    }else{ %> 
                          <input type="image" src='<%= ejbcawebbean.getImagefileInfix("noarrow.gif") %>' border="0" name="<%=SORTBY_CERTIFICATE_ACC %>" value="submit" ><%= ejbcawebbean.getText("CERTIFICATE") %>
                   <%    }
                       } %>
    </td>
    <td width="20%"><% if(sortby.equals(SORTBY_COMMENT_ACC)){ %>
                          <input type="image" src='<%= ejbcawebbean.getImagefileInfix("downarrow.gif") %>' border="0" name="<%=SORTBY_COMMENT_DEC %>" value="submit" ><%= ejbcawebbean.getText("COMMENT") %>              
                   <% }else{
                         if(sortby.equals(SORTBY_COMMENT_DEC)){ %>
                          <input type="image" src='<%= ejbcawebbean.getImagefileInfix("uparrow.gif") %>' border="0" name="<%=SORTBY_COMMENT_ACC %>" value="submit" ><%= ejbcawebbean.getText("COMMENT") %>                     
                   <%    }else{ %> 
                          <input type="image" src='<%= ejbcawebbean.getImagefileInfix("noarrow.gif") %>' border="0" name="<%=SORTBY_COMMENT_ACC %>" value="submit" ><%= ejbcawebbean.getText("COMMENT") %>
                   <%    }
                       } %>
    </td>
  </tr>
  <%     if(logentries == null || logentries.length == 0){     %>
  <tr id="LogTextRow0"> 
    <td width="9%"> &nbsp;</td>
    <td width="9%">&nbsp;</td>
    <td width="19%"><%= ejbcawebbean.getText("NOLOGENTRIESFOUND") %></td>
    <td width="9%">&nbsp;</td>
    <td width="9%">&nbsp;</td>
    <td width="20%">&nbsp;</td>
    <td width="20%">&nbsp;</td>
  </tr>
  <% } else{
         for(int i=0; i < logentries.length; i++){%>
  <tr id="LogTextRow<%= i%2 %>"> 
       <input type="hidden" name='<%= HIDDEN_USERNAME + i %>' value='<%= logentries[i].getValue(LogEntryView.USERNAME) %>'>
       <input type="hidden" name='<%= HIDDEN_CERTDN + i %>' value='<% if(logentries[i].getValue(LogEntryView.CERTIFICATEDN) != null) out.print(java.net.URLEncoder.encode(logentries[i].getValue(LogEntryView.CERTIFICATEDN),"UTF-8")); %>'>
       <input type="hidden" name='<%= HIDDEN_ADMINDN + i %>' value='<% if(logentries[i].getValue(LogEntryView.ADMINCERTDN) != null) out.print(java.net.URLEncoder.encode(logentries[i].getValue(LogEntryView.ADMINCERTDN),"UTF-8")); %>'>
    <td width="9%"><%= logentries[i].getValue(LogEntryView.TIME) %></td>
    <td width="9%"><%= ejbcawebbean.getText(ADMINTYPES[Integer.parseInt(logentries[i].getValue(LogEntryView.ADMINTYPE))]) %></td>
    <td width="19%">
       <%  if(Integer.parseInt(logentries[i].getValue(LogEntryView.ADMINTYPE)) == Admin.TYPE_CLIENTCERT_USER) 
             if(logentries[i].getValue(LogEntryView.ADMINDATA).equals(""))
                out.write(ejbcawebbean.getText("CERTIFICATENOTKNOWN"));
             else{%>
        <A  onclick='viewadmincert(<%= i %>)'>
        <u><%= logentries[i].getValue(LogEntryView.ADMINDATA) %></u> </A>
       <% } else         
            out.write(logentries[i].getValue(LogEntryView.ADMINDATA));
          %>    
    </td>
    <td width="9%"><%= logentries[i].getValue(LogEntryView.MODULE) %></td>
    <td width="9%"><%= logentries[i].getValue(LogEntryView.EVENT) %></td>
    <td width="9%"><% if(logentries[i].getValue(LogEntryView.USERNAME) == null)
                         out.write(ejbcawebbean.getText("NOENDENTITYINVOLVED"));
                       else{%> 
        <A  onclick='viewuser(<%= i %>)'>
        <u><%= logentries[i].getValue(LogEntryView.USERNAME) %></u> </A>
                    <% } %>
    </td>
    <td width="20%"><% if(logentries[i].getValue(LogEntryView.CERTIFICATEDN) == null)
                         out.write(ejbcawebbean.getText("NOCERTIFICATEINVOLVED"));
                       else
                         if(logentries[i].getValue(LogEntryView.CERTIFICATE).equals(""))
                           out.write(ejbcawebbean.getText("CERTIFICATENOTKNOWN"));
                         else{%> 
        <A  onclick='viewcert(<%= i %>)'>
        <u><%= logentries[i].getValue(LogEntryView.CERTIFICATE) %></u> </A>
                    <% } %>
    </td>
    <td width="20%"><%= logentries[i].getValue(LogEntryView.COMMENT) %></td>
  </tr>
 <%      }
       }%>
</table>
  <table width="100%" border="0" cellspacing="1" cellpadding="0">
    <tr>
      <td width="14%">
        <% if(logbean.previousButton(record,size)){ %>
          <input type="submit" name="<%=BUTTON_PREVIOUS %>" value="<%= ejbcawebbean.getText("PREVIOUS") %>">
        <% } %>
      </td>
      <td width="76%"> 
        &nbsp;&nbsp;
      </td>
      <td width="10%"> 
        <div align="right">
        <% if(logbean.nextButton(record,size)){ %>
          <input type="submit" name="<%=BUTTON_NEXT %>" value="<%= ejbcawebbean.getText("NEXT") %>">
        <% } %>
        </div>
      </td>
    </tr>
  </table>
    <div align="right">
      <%= ejbcawebbean.getText("ENTRIESPERPAGE") %></A>
      <select name="<%=SELECT_ENTRIESPERPAGE %>" onchange='document.form.<%=ACTION%>.value="<%=ACTION_CHANGEENTRIESPERPAGE %>"; javascript:document.form.submit();'>
      <% String[] availablesizes = globalconfiguration.getPossibleLogEntiresPerPage();
         for(int i=0; i < availablesizes.length; i++){ %>
        <option  value='<%=availablesizes[i]%>' <% if(size == Integer.parseInt(availablesizes[i]) ) out.write(" selected "); %>><%=availablesizes[i] %></option>
      <% } %>
     </select>  
  </form> 

  <%// Include Footer 
   String footurl =   globalconfiguration.getFootBanner(); %>
   
  <jsp:include page="<%= footurl %>" />
</body>
</html>
