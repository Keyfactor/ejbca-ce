<html>
<%@page contentType="text/html"%>
<%@page errorPage="/errorpage.jsp"  import="se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean,se.anatom.ejbca.ra.GlobalConfiguration, 
                 se.anatom.ejbca.webdist.rainterface.SortBy,se.anatom.ejbca.webdist.loginterface.LogEntryView,se.anatom.ejbca.webdist.loginterface.LogEntriesView,
             se.anatom.ejbca.webdist.loginterface.LogInterfaceBean, se.anatom.ejbca.log.LogEntry, se.anatom.ejbca.log.Admin, 
                 javax.ejb.CreateException, java.rmi.RemoteException, se.anatom.ejbca.util.query.*, java.util.Calendar, java.util.Date, java.text.DateFormat, java.util.Locale,
                 java.util.HashMap" %>
<jsp:useBean id="ejbcawebbean" scope="session" class="se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean" />
<jsp:setProperty name="ejbcawebbean" property="*" /> 
<jsp:useBean id="logbean" scope="session" class="se.anatom.ejbca.webdist.loginterface.LogInterfaceBean" />
<jsp:setProperty name="logbean" property="*" /> 
<jsp:useBean id="rabean" scope="session" class="se.anatom.ejbca.webdist.rainterface.RAInterfaceBean" />
<jsp:setProperty name="rabean" property="*" /> 
<%! // Declarations

  static final String ACTION                             = "action";
  static final String ACTION_CHANGEENTRIESPERPAGE        = "changeentriesperpage";
 
  static final String BUTTON_RELOAD            = "buttonreload";

  static final String BUTTON_NEXT              = "buttonnext";
  static final String BUTTON_PREVIOUS          = "buttonprevious";

  static final String SORTBY_TIME_ACC         = "sortbytimeaccending";
  static final String SORTBY_TIME_DEC         = "sortbytimedecending";
  static final String SORTBY_ADMINDATA_ACC    = "sortbyadmindataaccending";
  static final String SORTBY_ADMINDATA_DEC    = "sortbyadmindatadecending";
  static final String SORTBY_ADMINTYPE_ACC    = "sortbyadmintypeaccending";
  static final String SORTBY_ADMINTYPE_DEC    = "sortbyadmintypedecending";
  static final String SORTBY_USERNAME_ACC     = "sortbyusernameaccending";
  static final String SORTBY_USERNAME_DEC     = "sortbyusernamedecending";
  static final String SORTBY_CERTIFICATE_ACC  = "sortbycertificateaccending";
  static final String SORTBY_CERTIFICATE_DEC  = "sortbycertificatedecending";
  static final String SORTBY_EVENT_ACC        = "sortbyeventaccending";
  static final String SORTBY_EVENT_DEC        = "sortbyeventdecending";
  static final String SORTBY_COMMENT_ACC      = "sortbycommentaccending";
  static final String SORTBY_COMMENT_DEC      = "sortbycommentdecending";

  static final String SELECT_ENTRIESPERPAGE     = "selectentriesperpage";


  static final String HIDDEN_SORTBY             = "hiddensortby";
  static final String HIDDEN_RECORDNUMBER       = "hiddenrecordnumber"; 
  static final String HIDDEN_USERNAME           = "hiddenusername";
  static final String HIDDEN_CERTDN             = "hiddencertdn";
  static final String HIDDEN_ADMINDN            = "hiddenadmindn";

  static final String VALUE_NONE                = "-1";

  static final String USER_PARAMETER            = "username";
  static final String SUBJECTDN_PARAMETER       = "subjectdnparameter";

  static final String[] ADMINTYPES              = {"CLIENTCERT","PUBLICWEBUSER","RACMDLINE","CACMDLINE"};
%><%
  // Initialize environment.
  GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, "/ra_functionallity/view_end_entity_history"); 
                                            logbean.initialize(request,ejbcawebbean);
  final String VIEWCERT_LINK            = "/" + globalconfiguration.getAdminWebPath() + "viewcertificate.jsp";
  final String VIEWUSER_LINK            = "/" + globalconfiguration.getAdminWebPath() + "ra/viewendentity.jsp";

  String sortby         = SORTBY_TIME_DEC;

  String THIS_FILENAME            =  globalconfiguration.getRaPath()  + "/viewhistory.jsp";
  LogEntriesView logdata          = null;
  LogEntryView[] logentries       = null;
  boolean nouserparam             = false;
  String username                 = null;

  boolean largeresult             = false;
  boolean notauthorized           = false;
  // Determine action 
  int record   = 0;
  int size = ejbcawebbean.getLogEntriesPerPage();


  if(request.getParameter(USER_PARAMETER) != null){
    username = request.getParameter(USER_PARAMETER);
    logdata = logbean.filterByUsername(username);


    if(globalconfiguration.getEnableEndEntityProfileLimitations() && !rabean.isAuthorizedToViewUserHistory(username))
      notauthorized = true;
    else{

      if (request.getParameter(HIDDEN_RECORDNUMBER) != null ){
        record =  Integer.parseInt(request.getParameter(HIDDEN_RECORDNUMBER)); 
      } 

      if (request.getParameter(HIDDEN_SORTBY) != null ){
        sortby =  request.getParameter(HIDDEN_SORTBY); 
      } 

      if( request.getParameter(ACTION) != null){

        if( request.getParameter(ACTION).equals(ACTION_CHANGEENTRIESPERPAGE)){
          size = Integer.parseInt(request.getParameter(SELECT_ENTRIESPERPAGE));
          ejbcawebbean.setLogEntriesPerPage(size);
        }
 
       if( request.getParameter(BUTTON_PREVIOUS) != null ){
         record = Integer.parseInt(request.getParameter(HIDDEN_RECORDNUMBER));
         record -= ejbcawebbean.getLogEntriesPerPage();
         if(record < 0 ) record=0;
       }
       if( request.getParameter(BUTTON_NEXT) != null ){
         record = Integer.parseInt(request.getParameter(HIDDEN_RECORDNUMBER));
         record += ejbcawebbean.getLogEntriesPerPage();
       }
     }
   
     if( request.getParameter(SORTBY_TIME_ACC+".x") != null ){
       // Sortby username accending
       sortby = SORTBY_TIME_ACC;
       logdata.sortBy(SortBy.TIME,SortBy.ACCENDING);
     }
     if( request.getParameter(SORTBY_TIME_DEC+".x") != null ){
       // Sortby username accending
       sortby = SORTBY_TIME_DEC;
       logdata.sortBy(SortBy.TIME,SortBy.DECENDING);
     }
     if( request.getParameter(SORTBY_ADMINTYPE_ACC+".x") != null ){
       // Sortby username accending
       sortby = SORTBY_ADMINTYPE_ACC;
       logdata.sortBy(SortBy.ADMINTYPE,SortBy.ACCENDING);
     }
     if( request.getParameter(SORTBY_ADMINTYPE_DEC+".x") != null ){
       // Sortby username accending
       sortby = SORTBY_ADMINTYPE_DEC;
       logdata.sortBy(SortBy.ADMINTYPE,SortBy.DECENDING);
     }
     if( request.getParameter(SORTBY_ADMINDATA_ACC+".x") != null ){
       // Sortby username accending
       sortby = SORTBY_ADMINDATA_ACC;
       logdata.sortBy(SortBy.ADMINDATA,SortBy.ACCENDING);
     }
     if( request.getParameter(SORTBY_ADMINDATA_DEC+".x") != null ){
       // Sortby username accending
       sortby = SORTBY_ADMINDATA_DEC;
       logdata.sortBy(SortBy.ADMINDATA,SortBy.DECENDING);
     }
     if( request.getParameter(SORTBY_USERNAME_ACC+".x") != null ){
       // Sortby username accending
       sortby = SORTBY_USERNAME_ACC;
       logdata.sortBy(SortBy.USERNAME,SortBy.ACCENDING);
     }
     if( request.getParameter(SORTBY_USERNAME_DEC+".x") != null ){
       // Sortby username accending
       sortby = SORTBY_USERNAME_DEC;
       logdata.sortBy(SortBy.USERNAME,SortBy.DECENDING);
     }
     if( request.getParameter(SORTBY_CERTIFICATE_ACC+".x") != null ){
       // Sortby username accending
       sortby = SORTBY_CERTIFICATE_ACC;
       logdata.sortBy(SortBy.CERTIFICATE,SortBy.ACCENDING);
     }
     if( request.getParameter(SORTBY_CERTIFICATE_DEC+".x") != null ){
       // Sortby username accending
       sortby = SORTBY_CERTIFICATE_DEC;
       logdata.sortBy(SortBy.CERTIFICATE,SortBy.DECENDING);
     }
     if( request.getParameter(SORTBY_EVENT_ACC+".x") != null ){
       // Sortby username accending
       sortby = SORTBY_EVENT_ACC;
       logdata.sortBy(SortBy.EVENT,SortBy.ACCENDING);
     }
     if( request.getParameter(SORTBY_EVENT_DEC+".x") != null ){
       // Sortby username accending
       sortby = SORTBY_EVENT_DEC;
       logdata.sortBy(SortBy.EVENT,SortBy.DECENDING);
     }
     if( request.getParameter(SORTBY_COMMENT_ACC+".x") != null ){
        // Sortby username accending
       sortby = SORTBY_COMMENT_ACC;
       logdata.sortBy(SortBy.COMMENT,SortBy.ACCENDING);
     }
     if( request.getParameter(SORTBY_COMMENT_DEC+".x") != null ){
       // Sortby username accending
       sortby = SORTBY_COMMENT_DEC;
       logdata.sortBy(SortBy.COMMENT,SortBy.DECENDING);
     }

     logentries = logdata.getEntries(record,size);
     if(logentries  != null)
       if(logentries.length >= LogInterfaceBean.MAXIMUM_QUERY_ROWCOUNT) 
         largeresult = true; 
    }
  }  
  else{
    nouserparam = true;
  }
%>

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
<h2 align="center"><%= ejbcawebbean.getText("VIEWENDENTITYHISTORY") %></h2>
    <div align="right">
     <A  onclick='displayHelpWindow("<%= ejbcawebbean.getHelpfileInfix("ra_help.html") +"#viewhistory" %>")'>
     <u><%= ejbcawebbean.getText("HELP") %></u> </A>
  </div>
<form name="form" method="post" action="<%=THIS_FILENAME %>">
  <input type="hidden" name='<%= ACTION %>' value=''>
  <input type="hidden" name='<%= HIDDEN_RECORDNUMBER %>' value='<%=String.valueOf(record) %>'>
  <input type="hidden" name='<%= USER_PARAMETER %>' value='<%=username %>'>
  <input type="hidden" name='<%= HIDDEN_SORTBY  %>' value='<%=sortby %>'>
  <% if(nouserparam){ %>
    <div align="center"><h4 id="alert"><%=ejbcawebbean.getText("YOUMUSTSPECIFYUSERNAME") %></h4></div> 
  <% }else{ %>
    <% if(notauthorized){ %>
      <div align="center"><h4 id="alert"><%=ejbcawebbean.getText("NOTAUTHORIZEDTOVIEWHIST") %></h4></div> 
    <% }else{ %>
    <%   if(largeresult){ %>
         <H4 id="alert"><div align="center" ><%= ejbcawebbean.getText("TOLARGERESULT")  + " " + LogInterfaceBean.MAXIMUM_QUERY_ROWCOUNT
                                             + " " + ejbcawebbean.getText("ROWSWILLBEDISPLAYED") %> </div> </H4>  
    <%   } %>
  <p>
    <input type="button" name="<%=BUTTON_RELOAD %>" value="<%= ejbcawebbean.getText("RELOAD") %>" onclick='window.location.reload(true)'>
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
    <td width="10%"><% if(sortby.equals(SORTBY_TIME_ACC)){ %>
                          <input type="image" src='<%= ejbcawebbean.getImagefileInfix("downarrow.gif") %>' border="0" name="<%=SORTBY_TIME_DEC %>" value="submit" ><%= ejbcawebbean.getText("TIME") %>              
                   <% }else{
                         if(sortby.equals(SORTBY_TIME_DEC)){ %>
                          <input type="image" src='<%= ejbcawebbean.getImagefileInfix("uparrow.gif") %>' border="0" name="<%=SORTBY_TIME_ACC %>" value="submit" ><%= ejbcawebbean.getText("TIME") %>                     
                   <%    }else{ %> 
                          <input type="image" src='<%= ejbcawebbean.getImagefileInfix("noarrow.gif") %>' border="0" name="<%=SORTBY_TIME_ACC %>" value="submit" ><%= ejbcawebbean.getText("TIME") %>
                   <%    }
                       } %>
    </td>
    <td width="10%">
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
    <td width="20%">
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
    <td width="10%"><% if(sortby.equals(SORTBY_EVENT_ACC)){ %>
                          <input type="image" src='<%= ejbcawebbean.getImagefileInfix("downarrow.gif") %>' border="0" name="<%=SORTBY_EVENT_DEC %>" value="submit" ><%= ejbcawebbean.getText("EVENT") %>                        
                   <% }else{ 
                         if(sortby.equals(SORTBY_EVENT_DEC)){ %>
                          <input type="image" src='<%= ejbcawebbean.getImagefileInfix("uparrow.gif") %>' border="0" name="<%=SORTBY_EVENT_ACC %>" value="submit" ><%= ejbcawebbean.getText("EVENT") %>                 
                   <%    }else{ %> 
                          <input type="image" src='<%= ejbcawebbean.getImagefileInfix("noarrow.gif") %>' border="0" name="<%=SORTBY_EVENT_ACC %>" value="submit" ><%= ejbcawebbean.getText("EVENT") %>
                   <%    }
                       } %>
    </td>
    <td width="10%"><% if(sortby.equals(SORTBY_USERNAME_ACC)){ %>
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
    <td width="10%"> &nbsp;</td>
    <td width="10%">&nbsp;</td>
    <td width="20%"><%= ejbcawebbean.getText("NOLOGENTRIESFOUND") %></td>
    <td width="10%">&nbsp;</td>
    <td width="10%">&nbsp;</td>
    <td width="20%">&nbsp;</td>
    <td width="20%">&nbsp;</td>
  </tr>
  <% } else{
         for(int i=0; i < logentries.length; i++){%>
  <tr id="LogTextRow<%= i%2 %>"> 
       <input type="hidden" name='<%= HIDDEN_USERNAME + i %>' value='<%= logentries[i].getValue(LogEntryView.USERNAME) %>'>
       <input type="hidden" name='<%= HIDDEN_CERTDN + i %>' value='<% if(logentries[i].getValue(LogEntryView.CERTIFICATEDN) != null) out.print(java.net.URLEncoder.encode(logentries[i].getValue(LogEntryView.CERTIFICATEDN),"UTF-8")); %>'>
       <input type="hidden" name='<%= HIDDEN_ADMINDN + i %>' value='<% if(logentries[i].getValue(LogEntryView.ADMINCERTDN) != null) out.print(java.net.URLEncoder.encode(logentries[i].getValue(LogEntryView.ADMINCERTDN),"UTF-8")); %>'>
    <td width="10%"><%= logentries[i].getValue(LogEntryView.TIME) %></td>
    <td width="10%"><%= ejbcawebbean.getText(ADMINTYPES[Integer.parseInt(logentries[i].getValue(LogEntryView.ADMINTYPE))]) %></td>
    <td width="20%">
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
    <td width="10%"><%= logentries[i].getValue(LogEntryView.EVENT) %></td>
    <td width="10%"><% if(logentries[i].getValue(LogEntryView.USERNAME) == null)
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
     }  
   }

   String footurl =   globalconfiguration.getFootBanner(); %>
   
  <jsp:include page="<%= footurl %>" />
</body>
</html>
