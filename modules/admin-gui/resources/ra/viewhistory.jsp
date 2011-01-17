<%@ page pageEncoding="ISO-8859-1"%>
<% response.setContentType("text/html; charset="+org.ejbca.config.WebConfiguration.getWebContentEncoding()); %>
<%@page errorPage="/errorpage.jsp"  import="org.ejbca.core.model.ra.raadmin.GlobalConfiguration, 
    org.ejbca.ui.web.RequestHelper,org.ejbca.ui.web.admin.rainterface.SortBy,org.ejbca.ui.web.admin.loginterface.LogEntryView,org.ejbca.ui.web.admin.loginterface.LogEntriesView,
             org.ejbca.ui.web.admin.loginterface.LogInterfaceBean, org.ejbca.core.model.log.LogConstants, org.ejbca.core.model.log.Admin, java.util.Iterator, java.util.Collection" %>
<html>
<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />
<jsp:useBean id="logbean" scope="session" class="org.ejbca.ui.web.admin.loginterface.LogInterfaceBean" />
<jsp:useBean id="rabean" scope="session" class="org.ejbca.ui.web.admin.rainterface.RAInterfaceBean" />

<%! // Declarations

  static final String ACTION                             = "action";
  static final String ACTION_CHANGEENTRIESPERPAGE        = "changeentriesperpage";
 
  static final String BUTTON_RELOAD            = "buttonreload";
  static final String BUTTON_SHOW              = "buttonshow";

  static final String BUTTON_NEXT              = "buttonnext";
  static final String BUTTON_PREVIOUS          = "buttonprevious";

  static final String SORTBY_TIME_ACC         = "sortbytimeaccending";
  static final String SORTBY_TIME_DEC         = "sortbytimedecending";
  static final String SORTBY_ADMINDATA_ACC    = "sortbyadmindataaccending";
  static final String SORTBY_ADMINDATA_DEC    = "sortbyadmindatadecending";
  static final String SORTBY_ADMINTYPE_ACC    = "sortbyadmintypeaccending";
  static final String SORTBY_ADMINTYPE_DEC    = "sortbyadmintypedecending";
  static final String SORTBY_CA_ACC           = "sortbycaaccending";
  static final String SORTBY_CA_DEC           = "sortbycadecending";
  static final String SORTBY_MODULE_ACC       = "sortbymoduleaccending";
  static final String SORTBY_MODULE_DEC       = "sortbymoduledecending";
  static final String SORTBY_USERNAME_ACC     = "sortbyusernameaccending";
  static final String SORTBY_USERNAME_DEC     = "sortbyusernamedecending";
  static final String SORTBY_CERTIFICATE_ACC  = "sortbycertificateaccending";
  static final String SORTBY_CERTIFICATE_DEC  = "sortbycertificatedecending";
  static final String SORTBY_EVENT_ACC        = "sortbyeventaccending";
  static final String SORTBY_EVENT_DEC        = "sortbyeventdecending";
  static final String SORTBY_COMMENT_ACC      = "sortbycommentaccending";
  static final String SORTBY_COMMENT_DEC      = "sortbycommentdecending";

  static final String SELECT_ENTRIESPERPAGE     = "selectentriesperpage";
  static final String SELECT_VIEWLOGDEVICE      = "selectviewlogdevice";

  static final String HIDDEN_SORTBY             = "hiddensortby";
  static final String HIDDEN_RECORDNUMBER       = "hiddenrecordnumber"; 
  static final String HIDDEN_USERNAME           = "hiddenusername";
  static final String HIDDEN_CERTSERNO          = "hiddencertserno";
  static final String HIDDEN_ADMINSERNO         = "hiddenadminserno";

  static final String VALUE_NONE                = "-1";

  static final String USER_PARAMETER            = "username";
  static final String CERTSERNO_PARAMETER       = "certsernoparameter";
  static final String ISSUERDN_PARAMETER        = "issuerdn";

  final String[] ADMINTYPES             = Admin.ADMINTYPETEXTS;
%><%
  // Initialize environment.
  GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, "/ra_functionality/view_end_entity_history"); 
                                            rabean.initialize(request, ejbcawebbean);
                                            logbean.initialize(request,ejbcawebbean);
  final String VIEWCERT_LINK            = ejbcawebbean.getBaseUrl() + globalconfiguration.getAdminWebPath() + "viewcertificate.jsp";
  final String VIEWUSER_LINK            = ejbcawebbean.getBaseUrl() + globalconfiguration.getAdminWebPath() + "ra/viewendentity.jsp";

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

  String logDevice = request.getParameter(SELECT_VIEWLOGDEVICE);

  RequestHelper.setDefaultCharacterEncoding(request);

  if(request.getParameter(USER_PARAMETER) != null){
    username = java.net.URLDecoder.decode(request.getParameter(USER_PARAMETER),"UTF-8");
    if (logDevice == null) {
    	logDevice = (String) logbean.getAvailableLogDevices().iterator().next();
    }
    logdata = logbean.filterByUsername(logDevice, username, ejbcawebbean.getInformationMemory().getCAIdToNameMap());


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
     if( request.getParameter(SORTBY_CA_ACC+".x") != null ){
       // Sortby username accending
       sortby = SORTBY_CA_ACC;
       logdata.sortBy(SortBy.CA,SortBy.ACCENDING);
     }
     if( request.getParameter(SORTBY_CA_DEC+".x") != null ){
       // Sortby username accending
       sortby = SORTBY_CA_DEC;
       logdata.sortBy(SortBy.CA,SortBy.DECENDING);
     }
     if( request.getParameter(SORTBY_MODULE_ACC+".x") != null ){
       // Sortby username accending
       sortby = SORTBY_MODULE_ACC;
       logdata.sortBy(SortBy.MODULE,SortBy.ACCENDING);
     }
     if( request.getParameter(SORTBY_MODULE_DEC+".x") != null ){
       // Sortby username accending
       sortby = SORTBY_MODULE_DEC;
       logdata.sortBy(SortBy.MODULE,SortBy.DECENDING);
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
  <base href="<%= ejbcawebbean.getBaseUrl() %>" />
  <link rel="shortcut icon" href="<%=ejbcawebbean.getImagefileInfix("favicon.png")%>" type="image/png" />
  <link rel="stylesheet" type="text/css" href="<%= ejbcawebbean.getCssFile() %>" />
  <script type="text/javascript" src="<%= globalconfiguration.getAdminWebPath() %>ejbcajslib.js"></script>
  <script type="text/javascript">
<!--
function viewuser(row){
    var hiddenusernamefield = eval("document.form.<%= HIDDEN_USERNAME %>" + row);
    var username = hiddenusernamefield.value;
    var link = "<%= VIEWUSER_LINK %>?<%= USER_PARAMETER %>="+username;
    link = encodeURI(link);
    win_popup = window.open(link, 'view_cert','height=600,width=500,scrollbars=yes,toolbar=no,resizable=1');
    win_popup.focus();
}

function viewadmincert(row){
    var hiddencertsernofield = eval("document.form.<%= HIDDEN_ADMINSERNO %>" + row);
    var certserno = hiddencertsernofield.value;
    var link = "<%= VIEWCERT_LINK %>?<%= CERTSERNO_PARAMETER %>="+certserno;
    link = encodeURI(link);
    win_popup = window.open(link, 'view_cert','height=650,width=600,scrollbars=yes,toolbar=no,resizable=1');
    win_popup.focus();
}

function viewcert(row){
    var hiddencertsernofield = eval("document.form.<%= HIDDEN_CERTSERNO %>" + row);
    var certserno = hiddencertsernofield.value;
 
    var link = "<%= VIEWCERT_LINK %>?<%= CERTSERNO_PARAMETER %>="+certserno;
    link = encodeURI(link);
    win_popup = window.open(link, 'view_cert','height=650,width=600,scrollbars=yes,toolbar=no,resizable=1');
    win_popup.focus();
}


-->
</script>
</head>

<body class="popup" id="viewhistory">
<h2><%= ejbcawebbean.getText("VIEWENDENTITYHISTORY") %></h2>
<h3><%= ejbcawebbean.getText("FORENDENTITY") + " : " + username %></h3>
    <div align="right">
   <!--  <A  onclick='displayHelpWindow("<%= ejbcawebbean.getHelpfileInfix("ra_help.html") +"#viewhistory" %>")'>
     <u><%= ejbcawebbean.getText("HELP") %></u> </A> -->
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
	<%= ejbcawebbean.getText("FROM") %>
	<select name="<%=SELECT_VIEWLOGDEVICE %>" >
	<%	Collection availableLogDevices = logbean.getAvailableLogDevices();
		Iterator iter = availableLogDevices.iterator();
		while(iter.hasNext()){
			String deviceName = (String) iter.next();
			String deviceSelected = (deviceName.equalsIgnoreCase(logDevice) ? "selected" : ""); %>
			<option value='<%=deviceName %>' <%=deviceSelected %> ><%=deviceName %></option>
	<%	}	%>
	</select>  
    <input type="submit" name="<%=BUTTON_SHOW %>" value="<%= ejbcawebbean.getText("SHOW") %>">
    <input type="button" name="<%=BUTTON_RELOAD %>" value="<%= ejbcawebbean.getText("RELOAD") %>" onclick='window.location.reload(true)'>
  </p>
    
  <table width="100%" border="0" cellspacing="1" cellpadding="0">
    <tr> 
      <td width="14%"> 
        <% if(logbean.previousButton(record)){ %>
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
    <td width="7%">
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
    <td width="10%">
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

    <td width="10%"><% if(sortby.equals(SORTBY_CA_ACC)){ %>
                          <input type="image" src='<%= ejbcawebbean.getImagefileInfix("downarrow.gif") %>' border="0" name="<%=SORTBY_CA_DEC %>" value="submit" ><%= ejbcawebbean.getText("CA") %>                        
                   <% }else{ 
                         if(sortby.equals(SORTBY_CA_DEC)){ %>
                          <input type="image" src='<%= ejbcawebbean.getImagefileInfix("uparrow.gif") %>' border="0" name="<%=SORTBY_CA_ACC %>" value="submit" ><%= ejbcawebbean.getText("CA") %>                 
                   <%    }else{ %> 
                          <input type="image" src='<%= ejbcawebbean.getImagefileInfix("noarrow.gif") %>' border="0" name="<%=SORTBY_CA_ACC %>" value="submit" ><%= ejbcawebbean.getText("CA") %>
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
    <td width="9%">
                   <% if(sortby.equals(SORTBY_EVENT_ACC)){ %>
                          <input type="image" src='<%= ejbcawebbean.getImagefileInfix("downarrow.gif") %>' border="0" name="<%=SORTBY_EVENT_DEC %>" value="submit" ><%= ejbcawebbean.getText("EVENT") %>              
                   <% }else{
                         if(sortby.equals(SORTBY_EVENT_DEC)){ %>
                          <input type="image" src='<%= ejbcawebbean.getImagefileInfix("uparrow.gif") %>' border="0" name="<%=SORTBY_EVENT_ACC %>" value="submit" ><%= ejbcawebbean.getText("EVENT") %>                     
                   <%    }else{ %> 
                          <input type="image" src='<%= ejbcawebbean.getImagefileInfix("noarrow.gif") %>' border="0" name="<%=SORTBY_EVENT_ACC %>" value="submit" ><%= ejbcawebbean.getText("EVENT") %>
                   <%    }
                       } %>
    </td>
    <td width="7%"><% if(sortby.equals(SORTBY_USERNAME_ACC)){ %>
                          <input type="image" src='<%= ejbcawebbean.getImagefileInfix("downarrow.gif") %>' border="0" name="<%=SORTBY_USERNAME_DEC %>" value="submit" ><%= ejbcawebbean.getText("USERNAME") %>              
                   <% }else{
                         if(sortby.equals(SORTBY_USERNAME_DEC)){ %>
                          <input type="image" src='<%= ejbcawebbean.getImagefileInfix("uparrow.gif") %>' border="0" name="<%=SORTBY_USERNAME_ACC %>" value="submit" ><%= ejbcawebbean.getText("USERNAME") %>                     
                   <%    }else{ %> 
                          <input type="image" src='<%= ejbcawebbean.getImagefileInfix("noarrow.gif") %>' border="0" name="<%=SORTBY_USERNAME_ACC %>" value="submit" ><%= ejbcawebbean.getText("USERNAME") %>
                   <%    }
                       } %>
    </td>
    <td width="18%"><% if(sortby.equals(SORTBY_CERTIFICATE_ACC)){ %>
                          <input type="image" src='<%= ejbcawebbean.getImagefileInfix("downarrow.gif") %>' border="0" name="<%=SORTBY_CERTIFICATE_DEC %>" value="submit" ><%= ejbcawebbean.getText("CERTIFICATE") %>              
                   <% }else{
                         if(sortby.equals(SORTBY_CERTIFICATE_DEC)){ %>
                          <input type="image" src='<%= ejbcawebbean.getImagefileInfix("uparrow.gif") %>' border="0" name="<%=SORTBY_CERTIFICATE_ACC %>" value="submit" ><%= ejbcawebbean.getText("CERTIFICATE") %>                     
                   <%    }else{ %> 
                          <input type="image" src='<%= ejbcawebbean.getImagefileInfix("noarrow.gif") %>' border="0" name="<%=SORTBY_CERTIFICATE_ACC %>" value="submit" ><%= ejbcawebbean.getText("CERTIFICATE") %>
                   <%    }
                       } %>
    </td>
    <td width="18%"><% if(sortby.equals(SORTBY_COMMENT_ACC)){ %>
                          <input type="image" src='<%= ejbcawebbean.getImagefileInfix("downarrow.gif") %>' border="0" name="<%=SORTBY_COMMENT_DEC %>" value="submit" ><%= ejbcawebbean.getText("COMMENT") %>              
                   <% }else{
                         if(sortby.equals(SORTBY_COMMENT_DEC)){ %>
                          <input type="image" src='<%= ejbcawebbean.getImagefileInfix("uparrow.gif") %>' border="0" name="<%=SORTBY_COMMENT_ACC %>" value="submit" ><%= ejbcawebbean.getText("COMMENT") %>                     
                   <%    }else{ %> 
                          <input type="image" src='<%= ejbcawebbean.getImagefileInfix("noarrow.gif") %>' border="0" name="<%=SORTBY_COMMENT_ACC %>" value="submit" ><%= ejbcawebbean.getText("COMMENT") %>
                   <%    }
                       } %>
    </td>
    <td width="7%">
                   <img src='<%= ejbcawebbean.getImagefileInfix("noarrow.gif") %>' border="0" /><%= ejbcawebbean.getText("VERIFY") %>
    </td>
  </tr>
  <%     if(logentries == null || logentries.length == 0){     %>
  <tr id="LogTextRow0"> 
    <td width="9%"> &nbsp;</td>
    <td width="7%">&nbsp;</td>
    <td width="10%"><%= ejbcawebbean.getText("NOLOGENTRIESFOUND") %></td>
    <td width="10%">&nbsp;</td>
    <td width="5%">&nbsp;</td>
    <td width="9%">&nbsp;</td>
    <td width="7%">&nbsp;</td>
    <td width="18%">&nbsp;</td>
    <td width="18%">&nbsp;</td>
    <td width="7%">&nbsp;</td>
  </tr>
  <% } else{
         for(int i=0; i < logentries.length; i++){%>
  <tr id="LogTextRow<%= i%2 %>"> 
       <input type="hidden" name='<%= HIDDEN_USERNAME + i %>' value='<% if(logentries[i].getValue(LogEntryView.USERNAME) != null) out.print(java.net.URLEncoder.encode(logentries[i].getValue(LogEntryView.USERNAME),"UTF-8")); %>'>
       <input type="hidden" name='<%= HIDDEN_CERTSERNO + i %>' value='<% if(logentries[i].getValue(LogEntryView.CERTIFICATESERNO) != null) out.print(java.net.URLEncoder.encode(logentries[i].getValue(LogEntryView.CERTIFICATESERNO),"UTF-8")); %>'>
       <input type="hidden" name='<%= HIDDEN_ADMINSERNO + i %>' value='<% if(logentries[i].getValue(LogEntryView.ADMINCERTSERNO) != null) out.print(java.net.URLEncoder.encode(logentries[i].getValue(LogEntryView.ADMINCERTSERNO),"UTF-8")); %>'>
    <td width="9%"><%= logentries[i].getValue(LogEntryView.TIME) %></td>
    <td width="7%"><%= ejbcawebbean.getText(ADMINTYPES[Integer.parseInt(logentries[i].getValue(LogEntryView.ADMINTYPE))]) %></td>
    <td width="17%">
       <%  if(Integer.parseInt(logentries[i].getValue(LogEntryView.ADMINTYPE)) == Admin.TYPE_CLIENTCERT_USER) 
             if(logentries[i].getValue(LogEntryView.ADMINDATA).equals(""))
                out.write(ejbcawebbean.getText("CERTIFICATENOTKNOWN"));
             else{%>
        <A  style="cursor:pointer;" onclick='viewadmincert(<%= i %>)'>
        <u><%= logentries[i].getValue(LogEntryView.ADMINDATA) %></u> </A>
       <% } else         
            out.write(logentries[i].getValue(LogEntryView.ADMINDATA));
          %>    
    </td>
    <td width="10%"><%= logentries[i].getValue(LogEntryView.CA) %></td>
    <td width="5%"><%= logentries[i].getValue(LogEntryView.MODULE) %></td>
    <td width="9%"><%= logentries[i].getValue(LogEntryView.EVENT) %></td>
    <td width="7%"><% if(logentries[i].getValue(LogEntryView.USERNAME) == null)
                         out.write(ejbcawebbean.getText("NOENDENTITYINVOLVED"));
                       else{%> 
        <A  style="cursor:pointer;" onclick='viewuser(<%= i %>)'>
        <u><%= logentries[i].getValue(LogEntryView.USERNAME) %></u> </A>
                    <% } %>
    </td>
    <td width="18%"><% if(logentries[i].getValue(LogEntryView.CERTIFICATESERNO) == null)
                         out.write(ejbcawebbean.getText("NOCERTIFICATEINVOLVED"));
                       else
                         if(logentries[i].getValue(LogEntryView.CERTIFICATE).equals(""))
                           out.write(ejbcawebbean.getText("CERTIFICATENOTKNOWN"));
                         else{%> 
        <A  style="cursor:pointer;" onclick='viewcert(<%= i %>)'>
        <u><%= logentries[i].getValue(LogEntryView.CERTIFICATE) %></u> </A>
                    <% } %>
    </td>
    <td width="18%"><%= logentries[i].getValue(LogEntryView.COMMENT) %></td>
  </tr>
 <%      }
       }%>
</table>
  <table width="100%" border="0" cellspacing="1" cellpadding="0">
    <tr>
      <td width="14%">
        <% if(logbean.previousButton(record)){ %>
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

  <% }  
   } %>
   
</body>
</html>
