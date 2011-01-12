<%@ page pageEncoding="ISO-8859-1"%>
<% response.setContentType("text/html; charset="+org.ejbca.config.WebConfiguration.getWebContentEncoding()); %>
<%@page errorPage="/errorpage.jsp"  import=" org.ejbca.core.model.authorization.AuthorizationDeniedException,org.ejbca.core.model.ra.raadmin.GlobalConfiguration, 
    org.ejbca.ui.web.RequestHelper,org.ejbca.core.model.log.LogConfiguration,org.ejbca.util.HTMLTools,
                java.util.HashMap, java.util.Map, java.util.Iterator, java.util.Collection"%>

<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />
<jsp:useBean id="logbean" scope="session" class="org.ejbca.ui.web.admin.loginterface.LogInterfaceBean" />


<%! // Declarations 

  static final String ACTION                                 = "action";
  static final String ACTION_SAVE                            = "actionsave";
  static final String ACTION_CANCEL                          = "actioncancel";

  static final String SELECT_CA                              = "selectca";
  static final String SELECT_CLONE                           = "selectclone"; 

  static final String BUTTON_SELECTALLINFO                   = "buttonselectallinfo";
  static final String BUTTON_DESELECTALLINFO                 = "buttondeselectallinfo";
  static final String BUTTON_INVERTINFOSELECTION             = "buttoninvertinfoselection";
  static final String BUTTON_SELECTALLERROR                  = "buttonselectallerror";
  static final String BUTTON_DESELECTALLERROR                = "buttondeselectallerror";
  static final String BUTTON_INVERTERRORSELECTION            = "buttoninverterrorselection";

  static final String BUTTON_CHANGECA                        = "buttonchangeca";
  static final String BUTTON_CLONE                           = "buttonclone";
  static final String BUTTON_SAVE                            = "buttonsave";
  static final String BUTTON_CANCEL                          = "buttoncancel";

  static final String CHECKBOX_USELOGTODB                    = "checkboxuselogtodb";
  static final String CHECKBOX_USEEXTERNALLOG                = "checkboxuseexternallog";

  static final String CHECKBOX_INFOLOGROW                    = "checkboxinfologrow";
  static final String CHECKBOX_ERRORLOGROW                   = "checkboxerrorlogrow";

  static final String HIDDEN_INFOTEXTROW                     = "hiddeninfotextrow";
  static final String HIDDEN_ERRORTEXTROW                    = "hiddenerrortextrow";
  static final String HIDDEN_CAID                            = "hiddencaid";

  static final String CHECKBOX_VALUE             = "true";
%> 
<% 
  // Initialize environment.
  final String THIS_FILENAME                          =  "logconfiguration.jsp";

  GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, "/log_functionality/edit_log_configuration");                                              
                                            logbean.initialize(request,ejbcawebbean);

  String forwardurl = "/" + globalconfiguration .getMainFilename();
 
  Map caidtonamemap =  ejbcawebbean.getInformationMemory().getCAIdToNameMap();
  Collection authorizedcaids = ejbcawebbean.getAuthorizedCAIds();

  boolean nocachosen = true;
  int caid = -1;
  boolean cloneca = false;
  int clonecaid = -1;
  boolean logconfigurationsaved = false;

  RequestHelper.setDefaultCharacterEncoding(request);

  if(request.getParameter(HIDDEN_CAID) != null){
    caid = Integer.parseInt(request.getParameter(HIDDEN_CAID));
    nocachosen=false;
  }

  if( request.getParameter(BUTTON_CHANGECA) != null && request.getParameter(SELECT_CA) != null){
    caid = Integer.parseInt(request.getParameter(SELECT_CA));
    nocachosen=false;  
  }

  if( request.getParameter(BUTTON_CLONE) != null && request.getParameter(SELECT_CLONE) != null){
    clonecaid = Integer.parseInt(request.getParameter(SELECT_CLONE));
    cloneca = true;
  }

  // Check authorization.
  Iterator iter = authorizedcaids.iterator();
  boolean authorized = false;
  int tmp = caid;
  if(cloneca)
    tmp = clonecaid; 
  while(iter.hasNext()){
    if(((Integer) iter.next()).intValue() == tmp) authorized = true;
  }

  if(!authorized && !nocachosen)
    throw new AuthorizationDeniedException("ERROR: Not authorized to edit specified log configuration");

  LogConfiguration logconfiguration = null;
  if(cloneca)
    logconfiguration = logbean.loadLogConfiguration(clonecaid);
  else
    logconfiguration = logbean.loadLogConfiguration(caid);

    // Determine action 
  if( request.getParameter(BUTTON_CANCEL) != null){
      
%> 
 <jsp:forward page="<%= forwardurl %>"/>
<%  }

  // Build configuration tables.
    String[] inforows = logbean.getLocalInfoEventNames();
    HashMap texthashtoid = logbean.getEventNameHashToIdMap();
    String[] errorrows = logbean.getLocalErrorEventNames();



    if( request.getParameter(BUTTON_SAVE) != null){
/* Obsolete. This is configured in log.properties
        // Save log configuration.
        String value = request.getParameter(CHECKBOX_USELOGTODB);   
        if(value == null)
          logconfiguration.setUseLogDB(false); 
        else
          if(value.equals(CHECKBOX_VALUE))
            logconfiguration.setUseLogDB(true); 
          else
            logconfiguration.setUseLogDB(false); 
        value = request.getParameter(CHECKBOX_USEEXTERNALLOG);   
        if(value == null)
          logconfiguration.setUseExternalLogDevices(false); 
        else
          if(value.equals(CHECKBOX_VALUE))
            logconfiguration.setUseExternalLogDevices(true); 
          else
            logconfiguration.setUseExternalLogDevices(false); 
*/
  
         boolean dolog = true;
         for(int i=0; i <  inforows.length; i++){
            String value = request.getParameter(CHECKBOX_INFOLOGROW + i);
            if(value == null)
              dolog = false;
            else
              if(value.equals(CHECKBOX_VALUE))
                dolog=true;
              else
                dolog=false;

            value = request.getParameter(HIDDEN_INFOTEXTROW + i);
            logconfiguration.setLogEvent(((Integer)texthashtoid.get(value)).intValue(), dolog);
          }

          for(int i=0; i <  errorrows.length; i++){
            String value = request.getParameter(CHECKBOX_ERRORLOGROW + i);
            if(value == null)
              dolog = false;
            else
              if(value.equals(CHECKBOX_VALUE))
                dolog=true;
              else
                dolog=false;

            value = request.getParameter(HIDDEN_ERRORTEXTROW + i);
            logconfiguration.setLogEvent(((Integer)texthashtoid.get(value)).intValue(), dolog); 
          }
           
        logbean.saveLogConfiguration(caid, logconfiguration);
        logconfigurationsaved = true;
}





  
%>
<html>
<head>
<title><%= globalconfiguration .getEjbcaTitle() %></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>" />
  <link rel="stylesheet" type="text/css" href="<%= ejbcawebbean.getCssFile() %>" />
  <script type="text/javascript" src="<%= globalconfiguration .getAdminWebPath() %>ejbcajslib.js"></script>
</head>

<body>

<h1><%= ejbcawebbean.getText("LOGCONFIGURATION") %></h1>

<form name="form" method="post" action="<%= globalconfiguration .getLogPath() + "/logconfiguration/" + THIS_FILENAME %>">
<div align="center"> 
   <% if(logconfigurationsaved) out.write("<h3>" + ejbcawebbean.getText("LOGCONFIGURATIONSAVED") + "</h3>"); %>
   <h3><%= ejbcawebbean.getText("CONFIGURECA") %> 
   <select name="<%=SELECT_CA %>" >
      <% 
         iter = authorizedcaids.iterator();
         while(iter.hasNext()){ 
           int authcaid = ((Integer) iter.next()).intValue(); %>
         <option  value='<%= authcaid %>' <% 
                                        if(authcaid ==caid)
                                           out.write(" selected ");%>>
            <%= caidtonamemap.get(Integer.valueOf(authcaid)) %>
        </option>
        <% } %>
   </select>  
   <input type="submit" name="<%= BUTTON_CHANGECA %>" value="<%= ejbcawebbean.getText("SELECT") %>"></h3>
</div>
  <% if(!nocachosen){  %>
   <input type="hidden" name='<%=HIDDEN_CAID%>' value='<%= caid %>'>
  <table width="100%" border="0" cellspacing="3" cellpadding="3">
    <tr > 
      <td width="50%" valign="top"> 
        &nbsp; 
      </td>
      <td width="50%" valign="top"> 
   <!--     <div align="right"><A  onclick='displayHelpWindow("<%= ejbcawebbean.getHelpfileInfix("log_configuration_help.html") + "#logconfiguration"%>")'>
        <u><%= ejbcawebbean.getText("HELP") %></u> </A></div> -->
      </td>
    </tr>
   </table>
   <table id="logconfiguration" width="100%" border="0" cellspacing="3" cellpadding="3"> 
    <tr > 
      <td colspan="4" width="100%" valign="top" halign="left"> 
      	<span><%= ejbcawebbean.getText("LOGCONFIGURATIONINFO") %></span>
      </td>
<!--
      <td width="1%" class="checkbox" valign="top"> 
        <input type="checkbox" name="<%=CHECKBOX_USELOGTODB %>" value="<%=CHECKBOX_VALUE %>" 
                                                                                          <% if(logconfiguration.useLogDB())
                                                                                                out.write(" CHECKED "); %>>
      </td>
      <td width="49%" class="field" valign="top"> 
        <h3><%= ejbcawebbean.getText("USELOGDB") %></h3> 
      
      </td>
      <td width="1%" class="checkbox" valign="top"> 
        <input type="checkbox" name="<%=CHECKBOX_USEEXTERNALLOG %>" value="<%=CHECKBOX_VALUE %>" 
                                                                                          <% if(logconfiguration.useExternalLogDevices())
                                                                                                out.write(" CHECKED "); %>>
      </td>
      <td width="49%" class="field" valign="top"> 
        <h3><%= ejbcawebbean.getText("USEEXTERNALLOGDEVICES") %></h3>  
      </td>
-->
    </tr>
    <tr> 
      <td width="1%" class="checkbox" valign="top" id="InfoRow1"> 
          &nbsp;
      </td>
      <td width="49%" class="field" valign="top" id="InfoRow1"> 
          <h3><%= ejbcawebbean.getText("INFOEVENTS") %></h3>
      </td>
      <td width="1%" class="checkbox" valign="top" id="ErrorRow1"> 
          &nbsp;
      </td>
      <td width="49%" class="field" valign="top" id="ErrorRow1"> 
          <h3><%= ejbcawebbean.getText("ERROREVENTS") %></h3>
      </td>
    </tr>
   <%   int totalrows = inforows.length;
        if(errorrows.length > totalrows)
          totalrows = errorrows.length;
        for(int i= 0; i < totalrows; i++){ %>
    <tr> 
      <td width="1%" class="checkbox" valign="top" id="InfoRow<%= i%2 %>"> 
         <% if(inforows.length > i){ %>
        <input type="checkbox" name="<%=CHECKBOX_INFOLOGROW + i%>" value="<%=CHECKBOX_VALUE %>" 
        <% 
  	       // We must make this independent of language encoding, utf, html escaped etc
           Integer hashcode =  Integer.valueOf((inforows[i].hashCode()));
           String val = hashcode.toString();
           if(logconfiguration.getLogEvent(((Integer) texthashtoid.get(val)).intValue()).booleanValue())
               out.write(" CHECKED "); %>> 
        <input type="hidden" name='<%=HIDDEN_INFOTEXTROW + i %>' value="<%= val %>">
         <% } else{ %>
            &nbsp;
         <% } %>
      </td>
      <td width="49%" class="field" valign="top" id="InfoRow<%= i%2 %>"> 
         <% if(inforows.length > i){ %>
            <%= inforows[i] %>
         <% } else{ %>
            &nbsp;
         <% } %>
      </td>  
      <td width="1%" class="checkbox" valign="top" id="ErrorRow<%= i%2 %>"> 
          <% if(errorrows.length > i){ %>
        <input type="checkbox" name="<%=CHECKBOX_ERRORLOGROW + i%>" value="<%=CHECKBOX_VALUE %>" 
        <% 
     	   // We must make this independent of language encoding, utf, html escaped etc
           Integer hashcode =  Integer.valueOf((errorrows[i].hashCode()));
           String val = hashcode.toString();
           if(logconfiguration.getLogEvent(((Integer) texthashtoid.get(val)).intValue()).booleanValue())
               out.write(" CHECKED "); %>> 
        <input type="hidden" name='<%=HIDDEN_ERRORTEXTROW + i %>' value="<%= val %>">
         <% } else{ %>
            &nbsp;
         <% } %>
      </td>
      <td width="49%" class="field" valign="top" id="ErrorRow<%= i%2 %>"> 
         <% if(errorrows.length > i){ %>
            <%= errorrows[i] %>
         <% } else{ %>
            &nbsp;
         <% } %>
      </td>
    </tr>
     <% } %>
  </table>
  <table id="logconfigbuttons" width="100%" border="0" cellspacing="3" cellpadding="3">
    <tr> 
      <td width="50%" valign="top">
          <input type="button" name="<%=BUTTON_SELECTALLINFO %>" value="<%= ejbcawebbean.getText("SELECTALLINFO") %>"
                onClick='checkAll("document.form.<%= CHECKBOX_INFOLOGROW %>", <%= inforows.length %>)'>
          <input type="button" name="<%=BUTTON_DESELECTALLINFO %>" value="<%= ejbcawebbean.getText("UNSELECTALLINFO") %>"
                onClick='uncheckAll("document.form.<%= CHECKBOX_INFOLOGROW %>", <%= inforows.length %>)'>
          <input type="button" name="<%=BUTTON_INVERTINFOSELECTION %>" value="<%= ejbcawebbean.getText("INVERTINFOSELECTION") %>"           
                 onClick='switchAll("document.form.<%= CHECKBOX_INFOLOGROW %>", <%= inforows.length %>)'>
      </td>
      <td width="50%" valign="top"> 
          <input type="button" name="<%=BUTTON_SELECTALLERROR %>" value="<%= ejbcawebbean.getText("SELECTALLERROR") %>"
                onClick='checkAll("document.form.<%= CHECKBOX_ERRORLOGROW %>", <%= errorrows.length %>)'>
          <input type="button" name="<%=BUTTON_DESELECTALLERROR %>" value="<%= ejbcawebbean.getText("UNSELECTALLERROR") %>"
                onClick='uncheckAll("document.form.<%= CHECKBOX_ERRORLOGROW %>", <%= errorrows.length %>)'>
          <input type="button" name="<%=BUTTON_INVERTERRORSELECTION %>" value="<%= ejbcawebbean.getText("INVERTERRORSELECTION") %>"           
                 onClick='switchAll("document.form.<%= CHECKBOX_ERRORLOGROW %>", <%= errorrows.length %>)'>
      </td>

    </tr>

    <tr> 
      <td width="50%" valign="top"><%= ejbcawebbean.getText("USE") %>
   <select name="<%=SELECT_CLONE %>" >
      <% 
         iter = authorizedcaids.iterator();
         while(iter.hasNext()){ 
           int authcaid = ((Integer) iter.next()).intValue(); 
           if(caid != authcaid){ %>
         <option  value='<%= authcaid %>' >
            <%= caidtonamemap.get(Integer.valueOf(authcaid)) %>
        </option>
        <% }
         }%>
   </select>  
      <input type="submit" name="<%= BUTTON_CLONE %>" value="<%= ejbcawebbean.getText("ASTEMPLATE") %>">
      </td>
      <td width="50%" valign="top"> 
        <input type="submit" name="<%= BUTTON_SAVE %>" value="<%= ejbcawebbean.getText("SAVE") %>">
        <input type="submit" name="<%= BUTTON_CANCEL %>" value="<%= ejbcawebbean.getText("CANCEL") %>">
      </td>
    </tr>
  </table>
 <% } %>
 </form>
<% // Include Footer 
   String footurl = globalconfiguration .getFootBanner(); %>
   
  <jsp:include page="<%= footurl %>" />
 
</body>
</html>