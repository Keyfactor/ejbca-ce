<%@page contentType="text/html"%>
<%@page errorPage="/errorpage.jsp"  import="se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean,se.anatom.ejbca.ra.GlobalConfiguration, 
                se.anatom.ejbca.log.LogConfiguration, se.anatom.ejbca.webdist.loginterface.LogInterfaceBean, se.anatom.ejbca.log.LogEntry,
                se.anatom.ejbca.webdist.webconfiguration.WebLanguages, java.util.HashMap, java.util.Arrays"%>

<jsp:useBean id="ejbcawebbean" scope="session" class="se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean" />
<jsp:useBean id="logbean" scope="session" class="se.anatom.ejbca.webdist.loginterface.LogInterfaceBean" />


<%! // Declarations 

  static final String ACTION                                 = "action";
  static final String ACTION_SAVE                            = "actionsave";
  static final String ACTION_CANCEL                          = "actioncancel";

  static final String BUTTON_SELECTALLINFO                   = "buttonselectallinfo";
  static final String BUTTON_DESELECTALLINFO                 = "buttondeselectallinfo";
  static final String BUTTON_INVERTINFOSELECTION             = "buttoninvertinfoselection";
  static final String BUTTON_SELECTALLERROR                  = "buttonselectallerror";
  static final String BUTTON_DESELECTALLERROR                = "buttondeselectallerror";
  static final String BUTTON_INVERTERRORSELECTION            = "buttoninverterrorselection";

  static final String BUTTON_SAVE                            = "buttonsave";
  static final String BUTTON_CANCEL                          = "buttoncancel";

  static final String CHECKBOX_USELOGTODB                    = "checkboxuselogtodb";
  static final String CHECKBOX_USEEXTERNALLOG                = "checkboxuseexternallog";

  static final String CHECKBOX_INFOLOGROW                    = "checkboxinfologrow";
  static final String CHECKBOX_ERRORLOGROW                   = "checkboxerrorlogrow";

  static final String HIDDEN_INFOTEXTROW                     = "hiddeninfotextrow";
  static final String HIDDEN_ERRORTEXTROW                    = "hiddenerrortextrow";

  static final String CHECKBOX_VALUE             = "true";
%> 
<% 
  // Initialize environment.
  final String THIS_FILENAME                          =  "logconfiguration.jsp";

  GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, "/log_functionallity/edit_log_configuration"); 
                                            logbean.initialize(request, ejbcawebbean); 

  String forwardurl = "/" + globalconfiguration .getMainFilename(); 

  LogConfiguration logconfiguration = logbean.loadLogConfiguration();


    // Determine action 
  if( request.getParameter(BUTTON_CANCEL) != null){
      
%> 
 <jsp:forward page="<%= forwardurl %>"/>
<%  }

  // Build configuration tables.
    String[] inforows = logbean.getLocalInfoEventNames();
    HashMap texttoid = logbean.getEventNameToIdMap();
    String[] errorrows = logbean.getLocalErronEventNames();


    if( request.getParameter(BUTTON_SAVE) != null){
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
  
         boolean dolog = true;
         for(int i=0; i <  inforows.length; i++){
            value = request.getParameter(CHECKBOX_INFOLOGROW + i);
            if(value == null)
              dolog = false;
            else
              if(value.equals(CHECKBOX_VALUE))
                dolog=true;
              else
                dolog=false;

            value = request.getParameter(HIDDEN_INFOTEXTROW + i);
            logconfiguration.setLogEvent(((Integer) texttoid.get(value)).intValue(), dolog);
          }

          for(int i=0; i <  errorrows.length; i++){
            value = request.getParameter(CHECKBOX_ERRORLOGROW + i);
            if(value == null)
              dolog = false;
            else
              if(value.equals(CHECKBOX_VALUE))
                dolog=true;
              else
                dolog=false;

            value = request.getParameter(HIDDEN_ERRORTEXTROW + i);
            logconfiguration.setLogEvent(((Integer) texttoid.get(value)).intValue(), dolog); 
          }
           
        logbean.saveLogConfiguration(logconfiguration);
%>          
 <jsp:forward page="<%=forwardurl %>"/>
<%   }





  
%>
<html>
<head>
<title><%= globalconfiguration .getEjbcaTitle() %></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>">
  <link rel=STYLESHEET href="<%= ejbcawebbean.getCssFile() %>">
  <script language=javascript src="<%= globalconfiguration .getAdminWebPath() %>ejbcajslib.js"></script>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">
</head>

<body>
<div align="center"> 
  <h2><%= ejbcawebbean.getText("LOGCONFIGURATION") %><br>
  </h2>
</div>
<form name="form" method="post" action="<%= globalconfiguration .getLogPath() + "/logconfiguration/" + THIS_FILENAME %>">
  <table width="100%" border="0" cellspacing="3" cellpadding="3">
    <tr > 
      <td width="50%" valign="top"> 
        <div align="left"> 
          <h3>&nbsp;</h3>
        </div>
      </td>
      <td width="50%" valign="top"> 
        <div align="right"><A  onclick='displayHelpWindow("<%= ejbcawebbean.getHelpfileInfix("log_configuration_help.html") + "#logconfiguration"%>")'>
        <u><%= ejbcawebbean.getText("HELP") %></u> </A></div>
      </td>
    </tr>
   </table>
   <table width="100%" border="0" cellspacing="3" cellpadding="3"> 
    <tr > 
      <td width="40%" valign="top"> 
        <h3><%= ejbcawebbean.getText("USELOGDB") %></h3> 
      
      </td>
      <td width="10%" valign="top"> 
        <input type="checkbox" name="<%=CHECKBOX_USELOGTODB %>" value="<%=CHECKBOX_VALUE %>" 
                                                                                          <% if(logconfiguration.useLogDB())
                                                                                                out.write(" CHECKED "); %>>
      </td>
      <td width="40%" valign="top"> 
        <h3><%= ejbcawebbean.getText("USEEXTERNALLOGDEVICES") %></h3>  
      </td>
      <td width="10%" valign="top"> 
        <input type="checkbox" name="<%=CHECKBOX_USEEXTERNALLOG %>" value="<%=CHECKBOX_VALUE %>" 
                                                                                          <% if(logconfiguration.useExternalLogDevices())
                                                                                                out.write(" CHECKED "); %>>
      </td>
    </tr>
    <tr> 
      <td width="40%" valign="top" id="InfoRow1"> 
        <div align="center"><h3><%= ejbcawebbean.getText("INFOEVENTS") %></h3></div>
      </td>
      <td width="10%" valign="top" id="InfoRow1"> 
          &nbsp;
      </td>
      <td width="40%" valign="top" id="ErrorRow1"> 
        <div align="center"><h3><%= ejbcawebbean.getText("ERROREVENTS") %></h3></div>
      </td>
      <td width="10%" valign="top" id="ErrorRow1"> 
          &nbsp;
      </td>
    </tr>
   <%   int totalrows = inforows.length;
        if(errorrows.length > totalrows)
          totalrows = errorrows.length;
        for(int i= 0; i < totalrows; i++){ %>
    <tr> 
      <td width="40%" valign="top" id="InfoRow<%= i%2 %>"> 
         <% if(inforows.length > i){ %>
         &nbsp; &nbsp;<%= inforows[i] %>
         <% } else{ %>
           &nbsp;
         <% } %>
      </td>  
      <td width="10%" valign="top" id="InfoRow<%= i%2 %>"> 
         <% if(inforows.length > i){ %>
        <input type="checkbox" name="<%=CHECKBOX_INFOLOGROW + i%>" value="<%=CHECKBOX_VALUE %>" 
                                                                                          <% if(logconfiguration.getLogEvent(((Integer) texttoid.get(inforows[i])).intValue()).booleanValue())
                                                                                                out.write(" CHECKED "); %>> 
        <input type="hidden" name='<%=HIDDEN_INFOTEXTROW + i %>' value='<%= inforows[i] %>'>
         <% } else{ %>
            &nbsp;
         <% } %>
      </td>
      <td width="40%" valign="top" id="ErrorRow<%= i%2 %>"> 
          <% if(errorrows.length > i){ %>
         &nbsp; &nbsp;<%= errorrows[i] %>
         <% } else{ %>
            &nbsp;
         <% } %>
      </td>
      <td width="10%" valign="top" id="ErrorRow<%= i%2 %>"> 
          <% if(errorrows.length > i){ %>
        <input type="checkbox" name="<%=CHECKBOX_ERRORLOGROW + i%>" value="<%=CHECKBOX_VALUE %>" 
                                                                                          <% if(logconfiguration.getLogEvent(((Integer) texttoid.get(errorrows[i])).intValue()).booleanValue())
                                                                                                out.write(" CHECKED "); %>> 
        <input type="hidden" name='<%=HIDDEN_ERRORTEXTROW + i %>' value='<%= errorrows[i] %>'>
         <% } else{ %>
            &nbsp;
         <% } %>
      </td>
    </tr>
     <% } %>
  </table>
  <table width="100%" border="0" cellspacing="3" cellpadding="3">
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
      <td width="50%" valign="top">&nbsp;</td>
      <td width="50%" valign="top"> 
        <input type="submit" name="<%= BUTTON_SAVE %>" value="<%= ejbcawebbean.getText("SAVE") %>">
        <input type="submit" name="<%= BUTTON_CANCEL %>" value="<%= ejbcawebbean.getText("CANCEL") %>">
      </td>
    </tr>
  </table>
 </form>
<% // Include Footer 
   String footurl = globalconfiguration .getFootBanner(); %>
   
  <jsp:include page="<%= footurl %>" />
 
</body>
</html>