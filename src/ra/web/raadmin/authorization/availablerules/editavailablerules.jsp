<%@page contentType="text/html"%>
<%@page errorPage="/errorpage.jsp" import="se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean,se.anatom.ejbca.webdist.webconfiguration.GlobalConfiguration
               ,se.anatom.ejbca.webdist.webconfiguration.AuthorizationDataHandler, java.util.Vector"%>

<jsp:useBean id="ejbcawebbean" scope="session" class="se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean" />
<jsp:setProperty name="ejbcawebbean" property="*" /> 

<%! // Declarations  
  static final String ACTION                      = "action";
  static final String ACTION_EDIT_AVAILABLERULES  = "actioneditavailablerules";  

  static final String BUTTON_DELETE_AVAILABLERULE  = "buttondeleteavailablerule"; 
  static final String BUTTON_ADD_AVAILABLERULE     = "buttonaddavailablerule"; 
  static final String BUTTON_NEXT_AVAILABLERULE     = "buttonnextavailablerule";
  static final String BUTTON_PREVIOUS_AVAILABLERULE = "buttonpreviousavailablerule";

  static final String TEXTFIELD_RULENAME      = "textfieldusergroupname";
  static final String HIDDEN_RULENAME         = "hiddenusergroupname";


  static final String CHECKBOX_DELETEROW       = "checkboxdeleterow";
  static final String CHECKBOX_VALUE           = "true";
  static final String HIDDEN_DELETEROW         = "hiddendeleterow";
  static final String HIDDEN_RECORDNUMBER      = "hiddenrecordnumber"; 

%>
<% 


  // Initialize environment
  GlobalConfiguration globalconfiguration =ejbcawebbean.initialize(request); 
  String THIS_FILENAME            =  globalconfiguration .getAuthorizationPath()  + "/availablerules/editavailablerules.jsp";
  AuthorizationDataHandler adh    = ejbcawebbean.getAuthorizationDataHandler();

  if(request.getParameter(ACTION) != null){
    if( request.getParameter(BUTTON_ADD_AVAILABLERULE) != null ){
         // Add available rule to selected fields or alone if none is selected.
       java.util.Enumeration parameters = request.getParameterNames();
       java.util.Vector indexes = new  java.util.Vector();
       int index;
       while(parameters.hasMoreElements()){
         String parameter = (String) parameters.nextElement();
         if(parameter.startsWith(CHECKBOX_DELETEROW) && request.getParameter(parameter).equals(CHECKBOX_VALUE)) {
           index = java.lang.Integer.parseInt(parameter.substring(CHECKBOX_DELETEROW.length())); //Without []
           indexes.addElement(new Integer(index));
         }
       }
     
       // Get information from textfield.
       String newrule = request.getParameter(TEXTFIELD_RULENAME);
       if(newrule != null){
         if(newrule.startsWith("/"))
           newrule=newrule.substring(1);
         if(newrule.endsWith("/"))
           newrule=newrule.substring(0,newrule.length()-1);
         if(!newrule.trim().equals("")){
 
           if(indexes.size()==0){
             // Add a new basic rule
             adh.addAvailableAccessRule("/" + newrule);
           }
           else{
             Vector newrules = new Vector();
             for(int i = 0; i < indexes.size(); i++){
               index = ((java.lang.Integer) indexes.elementAt(i)).intValue();
               String selecteddir = request.getParameter(HIDDEN_DELETEROW+index);
               if(selecteddir!=null){
                 newrules.addElement(selecteddir + "/" + newrule);
               }
           }
           adh.addAvailableAccessRules(newrules);
         }
       }
      }
    }
    if( request.getParameter(BUTTON_DELETE_AVAILABLERULE) != null ){
         // Delete selected available access rules
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
         Vector removerules = new Vector();
         for(int i = 0; i < indexes.size(); i++){
           index = ((java.lang.Integer) indexes.elementAt(i)).intValue();
           String selecteddir = request.getParameter(HIDDEN_DELETEROW+index);  
           if(selecteddir!=null){
             removerules.addElement(selecteddir);
           }
         }
         adh.removeAvailableAccessRules(removerules); 
      }
    }
  } 

  int recordnumber = ejbcawebbean.getEntriesPerPage();
  int oldrecordnumber = 0;
  if (request.getParameter(HIDDEN_RECORDNUMBER) != null ){
    recordnumber =  Integer.parseInt(request.getParameter(HIDDEN_RECORDNUMBER)); 
    oldrecordnumber = recordnumber - ejbcawebbean.getEntriesPerPage();
    if(oldrecordnumber < 0) oldrecordnumber=0;
  }   

  if( request.getParameter(BUTTON_PREVIOUS_AVAILABLERULE) != null ){
    recordnumber = Integer.parseInt(request.getParameter(HIDDEN_RECORDNUMBER));
    oldrecordnumber = recordnumber;
    recordnumber -= ejbcawebbean.getEntriesPerPage();
    oldrecordnumber -= 2 * ejbcawebbean.getEntriesPerPage();  
    if(recordnumber < ejbcawebbean.getEntriesPerPage()) recordnumber=ejbcawebbean.getEntriesPerPage();
    if(oldrecordnumber < 0 ) oldrecordnumber = 0;
  }
  if( request.getParameter(BUTTON_NEXT_AVAILABLERULE) != null ){
    recordnumber = Integer.parseInt(request.getParameter(HIDDEN_RECORDNUMBER));
    oldrecordnumber = recordnumber;
    recordnumber += ejbcawebbean.getEntriesPerPage();
  }




   // Generate Html file.
   String[] dummy = {};
   String[] availableaccessrules = (String[]) adh.getAvailableAccessRules().toArray(dummy);
   if(recordnumber >= availableaccessrules.length){
     recordnumber = availableaccessrules.length;
     oldrecordnumber = recordnumber - ejbcawebbean.getEntriesPerPage();
     if(oldrecordnumber < 0) oldrecordnumber =0;
   }
   int numdeletecheckboxes=0;
%>
<html>
<head>
  <title><%= globalconfiguration .getEjbcaTitle() %></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>">
  <link rel=STYLESHEET href="<%= ejbcawebbean.getCssFile() %>">
  <script language=javascript src="<%= globalconfiguration .getRaAdminPath() %>ejbcajslib.js"></script>
</head>
<body>
<div align="center">
  <p><H1><%= ejbcawebbean.getText("AVAILABLEACCESSRULES") %></H1></p>
  <div align="right">
    <A  onclick='displayHelpWindow("<%= ejbcawebbean.getHelpfileInfix("authorization_help.html") + "#availableaccessrules" %>")'>
    <u><%= ejbcawebbean.getText("INFORMATIONANDHELP") %></u> </A>
  </div>
  <form name="availableaccessrules" method="post" action="<%=THIS_FILENAME %>">
    <input type="hidden" name='<%= ACTION %>' value='<%=ACTION_EDIT_AVAILABLERULES %>'>
    <input type="hidden" name='<%= HIDDEN_RECORDNUMBER %>' value='<%= String.valueOf(recordnumber) %>'>
    <table width="100%" border="0" cellspacing="0" cellpadding="0">
      <tr> 
        <td width="17%">&nbsp;</td>
        <td width="65%"><H2><%= ejbcawebbean.getText("CURRENTLYAVAILABLE") %></H2></td>
        <td width="18%">&nbsp;</td>
      </tr>
      <tr> 
        <td width="17%">&nbsp;</td>
        <td width="65%"><H3><%= ejbcawebbean.getText("ROW") %>&nbsp;<%=oldrecordnumber %>&nbsp;
                         <%= ejbcawebbean.getText("TO") %>&nbsp; <%=recordnumber %>&nbsp; 
                         <%= ejbcawebbean.getText("OF") %>&nbsp;<%= availableaccessrules.length %></H3>
        </td>
        <td width="18%">&nbsp;</td>
     </tr>
      <tr id="Header"> 
        <td width="17%"><H3><%= ejbcawebbean.getText("DELETE") %></H3></td>
        <td width="65%"><H3><%= ejbcawebbean.getText("DIRECTORY") %></H3></td>
        <td width="18%"><H3></H3></td>
      </tr>
      <% if(availableaccessrules == null || availableaccessrules.length == 0){ %>
      <tr id="Row0"> 
        <td width="17%">&nbsp;</td>
        <td width="65%"><%= ejbcawebbean.getText("NOAVAILABLEACCESSRULESD") %></td>  
        <td width="18%">&nbsp;</td>  
      </tr>
      <%}
        else{
          numdeletecheckboxes= recordnumber - oldrecordnumber; 
          int j = 0;
          for(int i =  oldrecordnumber ; i < recordnumber; i++){ %>
      <tr id="Row<%= i%2 %>"> <!-- User entries in css to make lines in table --> 
        <td width="17%">
          <input type="checkbox" name="<%=CHECKBOX_DELETEROW  + j  %>" value="<%= CHECKBOX_VALUE %>">
          <input type="hidden" name='<%= HIDDEN_DELETEROW + j %>' value='<%= availableaccessrules[i] %>'>
        </td>
        <td width="65%"><%= availableaccessrules[i] %></td>
        <td width="18%">&nbsp;</td>
      </tr>
      <%   j++;
         }
      }  %>
    </table>

  <table width="100%" border="0" cellspacing="0" cellpadding="0">
    <tr>
       <td width="10%" ></td>  
       <td width="80%" >
           <% if(recordnumber >  ejbcawebbean.getEntriesPerPage()){ %>
             <input type="submit" name="<%= BUTTON_PREVIOUS_AVAILABLERULE %>"
                value="<%= ejbcawebbean.getText("PREVIOUS") + " " + ejbcawebbean.getEntriesPerPage() %>">
           <% } %>&nbsp;&nbsp;&nbsp;&nbsp;
           <input type="button" value="<%= ejbcawebbean.getText("SELECTALL") %>" 
           onClick='checkAll("document.availableaccessrules.<%= CHECKBOX_DELETEROW %>", <%= numdeletecheckboxes %>)'>
           <input type="button" value="<%= ejbcawebbean.getText("UNSELECTALL") %>" 
           onClick='uncheckAll("document.availableaccessrules.<%= CHECKBOX_DELETEROW %>", <%= numdeletecheckboxes %>)'>
           <input type="button" value="<%=ejbcawebbean.getText("INVERTSELECTION") %>" 
           onClick='switchAll("document.availableaccessrules.<%= CHECKBOX_DELETEROW %>", <%= numdeletecheckboxes %>)'>
           &nbsp;&nbsp;&nbsp;&nbsp;
           <% if(recordnumber < availableaccessrules.length ){ %>
             <input type="submit" name="<%= BUTTON_NEXT_AVAILABLERULE %>"
                value="<%= ejbcawebbean.getText("NEXT") + " " + ejbcawebbean.getEntriesPerPage() %>">
           <% } %>
        </td>
        <td width="10%" ></td>  
    </tr>
    <tr> 
        <td width="40%" valign="left"><H3><%= ejbcawebbean.getText("DELETESELECTED") %>
           &nbsp;<input type="submit" onClick="return confirm('<%= ejbcawebbean.getText("AREYOUSURE") %>');" name="<%=BUTTON_DELETE_AVAILABLERULE %>" value="<%= ejbcawebbean.getText("DELETE") %>">
         </H3></td>
        <td width="18%" valign="middle">&nbsp; </td>
    </tr>
  </table>
  <table width="100%" border="0" cellspacing="0" cellpadding="0">
     <tr> 
        <td width="66%" valign="middle"><input type="text" name="<%=TEXTFIELD_RULENAME%>" size="40" maxlength="255">   
          <input type="submit" name="<%=BUTTON_ADD_AVAILABLERULE %>" onClick='return checkfieldforlegalchars("document.availableaccessrules.<%=TEXTFIELD_RULENAME%>","<%= ejbcawebbean.getText("ONLYCHARACTERS") %>")' value="<%= ejbcawebbean.getText("ADD") %>">
        </td>  <td width="16%">&nbsp;</td>
        <td width="18%" valign="middle">&nbsp; </td>
    </tr>
  </table>
  </form>
<%

   // Include Footer 
   String footurl =   globalconfiguration.getFootBanner(); %>
   
  <jsp:include page="<%= footurl %>" />

</body>
</html>
