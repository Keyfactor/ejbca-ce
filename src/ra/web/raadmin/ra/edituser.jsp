<html>
<%@page contentType="text/html"%>
<%@page errorPage="/errorpage.jsp"  import="se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean,se.anatom.ejbca.ra.GlobalConfiguration, 
                 se.anatom.ejbca.webdist.rainterface.UserView, se.anatom.ejbca.webdist.rainterface.RAInterfaceBean, 
                 se.anatom.ejbca.ra.raadmin.Profile,  se.anatom.ejbca.ra.UserDataRemote,
                 javax.ejb.CreateException, java.rmi.RemoteException" %>
<jsp:useBean id="ejbcawebbean" scope="session" class="se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean" />
<jsp:setProperty name="ejbcawebbean" property="*" /> 
<jsp:useBean id="rabean" scope="session" class="se.anatom.ejbca.webdist.rainterface.RAInterfaceBean" />
<jsp:setProperty name="rabean" property="*" /> 
<%! // Declarations

  static final String ACTION                   = "action";
  static final String ACTION_EDITUSER          = "edituser";
 
  static final String USER_PARAMETER           = "userparameter";

  static final String BUTTON_SAVE              = "buttonsave"; 
  static final String BUTTON_SAVEANDCLOSE      = "buttonsaveandclose";
  static final String BUTTON_CLOSE             = "buttonclose"; 

  static final String TEXTFIELD_PASSWORD          = "textfieldpassword";
  static final String TEXTFIELD_CONFIRMPASSWORD   = "textfieldconfirmpassword";
  static final String TEXTFIELD_COMMONNAME        = "textfieldcommonname";
  static final String TEXTFIELD_ORGANIZATIONUNIT  = "textfieldorganizationunit";
  static final String TEXTFIELD_ORGANIZATION      = "textfieldorganization";
  static final String TEXTFIELD_LOCALE            = "textfieldlocale";
  static final String TEXTFIELD_STATE             = "textfieldstate";
  static final String TEXTFIELD_COUNTRY           = "textfieldcountry";
  static final String TEXTFIELD_EMAIL             = "textfieldemail";

  static final String CHECKBOX_CLEARTEXTPASSWORD          = "checkboxcleartextpassword";
  static final String CHECKBOX_TYPEENDUSER                = "checkboxtypeenduser";
  static final String CHECKBOX_TYPERA                     = "checkboxtypera";
  static final String CHECKBOX_TYPERAADMIN                = "checkboxtyperaadmin";
  static final String CHECKBOX_TYPECA                     = "checkboxtypeca";
  static final String CHECKBOX_TYPECAADMIN                = "checkboxtypecaadmin";
  static final String CHECKBOX_TYPEROOTCA                 = "checkboxtyperootca";

  static final String CHECKBOX_VALUE             = "true";

%><%
  // Initialize environment.
  GlobalConfiguration  globalconfiguration = ejbcawebbean.initialize(request); 
  String THIS_FILENAME            =  globalconfiguration.getRaPath()  + "/edituser.jsp";
  boolean nouserparameter          = true;

  String[] userdata = null;
  String   username = null;

  if( request.getParameter(USER_PARAMETER) != null ){
    username = request.getParameter(USER_PARAMETER);
    userdata = rabean.findUser(username);
    nouserparameter = false;
  }
  

  if( request.getParameter(ACTION) != null){
    if( request.getParameter(ACTION).equals(ACTION_EDITUSER)){
      if( request.getParameter(BUTTON_SAVE) != null ||  request.getParameter(BUTTON_SAVEANDCLOSE) != null){
         String[] newuserdata = new String[UserView.NUMBEROF_USERFIELDS];

         String value = username;
         if(value !=null){
           value=value.trim(); 
           newuserdata[UserView.USERNAME] = value;
         }
         value = request.getParameter(TEXTFIELD_PASSWORD);
         if(value !=null){
           value=value.trim(); 
             if(!value.equals("")){
                newuserdata[UserView.PASSWORD] = value;           
             }
             else{
                newuserdata[UserView.PASSWORD] = null;
             }
         }
         value = request.getParameter(CHECKBOX_CLEARTEXTPASSWORD);
         if(value !=null){
           if(value.equals(CHECKBOX_VALUE)){
             newuserdata[UserView.CLEARTEXTPASSWORD] = UserView.TRUE;         
           }
           else{
               newuserdata[UserView.CLEARTEXTPASSWORD] = UserView.FALSE;  
             }
           }
           value = request.getParameter(TEXTFIELD_COMMONNAME);
           if(value !=null){
             value=value.trim(); 
             newuserdata[UserView.COMMONNAME] = value;
           }
           value = request.getParameter(TEXTFIELD_ORGANIZATIONUNIT);
           if(value !=null){
             value=value.trim(); 
             newuserdata[UserView.ORGANIZATIONUNIT] = value;
           }
           value = request.getParameter(TEXTFIELD_ORGANIZATION);
           if(value !=null){
             value=value.trim(); 
             newuserdata[UserView.ORGANIZATION] = value;
           }
           value = request.getParameter(TEXTFIELD_LOCALE);
           if(value !=null){
             value=value.trim(); 
             newuserdata[UserView.LOCALE] = value;
           }
           value = request.getParameter(TEXTFIELD_STATE);
           if(value !=null){
             value=value.trim(); 
             newuserdata[UserView.STATE] = value;
           }
           value = request.getParameter(TEXTFIELD_COUNTRY);
           if(value !=null){
             value=value.trim(); 
             newuserdata[UserView.COUNTRY] = value;
           }
           value = request.getParameter(TEXTFIELD_EMAIL);
           if(value !=null){
             value=value.trim(); 
             newuserdata[UserView.EMAIL] = value;
           }
           value = request.getParameter(CHECKBOX_TYPEENDUSER);
           if(value !=null){
             if(value.equals(CHECKBOX_VALUE)){
               newuserdata[UserView.TYPE_ENDUSER] = UserView.TRUE;   
             }
             else{
               newuserdata[UserView.TYPE_ENDUSER] = UserView.FALSE;   
             }
           }
           value = request.getParameter(CHECKBOX_TYPERA);
           if(value !=null){
             if(value.equals(CHECKBOX_VALUE)){
               newuserdata[UserView.TYPE_RA] = UserView.TRUE;                                  
             }
             else{
               newuserdata[UserView.TYPE_RA] = UserView.FALSE;                  
             }
           }  
           value = request.getParameter(CHECKBOX_TYPERAADMIN);
           if(value !=null){
             if(value.equals(CHECKBOX_VALUE)){
               newuserdata[UserView.TYPE_RAADMIN] = UserView.TRUE;                      
             }
             else{
               newuserdata[UserView.TYPE_RAADMIN] = UserView.FALSE;         
             }
           }
           value = request.getParameter(CHECKBOX_TYPECA);
           if(value !=null){
             if(value.equals(CHECKBOX_VALUE)){
               newuserdata[UserView.TYPE_CA] = UserView.TRUE;                
             }
             else{
               newuserdata[UserView.TYPE_CA] = UserView.FALSE;   
             }
           }
           value = request.getParameter(CHECKBOX_TYPECAADMIN);
           if(value !=null){
             if(value.equals(CHECKBOX_VALUE)){
               newuserdata[UserView.TYPE_CAADMIN] = UserView.TRUE;         
             }
             else{
               newuserdata[UserView.TYPE_CAADMIN] = UserView.FALSE;   
             }
           }
           value = request.getParameter(CHECKBOX_TYPEROOTCA);
           if(value !=null){
             if(value.equals(CHECKBOX_VALUE)){
               newuserdata[UserView.TYPE_ROOTCA] = UserView.TRUE;           
             }
             else{
               newuserdata[UserView.TYPE_ROOTCA] = UserView.FALSE;    
             }
           }
           rabean.changeUserData(newuserdata);
           userdata = newuserdata;
         }
      }
    }
  
%>
<head>
  <title><%= globalconfiguration .getEjbcaTitle() %></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>">
  <link rel=STYLESHEET href="<%= ejbcawebbean.getCssFile() %>">
  <script language='JavaScript'>
 <!--
function checkallfields(){
    var illegalfields = 0;

    if(!checkfieldforlegalchars("document.adduser.<%=TEXTFIELD_PASSWORD%>","<%= ejbcawebbean.getText("ONLYCHARACTERS2") %>"))
      illegalfields++;
 
    if(!checkfieldforlegalchars("document.adduser.<%=TEXTFIELD_COMMONNAME%>","<%= ejbcawebbean.getText("ONLYCHARACTERS2") %>"))
      illegalfields++;
  
    if(!checkfieldforlegalchars("document.adduser.<%=TEXTFIELD_ORGANIZATIONUNIT%>","<%= ejbcawebbean.getText("ONLYCHARACTERS2") %>"))
      illegalfields++;
  
    if(!checkfieldforlegalchars("document.adduser.<%=TEXTFIELD_ORGANIZATION%>","<%= ejbcawebbean.getText("ONLYCHARACTERS2") %>"))
      illegalfields++;

    if(!checkfieldforlegalchars("document.adduser.<%=TEXTFIELD_LOCALE%>","<%= ejbcawebbean.getText("ONLYCHARACTERS2") %>"))
      illegalfields++;
  
    if(!checkfieldforlegalchars("document.adduser.<%=TEXTFIELD_STATE%>","<%= ejbcawebbean.getText("ONLYCHARACTERS2") %>"))
      illegalfields++;

    if(!checkfieldforlegalchars("document.adduser.<%=TEXTFIELD_COUNTRY%>","<%= ejbcawebbean.getText("ONLYCHARACTERS2") %>"))
      illegalfields++;

    if(!checkfieldforlegalemailchars("document.adduser.<%=TEXTFIELD_EMAIL%>","<%= ejbcawebbean.getText("ONLYEMAILCHARS") %>"))
      illegalfields++;

    if(document.adduser.<%= TEXTFIELD_PASSWORD %>.value != document.adduser.<%= TEXTFIELD_CONFIRMPASSWORD %>.value){
      alert("<%= ejbcawebbean.getText("PASSWORDSDOESNTMATCH") %>");
      illegalfields++;
    } 

     return illegalfields == 0;  
}

function checkclearpassword(){
  var returnval=true;
  if( document.adduser.<%= TEXTFIELD_PASSWORD %>.value == "" ){
    alert("<%= ejbcawebbean.getText("CHANGEOFCLEARTEXTMODE") %>");
    returnval=false;
  }
  return returnval;
}

function checksaveclose(){
  var returnval = checkallfields();
 
  if(returnval){
    self.close();
  }
 
  return returnval;
}
   -->
  </script>
  <script language=javascript src="<%= globalconfiguration .getRaAdminPath() %>ejbcajslib.js"></script>
</head>
<body >
  <h2 align="center"><%= ejbcawebbean.getText("EDITUSER") %></h2>
  <div align="right"><A  onclick='displayHelpWindow("<%= ejbcawebbean.getHelpfileInfix("ra_help.html") + "#edituser" %>")'>
    <u><%= ejbcawebbean.getText("HELP") %></u> </A>
  </div>
  <%if(nouserparameter){%>
  <div align="center"><h4 id="alert"><%=ejbcawebbean.getText("YOUMUSTSPECIFYUSERNAME") %></h4></div> 
  <% } 
     else{
       if(userdata == null){%>
  <div align="center"><h4 id="alert"><%=ejbcawebbean.getText("USERDOESNTEXIST") %></h4></div> 
    <% }
       else{ %>

  <form name="adduser" action="<%= THIS_FILENAME %>" method="post">
     <input type="hidden" name='<%= ACTION %>' value='<%=ACTION_EDITUSER %>'>
     <input type="hidden" name='<%= USER_PARAMETER %>' value='<%=username %>'>
     <table border="0" cellpadding="0" cellspacing="2" width="400">
      <tr id="Row0">
	<td align="right"><%= ejbcawebbean.getText("USERNAME") %></td>
	<td>     <%=username %>
        </td>
      </tr>
      <tr id="Row1">
        <td align="right"><%= ejbcawebbean.getText("PASSWORD") %></td>
	<td><input type="password" name="<%= TEXTFIELD_PASSWORD %>" size="40" maxlength="255" tabindex="2"
                   value=''>
        </td>
      </tr>
      <tr id="Row0">
	<td align="right"><%= ejbcawebbean.getText("CONFIRMPASSWORD") %></td>
	<td><input type="password" name="<%= TEXTFIELD_CONFIRMPASSWORD %>" size="40" maxlength="255" tabindex="3"
                   value=''>
        </td>
      </tr>
      <tr id="Row0">
	<td align="right"><h4><%= ejbcawebbean.getText("CLEARTEXTPASSWORD") %></h4></td>
	<td><input type="checkbox" name="<%= CHECKBOX_CLEARTEXTPASSWORD %>" value="<%= CHECKBOX_VALUE %>" tabindex="4"
                <%if(userdata[UserView.CLEARTEXTPASSWORD] != null && userdata[UserView.CLEARTEXTPASSWORD].equals(UserView.TRUE))
                   out.write("CHECKED");%> onchange='return checkclearpassword()'> 
        </td>
      </tr>
      <tr id="Row1">
	<td>&nbsp;</td>
	<td>&nbsp;</td>
       </tr>
       <tr id="Row0">
	 <td align="right"><%= ejbcawebbean.getText("COMMONNAME") %></td>
	 <td><input type="text" name="<%= TEXTFIELD_COMMONNAME %>" size="40" maxlength="255" tabindex="5"
                    value='<% if(userdata[UserView.COMMONNAME] != null) out.write(userdata[UserView.COMMONNAME]); %>'> 
         </td>
       </tr>
       <tr id="Row1">
	 <td align="right"><%= ejbcawebbean.getText("ORGANIZATIONUNIT") %></td>
	 <td><input type="text" name="<%= TEXTFIELD_ORGANIZATIONUNIT %>" size="40" maxlength="255" tabindex="6"
                    value='<% if(userdata[UserView.ORGANIZATIONUNIT] != null) out.write(userdata[UserView.ORGANIZATIONUNIT]); %>'> 
         </td>
       </tr>
       <tr id="Row0">
	 <td align="right"><%= ejbcawebbean.getText("ORGANIZATION") %></td>
	 <td><input type="text" name="<%= TEXTFIELD_ORGANIZATION %>" size="40" maxlength="255" tabindex="7"
                    value='<% if(userdata[UserView.ORGANIZATION] != null) out.write(userdata[UserView.ORGANIZATION]); %>'> 
         </td>
       </tr>
       <tr id="Row1">
	 <td align="right"><%= ejbcawebbean.getText("LOCALE") %></td>
	 <td><input type="text" name="<%= TEXTFIELD_LOCALE %>" size="40" maxlength="255" tabindex="8"
                    value='<% if(userdata[UserView.LOCALE] != null) out.write(userdata[UserView.LOCALE]); %>'> 
         </td>
       </tr>
       <tr id="Row0">
	 <td align="right"><%= ejbcawebbean.getText("STATE") %></td>
	 <td><input type="text" name="<%= TEXTFIELD_STATE %>" size="40" maxlength="255" tabindex="9"
                    value='<% if(userdata[UserView.STATE] != null) out.write(userdata[UserView.STATE]); %>'> 
         </td>
       </tr>
       <tr id="Row1">
	 <td align="right"><%= ejbcawebbean.getText("COUNTRY") %></td>
	 <td><input type="text" name="<%= TEXTFIELD_COUNTRY %>" size="2" maxlength="2" tabindex="10"
                    value='<% if(userdata[UserView.COUNTRY] != null) out.write(userdata[UserView.COUNTRY]); %>'> 
          </td>
       </tr>
       <tr id="Row0">
	 <td>&nbsp;</td>
	 <td>&nbsp;</td>
       </tr>
       <tr id="Row1">
	 <td align="right"><%= ejbcawebbean.getText("EMAIL") %></td>
	 <td><input type="text" name="<%= TEXTFIELD_EMAIL %>" size="40" maxlength="255" tabindex="11"
                    value='<% if(userdata[UserView.EMAIL] != null) out.write(userdata[UserView.EMAIL]); %>'> 
         </td>
       </tr>
       <tr id="Row0">
	 <td align="right"><%= ejbcawebbean.getText("TYPES") %></td>
	 <td>
         </td>
       </tr>
    <tr  id="Row1"> 
      <td  align="right"> 
        <%= ejbcawebbean.getText("TYPEENDUSER") %> <br>
      </td>
      <td > 
        <input type="checkbox" name="<%=CHECKBOX_TYPEENDUSER%>" value="<%=CHECKBOX_VALUE %>" tabindex="12"
               <%if(userdata[UserView.TYPE_ENDUSER] != null && userdata[UserView.TYPE_ENDUSER].equals(UserView.TRUE))
                   out.write("CHECKED");%>> 
      </td>
    </tr>
    <tr  id="Row0"> 
      <td  align="right"> 
        <%= ejbcawebbean.getText("TYPERA") %> 
      </td>
      <td> 
        <input type="checkbox" name="<%=CHECKBOX_TYPERA%>" value="<%=CHECKBOX_VALUE %>" tabindex="13"
                <%if(userdata[UserView.TYPE_RA] != null && userdata[UserView.TYPE_RA].equals(UserView.TRUE))
                   out.write("CHECKED");%>> 
      </td>
    </tr>
    <tr  id="Row1"> 
      <td align="right"> 
        <%= ejbcawebbean.getText("TYPERAADMIN") %> 
      </td>
      <td > 
        <input type="checkbox" name="<%=CHECKBOX_TYPERAADMIN%>" value="<%=CHECKBOX_VALUE %>" tabindex="14"
                <%if(userdata[UserView.TYPE_RAADMIN] != null && userdata[UserView.TYPE_RAADMIN].equals(UserView.TRUE))
                   out.write("CHECKED");%>> 
      </td>
    </tr>
    <tr  id="Row0"> 
      <td  align="right"> 
        <%= ejbcawebbean.getText("TYPECA") %> 
      </td>
      <td > 
        <input type="checkbox" name="<%=CHECKBOX_TYPECA%>" value="<%=CHECKBOX_VALUE %>" tabindex="15"
                <%if(userdata[UserView.TYPE_CA] != null && userdata[UserView.TYPE_CA].equals(UserView.TRUE))
                   out.write("CHECKED");%>> 
      </td>
    </tr>
    <tr  id="Row1">
      <td align="right"> 
        <%= ejbcawebbean.getText("TYPECAADMIN") %> 
      </td>
      <td> 
        <input type="checkbox" name="<%=CHECKBOX_TYPECAADMIN%>" value="<%=CHECKBOX_VALUE %>" tabindex="16"
                <%if(userdata[UserView.TYPE_CAADMIN] != null && userdata[UserView.TYPE_CAADMIN].equals(UserView.TRUE))
                   out.write("CHECKED");%>> 
      </td>
    </tr>
    <tr  id="Row0"> 
      <td  align="right"> 
        <%= ejbcawebbean.getText("TYPEROOTCA") %> 
      </td>
      <td > 
        <input type="checkbox" name="<%=CHECKBOX_TYPEROOTCA%>" value="<%=CHECKBOX_VALUE %>" tabindex="17"
                <%if(userdata[UserView.TYPE_ROOTCA] != null && userdata[UserView.TYPE_ROOTCA].equals(UserView.TRUE))
                   out.write("CHECKED");%>> 
      </td>
    </tr>
       <tr id="Row1">
	 <td></td>
	 <td>
             <input type="submit" name="<%= BUTTON_SAVEANDCLOSE %>" value="<%= ejbcawebbean.getText("SAVEANDCLOSE") %>" tabindex="18"
                    onClick='return checksaveclose()'> 
             <input type="submit" name="<%= BUTTON_SAVE %>" value="<%= ejbcawebbean.getText("SAVE") %>" tabindex="19"
                    onClick='return checkallfields()'> 
             <input type="reset" name="<%= BUTTON_CLOSE %>" value="<%= ejbcawebbean.getText("CLOSE") %>" tabindex="20"
                    onClick='self.close()'>
       </td>
       </tr> 
     </table> 
   </form>
   <p></p>
   <% }
    }%>

</body>
</html>