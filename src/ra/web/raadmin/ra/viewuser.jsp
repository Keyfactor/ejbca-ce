<html>
<%@page contentType="text/html"%>
<%@page errorPage="/errorpage.jsp"  import="se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean, se.anatom.ejbca.ra.GlobalConfiguration, 
                 se.anatom.ejbca.webdist.rainterface.UserView, se.anatom.ejbca.webdist.rainterface.RAInterfaceBean, 
                 se.anatom.ejbca.ra.raadmin.Profile,  se.anatom.ejbca.ra.UserDataRemote,
                 javax.ejb.CreateException, java.rmi.RemoteException" %>
<jsp:useBean id="ejbcawebbean" scope="session" class="se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean" />
<jsp:setProperty name="ejbcawebbean" property="*" /> 
<jsp:useBean id="rabean" scope="session" class="se.anatom.ejbca.webdist.rainterface.RAInterfaceBean" />
<jsp:setProperty name="rabean" property="*" /> 
<%! // Declarations
 
  static final String USER_PARAMETER           = "userparameter";

  static final String BUTTON_CLOSE             = "buttonclose"; 

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
  GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request); 
  String THIS_FILENAME            =  globalconfiguration.getRaPath()  + "/viewuser.jsp";

  boolean nouserparameter          = true;

  String[] userdata = null;
  String   username = null;
  UserView user     = null;

  if( request.getParameter(USER_PARAMETER) != null ){
    username = request.getParameter(USER_PARAMETER);
    user = rabean.findUser(username);
    userdata = user.getValues();
    nouserparameter = false;
  }  
%>
<head>
  <title><%= globalconfiguration.getEjbcaTitle() %></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>">
  <link rel=STYLESHEET href="<%= ejbcawebbean.getCssFile() %>">
  <script language=javascript src="<%= globalconfiguration.getRaAdminPath() %>ejbcajslib.js"></script>
</head>
<body >
  <h2 align="center"><%= ejbcawebbean.getText("VIEWUSER") %></h2>
  <div align="right"><A  onclick='displayHelpWindow("<%= ejbcawebbean.getHelpfileInfix("ra_help.html")  + "#viewuser"%>")'>
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
     <input type="hidden" name='<%= USER_PARAMETER %>' value='<%=username %>'>
     <table border="0" cellpadding="0" cellspacing="2" width="400">
      <tr id="Row0">
	<td align="right"><%= ejbcawebbean.getText("USERNAME") %></td>
	<td><% if(userdata[UserView.USERNAME] != null) out.write(userdata[UserView.USERNAME]); %>
        </td>
      </tr>
      <tr id="Row1">
	<td align="right"><%= ejbcawebbean.getText("PROFILE") %></td>
	<td><% if(userdata[UserView.PROFILE] != null) out.write(userdata[UserView.PROFILE]);
               else out.write(ejbcawebbean.getText("NOPROFILEDEFINED")); %>
        </td>
      </tr>
      <tr id="Row0">
	<td align="right"><%= ejbcawebbean.getText("CLEARTEXTPASSWORD") %></td>
	<td><input type="checkbox" name="<%= CHECKBOX_CLEARTEXTPASSWORD %>" value="<%= CHECKBOX_VALUE %>" disabled="true"
            <%if(userdata[UserView.CLEARTEXTPASSWORD] != null && userdata[UserView.CLEARTEXTPASSWORD].equals(UserView.TRUE))
                   out.write("CHECKED");%>>
        </td>
      </tr>
       <tr id="Row1">
	 <td align="right"><%= ejbcawebbean.getText("COMMONNAME") %></td>
	 <td><% if(userdata[UserView.COMMONNAME] != null) out.write(userdata[UserView.COMMONNAME]); %> 
         </td>
       </tr>
       <tr id="Row0">
	 <td align="right"><%= ejbcawebbean.getText("ORGANIZATIONUNIT") %></td>
	 <td><% if(userdata[UserView.ORGANIZATIONUNIT] != null) out.write(userdata[UserView.ORGANIZATIONUNIT]); %> 
         </td>
       </tr>
       <tr id="Row1">
	 <td align="right"><%= ejbcawebbean.getText("ORGANIZATION") %></td>
	 <td><% if(userdata[UserView.ORGANIZATION] != null) out.write(userdata[UserView.ORGANIZATION]); %> 
         </td>
       </tr>
       <tr id="Row0">
	 <td align="right"><%= ejbcawebbean.getText("LOCALE") %></td>
	 <td><% if(userdata[UserView.LOCALE] != null) out.write(userdata[UserView.LOCALE]); %>
         </td>
       </tr>
       <tr id="Row1">
	 <td align="right"><%= ejbcawebbean.getText("STATE") %></td>
	 <td><% if(userdata[UserView.STATE] != null) out.write(userdata[UserView.STATE]); %> 
         </td>
       </tr>
       <tr id="Row0">
	 <td align="right"><%= ejbcawebbean.getText("COUNTRY") %></td>
	 <td><% if(userdata[UserView.COUNTRY] != null) out.write(userdata[UserView.COUNTRY]); %>
          </td>
       </tr>
       <tr id="Row1">
	 <td>&nbsp;</td>
	 <td>&nbsp;</td>
       </tr>
       <tr id="Row0">
	 <td align="right"><%= ejbcawebbean.getText("EMAIL") %></td>
	 <td><% if(userdata[UserView.EMAIL] != null) out.write(userdata[UserView.EMAIL]); %>
         </td>
       </tr>
       <tr id="Row1">
	 <td align="right"><%= ejbcawebbean.getText("CERTIFICATETYPE") %></td>
	 <td><% if(userdata[UserView.CERTIFICATETYPE] != null) out.write(userdata[UserView.CERTIFICATETYPE]); 
                else out.write(ejbcawebbean.getText("NOCERTIFICATETYPEDEFINED"));%>
         </td>
       </tr>
       <tr id="Row0">
	 <td align="right"><%= ejbcawebbean.getText("TYPES") %></td>
	 <td>
         </td>
       </tr>
    <tr  id="Row0"> 
      <td  align="right"> 
        <%= ejbcawebbean.getText("TYPEENDUSER") %> <br>
      </td>
      <td > 
        <input type="checkbox" name="<%=CHECKBOX_TYPEENDUSER%>" value="<%=CHECKBOX_VALUE %>" tabindex="12"
               <%if(userdata[UserView.TYPE_ENDUSER] != null && userdata[UserView.TYPE_ENDUSER].equals(UserView.TRUE))
                   out.write("CHECKED");%> disabled="true"> 
      </td>
    </tr>
    <tr  id="Row1"> 
      <td  align="right"> 
        <%= ejbcawebbean.getText("TYPERA") %> 
      </td>
      <td> 
        <input type="checkbox" name="<%=CHECKBOX_TYPERA%>" value="<%=CHECKBOX_VALUE %>" tabindex="13"
                <%if(userdata[UserView.TYPE_RA] != null && userdata[UserView.TYPE_RA].equals(UserView.TRUE))
                   out.write("CHECKED");%> disabled="true"> 
      </td>
    </tr>
    <tr  id="Row0"> 
      <td align="right"> 
        <%= ejbcawebbean.getText("TYPERAADMIN") %> 
      </td>
      <td > 
        <input type="checkbox" name="<%=CHECKBOX_TYPERAADMIN%>" value="<%=CHECKBOX_VALUE %>" tabindex="14"
                <%if(userdata[UserView.TYPE_RAADMIN] != null && userdata[UserView.TYPE_RAADMIN].equals(UserView.TRUE))
                   out.write("CHECKED");%> disabled="true"> 
      </td>
    </tr>
    <tr  id="Row1"> 
      <td  align="right"> 
        <%= ejbcawebbean.getText("TYPECA") %> 
      </td>
      <td > 
        <input type="checkbox" name="<%=CHECKBOX_TYPECA%>" value="<%=CHECKBOX_VALUE %>" tabindex="15"
                <%if(userdata[UserView.TYPE_CA] != null && userdata[UserView.TYPE_CA].equals(UserView.TRUE))
                   out.write("CHECKED");%> disabled="true"> 
      </td>
    </tr>
    <tr  id="Row0">
      <td align="right"> 
        <%= ejbcawebbean.getText("TYPECAADMIN") %> 
      </td>
      <td> 
        <input type="checkbox" name="<%=CHECKBOX_TYPECAADMIN%>" value="<%=CHECKBOX_VALUE %>" tabindex="16"
                <%if(userdata[UserView.TYPE_CAADMIN] != null && userdata[UserView.TYPE_CAADMIN].equals(UserView.TRUE))
                   out.write("CHECKED");%> disabled="true"> 
      </td>
    </tr>
    <tr  id="Row1"> 
      <td  align="right"> 
        <%= ejbcawebbean.getText("TYPEROOTCA") %> 
      </td>
      <td > 
        <input type="checkbox" name="<%=CHECKBOX_TYPEROOTCA%>" value="<%=CHECKBOX_VALUE %>" tabindex="17"
                <%if(userdata[UserView.TYPE_ROOTCA] != null && userdata[UserView.TYPE_ROOTCA].equals(UserView.TRUE))
                   out.write("CHECKED");%> disabled="true"> 
      </td>
    </tr>
    <tr id="Row1">
      <td>&nbsp;</td>
      <td>&nbsp</td>
    </tr> 
    <tr id="Row0">
      <td><%= ejbcawebbean.getText("CREATED") %></td>
      <td>
         <%= ejbcawebbean.printDateTime(user.getTimeCreated()) %>
       </td>
    </tr> 
    <tr id="Row1">
      <td><%= ejbcawebbean.getText("MODIFIED") %></td>
      <td>
         <%= ejbcawebbean.printDateTime(user.getTimeModified()) %>
       </td>
     </tr> 
       <tr id="Row0">
	 <td></td>
	 <td>
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