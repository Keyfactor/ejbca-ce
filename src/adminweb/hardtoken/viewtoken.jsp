<html>
<%@page contentType="text/html"%>
<%@page errorPage="/errorpage.jsp"  import="se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean, se.anatom.ejbca.ra.raadmin.GlobalConfiguration, 
                 se.anatom.ejbca.webdist.hardtokeninterface.HardTokenView, se.anatom.ejbca.webdist.hardtokeninterface.HardTokenInterfaceBean, se.anatom.ejbca.SecConst,
                 javax.ejb.CreateException, java.rmi.RemoteException, se.anatom.ejbca.webdist.rainterface.RAInterfaceBean, se.anatom.ejbca.webdist.rainterface.RevokedInfoView" %>
<jsp:useBean id="ejbcawebbean" scope="session" class="se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean" />
<jsp:setProperty name="ejbcawebbean" property="*" /> 
<jsp:useBean id="tokenbean" scope="session" class="se.anatom.ejbca.webdist.hardtokeninterface.HardTokenInterfaceBean" />
<jsp:setProperty name="tokenbean" property="*" /> 
<jsp:useBean id="rabean" scope="session" class="se.anatom.ejbca.webdist.rainterface.RAInterfaceBean" />
<jsp:setProperty name="rabean" property="*" /> 
<%! // Declarations
 
  static final String USER_PARAMETER           = "username";
  static final String TOKENSN_PARAMETER        = "tokensn";
  static final String INDEX_PARAMETER          = "index";

  static final String BUTTON_CLOSE             = "buttonclose"; 
  static final String BUTTON_REVOKE            = "buttonrevoke";
  static final String BUTTON_VIEW_PREVIOUS     = "buttonviewprevious"; 
  static final String BUTTON_VIEW_NEXT         = "buttonviewnext";

  static final String SELECT_REVOKE_REASON       = "selectrevokationreason";

  static final String CHECKBOX_VALUE             = "true";


%><%
  // Initialize environment.
  GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, "/ra_functionality/view_hardtoken"); 
                                            rabean.initialize(request, ejbcawebbean); 
                                            tokenbean.initialize(request);
  String THIS_FILENAME                    = globalconfiguration.getHardTokenPath() + "/viewtoken.jsp";

  final String VIEWCERT_LINK            = "/" + globalconfiguration.getAdminWebPath() + "viewcertificate.jsp";

  boolean noparameter              = true;
  boolean authorized               = true;
  boolean alluserstokens           = false;

  int numberoftokens = 0;
  int index = -1;
  HardTokenView tokendata = null;
  HardTokenView token = null;

  String   username = null;
  String   tokensn  = null;

  if(request.getParameter(BUTTON_VIEW_PREVIOUS) != null){
    String indexstring = request.getParameter(INDEX_PARAMETER);
    if(indexstring!= null)
      index = Integer.parseInt(indexstring) -1;
  }
  if(request.getParameter(BUTTON_VIEW_NEXT) != null){
    String indexstring = request.getParameter(INDEX_PARAMETER);
    if(indexstring!= null)
      index = Integer.parseInt(indexstring) +1;
  }

  if(request.getParameter(BUTTON_REVOKE) != null){
   String reasonstring = request.getParameter(SELECT_REVOKE_REASON);
   username = java.net.URLDecoder.decode(request.getParameter(USER_PARAMETER),"UTF-8");
   if(request.getParameter(TOKENSN_PARAMETER) != null){
     if(username != null && reasonstring != null){
       tokensn  = request.getParameter(TOKENSN_PARAMETER);  
        if(rabean.authorizedToRevokeCert(username) && ejbcawebbean.isAuthorizedNoLog(EjbcaWebBean.AUTHORIZED_RA_REVOKE_RIGHTS) 
          && !rabean.isAllTokenCertificatesRevoked(tokensn, username))   
          rabean.revokeTokenCertificates(tokensn, username, Integer.parseInt(reasonstring));   
     }
   }else{
     String indexstring = request.getParameter(INDEX_PARAMETER);  
     if(indexstring!= null)
      index = Integer.parseInt(indexstring); 
     else
       index=0;
     if(username != null && reasonstring != null){
       token = tokenbean.getHardTokenViewWithIndex(username, index);
        if(rabean.authorizedToRevokeCert(username) && ejbcawebbean.isAuthorizedNoLog(EjbcaWebBean.AUTHORIZED_RA_REVOKE_RIGHTS) 
          && !rabean.isAllTokenCertificatesRevoked(token.getTokenSN(), username))
          rabean.revokeTokenCertificates(token.getTokenSN(), username, Integer.parseInt(reasonstring));  
     }         
   }
  } 

  if( request.getParameter(TOKENSN_PARAMETER) != null ){
    username = java.net.URLDecoder.decode(request.getParameter(USER_PARAMETER),"UTF-8");
    tokensn  = request.getParameter(TOKENSN_PARAMETER);
    if(username != null && tokensn != null){
      noparameter=false;
      if(globalconfiguration.getEnableEndEntityProfileLimitations())
        authorized = rabean.authorizedToViewHardToken(username);
      token = tokenbean.getHardTokenView(tokensn);

      if(token == null)
        numberoftokens = 0;
      else
        numberoftokens = 1;
    }
  }else{
    if( request.getParameter(USER_PARAMETER) != null ){
      username = java.net.URLDecoder.decode(request.getParameter(USER_PARAMETER),"UTF-8");
      if(username!=null){
       alluserstokens=true;
       noparameter=false; 
       if(globalconfiguration.getEnableEndEntityProfileLimitations())
         authorized = rabean.authorizedToViewHardToken(username);
       if(authorized){
         if(index==-1){
           token = tokenbean.getHardTokenViewWithUsername(username);
           index=0;
         }
         else
           token = tokenbean.getHardTokenViewWithIndex(username, index);

         numberoftokens = tokenbean.getHardTokensInCache();
       }
     }  
   }
  }

 
  int row = 0; 
  int columnwidth = 200;
%>
<head>
  <title><%= globalconfiguration.getEjbcaTitle() %></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>">
  <link rel=STYLESHEET href="<%= ejbcawebbean.getCssFile() %>">
  <script language=javascript src="<%= globalconfiguration.getAdminWebPath() %>ejbcajslib.js"></script>
  <script language=javascript>
<!--
  <% if(token!=null){ %>
function confirmrevokation(){
  var returnval = false;
  if(document.viewtoken.<%= SELECT_REVOKE_REASON %>.options.selectedIndex == -1){
     alert("<%= ejbcawebbean.getText("AREVOKEATIONREASON") %>"); 
     returnval = false;
  }else{
    returnval = confirm("<%= ejbcawebbean.getText("AREYOUSUREREVOKECERT") %>");
  } 
  return returnval;
}

function viewcert(){
    var link = "<%= VIEWCERT_LINK %>?<%= USER_PARAMETER %>=<%=username%>&<%=TOKENSN_PARAMETER %>=<%=token.getTokenSN()%>";
    link = encodeURI(link);
    window.open(link, 'view_cert',config='height=600,width=600,scrollbars=yes,toolbar=no,resizable=1');
}
  <% } %>
-->
</script>
</head>
<body >
  <h2 align="center"><%= ejbcawebbean.getText("VIEWHARDTOKEN") %></h2>
 <!-- <div align="right"><A  onclick='displayHelpWindow("<%= ejbcawebbean.getHelpfileInfix("hardtoken_help.html")  + "#viewhardtoken"%>")'>
    <u><%= ejbcawebbean.getText("HELP") %></u> </A> -->
  </div>
  <%if(noparameter){%>
  <div align="center"><h4 id="alert"><%=ejbcawebbean.getText("YOUMUSTSPECIFYPARAMETER") %></h4></div> 
  <% } 
     else{
       if(token == null){%>
  <div align="center"><h4 id="alert"><%=ejbcawebbean.getText("HARDTOKENDOESNTEXIST") %></h4></div> 
    <% }
       else{ 
         if(!authorized){ %>
  <div align="center"><h4 id="alert"><%=ejbcawebbean.getText("NOTAUTHORIZEDTOVIEWTOKEN") %></h4></div> 
     <%  }else{%>

  <form name="viewtoken" action="<%= THIS_FILENAME %>" method="post">
     <input type="hidden" name='<%= USER_PARAMETER %>' value='<%=username %>'>
     <% if (tokensn != null){ %>
     <input type="hidden" name='<%= TOKENSN_PARAMETER %>' value='<%=tokensn %>'>
     <% } %>
     <input type="hidden" name='<%= INDEX_PARAMETER %>' value='<%=index %>'>

     <table border="0" cellpadding="0" cellspacing="2" width="400">
      <tr id="Row<%=(row++)%2%>">
	<td align="right" width="<%=columnwidth%>"><%= ejbcawebbean.getText("USERNAME") %></td>
	<td><% if(token.getUsername() != null) out.write(token.getUsername()); %>
        </td>
      </tr>
      <% if(alluserstokens){ %>
      <tr id="Row<%=(row++)%2%>">
	<td align="right"><%= ejbcawebbean.getText("HARDTOKENNR") %></td>
	<td><%= (index +1) + " " + ejbcawebbean.getText("OF") + " " + numberoftokens%>
        </td>
      </tr>
      <% } %>
       <tr id="Row<%=(row++)%2%>">
	 <td>&nbsp;</td>
	 <td>&nbsp;</td>
       </tr>
      <tr id="Row<%=(row++)%2%>">
	<td align="right" width="<%=columnwidth%>"><%= ejbcawebbean.getText("HARDTOKENTYPE") %></td>
	<td><% if(token.getHardTokenType().equals(""))
                 out.write(ejbcawebbean.getText("UNKNOWNHARDTOKENTYPE"));
               else
                 out.write(token.getHardTokenType());
             %>
        </td>
      </tr>
      <tr id="Row<%=(row++)%2%>">
	<td align="right" width="<%=columnwidth%>"><%= ejbcawebbean.getText("HARDTOKENSN") %></td>
	<td><%= token.getTokenSN()%>
        </td>
      </tr>
       <tr id="Row<%=(row++)%2%>">
	 <td align="right" width="<%=columnwidth%>">&nbsp;</td>
	 <td>&nbsp;</td>
       </tr>
      <% int numoffields = token.getNumberOfFields();
         for(int i = 0; i < numoffields; i++){ %>
       <tr id="Row<%=(row++)%2%>">
	 <td align="right" width="<%=columnwidth%>"><% if(!token.getTextOfField(i).equals(""))
                                                            out.write(ejbcawebbean.getText(token.getTextOfField(i)));
                                                       else 
                                                            out.write("&nbsp;");%></td>
	 <td><% Object o = token.getField(i); 
                if( o instanceof java.util.Date){
                  out.write(ejbcawebbean.printDateTime((java.util.Date) o));
                }else{
                  out.write(o.toString());
                }%> 
         </td>
       </tr>
       <% }  %>  
       <tr id="Row<%=(row++)%2%>">
	 <td>&nbsp;</td>
	 <td>&nbsp;</td>
       </tr>
       <tr id="Row0">
         <td align="right" width="<%=columnwidth%>"><%= ejbcawebbean.getText("CREATED") %></td>
         <td>
           <%= ejbcawebbean.printDateTime(token.getCreateTime()) %>
         </td>
       </tr> 
    <tr id="Row<%=(row++)%2%>">
      <td align="right" width="<%=columnwidth%>"><%= ejbcawebbean.getText("MODIFIED") %></td>
      <td>
           <%= ejbcawebbean.printDateTime(token.getModifyTime()) %>
       </td>
     </tr> 
    <tr id="Row<%=(row++)%2%>">
      <td align="right" width="<%=columnwidth%>"></td>
      <td>
        <% try{ 
             if(ejbcawebbean.isAuthorizedNoLog(EjbcaWebBean.AUTHORIZED_CA_VIEW_CERT)){ %>
        <A  onclick='viewcert()'>
        <u><%= ejbcawebbean.getText("VIEWCERTIFICATES") %></u> </A>
        <%   }
         }catch(se.anatom.ejbca.authorization.AuthorizationDeniedException ade){}
        %>&nbsp; 
       </td>
     </tr> 
     <tr id="Row<%=(row++)%2%>">
        <td width="<%=columnwidth%>">
          <% if(index > 0 ){ %>
           <input type="submit" name="<%= BUTTON_VIEW_PREVIOUS %>" value="<%= ejbcawebbean.getText("VIEWPREVIOUS") %>" tabindex="1">&nbsp;&nbsp;&nbsp;
          <% } %>
        </td>
	<td>
          <input type="reset" name="<%= BUTTON_CLOSE %>" value="<%= ejbcawebbean.getText("CLOSE") %>" tabindex="20"
                 onClick='self.close()'>
          <% if((index+1) < numberoftokens){ %>
          &nbsp;&nbsp;&nbsp;<input type="submit" name="<%= BUTTON_VIEW_NEXT %>" value="<%= ejbcawebbean.getText("VIEWNEXT") %>" tabindex="3">
          <% } %>
       </td>
     </tr> 
       <tr id="Row<%=(row++)%2%>">
          <td>  
            &nbsp;
          </td>
          <td>
       <% 
            if(rabean.authorizedToRevokeCert(username) && ejbcawebbean.isAuthorizedNoLog(EjbcaWebBean.AUTHORIZED_RA_REVOKE_RIGHTS) 
               && !rabean.isAllTokenCertificatesRevoked(token.getTokenSN(), username)){ %>
        <input type="submit" name="<%=BUTTON_REVOKE %>" value="<%= ejbcawebbean.getText("REVOKE") %>"
               onClick='return confirmrevokation()'><br>
        <select name="<%=SELECT_REVOKE_REASON %>" >
          <% for(int i=0; i < RevokedInfoView.reasontexts.length; i++){ 
               if(i!= 7){%>
               <option value='<%= i%>'><%= ejbcawebbean.getText(RevokedInfoView.reasontexts[i]) %></option>
          <%   } 
             }
           }%> 
        </select>
          &nbsp;
          </td>
       </tr> 
   </table> 
 </form>
  <p></p>
   <% }
    }
   }%>

</body>
</html>