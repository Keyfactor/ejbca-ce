<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ page pageEncoding="ISO-8859-1"%>
<% response.setContentType("text/html; charset="+org.ejbca.config.WebConfiguration.getWebContentEncoding()); %>
<%@page errorPage="/errorpage.jsp"  import="java.util.Iterator, org.ejbca.ui.web.admin.configuration.EjbcaWebBean, org.ejbca.config.GlobalConfiguration, 
    org.ejbca.ui.web.RequestHelper,org.ejbca.ui.web.admin.hardtokeninterface.HardTokenView,org.ejbca.core.model.SecConst,org.cesecore.authorization.AuthorizationDeniedException,
                 org.ejbca.ui.web.RevokedInfoView, org.ejbca.core.model.authorization.AccessRulesConstants" %>
<html>
<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />
<jsp:setProperty name="ejbcawebbean" property="*" /> 
<jsp:useBean id="tokenbean" scope="session" class="org.ejbca.ui.web.admin.hardtokeninterface.HardTokenInterfaceBean" />
<jsp:setProperty name="tokenbean" property="*" /> 
<jsp:useBean id="rabean" scope="session" class="org.ejbca.ui.web.admin.rainterface.RAInterfaceBean" />
<jsp:setProperty name="rabean" property="*" /> 
<%! // Declarations
 
  static final String USER_PARAMETER           = "username";
  static final String TOKENSN_PARAMETER        = "tokensn";
  static final String INDEX_PARAMETER          = "index";

  static final String BUTTON_CLOSE             = "buttonclose"; 
  static final String BUTTON_REVOKE            = "buttonrevoke";
  static final String BUTTON_KEYRECOVER        = "buttonkeyrecover";
  static final String BUTTON_VIEW_NEWER        = "buttonviewnewer"; 
  static final String BUTTON_VIEW_OLDER        = "buttonviewolder";

  static final String SELECT_REVOKE_REASON       = "selectrevocationreason";

  static final String CHECKBOX_VALUE             = "true";  


%><%
  // Initialize environment.
  GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, AccessRulesConstants.ROLE_ADMINISTRATOR, AccessRulesConstants.REGULAR_VIEWHARDTOKENS); 
                                            rabean.initialize(request, ejbcawebbean); 
                                            tokenbean.initialize(request, ejbcawebbean);
  String THIS_FILENAME                    = globalconfiguration.getHardTokenPath() + "/viewtoken.jsp";

  final String VIEWCERT_LINK            = ejbcawebbean.getBaseUrl() + globalconfiguration.getAdminWebPath() + "viewcertificate.jsp";
  final String VIEWTOKEN_LINK           = ejbcawebbean.getBaseUrl() + globalconfiguration.getAdminWebPath() + "hardtoken/viewtoken.jsp";

  boolean noparameter              = true;
  boolean authorized               = true;
  boolean includePUK               = false;
  boolean alluserstokens           = false;
  boolean usekeyrecovery           = false;

  int numberoftokens = 0;
  int index = -1;
  HardTokenView token = null;

  String   username = null;
  String   tokensn  = null;
  
  String message = null;

  RequestHelper.setDefaultCharacterEncoding(request);

  if(request.getParameter(BUTTON_VIEW_NEWER) != null){
    String indexstring = request.getParameter(INDEX_PARAMETER);
    if(indexstring!= null)
      index = Integer.parseInt(indexstring) -1;
  }
  if(request.getParameter(BUTTON_VIEW_OLDER) != null){
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
	    	try{
	          rabean.revokeTokenCertificates(tokensn, username, Integer.parseInt(reasonstring));   
	        }catch(org.ejbca.core.model.approval.ApprovalException e){
	     	   message = ejbcawebbean.getText("THEREALREADYEXISTSAPPOBJ");
	        }catch(org.ejbca.core.model.approval.WaitingForApprovalException e){
	     	   message = ejbcawebbean.getText("REQHAVEBEENADDEDFORAPPR");
	        }catch(org.ejbca.core.model.ra.AlreadyRevokedException e){
	     	   message = ejbcawebbean.getText("ALREADYREVOKED");
	        } 
     }
   }else{
     String indexstring = request.getParameter(INDEX_PARAMETER);  
     if(indexstring!= null)
      index = Integer.parseInt(indexstring); 
     else
       index=0;
     if(username != null && reasonstring != null){
       token = tokenbean.getHardTokenViewWithIndex(username, index, includePUK);
        if(rabean.authorizedToRevokeCert(username) && ejbcawebbean.isAuthorizedNoLog(EjbcaWebBean.AUTHORIZED_RA_REVOKE_RIGHTS) 
          && !rabean.isAllTokenCertificatesRevoked(token.getTokenSN(), username))
	    	try{
	          rabean.revokeTokenCertificates(token.getTokenSN(), username, Integer.parseInt(reasonstring));  
	        }catch(org.ejbca.core.model.approval.ApprovalException e){
	     	   message = ejbcawebbean.getText("THEREALREADYEXISTSAPPOBJ");
	        }catch(org.ejbca.core.model.approval.WaitingForApprovalException e){
	     	   message = ejbcawebbean.getText("REQHAVEBEENADDEDFORAPPR");
	        }catch(org.ejbca.core.model.ra.AlreadyRevokedException e){
	     	   message = ejbcawebbean.getText("ALREADYREVOKED");
	        } 
     }         
   }
  } 
  if(request.getParameter(BUTTON_KEYRECOVER) != null){
   boolean markforrecovery = false;
   String recoverytokensn = null;
   username = java.net.URLDecoder.decode(request.getParameter(USER_PARAMETER),"UTF-8");
   if(username != null){
     if(request.getParameter(TOKENSN_PARAMETER) != null){
       tokensn  = request.getParameter(TOKENSN_PARAMETER);  
       recoverytokensn = tokensn;
       markforrecovery = true;
     }else{
       String indexstring = request.getParameter(INDEX_PARAMETER);  
       if(indexstring!= null)
        index = Integer.parseInt(indexstring); 
       else
         index=0;
       token = tokenbean.getHardTokenViewWithIndex(username, index, includePUK);
       recoverytokensn = token.getTokenSN();
       markforrecovery = true;
     }         
    }
    if(markforrecovery && tokenbean.isTokenKeyRecoverable(recoverytokensn, username, rabean)){             
    	try{
         tokenbean.markTokenForKeyRecovery(recoverytokensn, username, rabean);
        }catch(org.ejbca.core.model.approval.ApprovalException e){
     	   message = ejbcawebbean.getText("THEREALREADYEXISTSAPPROVAL");
        }catch(org.ejbca.core.model.approval.WaitingForApprovalException e){
     	   message = ejbcawebbean.getText("REQHAVEBEENADDEDFORAPPR");
        } 
    } 
  }

  if( request.getParameter(TOKENSN_PARAMETER) != null ){
    username = java.net.URLDecoder.decode(request.getParameter(USER_PARAMETER),"UTF-8");
    tokensn  = request.getParameter(TOKENSN_PARAMETER);
    if(username != null && tokensn != null){
      noparameter=false;
      if(globalconfiguration.getEnableEndEntityProfileLimitations()){
    	  try{
    	    includePUK = rabean.authorizedToViewHardToken(username);
    	  }catch(AuthorizationDeniedException e){
    		  authorized = false;
    	  }
      }
      token = tokenbean.getHardTokenView(tokensn, includePUK);

      if(token == null)
        numberoftokens = 0;
      else{
        numberoftokens = 1;
        index = 0;
      }
    }
  }else{
    if( request.getParameter(USER_PARAMETER) != null ){
      username = java.net.URLDecoder.decode(request.getParameter(USER_PARAMETER),"UTF-8");
      if(username!=null){
       alluserstokens=true;
       noparameter=false; 
       if(globalconfiguration.getEnableEndEntityProfileLimitations()){
    	   try{
             includePUK = rabean.authorizedToViewHardToken(username);
 	       }catch(AuthorizationDeniedException e){
		     authorized = false;
	       }
       }
         if(index==-1){
           token = tokenbean.getHardTokenViewWithUsername(username,includePUK);
           index=0;
         }
         else
           token = tokenbean.getHardTokenViewWithIndex(username, index,includePUK);

         numberoftokens = tokenbean.getHardTokensInCache();
       
     }  
   }
  }

  if(token!= null){
    usekeyrecovery = globalconfiguration.getEnableKeyRecovery() && tokenbean.isTokenKeyRecoverable(token.getTokenSN(), username, rabean);
  }
 
  int row = 0; 
  int columnwidth = 200;
%>
<head>
  <title><c:out value="<%= globalconfiguration.getEjbcaTitle() %>" /></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>" />
  <link rel="shortcut icon" href="<%=ejbcawebbean.getImagefileInfix("favicon.png")%>" type="image/png" />
  <link rel="stylesheet" type="text/css" href="<c:out value='<%=ejbcawebbean.getCssFile() %>' />" />
  <script type="text/javascript" src="<%= globalconfiguration.getAdminWebPath() %>ejbcajslib.js"></script>
  <script type="text/javascript">
<!--
  <% if(token!=null){ %>
function confirmrevocation(){
  var returnval = false;
  if(document.viewtoken.<%= SELECT_REVOKE_REASON %>.options.selectedIndex == -1){
     alert("<%= ejbcawebbean.getText("AREVOKEATIONREASON", true) %>"); 
     returnval = false;
  }else{
    returnval = confirm("<%= ejbcawebbean.getText("AREYOUSUREREVOKETOKEN",true) %>");
  } 
  return returnval;
}

function confirmkeyrecovery(){
  var returnval = false;

  returnval = confirm("<%= ejbcawebbean.getText("AREYOUSUREKEYRECTOKEN",true) %>");
  
  return returnval;
}

function viewcert(){
    var link = "<%= VIEWCERT_LINK %>?<%= USER_PARAMETER %>=<%= java.net.URLEncoder.encode(username,"UTF-8")%>&<%=TOKENSN_PARAMETER %>=<%=token.getTokenSN()%>";
    link = encodeURI(link);
    win_popup = window.open(link, 'view_cert','height=650,width=600,scrollbars=yes,toolbar=no,resizable=1');
    win_popup.focus();
}

function viewcopies(link){
    link = encodeURI(link);
    location.href=link;
}

  <% } %>
-->
</script>
</head>

<body class="popup" id="viewtoken">

  <h2><%= ejbcawebbean.getText("VIEWHARDTOKEN") %></h2>

  <%if(noparameter){%>
  <div class="message alert"><%=ejbcawebbean.getText("YOUMUSTSPECIFYPARAMETER") %></div> 
  <% } 
     else{
       if(token == null){%>
  <div class="message alert"><%=ejbcawebbean.getText("HARDTOKENDOESNTEXIST") %></div> 
    <% }
       else{ 
         if(!authorized){ %>
  <div class="message alert"><%=ejbcawebbean.getText("NOTAUTHORIZEDTOVIEWTOKEN") %></div> 
     <%  }else{%>
    <% if(message != null){ %>
  <div class="message alert"><c:out value='<%= message%>'/></div>
  <% } %>
  <form name="viewtoken" action="<%= THIS_FILENAME %>" method="post">
     <input type="hidden" name='<%= USER_PARAMETER %>' value="<c:out value='<%=java.net.URLEncoder.encode(username,"UTF-8")%>'/>">
     <% if (tokensn != null){ %>
     <input type="hidden" name='<%= TOKENSN_PARAMETER %>' value="<c:out value='<%=token.getTokenSN() %>'/>">
     <% } %>
     <input type="hidden" name='<%= INDEX_PARAMETER %>' value='<%=index %>'>

     <table class="view" border="0" cellpadding="0" cellspacing="2" width="100%">
     
     <!-- ---------- Title ---------- -->
     
     <tr id="Row<%=(row++)%2%>" class="title">
	   <td align="right" width="<%=columnwidth%>"><%= ejbcawebbean.getText("USERNAME") %></td>
	   <td><% if(token.getUsername() != null) out.write(token.getUsername()); %>
       </td>
     </tr> 
     
     <!-- ---------- Index ---------- -->
     
      <% if(alluserstokens){ %>
      <tr id="Row<%=(row++)%2%>">
	<td align="right"><%= ejbcawebbean.getText("HARDTOKENNR") %></td>
	<td><%= (index +1) + " " + ejbcawebbean.getText("OF") + " " + numberoftokens%>
        </td>
      </tr>
      <% } %>
      
       <tr id="Row<%=(row++)%2%>">
         <td  align="right" width="<%=columnwidth%>"> 
           &nbsp;
           <% if(index < numberoftokens -1 ){ %>
           <input type="submit" name="<%= BUTTON_VIEW_OLDER %>" value="&lt; <%= ejbcawebbean.getText("VIEWOLDER") %>" tabindex="1" />
           <% } %>
         </td>
         <td>
           <% if(index > 0 ){ %>
           <input type="submit" name="<%= BUTTON_VIEW_NEWER %>" value="<%= ejbcawebbean.getText("VIEWNEWER") %> &gt;" tabindex="2" />
           <% } %>
           &nbsp;
         </td>
      </tr>
      
      <!-- ---------- Hard token information ---------- -->
       
      <tr id="Row<%=(row++)%2%>">
	    <td>&nbsp;</td>
	    <td>&nbsp;</td>
      </tr>
      
      <tr id="Row<%=(row++)%2%>">
	<td align="right" width="<%=columnwidth%>"><%= ejbcawebbean.getText("HARDTOKENPROFILE") %></td>        
	<td><% if(token.getHardTokenProfileId().intValue() != 0){
                  out.write((String) ejbcawebbean.getInformationMemory().getHardTokenProfileIdToNameMap().get(token.getHardTokenProfileId()));
                }else
                  out.write(ejbcawebbean.getText("NONE"));%>
        </td>
      </tr>
      
      <% if(token.getLabel() != null){ %>
      <tr id="Row<%=(row++)%2%>">
	<td align="right" width="<%=columnwidth%>"><%= ejbcawebbean.getText("LABEL") %></td>        
	<td><% out.write(ejbcawebbean.getText(token.getLabel()));%>
        </td>
      </tr>
      <% } %>
      
      <!-- ---------- Hard token content ---------- -->
      
      <tr id="Row<%=(row++)%2%>">
	<td align="right" width="<%=columnwidth%>"><%= ejbcawebbean.getText("HARDTOKENSN") %></td>
	<td><c:out value='<%= token.getTokenSN()%>'/></td>
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
                if(o != null){ 
                  if( o instanceof java.util.Date){
                    out.write(ejbcawebbean.formatAsISO8601((java.util.Date) o));
                  }else{
                    out.write(o.toString());
                  }
                }%> 
         </td>
       </tr>
       <% }  %>  
       
       <tr id="Row<%=(row++)%2%>">
	 <td>&nbsp;</td>
	 <td>&nbsp;</td>
       </tr>
       
       <tr id="Row<%=(row++)%2%>">
	 <td align="right" width="<%=columnwidth%>"><%= ejbcawebbean.getText("ORIGINALCOPYOF") %></td>
	 <td> <% 
            if(token.isOriginal()){
              out.write(ejbcawebbean.getText("THISISANORIGINAL"));             
              if(token.getCopies() == null || token.getCopies().size() == 0){
                 out.write("<br />" + ejbcawebbean.getText("NOCOPIESHAVEBEENMADE"));
              }else{
                 out.write("<br />" + ejbcawebbean.getText("FOLLOWINGCOPIESHAVEBEEN") + ":");
                 Iterator iter = token.getCopies().iterator();
                 while(iter.hasNext()){ 
                    String copytokensn = (String) iter.next();%>
                   <br />
                   <a  style="cursor:pointer;" onclick="parent.location=encodeURI('<%= VIEWTOKEN_LINK + "?" + TOKENSN_PARAMETER + "=" + copytokensn + "&" + USER_PARAMETER + "=" + java.net.URLEncoder.encode(username,"UTF-8")%>')">
                      <u><c:out value='<%= copytokensn %>'/></u> 
                   </a><%
                 }
              }     
            }else{
              out.write(ejbcawebbean.getText("THISISACOPYOF") + ":<br />");  
              String copyofsn = token.getCopyOf();%>
                 <a style="cursor:pointer;" onclick="parent.location=encodeURI('<%= VIEWTOKEN_LINK + "?" + TOKENSN_PARAMETER + "=" + copyofsn + "&" + USER_PARAMETER + "=" + java.net.URLEncoder.encode(username,"UTF-8")%>')">
                   <u><c:out value='<%= copyofsn %>'/></u> 
                 </a><%
            } %>
      </td> 
       </tr>
       
       <tr id="Row<%=(row++)%2%>">
	 <td>&nbsp;</td>
	 <td>&nbsp;</td>
       </tr>
       <tr id="Row<%=(row)%2%>">
         <td align="right" width="<%=columnwidth%>"><%= ejbcawebbean.getText("CREATED") %></td>
         <td>
           <%= ejbcawebbean.formatAsISO8601(token.getCreateTime()) %>
         </td>
       </tr> 
       
    <tr id="Row<%=(row++)%2%>">
      <td align="right" width="<%=columnwidth%>"><%= ejbcawebbean.getText("MODIFIED") %></td>
      <td>
           <%= ejbcawebbean.formatAsISO8601(token.getModifyTime()) %>
       </td>
     </tr> 
    <tr id="Row<%=(row++)%2%>">
      <td align="right" width="<%=columnwidth%>">&nbsp;</td>
      <td>
        <% try{ 
             if(ejbcawebbean.isAuthorizedNoLog(EjbcaWebBean.AUTHORIZED_CA_VIEW_CERT)){ %>
        <a style="cursor:pointer;" onclick='viewcert()'><u><%= ejbcawebbean.getText("VIEWCERTIFICATES") %></u> </a>
        <%   }
         }catch(AuthorizationDeniedException ade){}
        %>&nbsp; 
       </td>
     </tr> 
     
     <!-- ---------- Actions ---------- -->
     
     <tr id="Row<%=(row++)%2%>">
	<td>
       <%    if(usekeyrecovery ){ %>
        <input type="submit" name="<%=BUTTON_KEYRECOVER %>" value="<%= ejbcawebbean.getText("RECOVERKEY") %>"
               onClick='return confirmkeyrecovery()'>
       <%    }  %>
          &nbsp;
          </td>
          <td>
       <%    if(rabean.authorizedToRevokeCert(username) && ejbcawebbean.isAuthorizedNoLog(EjbcaWebBean.AUTHORIZED_RA_REVOKE_RIGHTS) 
               && !rabean.isAllTokenCertificatesRevoked(token.getTokenSN(),username)){ %>
        <select name="<%=SELECT_REVOKE_REASON %>" >
          <% for(int i=0; i < SecConst.reasontexts.length; i++){ 
               if(i!= 7){ %>
               <option value='<%= i%>'><%= ejbcawebbean.getText(SecConst.reasontexts[i]) %></option>
          <%   } 
             }
           } %> 
        </select>
        <input type="submit" name="<%=BUTTON_REVOKE %>" value="<%= ejbcawebbean.getText("REVOKE") %>"
               onClick='return confirmrevocation()'><br />
        
          &nbsp;
          </td>
       </tr>
       
      <tr id="Row<%=(row++)%2%>">
		<td align="right" width="<%=columnwidth%>">
		  &nbsp;
        </td>
		<td>
          <input type="reset" name="<%= BUTTON_CLOSE %>" value="<%= ejbcawebbean.getText("CLOSE") %>" tabindex="20"
                 onClick='self.close()' />
        </td>
      </tr> 
       
   </table> 
   
 </form>

   <% }
    }
   }%>

</body>
</html>