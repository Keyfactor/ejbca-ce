<!-- Version: $Id: viewcertificate.jsp,v 1.4 2002/08/28 12:22:25 herrvendil Exp $ -->

<html>
<%@page contentType="text/html"%>
<%@page errorPage="/errorpage.jsp"  import="java.math.BigInteger, se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean, se.anatom.ejbca.ra.GlobalConfiguration, 
                 se.anatom.ejbca.webdist.rainterface.RAInterfaceBean, se.anatom.ejbca.webdist.rainterface.CertificateView, se.anatom.ejbca.webdist.rainterface.RevokedInfoView,
                 javax.ejb.CreateException, java.rmi.RemoteException, se.anatom.ejbca.ra.authorization.AuthorizationDeniedException" %>
<jsp:useBean id="ejbcawebbean" scope="session" class="se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean" />
<jsp:setProperty name="ejbcawebbean" property="*" /> 
<jsp:useBean id="rabean" scope="session" class="se.anatom.ejbca.webdist.rainterface.RAInterfaceBean" />
<jsp:setProperty name="rabean" property="*" /> 
<jsp:useBean id="cabean" scope="session" class="se.anatom.ejbca.webdist.cainterface.CAInterfaceBean" />
<jsp:setProperty name="cabean" property="*" /> 
<%! // Declarations
 
  static final String USER_PARAMETER             = "username";
  static final String CERTSERNO_PARAMETER        = "certsernoparameter";
  static final String CACERT_PARAMETER           = "cacert";
  static final String HARDTOKENSN_PARAMETER      = "tokensn";

  static final String BUTTON_CLOSE               = "buttonclose"; 
  static final String BUTTON_VIEW_PREVIOUS       = "buttonviewprevious"; 
  static final String BUTTON_VIEW_NEXT           = "buttonviewnext";
  static final String BUTTON_REVOKE              = "buttonrevoke";
  static final String BUTTON_RECOVERKEY          = "buttonrekoverkey";

  static final String CHECKBOX_DIGITALSIGNATURE  = "checkboxdigitalsignature";
  static final String CHECKBOX_NONREPUDATION     = "checkboxnonrepudation";
  static final String CHECKBOX_KEYENCIPHERMENT   = "checkboxkeyencipherment";
  static final String CHECKBOX_DATAENCIPHERMENT  = "checkboxdataencipherment";
  static final String CHECKBOX_KEYAGREEMENT      = "checkboxkeyagreement";
  static final String CHECKBOX_KEYCERTSIGN       = "checkboxkeycertsign";
  static final String CHECKBOX_CRLSIGN           = "checkboxcrlsign";
  static final String CHECKBOX_ENCIPHERONLY      = "checkboxencipheronly";
  static final String CHECKBOX_DECIPHERONLY      = "checkboxdecipheronly";

  static final String SELECT_REVOKE_REASON       = "selectrevokationreason";

  static final String CHECKBOX_VALUE             = "true";

  static final String HIDDEN_INDEX               = "hiddenindex";

%><%
  // Initialize environment.
  GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, "/ca_functionallity/view_certificate"); 
                                            rabean.initialize(request);
                                            cabean.initialize(request); 

  String THIS_FILENAME            =  globalconfiguration.getAdminWebPath()  + "viewcertificate.jsp";

  boolean noparameter             = true;
  boolean notauthorized           = true;
  boolean cacerts                 = false;
  boolean usekeyrecovery          = globalconfiguration.getEnableKeyRecovery() && ejbcawebbean.isAuthorizedNoLog(EjbcaWebBean.AUTHORIZED_RA_KEYRECOVERY_RIGHTS);
  CertificateView certificatedata = null;
  String certificateserno         = null;
  String username                 = null;         
  String tokensn                  = null;
  int numberofcertificates        = 0;
  int currentindex                = 0;
  
  if( request.getParameter(HARDTOKENSN_PARAMETER) != null && request.getParameter(USER_PARAMETER ) != null){
     username = request.getParameter(USER_PARAMETER );
     tokensn  = request.getParameter(HARDTOKENSN_PARAMETER);
     try{  
       rabean.loadTokenCertificates(tokensn,username);
       notauthorized = false;
     }catch(AuthorizationDeniedException e){}
     noparameter = false;
  }

  if( request.getParameter(USER_PARAMETER ) != null && request.getParameter(HARDTOKENSN_PARAMETER) == null){
     username = request.getParameter(USER_PARAMETER );
     try{  
       rabean.loadCertificates(username);
       notauthorized = false;
     }catch(AuthorizationDeniedException e){}
     noparameter = false;
  }

  if( request.getParameter(CERTSERNO_PARAMETER ) != null){
     certificateserno = request.getParameter(CERTSERNO_PARAMETER );
     try{  
       rabean.loadCertificates(new BigInteger(certificateserno,16)); 
       notauthorized = false;
     }catch(AuthorizationDeniedException e){}
     noparameter = false;
  }
  if( request.getParameter(CACERT_PARAMETER ) != null){
     currentindex = Integer.parseInt(request.getParameter(CACERT_PARAMETER));
     try{  
       ejbcawebbean.isAuthorizedNoLog("/ca_functionallity/basic_functions");
       rabean.loadCACertificates(cabean.getCAInfo()); 
       notauthorized = false;
     }catch(AuthorizationDeniedException e){}
     noparameter = false;
     cacerts = true;
  }
  if(!noparameter){  
    if(request.getParameter(BUTTON_VIEW_PREVIOUS) == null && request.getParameter(BUTTON_VIEW_NEXT) == null && 
       request.getParameter(BUTTON_REVOKE) == null && request.getParameter(BUTTON_RECOVERKEY) == null){
      numberofcertificates = rabean.getNumberOfCertificates();
      if(numberofcertificates > 0)
        certificatedata = rabean.getCertificate(currentindex);
      }
   }
   if(request.getParameter(BUTTON_REVOKE) != null && request.getParameter(HIDDEN_INDEX)!= null && !cacerts){
     currentindex = Integer.parseInt(request.getParameter(HIDDEN_INDEX));
     noparameter=false;
     int reason = Integer.parseInt(request.getParameter(SELECT_REVOKE_REASON));
     certificatedata = rabean.getCertificate(currentindex);
     if(!cacerts && rabean.authorizedToRevokeCert(certificatedata) && ejbcawebbean.isAuthorizedNoLog(EjbcaWebBean.AUTHORIZED_RA_REVOKE_RIGHTS) 
        && !certificatedata.isRevoked())   
       rabean.revokeCert(certificatedata.getSerialNumberBigInt(), certificatedata.getUsername(),reason);
     try{
       if(tokensn !=null)
         rabean.loadTokenCertificates(tokensn,username);
       else 
         if(username != null)
           rabean.loadCertificates(username);
         else
           rabean.loadCertificates(new BigInteger(certificateserno,16));
       notauthorized = false;
     }catch(AuthorizationDeniedException e){
     }
     numberofcertificates = rabean.getNumberOfCertificates();
     certificatedata = rabean.getCertificate(currentindex);
   }
   if(request.getParameter(BUTTON_RECOVERKEY) != null && request.getParameter(HIDDEN_INDEX)!= null && !cacerts){
     // Mark certificate for key recovery.
     currentindex = Integer.parseInt(request.getParameter(HIDDEN_INDEX));
     noparameter=false;
     certificatedata = rabean.getCertificate(currentindex);
     if(!cacerts && rabean.keyRecoveryPossible(certificatedata) && usekeyrecovery)  
       rabean.markForRecovery(certificatedata); 
     try{
       if(tokensn !=null)
         rabean.loadTokenCertificates(tokensn,username);
       else 
         if(username != null)
           rabean.loadCertificates(username);
         else
           rabean.loadCertificates(new BigInteger(certificateserno,16));
       notauthorized = false;
     }catch(AuthorizationDeniedException e){
     }
     numberofcertificates = rabean.getNumberOfCertificates();
     certificatedata = rabean.getCertificate(currentindex);
   }
    
    if(request.getParameter(BUTTON_VIEW_PREVIOUS) != null){
       numberofcertificates = rabean.getNumberOfCertificates();
       noparameter=false;
       if(request.getParameter(HIDDEN_INDEX)!= null){
         currentindex = Integer.parseInt(request.getParameter(HIDDEN_INDEX)) -1;
         if(currentindex < 0){
           currentindex = 0;
         }
         certificatedata = rabean.getCertificate(currentindex);
         notauthorized = false;
       }
    }
    if(request.getParameter(BUTTON_VIEW_NEXT) != null){
       numberofcertificates = rabean.getNumberOfCertificates();
       noparameter=false;
       if(request.getParameter(HIDDEN_INDEX)!= null){
         currentindex = Integer.parseInt(request.getParameter(HIDDEN_INDEX)) + 1;
         if(currentindex > numberofcertificates -1){
           currentindex = numberofcertificates;
         }
         certificatedata = rabean.getCertificate(currentindex);
         notauthorized = false;
       }
    }




  int row = 0; 
  int columnwidth = 150;
%>
<head>
  <title><%= globalconfiguration.getEjbcaTitle() %></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>">
  <link rel=STYLESHEET href="<%= ejbcawebbean.getCssFile() %>">
  <script language=javascript src="<%= globalconfiguration.getAdminWebPath() %>ejbcajslib.js"></script>
  <script language=javascript>
<!--
function confirmrevokation(){
  var returnval = false;
  if(document.viewcertificate.<%= SELECT_REVOKE_REASON %>.options.selectedIndex == -1){
     alert("<%= ejbcawebbean.getText("AREVOKEATIONREASON") %>"); 
     returnval = false;
  }else{
    returnval = confirm("<%= ejbcawebbean.getText("AREYOUSUREREVOKECERT") %>");
  } 
  return returnval;
}

function confirmkeyrecovery(){
  return confirm("<%= ejbcawebbean.getText("AREYOUSUREKEYRECOVER") %>");
}
-->
</script>

</head>
<body >
  <h2 align="center"><%= ejbcawebbean.getText("VIEWCERTIFICATE") %></h2>
  <div align="right"><A  onclick='displayHelpWindow("<%= ejbcawebbean.getHelpfileInfix("viewcertificate_help.html") %>")'>
    <u><%= ejbcawebbean.getText("HELP") %></u> </A>
  </div>
  <%if(noparameter){%>
  <div align="center"><h4 id="alert"><%=ejbcawebbean.getText("YOUMUSTSPECIFYCERT") %></h4></div> 
  <% } 
     else{
      if(notauthorized){%>
  <div align="center"><h4 id="alert"><%=ejbcawebbean.getText("NOTAUTHORIZEDTOVIEWCERT") %></h4></div> 
  <%   } 
       else{
         if(certificatedata == null){%>
  <div align="center"><h4 id="alert"><%=ejbcawebbean.getText("CERTIFICATEDOESNTEXIST") %></h4></div> 
    <%   }
         else{ %>

  <form name="viewcertificate" action="<%= THIS_FILENAME %>" method="post">
    <% if(username != null){ %>
     <input type="hidden" name='<%= USER_PARAMETER %>' value='<%=username %>'> 
     <% } 
     if(tokensn != null){ %>
     <input type="hidden" name='<%= HARDTOKENSN_PARAMETER%>' value='<%=tokensn %>'> 
     <% }       

    if(certificateserno != null){ %>
     <input type="hidden" name='<%= CERTSERNO_PARAMETER %>' value='<%=certificateserno %>'> 
     <% } 
    if(cacerts){ %>
     <input type="hidden" name='<%= CACERT_PARAMETER %>' value='<%=currentindex %>'> 
     <% } %>
     <input type="hidden" name='<%= HIDDEN_INDEX %>' value='<%=currentindex %>'>
     <table border="0" cellpadding="0" cellspacing="2" width="500">
      <% if(username != null){%>
      <tr id="Row<%=(row++)%2%>">
	<td align="right" width="<%=columnwidth%>"><%= ejbcawebbean.getText("USERNAME") %></td>
	<td><%= certificatedata.getUsername() %>
        </td>
      </tr>
      <% if(tokensn != null){ %>
       <tr id="Row<%=(row++)%2%>">
	<td align="right" width="<%=columnwidth%>"><%= ejbcawebbean.getText("HARDTOKENSN") %></td>
	<td><%= tokensn %>
        </td>
      </tr> 
      <% } %> 
      <tr id="Row<%=(row++)%2%>">
	<td align="right" width="<%=columnwidth%>"><%= ejbcawebbean.getText("CERTIFICATENR") %></td>
	<td><%= (currentindex +1) + " " + ejbcawebbean.getText("OF") + " " + numberofcertificates %>
        </td>
      </tr>
      <% } %>
      <tr id="Row<%=(row++)%2%>">
	<td align="right" width="<%=columnwidth%>"><%= ejbcawebbean.getText("CERTIFICATEVERSION") %></td>
	<td> <%= certificatedata.getType() + " " + ejbcawebbean.getText("VER") + certificatedata.getVersion() %>
        </td>
      </tr>
       <tr id="Row<%=(row++)%2%>">
	 <td align="right" width="<%=columnwidth%>"><%= ejbcawebbean.getText("CERTSERIALNUMBER") %></td>
	 <td><%= certificatedata.getSerialNumber() %> 
         </td>
       </tr>
       <tr id="Row<%=(row++)%2%>">
	 <td align="right" width="<%=columnwidth%>"><%= ejbcawebbean.getText("ISSUERDN") %></td>
	 <td><%= certificatedata.getIssuerDN()%> 
         </td>
       </tr>
       <tr id="Row<%=(row++)%2%>">
	 <td align="right" width="<%=columnwidth%>"><%= ejbcawebbean.getText("VALIDFROM") %></td>
	 <td><%= ejbcawebbean.printDate(certificatedata.getValidFrom())  %> 
         </td>
       </tr>
       <tr id="Row<%=(row++)%2%>">
	 <td align="right" width="<%=columnwidth%>"><%= ejbcawebbean.getText("VALIDTO") %></td>
	 <td><%= ejbcawebbean.printDate(certificatedata.getValidTo()) %>
         </td>
       </tr>
       <tr id="Row<%=(row++)%2%>">
	 <td align="right" width="<%=columnwidth%>"><%= ejbcawebbean.getText("SUBJECTDN") %></td>
	 <td><%= certificatedata.getSubjectDN() %> 
         </td>
       </tr>
       <tr id="Row<%=(row++)%2%>">
	 <td align="right" width="<%=columnwidth%>"><%= ejbcawebbean.getText("PUBLICKEY") %></td>
	 <td><%= certificatedata.getPublicKeyAlgorithm() %> <% if(certificatedata.getPublicKeyLength() != null){
                                                                 out.write(" ( " + certificatedata.getPublicKeyLength() + ejbcawebbean.getText("BITS") + ")");  
                                                               } %>
         </td>
       </tr>
       <tr id="Row<%=(row++)%2%>">
	 <td align="right" width="<%=columnwidth%>"><%= ejbcawebbean.getText("BASICCONSTRAINTS") %></td>
	 <td><% if(Integer.parseInt(certificatedata.getBasicConstraints()) == -1)
                     out.write(ejbcawebbean.getText("ENDENTITY"));
                else
                     out.write(ejbcawebbean.getText("CA"));
                   %>
         </td>
       </tr>
       <tr id="Row<%=(row++)%2%>">
	 <td align="right" width="<%=columnwidth%>"><%= ejbcawebbean.getText("KEYUSAGE") %></td>
	 <td><% boolean first= true;
                boolean none = true;
                if(certificatedata.getKeyUsage(CertificateView.DIGITALSIGNATURE)){
                  out.write(ejbcawebbean.getText("DIGITALSIGNATURE"));
                  first=false;
                  none =false;
                }
                if(certificatedata.getKeyUsage(CertificateView.NONREPUDATION)){
                  if(!first) out.write(", "); 
                  first=false;
                  none =false;
                  out.write(ejbcawebbean.getText("NONREPUDATION"));
                }
                if(certificatedata.getKeyUsage(CertificateView.KEYENCIPHERMENT)){
                  if(!first) out.write(", "); 
                  first=false;
                  none =false;
                  out.write(ejbcawebbean.getText("KEYENCIPHERMENT"));
                }
                if(certificatedata.getKeyUsage(CertificateView.DATAENCIPHERMENT)){
                  if(!first) out.write(", "); 
                  first=false;
                  none =false;
                  out.write(ejbcawebbean.getText("DATAENCIPHERMENT"));
                }
                if(certificatedata.getKeyUsage(CertificateView.KEYAGREEMENT)){
                  if(!first) out.write(", "); 
                  first=false;
                  none =false;
                  out.write(ejbcawebbean.getText("KEYAGREEMENT"));
                }
                if(certificatedata.getKeyUsage(CertificateView.KEYCERTSIGN)){
                  if(!first) out.write(", "); 
                  first=false;               
                  none =false;
                  out.write(ejbcawebbean.getText("KEYCERTSIGN"));
                }
                if(certificatedata.getKeyUsage(CertificateView.CRLSIGN)){
                  if(!first) out.write(", "); 
                  first=false;
                  none =false;
                  out.write(ejbcawebbean.getText("CRLSIGN"));
                }
                if(certificatedata.getKeyUsage(CertificateView.ENCIPHERONLY)){
                  if(!first) out.write(", "); 
                  first=false;
                  none =false;
                  out.write(ejbcawebbean.getText("ENCIPHERONLY"));
                }
                if(certificatedata.getKeyUsage(CertificateView.DECIPHERONLY)){
                  if(!first) out.write(", "); 
                  first=false;
                  none =false;
                  out.write(ejbcawebbean.getText("DECIPHERONLY"));
               }
               if(none){
                  out.write(ejbcawebbean.getText("NOKEYUSAGESPECIFIED"));          
              }
%>
         </td>
       </tr>
       <tr id="Row<%=(row++)%2%>">
	 <td align="right" width="<%=columnwidth%>"><%= ejbcawebbean.getText("SIGNATUREALGORITHM") %></td>
	 <td> <%= certificatedata.getSignatureAlgoritm() %>
         </td>
       </tr>
       <tr  id="Row<%=(row++)%2%>"> 
        <td  align="right" width="<%=columnwidth%>"> 
          <%= ejbcawebbean.getText("SHA1FINGERPRINT") %> <br>
        </td>
        <td >  <%= certificatedata.getSHA1Fingerprint() %>
        </td>
       </tr>
       <tr  id="Row<%=(row++)%2%>"> 
        <td  align="right" width="<%=columnwidth%>"> 
          <%= ejbcawebbean.getText("MD5FINGERPRINT") %> <br>
        </td>
        <td >  <%= certificatedata.getMD5Fingerprint() %>
        </td>
       </tr>
       <tr  id="Row<%=(row++)%2%>"> 
        <td  align="right" width="<%=columnwidth%>"> 
          <%= ejbcawebbean.getText("REVOKED") %> <br>
        </td>
        <td >  <% if(certificatedata.isRevoked()){
                    out.write(ejbcawebbean.getText("YES") + "<br>" + ejbcawebbean.getText("REVOKATIONDATE") +
                              ejbcawebbean.printDate(certificatedata.getRevokationDate()) + "<br>" + ejbcawebbean.getText("REVOKATIONREASONS"));
                    String[] reasons = certificatedata.getRevokationReasons();
                    for(int i = 0; i < reasons.length; i++){
                      out.write(ejbcawebbean.getText(reasons[i]));
                      if(i+1 < reasons.length)
                        out.write(", ");
                    }
                  }
                  else{
                    out.write(ejbcawebbean.getText("NO"));
                  }%>
        </td>
       </tr>
       <tr id="Row<%=(row++)%2%>">
          <td>&nbsp;</td>
          <td>
          <% if(currentindex > 0 ){ %>
           <input type="submit" name="<%= BUTTON_VIEW_PREVIOUS %>" value="<%= ejbcawebbean.getText("VIEWPREVIOUS") %>" tabindex="1">&nbsp;&nbsp;&nbsp;
          <% } %>
            <input type="button" name="<%= BUTTON_CLOSE %>" value="<%= ejbcawebbean.getText("CLOSE") %>" tabindex="2"
                   onClick='self.close()'>  
          <% if(currentindex < numberofcertificates -1 ){ %>
          &nbsp;&nbsp;&nbsp;<input type="submit" name="<%= BUTTON_VIEW_NEXT %>" value="<%= ejbcawebbean.getText("VIEWNEXT") %>" tabindex="3">
          <% } %>
          &nbsp;
          </td>
       </tr> 
       <tr id="Row<%=(row++)%2%>">
          <td>  
       <% 
            if(!cacerts &&  rabean.keyRecoveryPossible(certificatedata) && usekeyrecovery){ %>
        <input type="submit" name="<%=BUTTON_RECOVERKEY %>" value="<%= ejbcawebbean.getText("RECOVERKEY") %>"
               onClick='return confirmkeyrecovery()'>
       <% } %>
         &nbsp;
          </td>
          <td>
       <% 
            if(!cacerts && rabean.authorizedToRevokeCert(certificatedata) && ejbcawebbean.isAuthorizedNoLog(EjbcaWebBean.AUTHORIZED_RA_REVOKE_RIGHTS) 
               && !certificatedata.isRevoked()){ %>
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
   <%   }
      }
    }%>

</body>
</html>
