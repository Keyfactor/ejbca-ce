<!-- Version: $Id: viewcertificate.jsp 9285 2010-06-24 07:22:34Z anatom $ -->
<%@ page pageEncoding="ISO-8859-1"%>
<% response.setContentType("text/html; charset="+org.ejbca.config.WebConfiguration.getWebContentEncoding()); %>
<%@page errorPage="/errorpage.jsp"  import="java.math.BigInteger, org.ejbca.ui.web.admin.configuration.EjbcaWebBean, org.ejbca.core.model.ra.raadmin.GlobalConfiguration, org.ejbca.core.model.ca.certificateprofiles.CertificateProfile,
    org.ejbca.ui.web.RequestHelper,org.ejbca.ui.web.CertificateView, org.ejbca.ui.web.RevokedInfoView,
                 org.ejbca.core.model.authorization.AuthorizationDeniedException, org.ejbca.util.CertTools" %>
<html>
<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />
<jsp:useBean id="rabean" scope="session" class="org.ejbca.ui.web.admin.rainterface.RAInterfaceBean" />
<jsp:useBean id="cabean" scope="session" class="org.ejbca.ui.web.admin.cainterface.CAInterfaceBean" />

<%! // Declarations
 
  static final String USER_PARAMETER             = "username";
  static final String CERTSERNO_PARAMETER        = "certsernoparameter";
  static final String CACERT_PARAMETER           = "caid";
  static final String HARDTOKENSN_PARAMETER      = "tokensn";

  static final String BUTTON_CLOSE               = "buttonclose"; 
  static final String BUTTON_VIEW_PREVIOUS       = "buttonviewprevious"; 
  static final String BUTTON_VIEW_NEXT           = "buttonviewnext";
  static final String BUTTON_REVOKE              = "buttonrevoke";
  static final String BUTTON_UNREVOKE            = "buttonunrevoke";
  static final String BUTTON_RECOVERKEY          = "buttonrekoverkey";
  static final String BUTTON_REPUBLISH           = "buttonrepublish";

  static final String CHECKBOX_DIGITALSIGNATURE  = "checkboxdigitalsignature";
  static final String CHECKBOX_NONREPUDIATION    = "checkboxnonrepudiation";
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
  GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, "/ca_functionality/view_certificate"); 
                                            rabean.initialize(request, ejbcawebbean);
                                            cabean.initialize(request, ejbcawebbean); 

  String THIS_FILENAME            =  globalconfiguration.getAdminWebPath()  + "viewcertificate.jsp";

  final String DOWNLOADCERTIFICATE_LINK     = globalconfiguration.getCaPath() 
                                                  + "/endentitycert";

  boolean noparameter             = true;
  boolean notauthorized           = true;
  boolean cacerts                 = false;
  boolean usekeyrecovery          = false;   
  CertificateView certificatedata = null;
  String certificateserno         = null;
  String issuerdn                 = null;
  String username                 = null;         
  String tokensn                  = null;
  String message                  = null;
  int numberofcertificates        = 0;
  int currentindex                = 0;
  int caid                        = 0;

  try{
    usekeyrecovery = globalconfiguration.getEnableKeyRecovery() && ejbcawebbean.isAuthorizedNoLog(EjbcaWebBean.AUTHORIZED_RA_KEYRECOVERY_RIGHTS);
  }catch(AuthorizationDeniedException ade){}

  RequestHelper.setDefaultCharacterEncoding(request);

  if( request.getParameter(HARDTOKENSN_PARAMETER) != null && request.getParameter(USER_PARAMETER ) != null){
     username = java.net.URLDecoder.decode(request.getParameter(USER_PARAMETER),"UTF-8");
     tokensn  = request.getParameter(HARDTOKENSN_PARAMETER);
     rabean.loadTokenCertificates(tokensn,username);
     notauthorized = false;
     noparameter = false;
  }

  if( request.getParameter(USER_PARAMETER ) != null && request.getParameter(HARDTOKENSN_PARAMETER) == null){
     username = java.net.URLDecoder.decode(request.getParameter(USER_PARAMETER),"UTF-8");
     rabean.loadCertificates(username);
     notauthorized = false;
     noparameter = false;
  }

  if( request.getParameter(CERTSERNO_PARAMETER ) != null){     
     String[] certdata = java.net.URLDecoder.decode(request.getParameter(CERTSERNO_PARAMETER ),"UTF-8").split(",",2);
     certificateserno = certdata[0];
     issuerdn = CertTools.stringToBCDNString(certdata[1]);
     rabean.loadCertificates(new BigInteger(certificateserno,16), issuerdn); 
     notauthorized = false;
     noparameter = false;
  }
  if( request.getParameter(CACERT_PARAMETER ) != null){
     caid = Integer.parseInt(request.getParameter(CACERT_PARAMETER));
     if(request.getParameter(BUTTON_VIEW_PREVIOUS) == null && request.getParameter(BUTTON_VIEW_NEXT) == null){
       try{  
         ejbcawebbean.isAuthorizedNoLog("/ca_functionality/basic_functions");
         ejbcawebbean.isAuthorized(org.ejbca.core.model.authorization.AccessRulesConstants.CAPREFIX + caid);
         rabean.loadCACertificates(cabean.getCACertificates(caid)); 
         numberofcertificates = rabean.getNumberOfCertificates();
         if(numberofcertificates > 0)
          currentindex = 0;     
         notauthorized = false;
       }catch(AuthorizationDeniedException e){}
       noparameter = false;
     }
     cacerts = true;
  }
  if(!noparameter){  
     if(request.getParameter(BUTTON_VIEW_PREVIOUS) == null && request.getParameter(BUTTON_VIEW_NEXT) == null && 
        request.getParameter(BUTTON_REVOKE) == null && request.getParameter(BUTTON_RECOVERKEY) == null &&
        request.getParameter(BUTTON_REPUBLISH) == null ){
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
     if(!cacerts && rabean.authorizedToRevokeCert(certificatedata.getUsername()) && ejbcawebbean.isAuthorizedNoLog(EjbcaWebBean.AUTHORIZED_RA_REVOKE_RIGHTS) 
        && !certificatedata.isRevoked()) {
		try {
	    	rabean.revokeCert(certificatedata.getSerialNumberBigInt(), certificatedata.getIssuerDNUnEscaped(), certificatedata.getUsername(),reason);
		} catch (org.ejbca.core.model.approval.ApprovalException e) {
			message = "THEREALREADYEXISTSAPPOBJ";
		} catch (org.ejbca.core.model.approval.WaitingForApprovalException e) {
			message = "REQHAVEBEENADDEDFORAPPR";
		}
	 }
     try {
       if(tokensn !=null) {
         rabean.loadTokenCertificates(tokensn,username);
       } else {
         if(username != null) {
           rabean.loadCertificates(username);
         } else {
           rabean.loadCertificates(new BigInteger(certificateserno,16), issuerdn);
         }
       }
       notauthorized = false;
     }catch(AuthorizationDeniedException e){
     }
     numberofcertificates = rabean.getNumberOfCertificates();
     certificatedata = rabean.getCertificate(currentindex);
   }
	 //-- Pushed unrevoke button
	if( (request.getParameter(BUTTON_UNREVOKE) != null) && request.getParameter(HIDDEN_INDEX)!= null && !cacerts){
	
		currentindex = Integer.parseInt(request.getParameter(HIDDEN_INDEX));
		noparameter = false;
		certificatedata = rabean.getCertificate(currentindex);

		if(!cacerts && rabean.authorizedToRevokeCert(certificatedata.getUsername()) 
			&& ejbcawebbean.isAuthorizedNoLog(EjbcaWebBean.AUTHORIZED_RA_REVOKE_RIGHTS) && certificatedata.isRevoked()
			&& "CERTIFICATEHOLD".equals(certificatedata.getRevokationReasons()[0])){
				//-- call to unrevoke method
				try {
					rabean.unrevokeCert(certificatedata.getSerialNumberBigInt(), certificatedata.getIssuerDNUnEscaped(), certificatedata.getUsername());
				} catch (org.ejbca.core.model.approval.ApprovalException e) {
					message = "THEREALREADYEXISTSAPPOBJ";
				} catch (org.ejbca.core.model.approval.WaitingForApprovalException e) {
					message = "REQHAVEBEENADDEDFORAPPR";
				}
		}
		
		try {
			if(tokensn !=null) {
				rabean.loadTokenCertificates(tokensn,username);
			} else {
				if(username != null) {
					rabean.loadCertificates(username);
				} else {
					rabean.loadCertificates(new BigInteger(certificateserno,16), issuerdn);
				}
			}
			notauthorized = false;
		}catch(AuthorizationDeniedException e){}
		
		numberofcertificates = rabean.getNumberOfCertificates();
		certificatedata = rabean.getCertificate(currentindex);
	}
   
   if(request.getParameter(BUTTON_RECOVERKEY) != null && request.getParameter(HIDDEN_INDEX)!= null && !cacerts){
     // Mark certificate for key recovery.
     currentindex = Integer.parseInt(request.getParameter(HIDDEN_INDEX));
     noparameter=false;
     certificatedata = rabean.getCertificate(currentindex);
     if(!cacerts && rabean.keyRecoveryPossible(certificatedata.getCertificate(), certificatedata.getUsername()) && usekeyrecovery){
         try{
        	 rabean.markForRecovery(certificatedata.getUsername(), certificatedata.getCertificate()); 
           }catch(org.ejbca.core.model.approval.ApprovalException e){
        	   message = "THEREALREADYEXISTSAPPROVAL";
           }catch(org.ejbca.core.model.approval.WaitingForApprovalException e){
        	   message = "REQHAVEBEENADDEDFORAPPR";
           }       
     }       
     try{
       if(tokensn !=null) {
        rabean.loadTokenCertificates(tokensn,username);
       } else { 
         if(username != null) {
           rabean.loadCertificates(username);
         } else {
           rabean.loadCertificates(new BigInteger(certificateserno,16), issuerdn);
         }
       }
       notauthorized = false;
     }catch(AuthorizationDeniedException e){
     }
     numberofcertificates = rabean.getNumberOfCertificates();
     certificatedata = rabean.getCertificate(currentindex);
   }
   if(request.getParameter(BUTTON_REPUBLISH) != null && request.getParameter(HIDDEN_INDEX)!= null && !cacerts){
     // Mark certificate for key recovery.
     currentindex = Integer.parseInt(request.getParameter(HIDDEN_INDEX));
     noparameter=false;
     certificatedata = rabean.getCertificate(currentindex);
     message = cabean.republish(certificatedata); 
     try{
       if(tokensn !=null)
         rabean.loadTokenCertificates(tokensn,username);
       else 
         if(username != null)
           rabean.loadCertificates(username);
         else
           rabean.loadCertificates(new BigInteger(certificateserno,16), issuerdn);
       notauthorized = false;
     }catch(AuthorizationDeniedException e){
     }
     numberofcertificates = rabean.getNumberOfCertificates();
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
     alert("<%= ejbcawebbean.getText("AREVOKEATIONREASON", true) %>"); 
     returnval = false;
  }else{
    returnval = confirm("<%= ejbcawebbean.getText("AREYOUSUREREVOKECERT",true) %>");
  } 
  return returnval;
}

function confirmunrevokation(){
  var returnval = confirm("<%= ejbcawebbean.getText("AREYOUSUREUNREVOKECERT",true) %>");
  return returnval;
}

function confirmkeyrecovery(){
  return confirm("<%= ejbcawebbean.getText("AREYOUSUREKEYRECOVER") %>");
}


function confirmrepublish(){
  return confirm("<%= ejbcawebbean.getText("AREYOUSUREREPUBLISH") %>");
}
-->
</script>

</head>
<body >
  <h2 align="center"><%= ejbcawebbean.getText("VIEWCERTIFICATE") %></h2>
 <!-- 
  <div align="right"><A  onclick='displayHelpWindow("<%= ejbcawebbean.getHelpfileInfix("viewcertificate_help.html") %>")'>
    <u><%= ejbcawebbean.getText("HELP") %></u> </A>  
  </div> 
  -->
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
         else{         	 
   if(message != null){ %>
      <div align="center"><h4 id="alert"><%=ejbcawebbean.getText(message) %></h4></div> 
  <% } %>
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
     <input type="hidden" name='<%= CACERT_PARAMETER %>' value='<%=caid %>'> 
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
	 <td><%= ejbcawebbean.printDateTime(certificatedata.getValidFrom())  %> 
         </td>
       </tr>
       <tr id="Row<%=(row++)%2%>">
	 <td align="right" width="<%=columnwidth%>"><%= ejbcawebbean.getText("VALIDTO") %></td>
	 <td><%= ejbcawebbean.printDateTime(certificatedata.getValidTo()) %>
         </td>
       </tr>
       <tr id="Row<%=(row++)%2%>">
	 <td align="right" width="<%=columnwidth%>"><%= ejbcawebbean.getText("SUBJECTDN") %></td>
	 <td><%= certificatedata.getSubjectDN() %> 
         </td>
       </tr>
       
      <% if (!certificatedata.getType().equalsIgnoreCase("CVC")) { %>
	       <tr id="Row<%=(row++)%2%>">
		 <td align="right" width="<%=columnwidth%>"><%= ejbcawebbean.getText("SUBALTNAME") %></td>
		 <td><% if(certificatedata.getSubjectAltName() == null)
	                  out.write(ejbcawebbean.getText("NONE"));
	                else
	                  out.write(certificatedata.getSubjectAltName());%> 
	         </td>
	       </tr>
	       <tr id="Row<%=(row++)%2%>">
		 <td align="right" width="<%=columnwidth%>"><%= ejbcawebbean.getText("SUBDIRATTR") %></td>
		 <td><% if(certificatedata.getSubjectDirAttr() == null)
	                  out.write(ejbcawebbean.getText("NONE"));
	                else
	                  out.write(certificatedata.getSubjectDirAttr());%> 
	         </td>
	       </tr>
     <% } // if (!certificatedata.getType().equalsIgnoreCase("CVC")) %>
       
       <tr id="Row<%=(row++)%2%>">
	 <td align="right" width="<%=columnwidth%>"><%= ejbcawebbean.getText("PUBLICKEY") %></td>
	 <td><%= certificatedata.getPublicKeyAlgorithm() %> 
	 	 <% out.write(" (" + certificatedata.getKeySpec(ejbcawebbean.getText("BITS")) + ")");
	 	    if (certificatedata.getPublicKeyModulus() != null) {
	 	    	out.write(": "+certificatedata.getPublicKeyModulus());  
            } %>
         </td>
       </tr>
       <tr id="Row<%=(row++)%2%>">
	 <td align="right" width="<%=columnwidth%>"><%= ejbcawebbean.getText("BASICCONSTRAINTS") %></td>
	 <td><%=  certificatedata.getBasicConstraints(ejbcawebbean.getText("NONE"), ejbcawebbean.getText("CANOLIMIT"), ejbcawebbean.getText("ENDENTITY"), ejbcawebbean.getText("CAPATHLENGTH"))  %>
         </td>
       </tr>
       
     <% if (!certificatedata.getType().equalsIgnoreCase("CVC")) { %>
	       <tr id="Row<%=(row++)%2%>">
		 <td align="right" width="<%=columnwidth%>"><%= ejbcawebbean.getText("KEYUSAGE") %></td>
		 <td><% boolean first= true;
	                boolean none = true;
	                if(certificatedata.getKeyUsage(CertificateProfile.DIGITALSIGNATURE)){
	                  out.write(ejbcawebbean.getText("DIGITALSIGNATURE"));
	                  first=false;
	                  none =false;
	                }
	                if(certificatedata.getKeyUsage(CertificateProfile.NONREPUDIATION)){
	                  if(!first) out.write(", "); 
	                  first=false;
	                  none =false;
	                  out.write(ejbcawebbean.getText("NONREPUDIATION"));
	                }
	                if(certificatedata.getKeyUsage(CertificateProfile.KEYENCIPHERMENT)){
	                  if(!first) out.write(", "); 
	                  first=false;
	                  none =false;
	                  out.write(ejbcawebbean.getText("KEYENCIPHERMENT"));
	                }
	                if(certificatedata.getKeyUsage(CertificateProfile.DATAENCIPHERMENT)){
	                  if(!first) out.write(", "); 
	                  first=false;
	                  none =false;
	                  out.write(ejbcawebbean.getText("DATAENCIPHERMENT"));
	                }
	                if(certificatedata.getKeyUsage(CertificateProfile.KEYAGREEMENT)){
	                  if(!first) out.write(", "); 
	                  first=false;
	                  none =false;
	                  out.write(ejbcawebbean.getText("KEYAGREEMENT"));
	                }
	                if(certificatedata.getKeyUsage(CertificateProfile.KEYCERTSIGN)){
	                  if(!first) out.write(", "); 
	                  first=false;               
	                  none =false;
	                  out.write(ejbcawebbean.getText("KEYCERTSIGN"));
	                }
	                if(certificatedata.getKeyUsage(CertificateProfile.CRLSIGN)){
	                  if(!first) out.write(", "); 
	                  first=false;
	                  none =false;
	                  out.write(ejbcawebbean.getText("CRLSIGN"));
	                }
	                if(certificatedata.getKeyUsage(CertificateProfile.ENCIPHERONLY)){
	                  if(!first) out.write(", "); 
	                  first=false;
	                  none =false;
	                  out.write(ejbcawebbean.getText("ENCIPHERONLY"));
	                }
	                if(certificatedata.getKeyUsage(CertificateProfile.DECIPHERONLY)){
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
		 <td align="right" width="<%=columnwidth%>"><%= ejbcawebbean.getText("EXTENDEDKEYUSAGE") %></td>
		 <td><% String[] extendedkeyusage = certificatedata.getExtendedKeyUsageAsTexts();
	                for(int i=0; i<extendedkeyusage.length; i++){
	                  if(i>0)
	                    out.write(", ");
	                  out.write( ejbcawebbean.getText(extendedkeyusage[i]));
	                }                
	                if(extendedkeyusage == null || extendedkeyusage.length == 0)
	                  out.write(ejbcawebbean.getText("NOEXTENDEDKEYUSAGESPECIFIED"));                       
	%>
	         </td>
	       </tr>
	       <tr id="Row<%=(row++)%2%>">
		 <td align="right" width="<%=columnwidth%>"><%= ejbcawebbean.getText("QUALIFIEDCERTSTATEMENT") %></td>
		 <td><% if (certificatedata.hasQcStatement()) {
			 out.write(ejbcawebbean.getText("YES"));
		 } else {
			 out.write(ejbcawebbean.getText("NO"));
		 }
	%>
	         </td>
	       </tr>
     <% } // if (!certificatedata.getType().equalsIgnoreCase("CVC")) %>
       
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
            if(!cacerts &&  rabean.keyRecoveryPossible(certificatedata.getCertificate(), certificatedata.getUsername()) && usekeyrecovery){ %>
        <input type="submit" name="<%=BUTTON_RECOVERKEY %>" value="<%= ejbcawebbean.getText("RECOVERKEY") %>"
               onClick='return confirmkeyrecovery()'><br>
       <% }
            if(!cacerts &&  rabean.userExist(certificatedata.getUsername()) && rabean.isAuthorizedToEditUser(certificatedata.getUsername())){ %>
        <input type="submit" name="<%=BUTTON_REPUBLISH %>" value="<%= ejbcawebbean.getText("REPUBLISH") %>"
               onClick='return confirmrepublish()'>
       <% } %>
         &nbsp;
          </td>
          <td>
       <%  try{
            if(!cacerts && rabean.authorizedToRevokeCert(certificatedata.getUsername()) && ejbcawebbean.isAuthorizedNoLog(EjbcaWebBean.AUTHORIZED_RA_REVOKE_RIGHTS)){
				if ( !certificatedata.isRevoked() ){
					//-- Certificate can be revoked or suspended
		%>    
        <input type="submit" name="<%=BUTTON_REVOKE %>" value="<%= ejbcawebbean.getText("REVOKE") %>"
               onClick='return confirmrevokation()'><br>
        <select name="<%=SELECT_REVOKE_REASON %>" >
          <% for(int i=0; i < RevokedInfoView.reasontexts.length; i++){ 
               if(i!= 7){%>
	               <option value='<%= i%>'><%= ejbcawebbean.getText(RevokedInfoView.reasontexts[i]) %></option>
          <%   } 
             }%>
        </select>
<% 
			  }else if ( certificatedata.isRevoked() && "CERTIFICATEHOLD".equals(certificatedata.getRevokationReasons()[0]) ){
				//-- Certificate can be unrevoked
%>
				<input type="submit" name="<%=BUTTON_UNREVOKE %>" value="<%= ejbcawebbean.getText("UNREVOKE") %>"
                onClick='return confirmunrevokation()'><br>	
<%
			  }
		   }
         }catch(AuthorizationDeniedException ade){}%> 
          &nbsp;
          </td>
       </tr> 
         <% if(!cacerts){ %>
         <tr id="Row<%=row%2%>">
            <td>&nbsp;</td>
            <td>               
              <a href="<%=DOWNLOADCERTIFICATE_LINK%>?cmd=iecert&certificatesn=<%= certificatedata.getSerialNumber()%>&issuer=<%= certificatedata.getIssuerDN() %>"><%= ejbcawebbean.getText("DOWNLOADIE")%></a><br>
              <a href="<%=DOWNLOADCERTIFICATE_LINK%>?cmd=nscert&certificatesn=<%= certificatedata.getSerialNumber()%>&issuer=<%= certificatedata.getIssuerDN() %>"><%= ejbcawebbean.getText("DOWNLOADNS")%></a><br>
              <a href="<%=DOWNLOADCERTIFICATE_LINK%>?cmd=cert&certificatesn=<%= certificatedata.getSerialNumber()%>&issuer=<%= certificatedata.getIssuerDN() %>"><%= ejbcawebbean.getText("DOWNLOADPEM")%></a>
            </td>   
         </tr> 
         <% } %>
     </table> 
   </form>
   <p></p>
   <%   }
      }
    }%>

</body>
</html>
