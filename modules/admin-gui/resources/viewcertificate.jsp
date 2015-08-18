<!-- Version: $Id: viewcertificate.jsp 9285 2010-06-24 07:22:34Z anatom $ -->
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ page pageEncoding="ISO-8859-1"%>
<% response.setContentType("text/html; charset="+org.ejbca.config.WebConfiguration.getWebContentEncoding()); %>
<%@page errorPage="/errorpage.jsp"  import="java.math.BigInteger, org.ejbca.ui.web.admin.configuration.EjbcaWebBean, org.ejbca.config.GlobalConfiguration, org.cesecore.certificates.certificateprofile.CertificateProfile,
    org.ejbca.ui.web.RequestHelper,org.ejbca.ui.web.CertificateView, org.ejbca.ui.web.RevokedInfoView,org.ejbca.core.model.SecConst,
                 org.cesecore.authorization.AuthorizationDeniedException, org.cesecore.util.CertTools, org.cesecore.certificates.certificate.CertificateConstants,
                 org.cesecore.authorization.control.StandardRules, org.ejbca.core.model.authorization.AccessRulesConstants" %>
<html>
<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />
<jsp:useBean id="rabean" scope="session" class="org.ejbca.ui.web.admin.rainterface.RAInterfaceBean" />
<jsp:useBean id="cabean" scope="session" class="org.ejbca.ui.web.admin.cainterface.CAInterfaceBean" />

<%! // Declarations
 
  static final String USER_PARAMETER             = "username";
  static final String CERTSERNO_PARAMETER        = "certsernoparameter";
  static final String CACERT_PARAMETER           = "caid";
  static final String HARDTOKENSN_PARAMETER      = "tokensn";
  static final String SERNO_PARAMETER            = "serno";
  static final String ISSUER_PARAMETER           = "issuer";
  static final String CADN_PARAMETER             = "cadn";

  static final String BUTTON_CLOSE               = "buttonclose"; 
  static final String BUTTON_VIEW_NEWER          = "buttonviewnewer"; 
  static final String BUTTON_VIEW_OLDER          = "buttonviewolder";
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

  static final String SELECT_REVOKE_REASON       = "selectrevocationreason";

  static final String CHECKBOX_VALUE             = "true";

  static final String HIDDEN_INDEX               = "hiddenindex";

%><%
  // Initialize environment.
  GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, AccessRulesConstants.REGULAR_VIEWCERTIFICATE); 
                                            rabean.initialize(request, ejbcawebbean);
                                            cabean.initialize(ejbcawebbean); 

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
     rabean.loadTokenCertificates(tokensn);
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
		String certSernoParam = java.net.URLDecoder.decode(request.getParameter(CERTSERNO_PARAMETER), "UTF-8");
		if (certSernoParam != null) {
			String[] certdata = ejbcawebbean.getCertSernoAndIssuerdn(certSernoParam);
			if (certdata != null && certdata.length > 0) {
			    rabean.loadCertificates(new BigInteger(certdata[0], 16),certdata[1]);
			}
		}
     notauthorized = false;
     noparameter = false;
  }
  if (request.getParameter(SERNO_PARAMETER) != null && request.getParameter(CACERT_PARAMETER) != null) {
		 String certificateSerno = request.getParameter(SERNO_PARAMETER);
		 caid = Integer.parseInt(request.getParameter(CACERT_PARAMETER));
	     rabean.loadCertificates(new BigInteger(certificateSerno,16), caid); 
	     notauthorized = false;
	     noparameter = false;
  } else if( request.getParameter(CACERT_PARAMETER ) != null){
     caid = Integer.parseInt(request.getParameter(CACERT_PARAMETER));
     if(request.getParameter(BUTTON_VIEW_NEWER) == null && request.getParameter(BUTTON_VIEW_OLDER) == null){
       try{  
         ejbcawebbean.isAuthorized(StandardRules.CAVIEW.resource(), StandardRules.CAACCESS.resource() + caid);
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
     if(request.getParameter(BUTTON_VIEW_NEWER) == null && request.getParameter(BUTTON_VIEW_OLDER) == null && 
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
        && (!certificatedata.isRevoked()||certificatedata.isRevokedAndOnHold()) ) {
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
         rabean.loadTokenCertificates(tokensn);
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
			&& ejbcawebbean.isAuthorizedNoLog(EjbcaWebBean.AUTHORIZED_RA_REVOKE_RIGHTS) && certificatedata.isRevokedAndOnHold()){
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
				rabean.loadTokenCertificates(tokensn);
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
        rabean.loadTokenCertificates(tokensn);
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
         rabean.loadTokenCertificates(tokensn);
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
    
    if(request.getParameter(BUTTON_VIEW_NEWER) != null){
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
    if(request.getParameter(BUTTON_VIEW_OLDER) != null){
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
  <title><c:out value="<%= globalconfiguration.getEjbcaTitle() %>" /></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>" />
  <link rel="shortcut icon" href="<%=ejbcawebbean.getImagefileInfix("favicon.png")%>" type="image/png" />
  <link rel="stylesheet" type="text/css" href="<%= ejbcawebbean.getCssFile() %>" />
  <script type="text/javascript" src="<%= globalconfiguration.getAdminWebPath() %>ejbcajslib.js"></script>
  <script type="text/javascript">
<!--
function confirmrevocation(){
  var returnval = false;
  if(document.viewcertificate.<%= SELECT_REVOKE_REASON %>.options.selectedIndex == -1){
     alert("<%= ejbcawebbean.getText("AREVOKEATIONREASON", true) %>"); 
     returnval = false;
  }else{
    returnval = confirm("<%= ejbcawebbean.getText("AREYOUSUREREVOKECERT",true) %>");
  } 
  return returnval;
}

function confirmunrevocation(){
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

<body class="popup" id="viewcertificate">

  <h2><%= ejbcawebbean.getText("VIEWCERTIFICATE") %></h2>

  <%if(noparameter){%>
  <div class="message alert"><%=ejbcawebbean.getText("YOUMUSTSPECIFYCERT") %></div> 
  <% } 
     else{
      if(notauthorized){%>
  <div class="message alert"><%=ejbcawebbean.getText("NOTAUTHORIZEDTOVIEWCERT") %></div> 
  <%   } 
       else{
         if(certificatedata == null){%>
  <div class="message alert"><%=ejbcawebbean.getText("CERTIFICATEDOESNTEXIST") %></div> 
    <%   }
         else{         	 
   if(message != null){ %>
      <div class="message alert"><%=ejbcawebbean.getText(message) %></div> 
  <% } %>


  <form name="viewcertificate" action="<%= THIS_FILENAME %>" method="post">
    <% if(username != null){ %>
     <input type="hidden" name='<%= USER_PARAMETER %>' value='<c:out value="<%= username %>"/>'> 
     <% } 
     if(tokensn != null){ %>
     <input type="hidden" name='<%= HARDTOKENSN_PARAMETER%>' value='<c:out value="<%= tokensn %>"/>'> 
     <% }       
    if(certificateserno != null){ %>
     <input type="hidden" name='<%= CERTSERNO_PARAMETER %>' value='<c:out value="<%= certificateserno %>"/>'> 
     <% } 
    if(cacerts){ %>
     <input type="hidden" name='<%= CACERT_PARAMETER %>' value='<c:out value="<%= caid %>"/>'> 
     <% } %>
     <input type="hidden" name='<%= HIDDEN_INDEX %>' value='<c:out value="<%= currentindex %>"/>'>


     <table class="view" border="0" cellpadding="0" cellspacing="2" width="100%">

      <!-- ---------- Title ---------- -->

      <% if(username != null){ %>
      <tr id="Row<%=(row++)%2%>" class="title">
		<td align="right" width="<%=columnwidth%>"><strong><%= ejbcawebbean.getText("USERNAME") %></strong></td>
		<td><strong><c:out value="<%= certificatedata.getUsername() %>"/></strong></td>
      </tr>
      <% } %>
      <% if(caid != 0){ %>
      <tr id="Row<%=(row++)%2%>" class="title">
		 <td align="right" width="<%=columnwidth%>"><strong><%= ejbcawebbean.getText("CANAME") %></strong></td>
		 <td><strong><c:out value="<%= cabean.getName(caid) %>"/></strong> (<c:out value="<%= caid %>"/>)</td>
      </tr>
      <% } %>

      <!-- ---------- Index ---------- -->

      <% if(username != null){ %>
      <% if(tokensn != null){ %>
       <tr id="Row<%=(row++)%2%>">
		<td align="right" width="<%=columnwidth%>"><%= ejbcawebbean.getText("HARDTOKENSN") %></td>
		<td><%= tokensn %></td>
      </tr> 
      <% } %> 

      <tr id="Row<%=(row++)%2%>">
		<td align="right" width="<%=columnwidth%>"><%= ejbcawebbean.getText("CERTIFICATENR") %></td>
		<td><%= (currentindex +1) + " " + ejbcawebbean.getText("OF") + " " + numberofcertificates %></td>
      </tr>
      <% } // if(username != null) %>

      <tr id="Row<%=(row++)%2%>">
         <td  align="right" width="<%=columnwidth%>"> 
           &nbsp;
           <% if (!cacerts && (currentindex < numberofcertificates -1) ){ %>
           <input type="submit" name="<%= BUTTON_VIEW_OLDER %>" value="&lt; <%= ejbcawebbean.getText("VIEWOLDER") %>" tabindex="1" />
           <% } else if (currentindex < numberofcertificates -1) {%>
           <input type="submit" name="<%= BUTTON_VIEW_OLDER %>" value="&lt; <%= ejbcawebbean.getText("VIEWISSUING") %>" tabindex="1" />
           <% } %>
         </td>
         <td>
           <% if (!cacerts && (currentindex > 0) ){ %>
           <input type="submit" name="<%= BUTTON_VIEW_NEWER %>" value="<%= ejbcawebbean.getText("VIEWNEWER") %> &gt;" tabindex="2" />
           <% } else if (currentindex > 0) {%>
           <input type="submit" name="<%= BUTTON_VIEW_NEWER %>" value="<%= ejbcawebbean.getText("VIEWSUBORDINATE") %> &gt;" tabindex="2" />
           <% } %>
           &nbsp;
         </td>
      </tr> 


      <!-- ---------- Certificate content ---------- -->

      <tr id="Row<%=(row++)%2%>">
		<td align="right" width="<%=columnwidth%>"><%= ejbcawebbean.getText("CERT_TYPEVERSION") %></td>
		<td> <%= certificatedata.getType() + " " + ejbcawebbean.getText("VER") + certificatedata.getVersion() %></td>
      </tr>
      
     <tr id="Row<%=(row++)%2%>">
		 <td align="right" width="<%=columnwidth%>"><%= ejbcawebbean.getText("CERT_SERIALNUMBER") %></td>
		 <td><%= rabean.getFormatedCertSN(certificatedata) %></td>
     </tr>
       
       <tr id="Row<%=(row++)%2%>">
		 <td align="right" width="<%=columnwidth%>"><%= ejbcawebbean.getText("CERT_ISSUERDN") %></td>
		 <td><span class="dn"><%= certificatedata.getIssuerDN() %></span></td>
       </tr>
       <tr id="Row<%=(row)%2%>">
		 <td align="right" width="<%=columnwidth%>"><%= ejbcawebbean.getText("CERT_VALIDFROM") %></td>
		 <td><%= certificatedata.getValidFromString() %></td>
       </tr>
       <tr id="Row<%=(row++)%2%>">
		 <td align="right" width="<%=columnwidth%>"><%= ejbcawebbean.getText("CERT_VALIDTO") %></td>
		 <td><%= certificatedata.getValidToString() %></td>
       </tr>
       <tr id="Row<%=(row++)%2%>" class="title">
		 <td align="right" width="<%=columnwidth%>"><strong><%= ejbcawebbean.getText("CERT_SUBJECTDN") %></strong></td>
		 <td><strong class="dn"><%= certificatedata.getSubjectDN() %></strong></td>
       </tr>
       
      <% if (!certificatedata.getType().equalsIgnoreCase("CVC")) { %>
       <tr id="Row<%=(row++)%2%>">
		 <td align="right" width="<%=columnwidth%>"><%= ejbcawebbean.getText("EXT_ABBR_SUBJECTALTNAME") %></td>
		 <td><% if(certificatedata.getSubjectAltName() == null)
	                  out.write(ejbcawebbean.getText("ALT_NONE"));
	                else
	                  out.write(certificatedata.getSubjectAltName());%> 
	         </td>
       </tr>
       <tr id="Row<%=(row++)%2%>">
		 <td align="right" width="<%=columnwidth%>"><%= ejbcawebbean.getText("EXT_ABBR_SUBJECTDIRATTRS") %></td>
		 <td><% if(certificatedata.getSubjectDirAttr() == null)
	                  out.write(ejbcawebbean.getText("SDA_NONE"));
	                else
	                  out.write(certificatedata.getSubjectDirAttr());%> 
	         </td>
       </tr>
     <% } // if (!certificatedata.getType().equalsIgnoreCase("CVC")) %>
       
       <tr id="Row<%=(row++)%2%>">
		 <td align="right" width="<%=columnwidth%>"><%= ejbcawebbean.getText("CERT_PUBLICKEY") %></td>
		 <td><%= certificatedata.getPublicKeyAlgorithm() %> 
		 	 <% out.write(" (" + certificatedata.getKeySpec(ejbcawebbean.getText("BITS")) + ")");
		 	    if (certificatedata.getPublicKeyModulus() != null) {
		 	    	out.write(": "+certificatedata.getPublicKeyModulus());  
	            } %>
         </td>
       </tr>
       <tr id="Row<%=(row++)%2%>" class="title">
		 <td align="right" width="<%=columnwidth%>"><strong><%= ejbcawebbean.getText("EXT_ABBR_BASICCONSTRAINTS") %></strong></td>
		 <td><strong><%= certificatedata.getBasicConstraints(ejbcawebbean.getText("EXT_UNUSED"), ejbcawebbean.getText("EXT_PKIX_BC_CANOLIMIT"), ejbcawebbean.getText("EXT_PKIX_BC_ENDENTITY"), ejbcawebbean.getText("EXT_PKIX_BC_CAPATHLENGTH")) %></strong>
         </td>
       </tr>
       
     <% if (!certificatedata.getType().equalsIgnoreCase("CVC")) { %>
       <tr id="Row<%=(row++)%2%>">
		 <td align="right" width="<%=columnwidth%>"><%= ejbcawebbean.getText("EXT_ABBR_KEYUSAGE") %></td>
		 <td><% boolean first= true;
	                boolean none = true;
	                if(certificatedata.getKeyUsage(CertificateConstants.DIGITALSIGNATURE)){
	                  out.write(ejbcawebbean.getText("KU_DIGITALSIGNATURE"));
	                  first=false;
	                  none =false;
	                }
	                if(certificatedata.getKeyUsage(CertificateConstants.NONREPUDIATION)){
	                  if(!first) out.write(", "); 
	                  first=false;
	                  none =false;
	                  out.write(ejbcawebbean.getText("KU_NONREPUDIATION"));
	                }
	                if(certificatedata.getKeyUsage(CertificateConstants.KEYENCIPHERMENT)){
	                  if(!first) out.write(", "); 
	                  first=false;
	                  none =false;
	                  out.write(ejbcawebbean.getText("KU_KEYENCIPHERMENT"));
	                }
	                if(certificatedata.getKeyUsage(CertificateConstants.DATAENCIPHERMENT)){
	                  if(!first) out.write(", "); 
	                  first=false;
	                  none =false;
	                  out.write(ejbcawebbean.getText("KU_DATAENCIPHERMENT"));
	                }
	                if(certificatedata.getKeyUsage(CertificateConstants.KEYAGREEMENT)){
	                  if(!first) out.write(", "); 
	                  first=false;
	                  none =false;
	                  out.write(ejbcawebbean.getText("KU_KEYAGREEMENT"));
	                }
	                if(certificatedata.getKeyUsage(CertificateConstants.KEYCERTSIGN)){
	                  if(!first) out.write(", "); 
	                  first=false;               
	                  none =false;
	                  out.write(ejbcawebbean.getText("KU_KEYCERTSIGN"));
	                }
	                if(certificatedata.getKeyUsage(CertificateConstants.CRLSIGN)){
	                  if(!first) out.write(", "); 
	                  first=false;
	                  none =false;
	                  out.write(ejbcawebbean.getText("KU_CRLSIGN"));
	                }
	                if(certificatedata.getKeyUsage(CertificateConstants.ENCIPHERONLY)){
	                  if(!first) out.write(", "); 
	                  first=false;
	                  none =false;
	                  out.write(ejbcawebbean.getText("KU_ENCIPHERONLY"));
	                }
	                if(certificatedata.getKeyUsage(CertificateConstants.DECIPHERONLY)){
	                  if(!first) out.write(", "); 
	                  first=false;
	                  none =false;
	                  out.write(ejbcawebbean.getText("KU_DECIPHERONLY"));
	               }
	               if(none){
	                  out.write(ejbcawebbean.getText("KU_NONE"));          
	              }
	%>
	         </td>
       </tr>
       <tr id="Row<%=(row++)%2%>">
		 <td align="right" width="<%=columnwidth%>"><%= ejbcawebbean.getText("EXT_ABBR_EXTENDEDKEYUSAGE") %></td>
		 <td><% String[] extendedkeyusage = certificatedata.getExtendedKeyUsageAsTexts();
	                for(int i=0; i<extendedkeyusage.length; i++){
	                  if(i>0)
	                    out.write(", ");
	                  out.write( ejbcawebbean.getText(extendedkeyusage[i]));
	                }                
	                if(extendedkeyusage == null || extendedkeyusage.length == 0)
	                  out.write(ejbcawebbean.getText("EKU_NONE"));                       
	%>
	         </td>
       </tr>
       
       <tr id="Row<%=(row++)%2%>">
         <td align="right" width="<%=columnwidth%>"><%= ejbcawebbean.getText("EXT_ABBR_NAMECONSTRAINTS") %></td>
         <td><% if (certificatedata.hasNameConstraints()) {
                 out.write(ejbcawebbean.getText("YES"));
             } else {
                 out.write(ejbcawebbean.getText("NO"));
             }
             %></td>
       </tr>
       
       <tr id="Row<%=(row++)%2%>">
		 <td align="right" width="<%=columnwidth%>"><%= ejbcawebbean.getText("EXT_ABBR_QCSTATEMENTS") %></td>
		 <td><% if (certificatedata.hasQcStatement()) {
				 out.write(ejbcawebbean.getText("YES"));
			 } else {
				 out.write(ejbcawebbean.getText("NO"));
			 }
			 %></td>
       </tr>
       <tr id="Row<%=(row++)%2%>">
         <td align="right" width="<%=columnwidth%>"><%= ejbcawebbean.getText("EXT_CERTIFICATE_TRANSPARENCY_SCTS") %></td>
         <td><% if (certificatedata.hasCertificateTransparencySCTs()) {
                 out.write(ejbcawebbean.getText("YES"));
             } else {
                 out.write(ejbcawebbean.getText("NO"));
             }
             %></td>
       </tr>
     <% } // if (!certificatedata.getType().equalsIgnoreCase("CVC")) %>
       
       <tr id="Row<%=(row++)%2%>">
		 <td align="right" width="<%=columnwidth%>"><%= ejbcawebbean.getText("SIGNATUREALGORITHM") %></td>
		 <td><%= certificatedata.getSignatureAlgoritm() %></td>
       </tr>


      <!-- ---------- Certificate information ---------- -->

       <tr  id="Row<%=(row++)%2%>"> 
         <td  align="right" width="<%=columnwidth%>"> 
           <%= ejbcawebbean.getText("SHA1FINGERPRINT") %>
         </td>
         <td ><%= certificatedata.getSHA1Fingerprint() %></td>
       </tr>
       <tr  id="Row<%=(row++)%2%>"> 
         <td  align="right" width="<%=columnwidth%>"> 
           <%= ejbcawebbean.getText("MD5FINGERPRINT") %>
         </td>
         <td ><%= certificatedata.getMD5Fingerprint() %></td>
       </tr>

       <tr  id="Row<%=(row++)%2%>"> 
         <td  align="right" width="<%=columnwidth%>"> 
           <%= ejbcawebbean.getText("REVOKED") %>
         </td>
         <td ><%  if(certificatedata.isRevoked()){
                    out.write(ejbcawebbean.getText("YES") + "<br/>"
                    		+ ejbcawebbean.getText("CRL_ENTRY_REVOCATIONDATE") + " "
                    		+ ejbcawebbean.formatAsISO8601(certificatedata.getRevocationDate()) + "<br/>"
                    		+ ejbcawebbean.getText("REVOCATIONREASONS") + " ");
                    final String reason = certificatedata.getRevocationReason();
                    if (reason != null) {
                    	out.write(ejbcawebbean.getText(reason));
                    }
                  } else {
                    out.write(ejbcawebbean.getText("NO"));
                  } %>
         </td>
       </tr>


      <!-- ---------- Actions ---------- -->

       <tr id="Row<%=(row++)%2%>">
          <td>  
            <% 
            if(!cacerts &&  rabean.keyRecoveryPossible(certificatedata.getCertificate(), certificatedata.getUsername()) && usekeyrecovery){ %>
            <input type="submit" name="<%=BUTTON_RECOVERKEY %>" value="<%= ejbcawebbean.getText("RECOVERKEY") %>"
                   onClick='return confirmkeyrecovery()'>
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
				if ( !certificatedata.isRevoked() || certificatedata.isRevokedAndOnHold() ){
					//-- Certificate can be revoked or suspended
		%>    
        <select name="<%=SELECT_REVOKE_REASON %>" >
          <% for(int i=0; i < SecConst.reasontexts.length; i++){ 
               if(i!= 7){%>
	               <option value='<%= i%>'><%= ejbcawebbean.getText(SecConst.reasontexts[i]) %></option>
          <%   } 
             }%>
        </select>
        <input type="submit" name="<%=BUTTON_REVOKE %>" value="<%= ejbcawebbean.getText("REVOKE") %>"
               onClick='return confirmrevocation()'>
<% 
			  }
			  if ( certificatedata.isRevokedAndOnHold() ){
				//-- Certificate can be unrevoked
%>
				<br/><br/>
				<input type="submit" name="<%=BUTTON_UNREVOKE %>" value="<%= ejbcawebbean.getText("UNREVOKE") %>"
                onClick='return confirmunrevocation()'>
<%
			  }
		   }
         }catch(AuthorizationDeniedException ade){}%> 
          &nbsp;
          </td>
       </tr> 

       <tr id="Row<%=row%2%>">
          <td>
            <% if (!cacerts && certificatedata.getCertificate()!=null) { %>
            <a href="<%=DOWNLOADCERTIFICATE_LINK%>?cmd=iecert&certificatesn=<%= certificatedata.getSerialNumber()%>&issuer=<%= certificatedata.getIssuerDNUnEscaped() %>"><%= ejbcawebbean.getText("DOWNLOADIE")%></a><br/>
            <a href="<%=DOWNLOADCERTIFICATE_LINK%>?cmd=nscert&certificatesn=<%= certificatedata.getSerialNumber()%>&issuer=<%= certificatedata.getIssuerDNUnEscaped() %>"><%= ejbcawebbean.getText("DOWNLOADNS")%></a><br/>
            <a href="<%=DOWNLOADCERTIFICATE_LINK%>?cmd=cert&certificatesn=<%= certificatedata.getSerialNumber()%>&issuer=<%= certificatedata.getIssuerDNUnEscaped() %>"><%= ejbcawebbean.getText("DOWNLOADPEM")%></a>
            <% } %>
            &nbsp;
          </td>   
          <td align="right" style="vertical-align: bottom;">
<%        // Show either a "Back"-link or a "Close"-button. Avoid link injection by using a fixed set of return options.
          String returnToLink = null;
          final String RETURNTO_PARAMETER = "returnTo";
          final String returnToParameter = request.getParameter(RETURNTO_PARAMETER);
          try {
              final int returnToId = Integer.parseInt(returnToParameter);
              switch (returnToId) {
              case 0: // 0 = send user to the audit log page
            	  returnToLink = ejbcawebbean.getBaseUrl() + globalconfiguration.getAdminWebPath() + "audit/search.jsf";
            	  break;
              }
          } catch (NumberFormatException e) {
          }
          // If there was to "returnTo" specified we assume that this page is displayes as a popup and e show a Close-button.
          if (returnToLink == null) { %>
            <input type="button" name="<%= BUTTON_CLOSE %>" value="<%= ejbcawebbean.getText("CLOSE") %>" tabindex="3" onClick='self.close()' />  
<%        } else { %>
            <input type="hidden" name='<%= RETURNTO_PARAMETER %>' value='<c:out value="<%= returnToParameter %>"/>'>
            <a href="<%=returnToLink%>" class="commandLink"><%= ejbcawebbean.getText("BACK")%></a><br/>
<%        } %>
          </td>
       </tr> 

     </table> 

   </form>

   <%   }
      }
    }%>

</body>
</html>
