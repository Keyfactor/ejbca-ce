<%@ page pageEncoding="ISO-8859-1"%>
<% response.setContentType("text/html; charset="+org.ejbca.config.WebConfiguration.getWebContentEncoding()); %>
<%@page errorPage="/errorpage.jsp"  import="java.util.*, java.security.cert.Certificate, java.security.cert.X509Certificate,org.ejbca.config.GlobalConfiguration,
    org.ejbca.ui.web.RequestHelper,org.cesecore.certificates.crl.CRLInfo, org.cesecore.authorization.AuthorizationDeniedException, org.ejbca.core.model.SecConst,
    org.cesecore.keys.token.CryptoToken, org.ejbca.core.model.authorization.AccessRulesConstants, org.cesecore.authorization.control.StandardRules, org.cesecore.util.CertTools, org.ejbca.util.HTMLTools"%>
<html>
<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />
<jsp:setProperty name="ejbcawebbean" property="*" /> 
<jsp:useBean id="cabean" scope="session" class="org.ejbca.ui.web.admin.cainterface.CAInterfaceBean" />
<jsp:setProperty name="cabean" property="*" /> 
<%!

  final static String HIDDEN_NUMBEROFCAS    = "hiddennumberofcas";
  final static String HIDDEN_CASUBJECTDN    = "hiddensubjectdn";

  final static String BUTTON_CREATECRL      = "buttoncreatecrl";
  final static String BUTTON_CREATEDELTACRL = "buttoncreatedeltacrl";
%>
<%   // Initialize environment
  GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, AccessRulesConstants.REGULAR_CABASICFUNCTIONS); 
                                            cabean.initialize(request, ejbcawebbean); 

  final String THIS_FILENAME                = globalconfiguration.getCaPath() 
                                                  + "/cafunctions.jsp";

  final String CREATECRL_LINK               = "/ca_functionality/create_crl";  
  final String GETCRL_LINK                  = globalconfiguration.getCaPath() 
                                                  + "/getcrl/getcrl.jsp";
  final String GETCRL_PAGE                  =    "getcrl.jsp"; 
  final String VIEWCERTIFICATE_LINK         = ejbcawebbean.getBaseUrl() + globalconfiguration.getAdminWebPath() + "viewcertificate.jsp";
  final String VIEWINFO_LINK                = ejbcawebbean.getBaseUrl() + globalconfiguration.getCaPath() + "/viewcainfo.jsp";
  final String DOWNLOADCERTIFICATE_LINK     = globalconfiguration.getCaPath() 
                                                  + "/cacert";
  final String DOWNLOADCRL_LINK             = globalconfiguration.getCaPath() + "/getcrl/getcrl";
  boolean createcrlrights = false;
  try{
     createcrlrights =ejbcawebbean.isAuthorized(CREATECRL_LINK);
  }catch(AuthorizationDeniedException e){}

  RequestHelper.setDefaultCharacterEncoding(request);

  if(request.getParameter(HIDDEN_NUMBEROFCAS) != null){
    int numberofcas = Integer.parseInt(request.getParameter(HIDDEN_NUMBEROFCAS));
    for(int i = 0; i < numberofcas; i++){       
       String casubjectdn = request.getParameter(HIDDEN_CASUBJECTDN+i);
       if( request.getParameter(BUTTON_CREATECRL+i) != null ){      
         // Check if user id authorized to create new crl.
         ejbcawebbean.isAuthorized(CREATECRL_LINK);
         ejbcawebbean.isAuthorized(StandardRules.CAACCESS.resource() + casubjectdn.hashCode());
         // Create new crl
         cabean.createCRL(casubjectdn);
      }         
      if( request.getParameter(BUTTON_CREATEDELTACRL+i) != null ){      
           // Check if user id authorized to create new delta crl.
           ejbcawebbean.isAuthorized(CREATECRL_LINK);
           ejbcawebbean.isAuthorized(StandardRules.CAACCESS.resource() + casubjectdn.hashCode());
           // Create new delta crl
           cabean.createDeltaCRL(casubjectdn);
      }
    }
  }

  TreeMap canames = ejbcawebbean.getInformationMemory().getAllCANames();

%>
<head>
  <title><%= globalconfiguration .getEjbcaTitle() %></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>" />
  <link rel="stylesheet" type="text/css" href="<%= ejbcawebbean.getCssFile() %>" />
  <script type="text/javascript" src="<%= globalconfiguration .getAdminWebPath() %>ejbcajslib.js"></script>
  <script type="text/javascript">
<!--  
function viewcacert(caid){   
    var link = "<%=VIEWCERTIFICATE_LINK%>?caid="+caid;
    link = encodeURI(link);     
    win_popup = window.open(link, 'view_cert','height=600,width=750,scrollbars=yes,toolbar=no,resizable=1');
    win_popup.focus();
} 

function viewcainfo(caid){        
    var link = "<%=VIEWINFO_LINK%>?caid="+caid;
    link = encodeURI(link);
    win_popup = window.open(link, 'view_info','height=550,width=750,scrollbars=yes,toolbar=no,resizable=1');
    win_popup.focus();
}

function getPasswordAndSubmit(formname) {
	var form = eval("document." + formname);
	var paswordInput = prompt("<%= ejbcawebbean.getText("JKSPASSWORD")%>","");
	if ( paswordInput != null && paswordInput != "") {
		form.password.value = paswordInput;
		form.submit();
	}
}
-->
  </script>
</head>

<body>

  <h1><%= ejbcawebbean.getText("CAFUNCTIONS") %></h1>

<!--  <div align="right"><A  onclick='displayHelpWindow("<%= ejbcawebbean.getHelpfileInfix("ca_help.html") %>")'>
    <u><%= ejbcawebbean.getText("HELP") %></u> </A> 
  </div> -->

	<br />
  <% // Display CA info one by one.
     Iterator iter = canames.keySet().iterator();
     int number = 0;
     while(iter.hasNext()){
       String caname = (String) iter.next();  
       int caid = ((Integer) canames.get(caname)).intValue();
       org.ejbca.ui.web.admin.cainterface.CAInfoView cainfo = cabean.getCAInfo(caid);
       if (cainfo == null) {
         continue;	// We are obviously not authorized to this CA
       }
       String subjectdn = cainfo.getCAInfo().getSubjectDN();
       Certificate[] certificatechain = (Certificate[]) cainfo.getCertificateChain().toArray(new Certificate[0]);
       int chainsize = certificatechain.length;
 %>
       <H3><%= ejbcawebbean.getText("BASICFUNCTIONSFOR") + " : " + caname%> &nbsp; <a href="<%=THIS_FILENAME%>"  onClick="viewcacert(<%=caid%>)"><%= ejbcawebbean.getText("VIEWCERTIFICATE")%></a>&nbsp;&nbsp;
                                                                            <a href="<%=THIS_FILENAME%>"  onClick="viewcainfo(<%=caid%>)"><%= ejbcawebbean.getText("VIEWINFO")%></a></H3>    
 
        <table> 
          <% int row = 0;
             for(int j = chainsize-1; j >= 0; j--){
               if(j == chainsize -1){              
          %>
          <tr id="Row<%=row%2%>">
            <td>
              <%= ejbcawebbean.getText("ROOTCA") + " : "%> 
            </td>
            <td>
               <% out.write(HTMLTools.htmlescape(CertTools.getSubjectDN(certificatechain[j]))); %>                  
            </td>
          </tr>
          <tr id="Row<%=row%2%>">
            <td>&nbsp;</td>
            <td>               
              <form name="<%= "JKSFORM"+Integer.toHexString((subjectdn+j).hashCode()) %>" method="POST" action="<%=DOWNLOADCERTIFICATE_LINK%>">
					<input type="hidden" name="cmd" value="jkscert"/>
					<input type="hidden" name="level" value="<%= j %>"/>
					<input type="hidden" name="issuer" value="<%= subjectdn %>"/>
					<input type="hidden" name="password" value=""/>
              </form>
              <a href="<%=DOWNLOADCERTIFICATE_LINK%>?cmd=iecacert&level=<%= j%>&issuer=<%= subjectdn %>"><%= ejbcawebbean.getText("DOWNLOADIE")%></a>&nbsp;&nbsp;&nbsp;
              <a href="<%=DOWNLOADCERTIFICATE_LINK%>?cmd=nscacert&level=<%= j%>&issuer=<%= subjectdn %>"><%= ejbcawebbean.getText("DOWNLOADNS")%></a>&nbsp;&nbsp;&nbsp;
              <a href="<%=DOWNLOADCERTIFICATE_LINK%>?cmd=cacert&level=<%= j%>&issuer=<%= subjectdn %>"><%= ejbcawebbean.getText("DOWNLOADPEM")%></a>&nbsp;&nbsp;&nbsp;
			  <a href="javascript: getPasswordAndSubmit('<%= "JKSFORM"+Integer.toHexString((subjectdn+j).hashCode()) %>');"><%= ejbcawebbean.getText("DOWNLOADJKS")%></a>
            </td>   
          </tr> 
          <%   }else{ %> 
          <tr id="Row<%=row%2%>">
           <td>
              <%= ejbcawebbean.getText("SUBORDINATECA") + " " + (chainsize-j-1) + " : "%>  
           </td>  
           <td>
               <% out.write(HTMLTools.htmlescape(CertTools.getSubjectDN(certificatechain[j]))); %>                  
           </td> 
          </tr>
          <tr id="Row<%=row%2%>">
            <td>&nbsp;</td>
            <td>               
              <form name="<%= "JKSFORM"+Integer.toHexString((subjectdn+j).hashCode()) %>" method="POST" action="<%=DOWNLOADCERTIFICATE_LINK%>">
					<input type="hidden" name="cmd" value="jkscert"/>
					<input type="hidden" name="level" value="<%= j %>"/>
					<input type="hidden" name="issuer" value="<%= subjectdn %>"/>
					<input type="hidden" name="password" value=""/>
              </form>
              <a href="<%=DOWNLOADCERTIFICATE_LINK%>?cmd=iecacert&level=<%= j%>&issuer=<%= subjectdn %>"><%= ejbcawebbean.getText("DOWNLOADIE")%></a>&nbsp;&nbsp;&nbsp;
              <a href="<%=DOWNLOADCERTIFICATE_LINK%>?cmd=nscacert&level=<%= j%>&issuer=<%= subjectdn %>"><%= ejbcawebbean.getText("DOWNLOADNS")%></a>&nbsp;&nbsp;&nbsp;
              <a href="<%=DOWNLOADCERTIFICATE_LINK%>?cmd=cacert&level=<%= j%>&issuer=<%= subjectdn %>"><%= ejbcawebbean.getText("DOWNLOADPEM")%></a>&nbsp;&nbsp;&nbsp;
			  <a href="javascript: getPasswordAndSubmit('<%= "JKSFORM"+Integer.toHexString((subjectdn+j).hashCode()) %>');"><%= ejbcawebbean.getText("DOWNLOADJKS")%></a>
            </td>   
          </tr>
          <% }
             row++;
          }%>
        </table> 
        <br />
        
        <!-- Full CRLs --> 
        <% CRLInfo crlinfo = cabean.getLastCRLInfo(cainfo.getCAInfo(), false);
           if(crlinfo == null){ 
             out.write(ejbcawebbean.getText("NOCRLHAVEBEENGENERATED"));
           }else{
           boolean expired = crlinfo.getExpireDate().compareTo(new Date()) < 0; %>
<%=ejbcawebbean.getText("LATESTCRL") + ": "  
  + ejbcawebbean.getText("CREATED") + " " + ejbcawebbean.formatAsISO8601(crlinfo.getCreateDate()) + ","%>
        <% if(expired){
              out.write(" <font id=\"alert\">" + ejbcawebbean.getText("EXPIRED") + " " + ejbcawebbean.formatAsISO8601(crlinfo.getExpireDate()) + "</font>");
           }else{
              out.write(ejbcawebbean.getText("EXPIRES") + " " + ejbcawebbean.formatAsISO8601(crlinfo.getExpireDate()));
           } 
           out.write(", " + ejbcawebbean.getText("NUMBER") + " " + crlinfo.getLastCRLNumber()); %>  
<i><a href="<%=DOWNLOADCRL_LINK%>?cmd=crl&issuer=<%= subjectdn %>" ><%=ejbcawebbean.getText("GETCRL") %></a></i>
<br />
<%        } %>

<% // Delta CRLs 
 	       CRLInfo deltacrlinfo = cabean.getLastCRLInfo(cainfo.getCAInfo(), true);
	       if(deltacrlinfo == null){ 
     	       if (cainfo.getCAInfo().getDeltaCRLPeriod() > 0) {
    	           out.write(ejbcawebbean.getText("NODELTACRLHAVEBEENGENERATED"));
     	       } else {
     	           out.write(ejbcawebbean.getText("DELTACRLSNOTENABLED"));
     	       }
	         %> <br /> <%
	       }else{
	       	 boolean expired = deltacrlinfo.getExpireDate().compareTo(new Date()) < 0; %>
	<%=ejbcawebbean.getText("LATESTDELTACRL") + ": "  
	  + ejbcawebbean.getText("CREATED") + " " + ejbcawebbean.formatAsISO8601(deltacrlinfo.getCreateDate()) + ","%>
	        <% if(expired){
	              out.write(" <font id=\"alert\">" + ejbcawebbean.getText("EXPIRED") + " " + ejbcawebbean.formatAsISO8601(deltacrlinfo.getExpireDate()) + "</font>");
	           }else{
	              out.write(ejbcawebbean.getText("EXPIRES") + " " + ejbcawebbean.formatAsISO8601(deltacrlinfo.getExpireDate()));
	           } 
           out.write(", " + ejbcawebbean.getText("NUMBER") + " " + deltacrlinfo.getLastCRLNumber()); %>  
<i><a href="<%=DOWNLOADCRL_LINK%>?cmd=deltacrl&issuer=<%= subjectdn %>" ><%=ejbcawebbean.getText("GETDELTACRL") %></a></i>
<br />
<br />
<%        } %>

<% // Display createcrl if admin is authorized
      if(createcrlrights){ %>
<br /> 
<form name='createcrl' method=GET action='<%=THIS_FILENAME %>'>
<input type='hidden' name='<%=HIDDEN_NUMBEROFCAS %>' value='<%=canames.keySet().size()%>'> 
<input type='hidden' name='<%=HIDDEN_CASUBJECTDN + number %>' value="<%=subjectdn%>"> 
<%=ejbcawebbean.getText("CREATENEWCRL") + " : " %>
       <% if ( (cainfo.getCAInfo().getStatus() == SecConst.CA_ACTIVE) && (cainfo.getCAInfo().getCATokenInfo().getTokenStatus() == CryptoToken.STATUS_ACTIVE) ) { %>
<input type='submit' name='<%=BUTTON_CREATECRL + number %>' value='<%=ejbcawebbean.getText("CREATECRL") %>'>
       <% }else{
           out.write(ejbcawebbean.getText("CAISNTACTIVE"));
          } 
       if(cainfo.getCAInfo().getDeltaCRLPeriod() > 0) { %>
<br />
<input type='hidden' name='<%=HIDDEN_CASUBJECTDN + number %>' value="<%=subjectdn%>"> 
<%=ejbcawebbean.getText("CREATENEWDELTACRL") + " : " %>
       <% if ( (cainfo.getCAInfo().getStatus() == SecConst.CA_ACTIVE) && (cainfo.getCAInfo().getCATokenInfo().getTokenStatus() == CryptoToken.STATUS_ACTIVE) ) { %>
<input type='submit' name='<%=BUTTON_CREATEDELTACRL + number %>' value='<%=ejbcawebbean.getText("CREATEDELTACRL") %>'>
       <% } else {
            out.write(ejbcawebbean.getText("CAISNTACTIVE"));
          }
       } %>
</form>
<%    } %>
<br />
<hr />
<% 
    number++;
  }  %>
   


<% // Include Footer 
   String footurl =  globalconfiguration.getFootBanner(); %>
   
  <jsp:include page="<%= footurl %>" />
</form>
</body>
</html>
