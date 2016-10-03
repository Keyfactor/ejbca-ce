<%
/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ page pageEncoding="ISO-8859-1"%>
<% response.setContentType("text/html; charset="+org.ejbca.config.WebConfiguration.getWebContentEncoding()); %>
<%@page errorPage="/errorpage.jsp" import="
java.util.*,
java.security.cert.Certificate,
java.security.cert.X509Certificate,
org.cesecore.authorization.AuthorizationDeniedException,
org.cesecore.authorization.control.StandardRules,
org.cesecore.certificates.ca.CAConstants,
org.cesecore.certificates.crl.CRLInfo,
org.cesecore.keys.token.CryptoToken,
org.cesecore.util.CertTools,
org.ejbca.config.GlobalConfiguration,
org.ejbca.core.model.authorization.AccessRulesConstants,
org.ejbca.ui.web.RequestHelper,
org.ejbca.util.HTMLTools,
org.ejbca.ui.web.admin.cainterface.CAInfoView
"%>
<html>
<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />
<jsp:setProperty name="ejbcawebbean" property="*" /> 
<jsp:useBean id="rabean" scope="session" class="org.ejbca.ui.web.admin.rainterface.RAInterfaceBean" />
<jsp:setProperty name="rabean" property="*" />
<jsp:useBean id="cabean" scope="session" class="org.ejbca.ui.web.admin.cainterface.CAInterfaceBean" />
<jsp:setProperty name="cabean" property="*" /> 
<%!

  final static String HIDDEN_NUMBEROFCAS    = "hiddennumberofcas";
  final static String HIDDEN_CAID           = "hiddencaid";
  final static String BUTTON_CREATECRL      = "buttoncreatecrl";
  final static String BUTTON_CREATEDELTACRL = "buttoncreatedeltacrl";
  
  final static String ACTION_IMPORT_CRL		= "actionimportcrl";
  final static String FILE_IMPORTCRL		= "fileimportcrl";
  final static String BUTTON_IMPORT_CRL 	= "buttonimportcrl";
  final static String SELECT_CA_IMPORTCRL	= "selectcaimportcrl";
  
  
  
%>
<%   // Initialize environment
  GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, AccessRulesConstants.ROLE_ADMINISTRATOR, StandardRules.CAVIEW.resource()); 
                                            cabean.initialize(ejbcawebbean); 

  final String THIS_FILENAME                = globalconfiguration.getCaPath() 
                                                  + "/cafunctions.jsp";

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
     createcrlrights = ejbcawebbean.isAuthorizedNoLog(StandardRules.CREATECRL.resource());
  }catch(AuthorizationDeniedException e){}

  RequestHelper.setDefaultCharacterEncoding(request);

	Map<String, String> requestMap = new HashMap<String, String>();
	byte[] filebuffer = rabean.getfileBuffer(request, requestMap);
	String msg = cabean.importCRL(requestMap.get(SELECT_CA_IMPORTCRL), filebuffer);
	if (msg.startsWith("Error:")) {
		%> <div style="color: #FF0000;"> <%
    } else {
    	%> <div style="color: #000000;"> <%
    } %>
    	<c:out value="<%= msg %>"/>
   	</div> <%
	
	
  if(request.getParameter(HIDDEN_NUMBEROFCAS) != null){
    int numberofcas = Integer.parseInt(request.getParameter(HIDDEN_NUMBEROFCAS));
    for(int i = 0; i < numberofcas; i++){       
       final String caidstr = request.getParameter(HIDDEN_CAID+i);
       final int caid;
       if (caidstr != null) {
    	   caid = Integer.parseInt(caidstr);
       } else {
    	   caid = 0;
       }
       if( request.getParameter(BUTTON_CREATECRL+i) != null ){      
         // Create new crl (with authorization checks)
         cabean.createCRL(caid);
      }         
      if( request.getParameter(BUTTON_CREATEDELTACRL+i) != null ){      
           // Create new delta crl (with authorization checks)
           cabean.createDeltaCRL(caid);
      }
    }
  }

  TreeMap<String, Integer> canames = ejbcawebbean.getInformationMemory().getAllCANames();

%>
<head>
  <title><c:out value="<%= globalconfiguration.getEjbcaTitle() %>" /></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>" />
  <link rel="stylesheet" type="text/css" href="<c:out value='<%=ejbcawebbean.getCssFile() %>' />" />
  <script type="text/javascript" src="<%= globalconfiguration .getAdminWebPath() %>ejbcajslib.js"></script>
  <script type="text/javascript">
<!--  
function viewcacert(caid){   
    var link = "<%=VIEWCERTIFICATE_LINK%>?caid="+caid;
    link = encodeURI(link);     
    win_popup = window.open(link, 'view_cert','height=650,width=750,scrollbars=yes,toolbar=no,resizable=1');
    win_popup.focus();
} 

function viewcainfo(caid){        
    var link = "<%=VIEWINFO_LINK%>?caid="+caid;
    link = encodeURI(link);
    win_popup = window.open(link, 'view_info','height=600,width=750,scrollbars=yes,toolbar=no,resizable=1');
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

  <h1><%= ejbcawebbean.getText("CASTRUCTUREANDCRL") %></h1>

<!--  <div align="right"><A  onclick='displayHelpWindow("<%= ejbcawebbean.getHelpfileInfix("ca_help.html") %>")'>
    <u><%= ejbcawebbean.getText("HELP") %></u> </A> 
  </div> -->

	<br />
  <% // Display CA info one by one.

  	 List<String> caNameList = new ArrayList<String>(canames.keySet());
  	 Collections.sort(caNameList, new Comparator<String>() {
  	   	public int compare(String o1, String o2) {
  	   	    return o1.compareToIgnoreCase(o2);
  	   	}
  	 });
  	 %>
  	 
  	 
  	 <h2>Import CRL</h2>  	 
  	 
  	 <form name="recievefile" action="<%= THIS_FILENAME %>" method="post" enctype='multipart/form-data' >
  	 	<input type="hidden" name='action' value='<%=ACTION_IMPORT_CRL %>'>
		<table class="action" width="70%" border="0" cellspacing="3" cellpadding="3">
			<tr> 
				<td width="10%" valign="top" align="right">Import CRL</td>

				<td width="55%" valign="top">
					<input TYPE="FILE" NAME="<%= FILE_IMPORTCRL %>">
				</td>

				<td width="20%" valign="top">
					<select name="<%=SELECT_CA_IMPORTCRL %>" size="1" >
            			<% for(String caNameForCrl : caNameList){ %>
           					<option  value='<c:out value="<%= caNameForCrl %>"/>'><c:out value="<%= caNameForCrl %>" /></option>
            			<% } %>
        			</select>
				</td>
			
				<td width="15%" valign="top">
					<input type="submit" name="<%= BUTTON_IMPORT_CRL %>" onClick='return check()' value="<%= ejbcawebbean.getText("IMPORT") %>" >
				</td>
			</tr>
		</table>
	 </form>
  	 
  	 
  	 
  	 <h2>Basic Functions</h2>
  	 
  	 <%
     int number = 0;
     for(String caname : caNameList) { 
       int caid = ((Integer) canames.get(caname)).intValue();
       CAInfoView cainfo = null;
       try {
           cainfo = cabean.getCAInfo(caid);
       } catch (AuthorizationDeniedException e) {
           continue; // We are obviously not authorized to this CA
       }
       if (cainfo == null) {
         continue;	// Something wrong happened retrieving this CA?       
       }
       String subjectdn = cainfo.getCAInfo().getSubjectDN();
       Certificate[] certificatechain = (Certificate[]) cainfo.getCertificateChain().toArray(new Certificate[0]);
       int chainsize = certificatechain.length;
 %>
       <H3><%= ejbcawebbean.getText("BASICFUNCTIONSFOR") + " : "%> <c:out value="<%= caname %>" /> &nbsp; <a href="<%=THIS_FILENAME%>"  onClick="viewcacert(<%=caid%>); return false;"><%= ejbcawebbean.getText("VIEWCERTIFICATE")%></a>&nbsp;&nbsp;
                                                                            <a href="<%=THIS_FILENAME%>"  onClick="viewcainfo(<%=caid%>); return false;"><%= ejbcawebbean.getText("VIEWINFO")%></a></H3>    
 
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
					<input type="hidden" name="level" value='<c:out value="<%= j %>" />'/>
					<input type="hidden" name="issuer" value='<c:out value="<%= subjectdn %>" />'/>
					<input type="hidden" name="password" value=""/>
              </form>
              <a href="<%=DOWNLOADCERTIFICATE_LINK%>?cmd=iecacert&level=<%= j%>&issuer=<%= java.net.URLEncoder.encode(subjectdn,"UTF-8") %>"><%= ejbcawebbean.getText("DOWNLOADIE")%></a>&nbsp;&nbsp;&nbsp;
              <a href="<%=DOWNLOADCERTIFICATE_LINK%>?cmd=nscacert&level=<%= j%>&issuer=<%= java.net.URLEncoder.encode(subjectdn,"UTF-8") %>"><%= ejbcawebbean.getText("DOWNLOADNS")%></a>&nbsp;&nbsp;&nbsp;
              <a href="<%=DOWNLOADCERTIFICATE_LINK%>?cmd=cacert&level=<%= j%>&issuer=<%= java.net.URLEncoder.encode(subjectdn,"UTF-8") %>"><%= ejbcawebbean.getText("DOWNLOADPEM")%></a>&nbsp;&nbsp;&nbsp;
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
					<input type="hidden" name="level" value='<c:out value="<%= j %>" />'/>
					<input type="hidden" name="issuer" value='<c:out value="<%= subjectdn %>" />'/>
					<input type="hidden" name="password" value=""/>
              </form>
              <a href="<%=DOWNLOADCERTIFICATE_LINK%>?cmd=iecacert&level=<%= j%>&issuer=<%= java.net.URLEncoder.encode(subjectdn,"UTF-8") %>"><%= ejbcawebbean.getText("DOWNLOADIE")%></a>&nbsp;&nbsp;&nbsp;
              <a href="<%=DOWNLOADCERTIFICATE_LINK%>?cmd=nscacert&level=<%= j%>&issuer=<%= java.net.URLEncoder.encode(subjectdn,"UTF-8") %>"><%= ejbcawebbean.getText("DOWNLOADNS")%></a>&nbsp;&nbsp;&nbsp;
              <a href="<%=DOWNLOADCERTIFICATE_LINK%>?cmd=cacert&level=<%= j%>&issuer=<%= java.net.URLEncoder.encode(subjectdn,"UTF-8") %>"><%= ejbcawebbean.getText("DOWNLOADPEM")%></a>&nbsp;&nbsp;&nbsp;
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
		<%=ejbcawebbean.getText("LATESTCRL") + ": " + ejbcawebbean.getText("CREATED") + " " + ejbcawebbean.formatAsISO8601(crlinfo.getCreateDate()) + ","%>
        <% if(expired){
              out.write(" <font id=\"alert\">" + ejbcawebbean.getText("EXPIRED") + " " + ejbcawebbean.formatAsISO8601(crlinfo.getExpireDate()) + "</font>");
           }else{
              out.write(ejbcawebbean.getText("EXPIRES") + " " + ejbcawebbean.formatAsISO8601(crlinfo.getExpireDate()));
           } 
           out.write(", " + ejbcawebbean.getText("NUMBER") + " " + crlinfo.getLastCRLNumber()); %>  
		<i><a href="<%=DOWNLOADCRL_LINK%>?cmd=crl&issuer=<%= java.net.URLEncoder.encode(subjectdn,"UTF-8") %>" ><%=ejbcawebbean.getText("GETCRL") %></a></i>
		<br />
		<% } %>

		<% // Delta CRLs 
 	    CRLInfo deltacrlinfo = cabean.getLastCRLInfo(cainfo.getCAInfo(), true);
	    if(deltacrlinfo == null){ 
     		if (cainfo.getCAInfo().getDeltaCRLPeriod() > 0) {
    	    	out.write(ejbcawebbean.getText("NODELTACRLHAVEBEENGENERATED"));
     	    } else {
     	    	out.write(ejbcawebbean.getText("DELTACRLSNOTENABLED"));
     	    } %> 
     	 <br /> 
     	 <% } else {
	       		boolean expired = deltacrlinfo.getExpireDate().compareTo(new Date()) < 0; %>
		 <%=ejbcawebbean.getText("LATESTDELTACRL") + ": " + ejbcawebbean.getText("CREATED") + " " + ejbcawebbean.formatAsISO8601(deltacrlinfo.getCreateDate()) + ","%>
	     <% if(expired){
	     		out.write(" <font id=\"alert\">" + ejbcawebbean.getText("EXPIRED") + " " + ejbcawebbean.formatAsISO8601(deltacrlinfo.getExpireDate()) + "</font>");
	        } else {
	        	out.write(ejbcawebbean.getText("EXPIRES") + " " + ejbcawebbean.formatAsISO8601(deltacrlinfo.getExpireDate()));
	        } 
            out.write(", " + ejbcawebbean.getText("NUMBER") + " " + deltacrlinfo.getLastCRLNumber()); %>  
		<i><a href="<%=DOWNLOADCRL_LINK%>?cmd=deltacrl&issuer=<%= java.net.URLEncoder.encode(subjectdn,"UTF-8") %>" ><%=ejbcawebbean.getText("GETDELTACRL") %></a></i>
		<br />
		<br />
		<% } %>

	  <% // Display createcrl if admin is authorized
      if(createcrlrights){ %>
		<br />
		<form name='createcrl' method=GET action='<%=THIS_FILENAME %>'>
			<input type='hidden' name='<%=HIDDEN_NUMBEROFCAS %>' value='<%=canames.keySet().size()%>'> 
			<input type='hidden' name='<%=HIDDEN_CAID + number %>' value='<c:out value="<%= caid %>" />'> 
			<%=ejbcawebbean.getText("CREATENEWCRL") + " : " %>
       		<% if ( cainfo.getCAInfo().getStatus() == CAConstants.CA_ACTIVE ) {	%>
				<input type='submit' name='<%=BUTTON_CREATECRL + number %>' value='<%=ejbcawebbean.getText("CREATECRL") %>'>
       		<% }else{
           		out.write(ejbcawebbean.getText("CAISNTACTIVE"));
         		} 
       		if(cainfo.getCAInfo().getDeltaCRLPeriod() > 0) { %>
			<br />
			<input type='hidden' name='<%=HIDDEN_CAID + number %>' value='<c:out value="<%= caid %>" />'> 
			<%=ejbcawebbean.getText("CREATENEWDELTACRL") + " : " %>
      		<% if ( cainfo.getCAInfo().getStatus() == CAConstants.CA_ACTIVE) { %>
				<input type='submit' name='<%=BUTTON_CREATEDELTACRL + number %>' value='<%=ejbcawebbean.getText("CREATEDELTACRL") %>'>
       		<% } else {
            	out.write(ejbcawebbean.getText("CAISNTACTIVE"));
          	   }
       		} %>
		</form>
	<% } %>
		<br />
		<hr />
	<%  number++;
	} %>
   

		<% // Include Footer 
   		String footurl =  globalconfiguration.getFootBanner(); %>
   
  		<jsp:include page="<%= footurl %>" />
		</form>
	</body>
</html>
