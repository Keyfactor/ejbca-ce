<%@ page pageEncoding="ISO-8859-1"%>
<%@ page contentType="text/html; charset=@page.encoding@" %>
<%@page errorPage="/errorpage.jsp"  import="org.ejbca.ui.web.admin.configuration.EjbcaWebBean, org.ejbca.core.model.ra.raadmin.GlobalConfiguration, 
                 org.ejbca.ui.web.admin.cainterface.CAInfoView, org.ejbca.util.CertTools, org.ejbca.ui.web.admin.cainterface.CAInterfaceBean, org.ejbca.core.model.SecConst,
                 org.ejbca.core.model.authorization.AuthorizationDeniedException,
                 javax.ejb.CreateException, java.rmi.RemoteException, java.security.cert.X509Certificate" %>

<html>
<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />
<jsp:useBean id="cabean" scope="session" class="org.ejbca.ui.web.admin.cainterface.CAInterfaceBean" />
<jsp:useBean id="viewcainfohelper" scope="session" class="org.ejbca.ui.web.admin.cainterface.ViewCAInfoJSPHelper" />

<%
  // Initialize environment.
  GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, "/ca_functionality/basic_functions"); 
                                            cabean.initialize(request, ejbcawebbean);
  String THIS_FILENAME                    = globalconfiguration.getCaPath()  + "/viewcainfo.jsp";

  final String VIEWCERT_LINK            = ejbcawebbean.getBaseUrl() + globalconfiguration.getAdminWebPath() + "viewcertificate.jsp";

  viewcainfohelper.initialize(request, ejbcawebbean, cabean);
  viewcainfohelper.parseRequest(request);
  
  int row = 0; 
  int columnwidth = 200;
%>
<head>
  <title><%= globalconfiguration.getEjbcaTitle() %></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>">
  <link rel=STYLESHEET href="<%= ejbcawebbean.getCssFile() %>">
  <script language=javascript src="<%= globalconfiguration.getAdminWebPath() %>ejbcajslib.js"></script>
</head>
<SCRIPT language="JavaScript">
<!--
function viewocspcert(){
	<%
	X509Certificate ocspcert = viewcainfohelper.ocspcert;
	String ocspdn = "N/A";
	String ocspserno = "N/A";
	if (ocspcert != null) {
		ocspdn = CertTools.getIssuerDN(viewcainfohelper.ocspcert);
		ocspserno = viewcainfohelper.ocspcert.getSerialNumber().toString(16);
	}
	%>
    var link = "<%= VIEWCERT_LINK %>?<%= viewcainfohelper.CERTSERNO_PARAMETER %>=<%=java.net.URLEncoder.encode(ocspserno + "," + ocspdn,"UTF-8")%>";
    link = encodeURI(link);
    win_popup = window.open(link, 'view_cert','height=600,width=600,scrollbars=yes,toolbar=no,resizable=1');
    win_popup.focus();
}
-->
</SCRIPT>
<body >

  <h2 align="center"><%= ejbcawebbean.getText("CAINFORMATION") %></h2>
  <!-- <div align="right"><A  onclick='displayHelpWindow("<%= ejbcawebbean.getHelpfileInfix("ra_help.html")  + "#viewendentity"%>")'>
    <u><%= ejbcawebbean.getText("HELP") %></u> </A> 
  </div>-->
  <%if(viewcainfohelper.generalerrormessage != null){%>
  <div align="center"><h4 id="alert"><%=ejbcawebbean.getText(viewcainfohelper.generalerrormessage) %></h4></div> 
  <% } 
     else{
       if(viewcainfohelper.activationerrormessage != null){ %>
  <div align="center"><h4 id="alert"><%=ejbcawebbean.getText(viewcainfohelper.activationerrormessage) + " : " + viewcainfohelper.activationerrorreason %></h4></div> 
     <%  }       
         if(viewcainfohelper.activationmessage != null){ %>
              <div align="center"><h4><%=ejbcawebbean.getText(viewcainfohelper.activationmessage) %></h4></div> 
     <%  }%>

  <form name="viewcainfo" action="<%= THIS_FILENAME %>" method="post">
     <input type="hidden" name='<%= viewcainfohelper.CA_PARAMETER %>' value='<%=viewcainfohelper.caid %>'>
     <table border="0" cellpadding="0" cellspacing="2" width="400">
     <% for(int i=0; i < viewcainfohelper.cainfo.getCAInfoData().length; i++){ %>
      <tr id="Row<%=(row++)%2%>">
	<td align="right" width="<%=columnwidth%>"><%= viewcainfohelper.cainfo.getCAInfoDataText()[i] %></td>
	<td>&nbsp;&nbsp;<%= viewcainfohelper.cainfo.getCAInfoData()[i] %>
        </td>
      </tr>    
      <% } %>
     
     <% if(viewcainfohelper.can_activate && viewcainfohelper.ishardcatoken && (viewcainfohelper.status == SecConst.CA_OFFLINE || viewcainfohelper.hardtokenoffline)){ %> 
     <tr id="Row<%=(row++)%2%>">
  	    <td width="<%=columnwidth%>"></td>
	    <td>
 	         <%= ejbcawebbean.getText("AUTHENTICATIONCODE") + ": " %>
	         <input type="password" name="<%= viewcainfohelper.PASSWORD_AUTHENTICATIONCODE %>" size="10" maxlength="255"  value=''>
             <input type="submit" name="<%= viewcainfohelper.BUTTON_ACTIVATE %>" value="<%= ejbcawebbean.getText("ACTIVATE") %>" onClick='return confirm("<%= ejbcawebbean.getText("AREYOUSUREACTIVATECA") %>")'>
        </td>
      </tr> 
     <% }
        if(viewcainfohelper.can_activate && viewcainfohelper.ishardcatoken && viewcainfohelper.status == SecConst.CA_ACTIVE){ %>     
     <tr id="Row<%=(row++)%2%>">
	 <td width="<%=columnwidth%>"></td>
	 <td>
             <input type="submit" name="<%= viewcainfohelper.BUTTON_MAKEOFFLINE %>" value="<%= ejbcawebbean.getText("MAKEOFFLINE") %>" onClick='return confirm("<%= ejbcawebbean.getText("AREYOUSUREMAKECAOFFLINE") %>")'>
         </td>
      </tr>           
     <% } %>      
      <tr id="Row<%=(row++)%2%>">
	    <td width="<%=columnwidth%>"></td>
	    <td>
             <input type="button" name="<%= viewcainfohelper.BUTTON_CLOSE %>" value="<%= ejbcawebbean.getText("CLOSE") %>" 
                    onClick='self.close()'>
        </td>
      </tr> 
     </table> 
   </form>
   <p></p>
   <% }%>

</body>
</html>