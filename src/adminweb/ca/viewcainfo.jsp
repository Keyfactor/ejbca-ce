<html>
<%@page contentType="text/html"%>
<%@page errorPage="/errorpage.jsp"  import="se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean, se.anatom.ejbca.ra.raadmin.GlobalConfiguration, 
                 se.anatom.ejbca.webdist.cainterface.CAInfoView, se.anatom.ejbca.util.CertTools, se.anatom.ejbca.webdist.cainterface.CAInterfaceBean, se.anatom.ejbca.SecConst,
                 se.anatom.ejbca.authorization.AuthorizationDeniedException,
                 javax.ejb.CreateException, java.rmi.RemoteException" %>
<jsp:useBean id="ejbcawebbean" scope="session" class="se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean" />
<jsp:useBean id="cabean" scope="session" class="se.anatom.ejbca.webdist.cainterface.CAInterfaceBean" />

<%! // Declarations
 
  static final String CA_PARAMETER           = "caid";

  static final String CERTSERNO_PARAMETER       = "certsernoparameter"; 

  static final String BUTTON_CLOSE             = "buttonclose"; 


%><%
  // Initialize environment.
  GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, "/ca_functionality/basic_functions"); 
                                            cabean.initialize(request, ejbcawebbean);
  String THIS_FILENAME                    = globalconfiguration.getCaPath()  + "/viewcainfo.jsp";

  final String VIEWCERT_LINK            = globalconfiguration.getAdminWebPath() + "viewcertificate.jsp";

  boolean nocaparameter          = true;
  boolean notauthorized            = false;

  
  CAInfoView cainfo = null;
  String[] cainfodata = null;
  String[] cainfotexts = null;
  int caid = 0; 
  java.security.cert.X509Certificate ocspcert = null;
   

  if( request.getParameter(CA_PARAMETER) != null ){
    caid = Integer.parseInt(java.net.URLDecoder.decode(request.getParameter(CA_PARAMETER),"UTF-8"));
    try{
      cainfo = cabean.getCAInfo(caid);
      ocspcert = cainfo.getOCSPSignerCertificate();
    } catch(AuthorizationDeniedException e){
       notauthorized = true;
    }
    nocaparameter = false;
    if(cainfo!=null){
      cainfodata  = cainfo.getCAInfoData();
      cainfotexts = cainfo.getCAInfoDataText(); 
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
</head>
<SCRIPT language="JavaScript">
<!--
function viewocspcert(){        
    var link = "<%= VIEWCERT_LINK %>?<%= CERTSERNO_PARAMETER %>=<%=ocspcert.getSerialNumber().toString(16) + "," + CertTools.getIssuerDN(ocspcert)%>";
    link = encodeURI(link);
    window.open(link, 'view_cert','height=600,width=500,scrollbars=yes,toolbar=no,resizable=1');
}
-->
</SCRIPT>
<body >

  <h2 align="center"><%= ejbcawebbean.getText("CAINFORMATION") %></h2>
  <!-- <div align="right"><A  onclick='displayHelpWindow("<%= ejbcawebbean.getHelpfileInfix("ra_help.html")  + "#viewendentity"%>")'>
    <u><%= ejbcawebbean.getText("HELP") %></u> </A> -->
  </div>
  <%if(nocaparameter){%>
  <div align="center"><h4 id="alert"><%=ejbcawebbean.getText("YOUMUSTSPECIFYCAID") %></h4></div> 
  <% } 
     else{
       if(cainfo == null){%>
  <div align="center"><h4 id="alert"><%=ejbcawebbean.getText("CADOESNTEXIST") %></h4></div> 
    <% }
       else{ 
         if(notauthorized){ %>
  <div align="center"><h4 id="alert"><%=ejbcawebbean.getText("NOTAUTHORIZEDTOVIEWCA") %></h4></div> 
     <%  }else{%>

  <form name="adduser" action="<%= THIS_FILENAME %>" method="post">
     <input type="hidden" name='<%= CA_PARAMETER %>' value='<%=caid %>'>
     <table border="0" cellpadding="0" cellspacing="2" width="400">
     <% for(int i=0; i < cainfotexts.length; i++){ %>
      <tr id="Row<%=(row++)%2%>">
	<td align="right" width="<%=columnwidth%>"><%= cainfotexts[i] %></td>
	<td>&nbsp;&nbsp;<%= cainfodata[i] %>
        </td>
      </tr>    
      <% } %>
      <tr id="Row<%=(row++)%2%>">
	 <td width="<%=columnwidth%>"></td>
	 <td>
             <input type="reset" name="<%= BUTTON_CLOSE %>" value="<%= ejbcawebbean.getText("CLOSE") %>" tabindex="20"
                    onClick='self.close()'>
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