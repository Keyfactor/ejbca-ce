<html>
<%@page contentType="text/html"%>
<%@page errorPage="/errorpage.jsp"  import="se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean,se.anatom.ejbca.ra.GlobalConfiguration,
                                              se.anatom.ejbca.webdist.cainterface.CAInterfaceBean, se.anatom.ejbca.webdist.rainterface.CertificateView,
                                              se.anatom.ejbca.ra.raadmin.DNFieldExtractor, se.anatom.ejbca.ra.authorization.AuthorizationDeniedException"%>
<jsp:useBean id="ejbcawebbean" scope="session" class="se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean" />
<jsp:setProperty name="ejbcawebbean" property="*" /> 
<jsp:useBean id="cabean" scope="session" class="se.anatom.ejbca.webdist.cainterface.CAInterfaceBean" />
<jsp:setProperty name="cabean" property="*" /> 
<%!
  final static String BUTTON_CREATECRL      = "buttoncreatecrl";
%>
<%   // Initialize environment
  GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, "ca_functionallity/basic_functions"); 
                                            cabean.initialize(request); 

  final String THIS_FILENAME                = globalconfiguration.getCaPath() 
                                                  + "/cafunctions.jsp";

  final String CREATECRL_LINK               = "/ca_functionallity/create_crl";
  final String CREATECRL_PAGE               =  "createcrl/createcrl.jsp";
  final String GETCRL_LINK                  = globalconfiguration.getCaPath() 
                                                  + "getcrl.jsp";
  final String GETCRL_PAGE                  =    "getcrl.jsp"; 
  final String VIEWCERTIFICATE_LINK         = "/" +globalconfiguration.getAdminWebPath() + "viewcertificate.jsp";
  final String DOWNLOADCERTIFICATE_LINK     = globalconfiguration.getCaPath() 
                                                  + "/cacert";
  final String DOWNLOADCRL_LINK             = globalconfiguration.getCaPath() 
                                                  + "getcrl";

  if( request.getParameter(BUTTON_CREATECRL) != null ){
     // Check if user id authorized to create new crl.
     ejbcawebbean.isAuthorized(CREATECRL_LINK);
     // Create new crl
     cabean.createCRL();
  }

%>
<head>
  <title><%= globalconfiguration .getEjbcaTitle() %></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>">

  <link rel=STYLESHEET href="<%= ejbcawebbean.getCssFile() %>">
  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">
  <script language=javascript src="<%= globalconfiguration .getAdminWebPath() %>ejbcajslib.js"></script>
</head>
<body>
  <h2 align="center"><%= ejbcawebbean.getText("CAFUNCTIONS") %></h2>
<!--  <div align="right"><A  onclick='displayHelpWindow("<%= ejbcawebbean.getHelpfileInfix("ca_help.html") %>")'>
    <u><%= ejbcawebbean.getText("HELP") %></u> </A> -->
  </div>

  <% // Display CA info
     CertificateView[] cacerts = cabean.getCAInfo(); 
     
     if(cacerts != null){ 
        int index = cacerts.length-1; %>
        <table> 
          <tr id="Row0">
            <td>
              <%= ejbcawebbean.getText("ROOTCA") + " : "%> 
            </td>
            <td>
               <%= cacerts[index].getSubjectDNField(DNFieldExtractor.CN,0)
                  + ", " +  cacerts[index].getSubjectDNField(DNFieldExtractor.O,0) 
                  + ", " + cacerts[index].getSubjectDNField(DNFieldExtractor.C,0) %>
            </td>
          </tr>
          <tr id="Row0">
            <td>&nbsp;</td>
            <td> 
              <a href="<%=THIS_FILENAME%>"  onClick="window.open('<%=VIEWCERTIFICATE_LINK%>?cacert=<%=index%>', 'view_cert',config='height=600,width=600,scrollbars=yes,toolbar=no,resizable=1')";><%= ejbcawebbean.getText("VIEWCERTIFICATE")%></a>&nbsp;&nbsp;&nbsp;
              <a href="<%=DOWNLOADCERTIFICATE_LINK%>?cmd=iecacert&level=0"><%= ejbcawebbean.getText("DOWNLOADIE")%></a>&nbsp;&nbsp;&nbsp;
              <a href="<%=DOWNLOADCERTIFICATE_LINK%>?cmd=nscacert&level=0"><%= ejbcawebbean.getText("DOWNLOADNS")%></a>&nbsp;&nbsp;&nbsp;
              <a href="<%=DOWNLOADCERTIFICATE_LINK%>?cmd=cacert&level=0"><%= ejbcawebbean.getText("DOWNLOADPEM")%></a>
            </td>   
          </tr> 
          <%for(int i = 1; i < cacerts.length-1; i++){
              index--; %>
          <tr id="Row<%=i%2%>">
           <td>
              <%= ejbcawebbean.getText("SUBORDINATECA") + index + " : "%>  
           </td>  
           <td>
               <%= cacerts[index].getSubjectDNField(DNFieldExtractor.CN,0)
                  + ", " +  cacerts[index].getSubjectDNField(DNFieldExtractor.O,0) 
                  + ", " + cacerts[index].getSubjectDNField(DNFieldExtractor.C,0) %> 
           </td> 
          </tr>
          <tr id="Row<%=i%2%>">
            <td>&nbsp;</td>
            <td> 
              <a href="<%=THIS_FILENAME%>"  onClick="window.open('<%=VIEWCERTIFICATE_LINK%>?cacert=<%=index%>', 'view_cert',config='height=600,width=600,scrollbars=yes,toolbar=no,resizable=1')";><%= ejbcawebbean.getText("VIEWCERTIFICATE")%></a>&nbsp;&nbsp;&nbsp;
              <a href="<%=DOWNLOADCERTIFICATE_LINK%>?cmd=iecacert&level=<%=index%>"><%= ejbcawebbean.getText("DOWNLOADIE")%></a>&nbsp;&nbsp;&nbsp;
              <a href="<%=DOWNLOADCERTIFICATE_LINK%>?cmd=nscacert&level=<%=index%>"><%= ejbcawebbean.getText("DOWNLOADNS")%></a>&nbsp;&nbsp;&nbsp;
              <a href="<%=DOWNLOADCERTIFICATE_LINK%>?cmd=cacert&level=<%=index%>"><%= ejbcawebbean.getText("DOWNLOADPEM")%></a>
            </td>   
          </tr>
       <% } %>
        </table>
  <% }  %>
   
  


  <% // Display getcrl  %>
        <jsp:include page="<%= GETCRL_PAGE %>" />

  <% // Display createcrl is admin is authorized
    try{
      if(ejbcawebbean.isAuthorized(CREATECRL_LINK)){ %>
        <jsp:include page="<%= CREATECRL_PAGE %>" />
<%   }
    }catch(AuthorizationDeniedException e){} %>


<% // Include Footer 
   String footurl =  globalconfiguration.getFootBanner(); %>
   
  <jsp:include page="<%= footurl %>" />
</body>
</html>
