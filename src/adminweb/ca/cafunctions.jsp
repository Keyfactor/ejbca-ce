<%@ page pageEncoding="ISO-8859-1"%>
<%@page errorPage="/errorpage.jsp"  import=" java.util.*, java.security.cert.Certificate, java.security.cert.X509Certificate, se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean,se.anatom.ejbca.ra.raadmin.GlobalConfiguration,
                                              se.anatom.ejbca.webdist.cainterface.CAInterfaceBean, se.anatom.ejbca.webdist.rainterface.CertificateView,
                                              se.anatom.ejbca.ca.caadmin.CAInfo, se.anatom.ejbca.ca.store.CRLInfo, se.anatom.ejbca.authorization.AuthorizationDeniedException, se.anatom.ejbca.SecConst"%>
<html>
<jsp:useBean id="ejbcawebbean" scope="session" class="se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean" />
<jsp:setProperty name="ejbcawebbean" property="*" /> 
<jsp:useBean id="cabean" scope="session" class="se.anatom.ejbca.webdist.cainterface.CAInterfaceBean" />
<jsp:setProperty name="cabean" property="*" /> 
<%!

  final static String HIDDEN_NUMBEROFCAS    = "hiddennumberofcas";
  final static String HIDDEN_CASUBJECTDN    = "hiddensubjectdn";

  final static String BUTTON_CREATECRL      = "buttoncreatecrl";
%>
<%   // Initialize environment
  GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, "/ca_functionality/basic_functions"); 
                                            cabean.initialize(request, ejbcawebbean); 

  final String THIS_FILENAME                = globalconfiguration.getCaPath() 
                                                  + "/cafunctions.jsp";

  final String CREATECRL_LINK               = "/ca_functionality/create_crl";  
  final String GETCRL_LINK                  = globalconfiguration.getCaPath() 
                                                  + "/getcrl/getcrl.jsp";
  final String GETCRL_PAGE                  =    "getcrl.jsp"; 
  final String VIEWCERTIFICATE_LINK         = globalconfiguration.getBaseUrl() + globalconfiguration.getAdminWebPath() + "viewcertificate.jsp";
  final String VIEWINFO_LINK                = globalconfiguration.getBaseUrl() + globalconfiguration.getCaPath() + "/viewcainfo.jsp";
  final String DOWNLOADCERTIFICATE_LINK     = globalconfiguration.getCaPath() 
                                                  + "/cacert";
  final String DOWNLOADCRL_LINK             = globalconfiguration.getCaPath() + "/getcrl/getcrl";
  boolean createcrlrights = false;
  try{
     createcrlrights =ejbcawebbean.isAuthorized(CREATECRL_LINK);
  }catch(AuthorizationDeniedException e){}


  if(request.getParameter(HIDDEN_NUMBEROFCAS) != null){
    int numberofcas = Integer.parseInt(request.getParameter(HIDDEN_NUMBEROFCAS));
    for(int i = 0; i < numberofcas; i++){       
       String casubjectdn = request.getParameter(HIDDEN_CASUBJECTDN+i);
       if( request.getParameter(BUTTON_CREATECRL+i) != null ){      
         // Check if user id authorized to create new crl.
         ejbcawebbean.isAuthorized(CREATECRL_LINK);
         ejbcawebbean.isAuthorized(se.anatom.ejbca.authorization.AvailableAccessRules.CAPREFIX + casubjectdn.hashCode());
         // Create new crl
         cabean.createCRL(casubjectdn);
      }         
    }
  }

  TreeMap canames = ejbcawebbean.getInformationMemory().getCANames();

%>
<head>
  <title><%= globalconfiguration .getEjbcaTitle() %></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>">

  <link rel=STYLESHEET href="<%= ejbcawebbean.getCssFile() %>">
  <script language=javascript src="<%= globalconfiguration .getAdminWebPath() %>ejbcajslib.js"></script>
</head>
<body>
<SCRIPT language="JavaScript">
<!--  
function viewcacert(caid){   
    var link = "<%=VIEWCERTIFICATE_LINK%>?caid="+caid;
    link = encodeURI(link);     
    win_popup = window.open(link, 'view_cert','height=600,width=600,scrollbars=yes,toolbar=no,resizable=1');
    win_popup.focus();
} 

function viewcainfo(caid){        
    var link = "<%=VIEWINFO_LINK%>?caid="+caid;
    link = encodeURI(link);
    win_popup = window.open(link, 'view_info','height=450,width=450,scrollbars=yes,toolbar=no,resizable=1');
    win_popup.focus();
}
-->
</SCRIPT>
<form name='createcrl' method=GET action='<%=THIS_FILENAME %>'>
<input type='hidden' name='<%=HIDDEN_NUMBEROFCAS %>' value='<%=canames.keySet().size()%>'> 
  <h2 align="center"><%= ejbcawebbean.getText("CAFUNCTIONS") %></h2>
<!--  <div align="right"><A  onclick='displayHelpWindow("<%= ejbcawebbean.getHelpfileInfix("ca_help.html") %>")'>
    <u><%= ejbcawebbean.getText("HELP") %></u> </A> 
  </div> -->

  <% // Display CA info one by one.
     Iterator iter = canames.keySet().iterator();
     int number = 0;
     while(iter.hasNext()){
       String caname = (String) iter.next();  
       int caid = ((Integer) canames.get(caname)).intValue();
       se.anatom.ejbca.webdist.cainterface.CAInfoView cainfo = cabean.getCAInfo(caid);
       String subjectdn = cainfo.getCAInfo().getSubjectDN();
       Certificate[] certificatechain = (Certificate[]) cainfo.getCertificateChain().toArray(new Certificate[0]);
       int chainsize = certificatechain.length;
 %>
       <br>
       <H3><%= ejbcawebbean.getText("BASICFUNCTIONSFOR") + " : " + caname%> <a href="<%=THIS_FILENAME%>"  onClick="viewcacert(<%=caid%>)"><%= ejbcawebbean.getText("VIEWCERTIFICATE")%></a>&nbsp;&nbsp;
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
               <% if(certificatechain[j] instanceof X509Certificate)
                    out.write(((X509Certificate) certificatechain[j]).getSubjectDN().toString()); %>                  
            </td>
          </tr>
          <tr id="Row<%=row%2%>">
            <td>&nbsp;</td>
            <td>               
              <a href="<%=DOWNLOADCERTIFICATE_LINK%>?cmd=iecacert&level=<%= j%>&issuer=<%= subjectdn %>"><%= ejbcawebbean.getText("DOWNLOADIE")%></a>&nbsp;&nbsp;&nbsp;
              <a href="<%=DOWNLOADCERTIFICATE_LINK%>?cmd=nscacert&level=<%= j%>&issuer=<%= subjectdn %>"><%= ejbcawebbean.getText("DOWNLOADNS")%></a>&nbsp;&nbsp;&nbsp;
              <a href="<%=DOWNLOADCERTIFICATE_LINK%>?cmd=cacert&level=<%= j%>&issuer=<%= subjectdn %>"><%= ejbcawebbean.getText("DOWNLOADPEM")%></a>
            </td>   
          </tr> 
          <%   }else{ %> 
          <tr id="Row<%=row%2%>">
           <td>
              <%= ejbcawebbean.getText("SUBORDINATECA") + " " + (j+1) + " : "%>  
           </td>  
           <td>
               <% if(certificatechain[j] instanceof X509Certificate)
                    out.write(((java.security.cert.X509Certificate) certificatechain[j]).getSubjectDN().toString()); %>                  
           </td> 
          </tr>
          <tr id="Row<%=row%2%>">
            <td>&nbsp;</td>
            <td>               
              <a href="<%=DOWNLOADCERTIFICATE_LINK%>?cmd=iecacert&level=<%= j%>&issuer=<%= subjectdn %>"><%= ejbcawebbean.getText("DOWNLOADIE")%></a>&nbsp;&nbsp;&nbsp;
              <a href="<%=DOWNLOADCERTIFICATE_LINK%>?cmd=nscacert&level=<%= j%>&issuer=<%= subjectdn %>"><%= ejbcawebbean.getText("DOWNLOADNS")%></a>&nbsp;&nbsp;&nbsp;
              <a href="<%=DOWNLOADCERTIFICATE_LINK%>?cmd=cacert&level=<%= j%>&issuer=<%= subjectdn %>"><%= ejbcawebbean.getText("DOWNLOADPEM")%></a>
            </td>   
          </tr>
          <% }
             row++;
          }%>
        </table> 
        <br> 
        <% CRLInfo crlinfo = cabean.getLastCRLInfo(subjectdn);
           if(crlinfo == null){ 
             out.write(ejbcawebbean.getText("NOCRLHAVEBEENGENERATED"));
           }else{
           boolean expired = crlinfo.getExpireDate().compareTo(new Date()) < 0; %>
<%=ejbcawebbean.getText("LATESTCRL") + ": "  
  + ejbcawebbean.getText("CREATED") + " " + ejbcawebbean.printDateTime(crlinfo.getCreateDate()) + ","%>
        <% if(expired){
              out.write(" <font id=\"alert\">" + ejbcawebbean.getText("EXPIRED") + " " + ejbcawebbean.printDateTime(crlinfo.getExpireDate()) + "</font>");
           }else{
              out.write(ejbcawebbean.getText("EXPIRES") + " " + ejbcawebbean.printDateTime(crlinfo.getExpireDate()));
           } 
           out.write(", " + ejbcawebbean.getText("NUMBER") + " " + crlinfo.getLastCRLNumber()); %>  
<i><a href="<%=DOWNLOADCRL_LINK%>?cmd=crl&issuer=<%= subjectdn %>" ><%=ejbcawebbean.getText("GETCRL") %></a></i>
<br>
<% // Display createcrl if admin is authorized
      }
      if(createcrlrights){ %>
<br> 
<input type='hidden' name='<%=HIDDEN_CASUBJECTDN + number %>' value='<%=subjectdn%>'> 
<%=ejbcawebbean.getText("CREATENEWCRL") + " : " %>
       <% if(cainfo.getCAInfo().getStatus() == SecConst.CA_ACTIVE){ %>
<input type='submit' name='<%=BUTTON_CREATECRL + number %>' value='<%=ejbcawebbean.getText("CREATECRL") %>'>
       <% }else{
           out.write(ejbcawebbean.getText("CAISNTACTIVE"));
          } %> 
<br>          
<%    } %>
<br>
<hr>
<% 
    number++;
  }  %>
   


<% // Include Footer 
   String footurl =  globalconfiguration.getFootBanner(); %>
   
  <jsp:include page="<%= footurl %>" />
</form>
</body>
</html>
