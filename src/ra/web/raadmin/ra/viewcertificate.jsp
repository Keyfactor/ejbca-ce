<html>
<%@page contentType="text/html"%>
<%@page errorPage="/errorpage.jsp"  import="se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean, se.anatom.ejbca.webdist.webconfiguration.GlobalConfiguration, 
                 se.anatom.ejbca.webdist.rainterface.RAInterfaceBean, se.anatom.ejbca.webdist.rainterface.CertificateView,
                 javax.ejb.CreateException, java.rmi.RemoteException" %>
<jsp:useBean id="ejbcawebbean" scope="session" class="se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean" />
<jsp:setProperty name="ejbcawebbean" property="*" /> 
<jsp:useBean id="rabean" scope="session" class="se.anatom.ejbca.webdist.rainterface.RAInterfaceBean" />
<jsp:setProperty name="rabean" property="*" /> 
<%! // Declarations
 
  static final String SUBJECTDN_PARAMETER        = "subjectdnparameter";
  static final String USER_PARAMETER             = "userparameter";


  static final String BUTTON_CLOSE               = "buttonclose"; 
  static final String BUTTON_VIEW_PREVIOUS       = "buttonviewprevious"; 
  static final String BUTTON_VIEW_NEXT           = "buttonviewnext";

  static final String CHECKBOX_DIGITALSIGNATURE  = "checkboxdigitalsignature";
  static final String CHECKBOX_NONREPUDATION     = "checkboxnonrepudation";
  static final String CHECKBOX_KEYENCIPHERMENT   = "checkboxkeyencipherment";
  static final String CHECKBOX_DATAENCIPHERMENT  = "checkboxdataencipherment";
  static final String CHECKBOX_KEYAGREEMENT      = "checkboxkeyagreement";
  static final String CHECKBOX_KEYCERTSIGN       = "checkboxkeycertsign";
  static final String CHECKBOX_CRLSIGN           = "checkboxcrlsign";
  static final String CHECKBOX_ENCIPHERONLY      = "checkboxencipheronly";
  static final String CHECKBOX_DECIPHERONLY      = "checkboxdecipheronly";

  static final String CHECKBOX_VALUE             = "true";

  static final String HIDDEN_INDEX               = "hiddenindex";

%><%
  // Initialize environment.
  GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request); 
  String THIS_FILENAME            =  globalconfiguration.getRaPath()  + "/viewcertificate.jsp";

  boolean nosubjectdnparameter    = true;
  CertificateView certificatedata = null;
  String certificatesubjectdn     = null;
  String username                 = null;         
  int numberofcertificates        = 0;
  int currentindex                = 0;
  
  if( request.getParameter(USER_PARAMETER ) != null ){
    username = request.getParameter(USER_PARAMETER );
  }

  if( request.getParameter(SUBJECTDN_PARAMETER) != null ){
    nosubjectdnparameter = false;
    if(request.getParameter(BUTTON_VIEW_PREVIOUS) == null && request.getParameter(BUTTON_VIEW_NEXT) == null){
      // load certificates and get the one with latest expiring date.
      certificatesubjectdn = request.getParameter(SUBJECTDN_PARAMETER);
      rabean.loadCertificates(certificatesubjectdn);
      numberofcertificates = rabean.getNumberOfCertificates();
      if(numberofcertificates > 0)
        certificatedata = rabean.getCertificate(0);
    }
    if(request.getParameter(BUTTON_VIEW_PREVIOUS) != null){
       numberofcertificates = rabean.getNumberOfCertificates();
       if(request.getParameter(HIDDEN_INDEX)!= null){
         currentindex = Integer.parseInt(request.getParameter(HIDDEN_INDEX)) -1;
         if(currentindex < 0){
           currentindex = 0;
         }
         certificatedata = rabean.getCertificate(currentindex);
       }
    }
    if(request.getParameter(BUTTON_VIEW_NEXT) != null){
       numberofcertificates = rabean.getNumberOfCertificates();
       if(request.getParameter(HIDDEN_INDEX)!= null){
         currentindex = Integer.parseInt(request.getParameter(HIDDEN_INDEX)) + 1;
         if(currentindex > numberofcertificates -1){
           currentindex = numberofcertificates;
         }
         certificatedata = rabean.getCertificate(currentindex);
       }
    }
  }  
%>
<head>
  <title><%= globalconfiguration.getEjbcaTitle() %></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>">
  <link rel=STYLESHEET href="<%= ejbcawebbean.getCssFile() %>">
  <script language=javascript src="<%= globalconfiguration.getRaAdminPath() %>ejbcajslib.js"></script>
</head>
<body >
  <h2 align="center"><%= ejbcawebbean.getText("VIEWCERTIFICATE") %></h2>
  <div align="right"><A  onclick='displayHelpWindow("<%= ejbcawebbean.getHelpfileInfix("viewcertificate_help.html") %>")'>
    <u><%= ejbcawebbean.getText("INFORMATIONANDHELP") %></u> </A>
  </div>
  <%if(nosubjectdnparameter){%>
  <div align="center"><h4 id="alert"><%=ejbcawebbean.getText("YOUMUSTSPECIFYCERT") + "'" + SUBJECTDN_PARAMETER + "'"%></h4></div> 
  <% } 
     else{
       if(certificatedata == null){%>
  <div align="center"><h4 id="alert"><%=ejbcawebbean.getText("CERTIFICATEDOESNTEXIST") %></h4></div> 
    <% }
       else{ %>

  <form name="viewcertificate" action="<%= THIS_FILENAME %>" method="post">
     <input type="hidden" name='<%= SUBJECTDN_PARAMETER %>' value='<%=certificatesubjectdn %>'> 
     <% if(username != null){ %>
     <input type="hidden" name='<%= USER_PARAMETER %>' value='<%=username %>'> 
     <% } %>
     <input type="hidden" name='<%= HIDDEN_INDEX %>' value='<%=currentindex %>'>
     <table border="0" cellpadding="0" cellspacing="2" width="400">
      <% if(username != null){%>
      <tr id="Row0">
	<td align="right"><%= ejbcawebbean.getText("USERNAME") %></td>
	<td><%= username %>
        </td>
      </tr>
      <tr id="Row1">
	<td align="right"><%= ejbcawebbean.getText("CERTIFICATENR") %></td>
	<td><%= (currentindex +1) + " " + ejbcawebbean.getText("OF") + " " + numberofcertificates %>
        </td>
      </tr>
      <% } %>
      <tr id="Row0">
	<td align="right"><%= ejbcawebbean.getText("CERTIFICATETYPE") %></td>
	<td> <%= certificatedata.getType() + " " + ejbcawebbean.getText("VER") + certificatedata.getVersion() %>
        </td>
      </tr>
       <tr id="Row1">
	 <td align="right"><%= ejbcawebbean.getText("SERIALNUMBER") %></td>
	 <td><%= certificatedata.getSerialNumber() %> 
         </td>
       </tr>
       <tr id="Row0">
	 <td align="right"><%= ejbcawebbean.getText("ISSUERDN") %></td>
	 <td><%= certificatedata.getIssuerDN()%> 
         </td>
       </tr>
       <tr id="Row1">
	 <td align="right"><%= ejbcawebbean.getText("VALIDFROM") %></td>
	 <td><%= ejbcawebbean.printDate(certificatedata.getValidFrom())  %> 
         </td>
       </tr>
       <tr id="Row0">
	 <td align="right"><%= ejbcawebbean.getText("VALIDTO") %></td>
	 <td><%= ejbcawebbean.printDate(certificatedata.getValidTo()) %>
         </td>
       </tr>
       <tr id="Row1">
	 <td align="right"><%= ejbcawebbean.getText("SUBJECTDN") %></td>
	 <td><%= certificatedata.getSubjectDN() %> 
         </td>
       </tr>
       <tr id="Row0">
	 <td align="right"><%= ejbcawebbean.getText("PUBLICKEY") %></td>
	 <td><%= certificatedata.getPublicKeyAlgorithm() %> <% if(certificatedata.getPublicKeyLength() != null){
                                                                 out.write(" ( " + certificatedata.getPublicKeyLength() + ejbcawebbean.getText("BITS") + ")");  
                                                               } %>
         </td>
       </tr>
       <tr id="Row1">
	 <td align="right"><%= ejbcawebbean.getText("BASICCONSTRAINTS") %></td>
	 <td><%= certificatedata.getBasicConstraints() %>
         </td>
       </tr>
       <tr id="Row0">
	 <td align="right"><%= ejbcawebbean.getText("KEYUSAGE") %></td>
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
       <tr id="Row1">
	 <td align="right"><%= ejbcawebbean.getText("SIGNATUREALGORITHM") %></td>
	 <td> <%= certificatedata.getSignatureAlgoritm() %>
         </td>
       </tr>
       <tr  id="Row0"> 
        <td  align="right"> 
          <%= ejbcawebbean.getText("SHA1FINGERPRINT") %> <br>
        </td>
        <td >  <%= certificatedata.getSHA1Fingerprint() %>
        </td>
       </tr>
       <tr  id="Row0"> 
        <td  align="right"> 
          <%= ejbcawebbean.getText("MD5FINGERPRINT") %> <br>
        </td>
        <td >  <%= certificatedata.getMD5Fingerprint() %>
        </td>
       </tr>
       <tr  id="Row1"> 
        <td  align="right"> 
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
       <tr id="Row0">
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
     </table> 
   </form>
   <p></p>
   <% }
    }%>

</body>
</html>
