<html>
<%@page contentType="text/html"%>
<%@page errorPage="/errorpage.jsp" import="java.util.ArrayList, java.util.TreeMap, java.util.Iterator, se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean,se.anatom.ejbca.ra.GlobalConfiguration, se.anatom.ejbca.SecConst
               ,se.anatom.ejbca.webdist.hardtokeninterface.HardTokenInterfaceBean, se.anatom.ejbca.hardtoken.HardTokenIssuer, se.anatom.ejbca.hardtoken.HardTokenIssuerData, se.anatom.ejbca.hardtoken.HardTokenIssuerExistsException,
               se.anatom.ejbca.hardtoken.HardTokenIssuerDoesntExistsException, se.anatom.ejbca.hardtoken.AvailableHardToken, se.anatom.ejbca.webdist.rainterface.CertificateView"%>

<jsp:useBean id="ejbcawebbean" scope="session" class="se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean" />
<jsp:setProperty name="ejbcawebbean" property="*" /> 
<jsp:useBean id="tokenbean" scope="session" class="se.anatom.ejbca.webdist.hardtokeninterface.HardTokenInterfaceBean" />
<jsp:useBean id="cabean" scope="session" class="se.anatom.ejbca.webdist.cainterface.CAInterfaceBean" />

<%! // Declarations 
  static final String ACTION                        = "action";
  static final String ACTION_EDIT_ISSUERS           = "editissuers";
  static final String ACTION_EDIT_ISSUER            = "editissuer";

  static final String CHECKBOX_VALUE                = "true";

//  Used in profiles.jsp
  static final String BUTTON_EDIT_ISSUER       = "buttoneditissuer"; 
  static final String BUTTON_DELETE_ISSUER     = "buttondeleteissuer";
  static final String BUTTON_ADD_ISSUER        = "buttonaddissuer"; 
  static final String BUTTON_RENAME_ISSUER     = "buttonrenameissuer";
  static final String BUTTON_CLONE_ISSUER      = "buttoncloneissuer";

  static final String SELECT_ISSUER            = "selectissuer";
  static final String TEXTFIELD_ALIAS          = "textfieldalias";
  static final String HIDDEN_ALIAS             = "hiddenalias";
  static final String TEXTFIELD_CERTSN         = "textfieldcertsn";
 
// Buttons used in profile.jsp
  static final String BUTTON_SAVE              = "buttonsave";
  static final String BUTTON_CANCEL            = "buttoncancel";
 
  static final String SELECT_AVAILABLEHARDTOKENS            = "selectavailablehardtokens";

  static final String SELECT_TYPE                         = "selecttype";
  String alias = null;
  String certsn = null;
%>
<% 

  // Initialize environment
  String includefile = "hardtokenissuerspage.jsp";

  boolean  issuerexists             = false;
  boolean  issuerdeletefailed       = false;

  String value=null;
  HardTokenIssuer issuer=null;
 

  GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request,"/hardtoken_functionallity/edit_hardtoken_issuers"); 
                                            tokenbean.initialize(request);
                                            cabean.initialize(request); 

  String THIS_FILENAME                    = globalconfiguration.getHardTokenPath() + "/edithardtokenissuers.jsp";
%>
 
<head>
  <title><%= globalconfiguration .getEjbcaTitle() %></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>">
  <link rel=STYLESHEET href="<%= ejbcawebbean.getCssFile() %>">
  <script language=javascript src="<%= globalconfiguration .getAdminWebPath() %>ejbcajslib.js"></script>
</head>
<body>

<%  
   // Get Certificate issuer DN
   CertificateView[] cacerts = cabean.getCAInfo();
   String certissuerdn= cacerts[cacerts.length-1].getIssuerDN();

   // Determine action 
  if( request.getParameter(ACTION) != null){
    if( request.getParameter(ACTION).equals(ACTION_EDIT_ISSUERS)){
      if( request.getParameter(BUTTON_EDIT_ISSUER) != null){
          // Display  profilepage.jsp
         alias = request.getParameter(SELECT_ISSUER);
         if(alias != null){
           if(!alias.trim().equals("")){
             includefile="hardtokenissuerpage.jsp"; 
           } 
           else{ 
            alias= null;
          } 
        }
        if(alias == null){   
          includefile="hardtokenissuerspage.jsp";     
        }
      }
      if( request.getParameter(BUTTON_DELETE_ISSUER) != null) {
          // Delete profile and display profilespage. 
          alias = request.getParameter(SELECT_ISSUER);
          if(alias != null){
            if(!alias.trim().equals("")){
              issuerdeletefailed = !tokenbean.removeHardTokenIssuer(alias);
            }
          }
          includefile="hardtokenissuerspage.jsp";          
      }
      if( request.getParameter(BUTTON_RENAME_ISSUER) != null){ 
         // Rename selected profile and display profilespage.
       String newalias  = request.getParameter(TEXTFIELD_ALIAS);
       String newcertsn = request.getParameter(TEXTFIELD_CERTSN);
       String oldalias = request.getParameter(SELECT_ISSUER);
       if(oldalias != null && newalias != null && newcertsn!=null){
         if(!newalias.trim().equals("") && !oldalias.trim().equals("") && !newcertsn.trim().equals("")){
           try{
             tokenbean.renameHardTokenIssuer(oldalias.trim(),newalias.trim(),newcertsn.trim(),certissuerdn);
           }catch( HardTokenIssuerExistsException e){
             issuerexists=true;
           }        
         }
       }      
       includefile="hardtokenissuerspage.jsp"; 
      }
      if( request.getParameter(BUTTON_ADD_ISSUER) != null){
         // Add profile and display profilespage.
         alias = request.getParameter(TEXTFIELD_ALIAS);
         String newcertsn = request.getParameter(TEXTFIELD_CERTSN);
         if(alias != null && newcertsn != null){
           if(!alias.trim().equals("") && !newcertsn.trim().equals("")){
             try{
               tokenbean.addHardTokenIssuer(alias.trim(), newcertsn.trim(),certissuerdn);
             }catch( HardTokenIssuerExistsException e){
               issuerexists=true;
             }
           }      
         }
         includefile="hardtokenissuerspage.jsp"; 
      }
      if( request.getParameter(BUTTON_CLONE_ISSUER) != null){
         // clone profile and display profilespage.
       String newalias  = request.getParameter(TEXTFIELD_ALIAS);
       String newcertsn = request.getParameter(TEXTFIELD_CERTSN);
       String oldalias = request.getParameter(SELECT_ISSUER);
       if(oldalias != null && newalias != null && newcertsn != null){
         if(!oldalias.trim().equals("") && !newalias.trim().equals("") && !newcertsn.trim().equals("")){
             try{ 
               tokenbean.cloneHardTokenIssuer(oldalias.trim(),newalias.trim(), newcertsn.trim(), certissuerdn);
             }catch( HardTokenIssuerExistsException e){
               issuerexists=true;
             }
         }
       }      
       includefile="hardtokenissuerspage.jsp"; 
      }
    }
    if( request.getParameter(ACTION).equals(ACTION_EDIT_ISSUER)){
         // Display edit access rules page.
       alias = request.getParameter(HIDDEN_ALIAS);
       if(alias != null){
         if(!alias.trim().equals("")){
           if(request.getParameter(BUTTON_SAVE) != null){
             issuer = tokenbean.getHardTokenIssuerData(alias).getHardTokenIssuer();
             // Save changes.
             ArrayList availabletokens = new ArrayList();
 
             String[] values = request.getParameterValues(SELECT_AVAILABLEHARDTOKENS);
             
             if(values!= null){
               for(int i=0; i< values.length; i++){
                 availabletokens.add(new Integer(values[i]));                     
               }
             } 
             issuer.setAvailableHardTokens(availabletokens);
                      
             tokenbean.changeHardTokenIssuer(alias,issuer);
             includefile="hardtokenissuerspage.jsp";
           }
           if(request.getParameter(BUTTON_CANCEL) != null){
              // Don't save changes.
             includefile="hardtokenissuerspage.jsp";
           }
         }
      }
    }
  }
 // Include page
  if( includefile.equals("hardtokenissuerspage.jsp")){ %>
   <%@ include file="hardtokenissuerspage.jsp" %>
<%}
  if( includefile.equals("hardtokenissuerpage.jsp")){ %>
   <%@ include file="hardtokenissuerpage.jsp" %> 
<%}

   // Include Footer 
   String footurl =   globalconfiguration.getFootBanner(); %>
   
  <jsp:include page="<%= footurl %>" />

</body>
</html>
