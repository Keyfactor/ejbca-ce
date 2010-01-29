<%@ page pageEncoding="ISO-8859-1"%>
<% response.setContentType("text/html; charset="+org.ejbca.config.WebConfiguration.getWebContentEncoding()); %>
<%@page errorPage="/errorpage.jsp" import="java.util.*, java.io.*, java.security.cert.Certificate, org.apache.commons.fileupload.*, org.ejbca.ui.web.admin.configuration.EjbcaWebBean,org.ejbca.core.model.ra.raadmin.GlobalConfiguration, org.ejbca.core.model.SecConst, org.ejbca.util.FileTools, org.ejbca.util.CertTools, org.ejbca.util.FileTools, org.ejbca.core.model.authorization.AuthorizationDeniedException,
    org.ejbca.ui.web.RequestHelper, org.ejbca.ui.web.admin.cainterface.CAInterfaceBean, org.ejbca.core.model.ca.caadmin.CAInfo, org.ejbca.core.model.ca.caadmin.X509CAInfo, org.ejbca.core.model.ca.caadmin.CVCCAInfo, org.ejbca.core.model.ca.catoken.CATokenInfo, org.ejbca.core.model.ca.catoken.SoftCAToken, org.ejbca.core.model.ca.catoken.SoftCATokenInfo, org.ejbca.ui.web.admin.cainterface.CADataHandler,
               org.ejbca.ui.web.admin.rainterface.RevokedInfoView, org.ejbca.ui.web.admin.configuration.InformationMemory, org.bouncycastle.asn1.x509.X509Name, org.ejbca.core.EjbcaException,
               org.ejbca.core.protocol.PKCS10RequestMessage, org.ejbca.core.protocol.IRequestMessage, org.ejbca.core.model.ca.caadmin.CAExistsException, org.ejbca.core.model.ca.caadmin.CADoesntExistsException, org.ejbca.core.model.ca.catoken.CATokenOfflineException, org.ejbca.core.model.ca.catoken.CATokenAuthenticationFailedException,
               org.ejbca.core.model.ca.caadmin.extendedcaservices.OCSPCAServiceInfo,org.ejbca.core.model.ca.caadmin.extendedcaservices.XKMSCAServiceInfo, org.ejbca.core.model.ca.caadmin.extendedcaservices.CmsCAServiceInfo, org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceInfo, org.ejbca.core.model.ca.catoken.CATokenManager, org.ejbca.core.model.ca.catoken.AvailableCAToken, org.ejbca.core.model.ca.catoken.HardCATokenInfo, org.ejbca.core.model.ca.catoken.CATokenConstants,
               org.ejbca.util.dn.DNFieldExtractor,org.ejbca.util.dn.DnComponents,org.ejbca.core.model.ca.catoken.ICAToken,org.ejbca.core.model.ca.catoken.BaseCAToken, org.ejbca.core.model.ca.catoken.NullCAToken, org.ejbca.core.model.ca.catoken.NullCATokenInfo, org.ejbca.core.model.ca.certificateprofiles.CertificateProfile, org.ejbca.core.model.ca.certificateprofiles.CertificatePolicy, org.ejbca.ui.web.admin.cainterface.CAInfoView, org.bouncycastle.jce.exception.ExtCertPathValidatorException,
               org.ejbca.util.SimpleTime, org.ejbca.util.ValidityDate, org.ejbca.ui.web.ParameterError" %>



<%@page import="org.ejbca.core.model.util.AlgorithmTools"%>
<%@page import="java.security.cert.CertificateException"%>
<%@page import="javax.ejb.EJBException"%>
<%@page import="java.security.InvalidParameterException"%>
<%@page import="java.security.InvalidAlgorithmParameterException"%>
<%@page import="org.ejbca.util.YearMonthDayTime"%>
<html>
<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />
<jsp:useBean id="cabean" scope="session" class="org.ejbca.ui.web.admin.cainterface.CAInterfaceBean" />

<%! // Declarations 
  static final String ACTION                              = "action";
  static final String ACTION_EDIT_CAS                     = "editcas";
  static final String ACTION_EDIT_CA                      = "editca";
  static final String ACTION_CREATE_CA                    = "createca";
  static final String ACTION_CHOOSE_CATYPE                = "choosecatype";
  static final String ACTION_CHOOSE_CATOKENTYPE           = "choosecatokentype";
  static final String ACTION_MAKEREQUEST                  = "makerequest";
  static final String ACTION_MAKECROSSREQUEST             = "makecrossrequest";
  static final String ACTION_SIGNREQUEST                  = "signrequest";
  static final String ACTION_RECEIVERESPONSE              = "receiveresponse";
  static final String ACTION_PROCESSREQUEST               = "processrequest";
  static final String ACTION_PROCESSREQUEST2              = "processrequest2";
  static final String ACTION_RENEWCA_MAKEREQUEST          = "renewcamakeresponse";  
  static final String ACTION_RENEWCA_RECIEVERESPONSE      = "renewcarecieveresponse";  
  static final String ACTION_IMPORTCA		              = "importca";
  static final String ACTION_IMPORTCACERT	              = "importcacert";

  static final String CHECKBOX_VALUE           = "true";

//  Used in choosecapage.jsp
  static final String BUTTON_EDIT_CA                       = "buttoneditca"; 
  static final String BUTTON_DELETE_CA                     = "buttondeleteca";
  static final String BUTTON_CREATE_CA                     = "buttoncreateca"; 
  static final String BUTTON_RENAME_CA                     = "buttonrenameca";
  static final String BUTTON_PROCESSREQUEST                = "buttonprocessrequest";
  static final String BUTTON_SIGNREQUEST                   = "buttonsignrequest";
  static final String BUTTON_IMPORTCA		               = "buttonimportca";
  static final String BUTTON_EXPORTCA		               = "buttonexportca";
  static final String BUTTON_IMPORTCACERT	               = "buttonimportcacert";
  

  static final String SELECT_CAS                           = "selectcas";
  static final String TEXTFIELD_CANAME                     = "textfieldcaname";
  static final String HIDDEN_CANAME                        = "hiddencaname";
  static final String HIDDEN_CAID                          = "hiddencaid";
  static final String HIDDEN_CATYPE                        = "hiddencatype";
  static final String HIDDEN_CATOKEN                       = "hiddencatoken";    
  static final String HIDDEN_CATOKENPATH                   = "hiddencatokenpath";
  static final String HIDDEN_CATOKENTYPE                   = "hiddencatokentype";
  static final String HIDDEN_RENEWKEYS                     = "hiddenrenewkeys";
  static final String HIDDEN_RENEWAUTHCODE                 = "hiddenrenewauthcode";
  static final String HIDDEN_PROCESSREQUESTDN              = "hiddenprocessrequestdn";  
  static final String HIDDEN_PROCESSREQUEST                = "hiddenprocessrequest";  
 
// Buttons used in editcapage.jsp
  static final String BUTTON_SAVE                       = "buttonsave";
  static final String BUTTON_CREATE                     = "buttoncreate";
  static final String BUTTON_CANCEL                     = "buttoncancel";
  static final String BUTTON_MAKEREQUEST                = "buttonmakerequest";
  static final String BUTTON_RECEIVEREQUEST             = "buttonreceiverequest";
  static final String BUTTON_RENEWCA                    = "buttonrenewca";
  static final String BUTTON_REVOKECA                   = "buttonrevokeca";  
  static final String BUTTON_RECIEVEFILE                = "buttonrecievefile";     
  static final String BUTTON_PUBLISHCA                  = "buttonpublishca";     
  static final String BUTTON_REVOKERENEWOCSPCERTIFICATE = "checkboxrenewocspcertificate";
  static final String BUTTON_REVOKERENEWXKMSCERTIFICATE = "checkboxrenewxkmscertificate";
  static final String BUTTON_REVOKERENEWCMSCERTIFICATE  = "checkboxrenewcmscertificate";
  static final String BUTTON_GENDEFAULTCRLDISTPOINT     = "checkboxgeneratedefaultcrldistpoint";
  static final String BUTTON_GENDEFAULTCRLISSUER        = "checkboxgeneratedefaultcrlissuer";
  static final String BUTTON_GENCADEFINEDFRESHESTCRL    = "checkboxgeneratecadefinedfresherstcrl";
  static final String BUTTON_GENDEFAULTOCSPLOCATOR      = "checkbexgeneratedefaultocsplocator";

  static final String TEXTFIELD_KEYSEQUENCE           = "textfieldkeysequence";
  static final String TEXTFIELD_SUBJECTDN             = "textfieldsubjectdn";
  static final String TEXTFIELD_SUBJECTALTNAME        = "textfieldsubjectaltname";  
  static final String TEXTFIELD_CRLPERIOD             = "textfieldcrlperiod";
  static final String TEXTFIELD_CRLISSUEINTERVAL      = "textfieldcrlissueinterval";
  static final String TEXTFIELD_CRLOVERLAPTIME        = "textfieldcrloverlaptime";
  static final String TEXTFIELD_DELTACRLPERIOD        = "textfielddeltacrlperiod";
  static final String TEXTFIELD_DESCRIPTION           = "textfielddescription";
  static final String TEXTFIELD_VALIDITY              = "textfieldvalidity";
  static final String TEXTFIELD_POLICYID              = "textfieldpolicyid";
  static final String TEXTFIELD_HARDCATOKENPROPERTIES = "textfieldhardcatokenproperties";
  static final String TEXTFIELD_AUTHENTICATIONCODE    = "textfieldauthenticationcode";
  static final String TEXTFIELD_AUTHENTICATIONCODERENEW = "textfieldauthenticationcoderenew";
  static final String TEXTFIELD_DEFAULTCRLDISTPOINT   = "textfielddefaultcrldistpoint";
  static final String TEXTFIELD_DEFAULTCRLISSUER      = "textfielddefaultcrlissuer";
  static final String TEXTFIELD_DEFAULTOCSPLOCATOR    = "textfielddefaultocsplocator";
  static final String TEXTFIELD_CADEFINEDFRESHESTCRL  = "textfieldcadefinedfreshestcrl";
  static final String TEXTFIELD_KEYSPEC               = "textfieldkeyspec";
  static final String TEXTFIELD_IMPORTCA_PASSWORD	  = "textfieldimportcapassword";
  static final String TEXTFIELD_IMPORTCA_SIGKEYALIAS  = "textfieldimportcasigkeyalias";
  static final String TEXTFIELD_IMPORTCA_ENCKEYALIAS  = "textfieldimportcaenckeyalias";
  static final String TEXTFIELD_IMPORTCA_NAME		  = "textfieldimportcaname";


  static final String CHECKBOX_AUTHORITYKEYIDENTIFIER             = "checkboxauthoritykeyidentifier";
  static final String CHECKBOX_AUTHORITYKEYIDENTIFIERCRITICAL     = "checkboxauthoritykeyidentifiercritical";
  static final String CHECKBOX_USECRLNUMBER                       = "checkboxusecrlnumber";
  static final String CHECKBOX_CRLNUMBERCRITICAL                  = "checkboxcrlnumbercritical";
  static final String CHECKBOX_FINISHUSER                         = "checkboxfinishuser";
  static final String CHECKBOX_USEUTF8POLICYTEXT                  = "checkboxuseutf8policytext";
  static final String CHECKBOX_USEPRINTABLESTRINGSUBJECTDN        = "checkboxuseprintablestringsubjectdn";
  static final String CHECKBOX_USELDAPDNORDER                     = "checkboxuseldapdnorder";
  static final String CHECKBOX_USECRLDISTRIBUTIONPOINTONCRL       = "checkboxusecrldistributionpointoncrl";
  static final String CHECKBOX_CRLDISTRIBUTIONPOINTONCRLCRITICAL  = "checkboxcrldistributionpointoncrlcritical";
  
  static final String CHECKBOX_ACTIVATEOCSPSERVICE                = "checkboxactivateocspservice";  
  static final String CHECKBOX_ACTIVATEXKMSSERVICE                = "checkboxactivatexkmsservice";
  static final String CHECKBOX_ACTIVATECMSSERVICE                 = "checkboxactivatecmsservice";
  static final String CHECKBOX_RENEWKEYS                          = "checkboxrenewkeys";  
  static final String CHECKBOX_AUTHENTICATIONCODEAUTOACTIVATE     = "checkboxauthcodeautoactivate";
  
  /** Use previous key to sign requests by CA, primarily used to create authenticated CVC requests */
  static final String CHECKBOX_USEPREVIOUSKEY                     = "checkboxusepreviouskey";
  /** Create a link certificate when signign request by CA, primarily used to create CVC link certificates */
  static final String CHECKBOX_CREATELINKCERT                     = "checkboxcreatelinkcert";
  
  static final String SELECT_REVOKEREASONS                        = "selectrevokereasons";
  static final String SELECT_CATYPE                               = "selectcatype";  
  static final String SELECT_CATOKEN                              = "selectcatoken";
  static final String SELECT_SIGNEDBY                             = "selectsignedby"; 
  static final String SELECT_KEYSIZE                              = "selectsize";
  static final String SELECT_KEYSIZE_DSA                          = "selectsizedsa";
  static final String SELECT_AVAILABLECRLPUBLISHERS               = "selectavailablecrlpublishers";
  static final String SELECT_CERTIFICATEPROFILE                   = "selectcertificateprofile";
  static final String SELECT_SIGNATUREALGORITHM                   = "selectsignaturealgorithm";
  static final String SELECT_APPROVALSETTINGS                     = "approvalsettings";
  static final String SELECT_NUMOFREQUIREDAPPROVALS               = "numofrequiredapprovals";

  static final String FILE_RECIEVEFILE                            = "filerecievefile";
  static final String FILE_CACERTFILE                             = "filecacertfile";
  static final String FILE_REQUESTFILE                            = "filerequestfile";   

  static final String CERTSERNO_PARAMETER       = "certsernoparameter"; 

  // These constants is an index in to the arrays in recievefile.jspf
  static final int    MAKEREQUESTMODE     = 0;
  static final int    RECIEVERESPONSEMODE = 1;
  static final int    PROCESSREQUESTMODE  = 2;   
  static final int    SIGNREQUESTMODE     = 3;   
  static final int    MAKECROSSREQUESTMODE = 4;   
  
  static final int    CERTREQGENMODE      = 0;
  static final int    CERTGENMODE         = 1;
%>
<% 
         
  // Initialize environment
  int caid = 0;
  String caname = null;
  boolean reGenerateKeys = false;
  String renewauthenticationcode = null;
  String includefile = "choosecapage.jspf"; 
  String processedsubjectdn = "";
  int catype = CAInfo.CATYPE_X509;  // default
  int catokentype = CATokenInfo.CATOKENTYPE_P12; // default
  String catokenpath = "NONE";
  String importcaname = null;
  String importpassword = null;
  String importsigalias = null;
  String importencalias = null;
  String usepreviouskey = null;
  String createlinkcert = null;

  InputStream file = null;

  boolean  caexists             = false;
  boolean  cadeletefailed       = false;
  boolean  illegaldnoraltname   = false;
  boolean  errorrecievingfile   = false;
  boolean  ocsprenewed          = false;
  boolean  xkmsrenewed          = false;
  boolean  cmsrenewed           = false;
  boolean  catokenoffline       = false;
  boolean  catokenauthfailed    = false;
  String errormessage = null;
  

  GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, "/super_administrator"); 
                                            cabean.initialize(request, ejbcawebbean); 

  CADataHandler cadatahandler     = cabean.getCADataHandler(); 

  String THIS_FILENAME            =  globalconfiguration.getCaPath()  + "/editcas/editcas.jsp";
  String action = "";

  final String VIEWCERT_LINK            = ejbcawebbean.getBaseUrl() + globalconfiguration.getAdminWebPath() + "viewcertificate.jsp";
  
  boolean issuperadministrator = false;
  boolean editca = false;
  boolean processrequest = false;
  boolean buttoncancel = false; 
  boolean caactivated = false;
  boolean carenewed = false;
  boolean capublished = false;

  int filemode = 0;
  int row = 0;

  HashMap caidtonamemap = cabean.getCAIdToNameMap();
  InformationMemory info = ejbcawebbean.getInformationMemory();

%>
 
<head>
  <title><%= globalconfiguration .getEjbcaTitle() %></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>">
  <link rel=STYLESHEET href="<%= ejbcawebbean.getCssFile() %>">
  <script language=javascript src="<%= globalconfiguration.getAdminWebPath() %>ejbcajslib.js"></script>
</head>


<%
  RequestHelper.setDefaultCharacterEncoding(request);

   if(FileUpload.isMultipartContent(request)){     
     errorrecievingfile = true;
     DiskFileUpload upload = new DiskFileUpload();
     upload.setSizeMax(60000);                   
     upload.setSizeThreshold(59999);
     List /* FileItem */ items = upload.parseRequest(request);     

     Iterator iter = items.iterator();
     while (iter.hasNext()) {     
     FileItem item = (FileItem) iter.next();


       if (item.isFormField()) {         
         if(item.getFieldName().equals(ACTION))
           action = item.getString(); 
         if(item.getFieldName().equals(HIDDEN_CAID))
           caid = Integer.parseInt(item.getString());
         if(item.getFieldName().equals(HIDDEN_CANAME))
           caname = item.getString();
         if(item.getFieldName().equals(HIDDEN_RENEWAUTHCODE))
             renewauthenticationcode = item.getString();
         if(item.getFieldName().equals(HIDDEN_RENEWKEYS))
             reGenerateKeys = Boolean.valueOf(item.getString()).booleanValue();
         if(item.getFieldName().equals(BUTTON_CANCEL))
           buttoncancel = true; 
         if(item.getFieldName().equals(TEXTFIELD_IMPORTCA_NAME))
           importcaname = item.getString();
         if(item.getFieldName().equals(TEXTFIELD_IMPORTCA_PASSWORD))
           importpassword = item.getString();
         if(item.getFieldName().equals(TEXTFIELD_IMPORTCA_SIGKEYALIAS))
           importsigalias = item.getString();
         if(item.getFieldName().equals(TEXTFIELD_IMPORTCA_ENCKEYALIAS))
           importencalias = item.getString();
         if(item.getFieldName().equals(CHECKBOX_USEPREVIOUSKEY))
        	 usepreviouskey = item.getString();
         if(item.getFieldName().equals(CHECKBOX_CREATELINKCERT))
        	 createlinkcert = item.getString();
       }else{         
         file = item.getInputStream(); 
         errorrecievingfile = false;                          
       }
     } 
   }else{
     action = request.getParameter(ACTION);
   }
  try{
  // Determine action 
  if( action != null){
    if( action.equals(ACTION_EDIT_CAS)){
      // Actions in the choose CA page.
      if( request.getParameter(BUTTON_EDIT_CA) != null){
          // Display  profilepage.jsp         
         includefile="choosecapage.jspf";
         if(request.getParameter(SELECT_CAS) != null && !request.getParameter(SELECT_CAS).equals("")){
           caid = Integer.parseInt(request.getParameter(SELECT_CAS));
           if(caid != 0){             
             editca = true;
             catype = cadatahandler.getCAInfo(caid).getCAInfo().getCAType();
             includefile="editcapage.jspf";              
           }
         } 
      }
      if( request.getParameter(BUTTON_DELETE_CA) != null) {
          // Delete profile and display choosecapage. 
          if(request.getParameter(SELECT_CAS) != null && !request.getParameter(SELECT_CAS).equals("")){
            caid = Integer.parseInt(request.getParameter(SELECT_CAS));
            if(caid != 0){             
                cadeletefailed = !cadatahandler.removeCA(caid);
            }
          }
          includefile="choosecapage.jspf";             
      }
      if( request.getParameter(BUTTON_RENAME_CA) != null){ 
         // Rename selected profile and display profilespage.
       if(request.getParameter(SELECT_CAS) != null  && !request.getParameter(SELECT_CAS).equals("") && request.getParameter(TEXTFIELD_CANAME) != null){
         String newcaname = request.getParameter(TEXTFIELD_CANAME).trim();
         String oldcaname = (String) caidtonamemap.get(new Integer(request.getParameter(SELECT_CAS)));    
         if(!newcaname.equals("") ){           
           try{
             cadatahandler.renameCA(oldcaname, newcaname);
           }catch( CAExistsException e){
             caexists=true;
           }                
         }
        }      
        includefile="choosecapage.jspf"; 
      }
      if( request.getParameter(BUTTON_IMPORTCA) != null){ 
         // Import CA from p12-file. Start by prompting for file and keystore password.
		includefile="importca.jspf";
      }
      if( request.getParameter(BUTTON_IMPORTCACERT) != null){ 
         // Import CA from p12-file. Start by prompting for file and keystore password.
		includefile="importcacert.jspf";
      }
      if( request.getParameter(BUTTON_CREATE_CA) != null){
         // Add profile and display profilespage.
         includefile="choosecapage.jspf"; 
         caname = request.getParameter(TEXTFIELD_CANAME);
         if(caname != null){
           caname = caname.trim();
           if(!caname.equals("")){             
             editca = false;
             includefile="editcapage.jspf";              
           }      
         }         
      }
      if( request.getParameter(BUTTON_PROCESSREQUEST) != null){
         caname = request.getParameter(TEXTFIELD_CANAME);
         if(caname != null){
           caname = caname.trim();
           if(!caname.equals("")){             
             filemode = PROCESSREQUESTMODE;
             includefile="recievefile.jspf";               
           }      
         }                        
      }
      if( request.getParameter(BUTTON_SIGNREQUEST) != null){
          caname = request.getParameter(TEXTFIELD_CANAME);
          if(caname != null){
            caname = caname.trim();
            if(!caname.equals("")){
              CAInfoView reqcainfo = cabean.getCAInfo(caname);
              if (reqcainfo != null) {
                  caid = reqcainfo.getCAInfo().getCAId();
                  filemode = SIGNREQUESTMODE;
                  includefile="recievefile.jspf";            	  
              }
            }      
          }                        
       }
    }
    if( action.equals(ACTION_CREATE_CA)){
      if( request.getParameter(BUTTON_CREATE)  != null || request.getParameter(BUTTON_MAKEREQUEST)  != null){
         // Create and save CA                          
         caname = request.getParameter(HIDDEN_CANAME);
          
         CATokenInfo catoken = null;
         catokentype = Integer.parseInt(request.getParameter(HIDDEN_CATOKENTYPE));
         String signkeyspec = "2048"; // Default signature key, for OCSP, CMS and XKMS, is 2048 bit RSA
         String signkeytype = CATokenConstants.KEYALGORITHM_RSA;
         
         if(catokentype == CATokenInfo.CATOKENTYPE_P12){
           String signalg = request.getParameter(SELECT_SIGNATUREALGORITHM);
           String encalg = AlgorithmTools.getEncSigAlgFromSigAlg(signalg);
           String authenticationcode = request.getParameter(TEXTFIELD_AUTHENTICATIONCODE);
           String autoactivate = request.getParameter(CHECKBOX_AUTHENTICATIONCODEAUTOACTIVATE);
           String enckeyspec = request.getParameter(SELECT_KEYSIZE);
           String enckeytype = CATokenConstants.KEYALGORITHM_RSA;
           signkeytype = AlgorithmTools.getKeyAlgorithmFromSigAlg(signalg);
           if (signalg.indexOf("ECDSA") != -1) {
        	   signkeyspec = request.getParameter(TEXTFIELD_KEYSPEC);
        	   encalg = CATokenConstants.SIGALG_SHA1_WITH_RSA;
           } else if(signalg.indexOf("DSA") != -1) {
        	   signkeyspec = request.getParameter(SELECT_KEYSIZE_DSA);
        	   encalg = CATokenConstants.SIGALG_SHA1_WITH_RSA;
           } else {
        	   signkeyspec = request.getParameter(SELECT_KEYSIZE);
           }
           if(signkeyspec == null || signalg == null || signkeytype == null)
             throw new Exception("Error in CATokenData");  
           catoken = new SoftCATokenInfo();
           catoken.setSignatureAlgorithm(signalg);
           ((SoftCATokenInfo) catoken).setSignKeyAlgorithm(signkeytype);
           ((SoftCATokenInfo) catoken).setSignKeySpec(signkeyspec);              
           catoken.setEncryptionAlgorithm(encalg);
           ((SoftCATokenInfo) catoken).setEncKeyAlgorithm(enckeytype);
           ((SoftCATokenInfo) catoken).setEncKeySpec(enckeyspec); 
           catoken.setAuthenticationCode(authenticationcode);
           if ( (autoactivate != null) && (autoactivate.equals("true")) ) {
               // it is not possible to use empty autoactivation passwords for soft tokens
               if ( (authenticationcode != null) && (authenticationcode.length() > 0) ) {
                   String properties = BaseCAToken.setAutoActivatePin(null, authenticationcode, true);
                   catoken.setProperties(properties);
               }
           }          
         } 
         if(catokentype == CATokenInfo.CATOKENTYPE_HSM){
            catokenpath = request.getParameter(HIDDEN_CATOKENPATH);
            String properties = request.getParameter(TEXTFIELD_HARDCATOKENPROPERTIES);
            String signalg = request.getParameter(SELECT_SIGNATUREALGORITHM);
            String authenticationcode = request.getParameter(TEXTFIELD_AUTHENTICATIONCODE);
            if(catokenpath == null || catokenpath == null || signalg == null)
              throw new Exception("Error in CATokenData");  
            catoken = new HardCATokenInfo();           
            catoken.setClassPath(catokenpath);
            catoken.setProperties(properties);
            catoken.setSignatureAlgorithm(signalg);
            catoken.setAuthenticationCode(authenticationcode);
         }

         if (catokentype != CATokenInfo.CATOKENTYPE_NULL) {
             String sequence = CATokenConstants.DEFAULT_KEYSEQUENCE;
             if(request.getParameter(TEXTFIELD_KEYSEQUENCE) != null)
               sequence = request.getParameter(TEXTFIELD_KEYSEQUENCE);
             catoken.setKeySequence(sequence);        	 
         }
         
         catype  = Integer.parseInt(request.getParameter(HIDDEN_CATYPE));
         String subjectdn = request.getParameter(TEXTFIELD_SUBJECTDN);
         try{
             X509Name dummy = CertTools.stringToBcX509Name(subjectdn);
         }catch(Exception e){
             illegaldnoraltname = true;
         }
         int certprofileid = 0;
         CertificateProfile certprof = null;
         if(request.getParameter(SELECT_CERTIFICATEPROFILE) != null)
           certprofileid = Integer.parseInt(request.getParameter(SELECT_CERTIFICATEPROFILE));
         int signedby = 0;
         if(request.getParameter(SELECT_SIGNEDBY) != null)
            signedby = Integer.parseInt(request.getParameter(SELECT_SIGNEDBY));
         
         String description = request.getParameter(TEXTFIELD_DESCRIPTION);        
         if(description == null)
           description = "";
         
         final long validity = ValidityDate.encode(request.getParameter(TEXTFIELD_VALIDITY));
         if ( validity<0 ) {
             throw new ParameterError(ejbcawebbean.getText("INVALIDVALIDITYORCERTEND"));
         }

         if(catoken != null && catype != 0 && subjectdn != null && caname != null && signedby != 0  ){

        	 // Approvals is generic for all types of CAs
             String[] values = request.getParameterValues(SELECT_APPROVALSETTINGS);
             ArrayList approvalsettings = new ArrayList(); 
             if(values != null){
               for(int i=0; i < values.length; i++){
            	   approvalsettings.add(new Integer(values[i]));
               }
             }
             String value = request.getParameter(SELECT_NUMOFREQUIREDAPPROVALS);
             int numofreqapprovals = 1;
             if(value != null){
            	 numofreqapprovals = Integer.parseInt(value);
             }
             boolean finishuser = false;
             value = request.getParameter(CHECKBOX_FINISHUSER);
             if(value != null)
               finishuser = value.equals(CHECKBOX_VALUE);         


             
           if(catype == CAInfo.CATYPE_X509){
              // Create a X509 CA
              String subjectaltname = request.getParameter(TEXTFIELD_SUBJECTALTNAME);             
              if(subjectaltname == null)
                subjectaltname = ""; 
              else{
                if(!subjectaltname.trim().equals("")){
                   DNFieldExtractor subtest = 
                     new DNFieldExtractor(subjectaltname,DNFieldExtractor.TYPE_SUBJECTALTNAME);                   
                   if(subtest.isIllegal() || subtest.existsOther()){
                     illegaldnoraltname = true;
                   }
                }
              }    

              /* Process certificate policies. */
              String policyid = request.getParameter(TEXTFIELD_POLICYID);
              ArrayList policies = new ArrayList();
              certprof = cabean.getCertificateProfile(certprofileid);
			  if (!(policyid == null || policyid.trim().equals(""))){
            	  String[] str = policyid.split("\\s+");
            		if (str.length > 1) {
            			policies.add(new CertificatePolicy(str[0], CertificatePolicy.id_qt_cps, str[1]));
            		} else {
            			policies.add(new CertificatePolicy((policyid.trim()),null,null));
            		}
              }
              if ((certprof.getCertificatePolicies().size() > 0) && (certprof.getCertificatePolicies() != null)) {
            	  policies.addAll(certprof.getCertificatePolicies());
              }

              boolean useauthoritykeyidentifier = false;
              boolean authoritykeyidentifiercritical = false;
              value = request.getParameter(CHECKBOX_AUTHORITYKEYIDENTIFIER);
              if(value != null){
                 useauthoritykeyidentifier = value.equals(CHECKBOX_VALUE);                 
                 value = request.getParameter(CHECKBOX_AUTHORITYKEYIDENTIFIERCRITICAL); 
                 if(value != null){
                   authoritykeyidentifiercritical = value.equals(CHECKBOX_VALUE);
                 } 
                 else
                   authoritykeyidentifiercritical = false;
              }

         	 // CRL periods and publishers is specific for X509 CAs
              long crlperiod = SimpleTime.getInstance(request.getParameter(TEXTFIELD_CRLPERIOD), "1"+SimpleTime.TYPE_DAYS).getLong();
              long crlIssueInterval = SimpleTime.getInstance(request.getParameter(TEXTFIELD_CRLISSUEINTERVAL), "0"+SimpleTime.TYPE_MINUTES).getLong();
              long crlOverlapTime = SimpleTime.getInstance(request.getParameter(TEXTFIELD_CRLOVERLAPTIME), "10"+SimpleTime.TYPE_MINUTES).getLong();
              long deltacrlperiod = SimpleTime.getInstance(request.getParameter(TEXTFIELD_DELTACRLPERIOD), "0"+SimpleTime.TYPE_MINUTES).getLong();              
              values = request.getParameterValues(SELECT_AVAILABLECRLPUBLISHERS);
              ArrayList crlpublishers = new ArrayList(); 
              if(values != null){
                for(int i=0; i < values.length; i++){
                   crlpublishers.add(new Integer(values[i]));
                }
              }

              boolean usecrlnumber = false;
              boolean crlnumbercritical = false;
              value = request.getParameter(CHECKBOX_USECRLNUMBER);
              if(value != null){
                 usecrlnumber = value.equals(CHECKBOX_VALUE);                 
                 value = request.getParameter(CHECKBOX_CRLNUMBERCRITICAL); 
                 if(value != null){
                   crlnumbercritical = value.equals(CHECKBOX_VALUE);
                 } 
                 else
                   crlnumbercritical = false;
              }              
              
             String defaultcrldistpoint = request.getParameter(TEXTFIELD_DEFAULTCRLDISTPOINT);
             String defaultcrlissuer = request.getParameter(TEXTFIELD_DEFAULTCRLISSUER);
             String defaultocsplocator  = request.getParameter(TEXTFIELD_DEFAULTOCSPLOCATOR);
              
             String cadefinedfreshestcrl = "";
             if (request.getParameter(TEXTFIELD_CADEFINEDFRESHESTCRL) != null) {
                 cadefinedfreshestcrl = request.getParameter(TEXTFIELD_CADEFINEDFRESHESTCRL);
             }
             
             boolean useutf8policytext = false;
             value = request.getParameter(CHECKBOX_USEUTF8POLICYTEXT);
             if(value != null) {
            	 useutf8policytext = value.equals(CHECKBOX_VALUE);                             
             }
             boolean useprintablestringsubjectdn = false;
             value = request.getParameter(CHECKBOX_USEPRINTABLESTRINGSUBJECTDN);
             if(value != null) {
            	 useprintablestringsubjectdn = value.equals(CHECKBOX_VALUE);                             
             }
             boolean useldapdnorder = false;
             value = request.getParameter(CHECKBOX_USELDAPDNORDER);
             if(value != null) {
            	 useldapdnorder = value.equals(CHECKBOX_VALUE);                             
             }
             boolean usecrldistpointoncrl = false;
             value = request.getParameter(CHECKBOX_USECRLDISTRIBUTIONPOINTONCRL);
             if(value != null) {
                 usecrldistpointoncrl = value.equals(CHECKBOX_VALUE);                             
             }
             boolean crldistpointoncrlcritical = false;
             value = request.getParameter(CHECKBOX_CRLDISTRIBUTIONPOINTONCRLCRITICAL);
             if(value != null) {
                 crldistpointoncrlcritical = value.equals(CHECKBOX_VALUE);                             
             }

             int ocspactive = ExtendedCAServiceInfo.STATUS_INACTIVE;
             value = request.getParameter(CHECKBOX_ACTIVATEOCSPSERVICE);
             if(value != null && value.equals(CHECKBOX_VALUE))
                ocspactive = ExtendedCAServiceInfo.STATUS_ACTIVE;
             
             int xkmsactive = ExtendedCAServiceInfo.STATUS_INACTIVE;
             value = request.getParameter(CHECKBOX_ACTIVATEXKMSSERVICE);
             if(value != null && value.equals(CHECKBOX_VALUE))
                xkmsactive = ExtendedCAServiceInfo.STATUS_ACTIVE; 
              
             int cmsactive = ExtendedCAServiceInfo.STATUS_INACTIVE;
             value = request.getParameter(CHECKBOX_ACTIVATECMSSERVICE);
             if(value != null && value.equals(CHECKBOX_VALUE))
                cmsactive = ExtendedCAServiceInfo.STATUS_ACTIVE; 
             
             if(crlperiod != 0 && !illegaldnoraltname){
            	 
             if(request.getParameter(BUTTON_CREATE) != null){           
      
				 // Create and active OSCP CA Service.
				 ArrayList extendedcaservices = new ArrayList();
				 String keySpec = signkeyspec;
				 String keyAlg = signkeytype;
				 if (keyAlg.equals(CATokenConstants.KEYALGORITHM_RSA)) {
					 // Never use larger keys than 2048 bit RSA for OCSP, CMS and XKMS signing
					 int len = Integer.parseInt(keySpec);
					 if (len > 2048) {
						 keySpec = "2048";				 
					 }
				 }
				 extendedcaservices.add(
				             new OCSPCAServiceInfo(ocspactive,
								  "CN=OCSPSignerCertificate, " + subjectdn,
					     		  "",
					     		  keySpec,
								  keyAlg));
				 extendedcaservices.add(
			             new XKMSCAServiceInfo(xkmsactive,
							  "CN=XKMSCertificate, " + subjectdn,
				     		  "",
				     		  keySpec,
							  keyAlg));
				 extendedcaservices.add(
			             new CmsCAServiceInfo(cmsactive,
							  "CN=CMSCertificate, " + subjectdn,
				     		  "",
				     		  keySpec,
							  keyAlg));
                 X509CAInfo x509cainfo = new X509CAInfo(subjectdn, caname, SecConst.CA_ACTIVE, new Date(), subjectaltname,
                                                        certprofileid, validity, 
                                                        null, catype, signedby,
                                                        null, catoken, description, -1, null,
                                                        policies, crlperiod, crlIssueInterval, crlOverlapTime, deltacrlperiod, crlpublishers, 
                                                        useauthoritykeyidentifier, 
                                                        authoritykeyidentifiercritical,
                                                        usecrlnumber, 
                                                        crlnumbercritical, 
                                                        defaultcrldistpoint,
                                                        defaultcrlissuer,
                                                        defaultocsplocator, cadefinedfreshestcrl,
                                                        finishuser, extendedcaservices,
                                                        useutf8policytext,
                                                        approvalsettings,
                                                        numofreqapprovals,
                                                        useprintablestringsubjectdn,
                                                        useldapdnorder,
                                                        usecrldistpointoncrl,
                                                        crldistpointoncrlcritical,
                                                        true);
                 try{
                   cadatahandler.createCA((CAInfo) x509cainfo);
                 }catch(CAExistsException caee){
                    caexists = true; 
                 }catch(CATokenAuthenticationFailedException catfe){
                    catokenauthfailed = true;
                    errormessage = catfe.getMessage();
                    Throwable t = catfe.getCause();
                    while (t != null) {
						String msg = t.getMessage();
						if (msg != null) {
	                    	errormessage = errormessage + "<br/>" + msg;							
						}
                    	t = t.getCause();
                    }
                 } catch(EJBException ejbe) {
                	Exception ex = ejbe.getCausedByException();
                	if(ex instanceof InvalidAlgorithmParameterException) {
                		errormessage = ejbcawebbean.getText("INVALIDSIGORKEYALGPARAM") + ": " + ex.getLocalizedMessage();
                	} else {
	               		throw ejbe;
               		}
                 }
                 includefile="choosecapage.jspf"; 
               }
               
         if(request.getParameter(BUTTON_MAKEREQUEST) != null){
                 caid = CertTools.stringToBCDNString(subjectdn).hashCode();  
				 // Create and OSCP CA Service.
				 ArrayList extendedcaservices = new ArrayList();
				 String keySpec = signkeyspec;
				 String keyAlg = signkeytype;
				 if (keyAlg.equals(CATokenConstants.KEYALGORITHM_RSA)) {
					 // Never use larger keys than 2048 bit RSA for OCSP, CMS and XKMS signing
					 int len = Integer.parseInt(keySpec);
					 if (len > 2048) {
						 keySpec = "2048";				 
					 }
				 }
				 extendedcaservices.add(
				             new OCSPCAServiceInfo(ocspactive,
								  "CN=OCSPSignerCertificate, " + subjectdn,
					     		          "",
								  keySpec,
								  keyAlg));
				 extendedcaservices.add(
			             new XKMSCAServiceInfo(xkmsactive,
							  "CN=XKMSCertificate, " + subjectdn,
				     		          "",
							  keySpec,
							  keyAlg));
				 extendedcaservices.add(
			             new CmsCAServiceInfo(cmsactive,
							  "CN=CMSCertificate, " + subjectdn,
				     		          "",
							  keySpec,
							  keyAlg));
                 X509CAInfo x509cainfo = new X509CAInfo(subjectdn, caname, SecConst.CA_ACTIVE, new Date(), subjectaltname,
                                                        certprofileid, validity,
                                                        null, catype, CAInfo.SIGNEDBYEXTERNALCA,
                                                        null, catoken, description, -1, null, 
                                                        policies, crlperiod, crlIssueInterval, crlOverlapTime, deltacrlperiod, crlpublishers, 
                                                        useauthoritykeyidentifier, 
                                                        authoritykeyidentifiercritical,
                                                        usecrlnumber, 
                                                        crlnumbercritical, 
                                                        defaultcrldistpoint,
                                                        defaultcrlissuer,
                                                        defaultocsplocator, cadefinedfreshestcrl,
                                                        finishuser, extendedcaservices,
                                                        useutf8policytext,
                                                        approvalsettings,
                                                        numofreqapprovals,
                                                        useprintablestringsubjectdn,
                                                        useldapdnorder,
                                                        usecrldistpointoncrl,
                                                        crldistpointoncrlcritical,
                                                        true);
                 cabean.saveRequestInfo(x509cainfo);                
                 filemode = MAKEREQUESTMODE;
                 includefile="recievefile.jspf"; 
               }
             }                          
           } // if(catype == CAInfo.CATYPE_X509)
        	   
           if(catype == CAInfo.CATYPE_CVC) {
               // Only default values for these that are not used
               int crlperiod = 2400;
               int crlIssueInterval = 0;
               int crlOverlapTime = 0;
               int deltacrlperiod = 0;
               ArrayList crlpublishers = new ArrayList(); 

               if(crlperiod != 0 && !illegaldnoraltname){
          		 // A CVC CA does not have any of the external services OCSP, XKMS, CMS
          		 ArrayList extendedcaservices = new ArrayList();

                 if(request.getParameter(BUTTON_MAKEREQUEST) != null){
                     caid = CertTools.stringToBCDNString(subjectdn).hashCode();
                     signedby = CAInfo.SIGNEDBYEXTERNALCA;
                 }
                 
                 // Create the CAInfo to be used for either generating the whole CA or making a request
                 CVCCAInfo cvccainfo = new CVCCAInfo(subjectdn, caname, SecConst.CA_ACTIVE, new Date(),
                         certprofileid, validity, 
                         null, catype, signedby,
                         null, catoken, description, -1, null,
                         crlperiod, crlIssueInterval, crlOverlapTime, deltacrlperiod, crlpublishers, 
                         finishuser, extendedcaservices,
                         approvalsettings,
                         numofreqapprovals,
                         true);
                                  
          		if(request.getParameter(BUTTON_CREATE) != null){           
                     try{
                       cadatahandler.createCA(cvccainfo);
                     }catch(CAExistsException caee){
                        caexists = true; 
                     }catch(CATokenAuthenticationFailedException catfe){
                        catokenauthfailed = true;
                     }
                     includefile="choosecapage.jspf"; 
                   }
                   
             if(request.getParameter(BUTTON_MAKEREQUEST) != null){
                     cabean.saveRequestInfo(cvccainfo);                
                     filemode = MAKEREQUESTMODE;
                     includefile="recievefile.jspf"; 
                   }
                 }                          
            } // if(catype == CAInfo.CATYPE_CVC)
         } 
       } 
       if(request.getParameter(BUTTON_CANCEL) != null){
         // Don't save changes.
         includefile="choosecapage.jspf"; 
       }                        
      }
    if( action.equals(ACTION_EDIT_CA)){
      if( request.getParameter(BUTTON_SAVE)  != null || 
          request.getParameter(BUTTON_RECEIVEREQUEST)  != null || 
          request.getParameter(BUTTON_RENEWCA)  != null ||
          request.getParameter(BUTTON_REVOKECA)  != null ||
          request.getParameter(BUTTON_PUBLISHCA) != null ||
          request.getParameter(BUTTON_MAKEREQUEST) != null ||
          request.getParameter(BUTTON_REVOKERENEWOCSPCERTIFICATE) != null ||
          request.getParameter(BUTTON_REVOKERENEWCMSCERTIFICATE) != null ||
          request.getParameter(BUTTON_REVOKERENEWXKMSCERTIFICATE) != null){
         // Create and save CA                          
         caid = Integer.parseInt(request.getParameter(HIDDEN_CAID));
         caname = request.getParameter(HIDDEN_CANAME);
         catype = Integer.parseInt(request.getParameter(HIDDEN_CATYPE));
         
         catokentype = Integer.parseInt(request.getParameter(HIDDEN_CATOKENTYPE));
         // Authentication code if we should be able to activate the CA token after editing
         String authenticationcode = request.getParameter(TEXTFIELD_AUTHENTICATIONCODE);
         if ( (authenticationcode == null) || (authenticationcode.length() == 0) ) {
        	 authenticationcode = null;
         }
        		 
         // We need to pick up the old CATokenInfo, so we don't overwrite with default values when we save the CA further down
         CAInfoView infoView = cadatahandler.getCAInfo(caid);  
         CATokenInfo catoken = infoView.getCATokenInfo();
         
         if(catokentype == CATokenInfo.CATOKENTYPE_P12){
           String autoactivate = request.getParameter(CHECKBOX_AUTHENTICATIONCODEAUTOACTIVATE);
           if (catoken == null) {
               catoken = new SoftCATokenInfo();                  	   
           }
           catoken.setAuthenticationCode(authenticationcode);
           if ( (autoactivate != null) && (autoactivate.equals("true")) ) {
               // it is not possible to use empty autoactivation passwords for soft tokens
               if ( (authenticationcode != null) && (authenticationcode.length() > 0) ) {
                   String properties = BaseCAToken.setAutoActivatePin(null, authenticationcode, true);
                   catoken.setProperties(properties);
               }
           } else {
               catoken.setProperties("");
           }
           
         } 
         if(catokentype == CATokenInfo.CATOKENTYPE_HSM){
            String properties = request.getParameter(TEXTFIELD_HARDCATOKENPROPERTIES);
            if(catokenpath == null)
              throw new Exception("Error in CATokenData");  
            if (catoken == null) {
                catoken = new HardCATokenInfo();                       
            }
            catoken.setAuthenticationCode(authenticationcode);
            catoken.setProperties(properties);
         }

         if (catokentype != CATokenInfo.CATOKENTYPE_NULL) {
             String sequence = CATokenConstants.DEFAULT_KEYSEQUENCE;
             if(request.getParameter(TEXTFIELD_KEYSEQUENCE) != null)
               sequence = request.getParameter(TEXTFIELD_KEYSEQUENCE);
             catoken.setKeySequence(sequence);        	 
         }
          
         String description = request.getParameter(TEXTFIELD_DESCRIPTION);        
         if(description == null){
        	 description = "";
         }
         
         final long validity = ValidityDate.encode(request.getParameter(TEXTFIELD_VALIDITY));
         if ( validity<0 ) {
             throw new ParameterError(ejbcawebbean.getText("INVALIDVALIDITYORCERTEND"));
         }
            

         if(caid != 0  && catype !=0 ){
        	 
        	 // First common info for both X509 CAs and CVC CAs
        	CAInfo cainfo = null;
            long crlperiod = SimpleTime.getInstance(request.getParameter(TEXTFIELD_CRLPERIOD), "0"+SimpleTime.TYPE_MINUTES).getLong();
            long crlIssueInterval = SimpleTime.getInstance(request.getParameter(TEXTFIELD_CRLISSUEINTERVAL), "0"+SimpleTime.TYPE_MINUTES).getLong();
            long crlOverlapTime = SimpleTime.getInstance(request.getParameter(TEXTFIELD_CRLOVERLAPTIME), "0"+SimpleTime.TYPE_MINUTES).getLong();
            long deltacrlperiod = SimpleTime.getInstance(request.getParameter(TEXTFIELD_DELTACRLPERIOD), "0"+SimpleTime.TYPE_MINUTES).getLong();
            boolean finishuser = false;
            String value = request.getParameter(CHECKBOX_FINISHUSER);
            if(value != null)
              finishuser = value.equals(CHECKBOX_VALUE);         
            String[] values = request.getParameterValues(SELECT_APPROVALSETTINGS);
            ArrayList approvalsettings = new ArrayList(); 
            if(values != null){
              for(int i=0; i < values.length; i++){
           	   approvalsettings.add(new Integer(values[i]));
              }
            }
            
            value = request.getParameter(SELECT_NUMOFREQUIREDAPPROVALS);
            int numofreqapprovals = 1;
            if(value != null){
           	 numofreqapprovals = Integer.parseInt(value);
            }
            
            values = request.getParameterValues(SELECT_AVAILABLECRLPUBLISHERS);
            ArrayList crlpublishers = new ArrayList(); 
            if(values != null){
                for(int i=0; i < values.length; i++){
                   crlpublishers.add(new Integer(values[i]));
                }
             }
             
            // Info specific for X509 CA
            if(catype == CAInfo.CATYPE_X509){
                                          
              boolean useauthoritykeyidentifier = false;
              boolean authoritykeyidentifiercritical = false;
              value = request.getParameter(CHECKBOX_AUTHORITYKEYIDENTIFIER);
              if(value != null){
                 useauthoritykeyidentifier = value.equals(CHECKBOX_VALUE);                 
                 value = request.getParameter(CHECKBOX_AUTHORITYKEYIDENTIFIERCRITICAL); 
                 if(value != null){
                   authoritykeyidentifiercritical = value.equals(CHECKBOX_VALUE);
                 } 
                 else
                   authoritykeyidentifiercritical = false;
              }


              boolean usecrlnumber = false;
              boolean crlnumbercritical = false;

              value = request.getParameter(CHECKBOX_USECRLNUMBER);
              if(value != null){
                 usecrlnumber = value.equals(CHECKBOX_VALUE);                 
                 value = request.getParameter(CHECKBOX_CRLNUMBERCRITICAL); 
                 if(value != null){
                   crlnumbercritical = value.equals(CHECKBOX_VALUE);
                 } 
                 else
                   crlnumbercritical = false;
              }              
              
             String defaultcrldistpoint = request.getParameter(TEXTFIELD_DEFAULTCRLDISTPOINT);
             String defaultcrlissuer = request.getParameter(TEXTFIELD_DEFAULTCRLISSUER);
             String defaultocsplocator  = request.getParameter(TEXTFIELD_DEFAULTOCSPLOCATOR);

             String cadefinedfreshestcrl = "";
             if (request.getParameter(TEXTFIELD_CADEFINEDFRESHESTCRL) != null) {
			 	cadefinedfreshestcrl = request.getParameter(TEXTFIELD_CADEFINEDFRESHESTCRL);
			 }
              
             boolean  useutf8policytext = false;
             value = request.getParameter(CHECKBOX_USEUTF8POLICYTEXT);
             if(value != null) {
            	 useutf8policytext = value.equals(CHECKBOX_VALUE);         
             }
             
             boolean useprintablestringsubjectdn = false;
             value = request.getParameter(CHECKBOX_USEPRINTABLESTRINGSUBJECTDN);
             if(value != null) {
            	 useprintablestringsubjectdn = value.equals(CHECKBOX_VALUE);                             
             }
             boolean useldapdnorder = false;
             value = request.getParameter(CHECKBOX_USELDAPDNORDER);
             if(value != null) {
            	 useldapdnorder = value.equals(CHECKBOX_VALUE);                             
             }
             boolean usecrldistpointoncrl = false;
             value = request.getParameter(CHECKBOX_USECRLDISTRIBUTIONPOINTONCRL);
             if(value != null) {
                 usecrldistpointoncrl = value.equals(CHECKBOX_VALUE);                             
             }
             boolean crldistpointoncrlcritical = false;
             value = request.getParameter(CHECKBOX_CRLDISTRIBUTIONPOINTONCRLCRITICAL);
             if(value != null) {
                 crldistpointoncrlcritical = value.equals(CHECKBOX_VALUE);
             }

              // Create extended CA Service updatedata.
              int active = ExtendedCAServiceInfo.STATUS_INACTIVE;
              value = request.getParameter(CHECKBOX_ACTIVATEOCSPSERVICE);
              if(value != null && value.equals(CHECKBOX_VALUE))
                active = ExtendedCAServiceInfo.STATUS_ACTIVE; 
              
              int xkmsactive = ExtendedCAServiceInfo.STATUS_INACTIVE;
              value = request.getParameter(CHECKBOX_ACTIVATEXKMSSERVICE);
              if(value != null && value.equals(CHECKBOX_VALUE))
            	  xkmsactive = ExtendedCAServiceInfo.STATUS_ACTIVE; 

              int cmsactive = ExtendedCAServiceInfo.STATUS_INACTIVE;
              value = request.getParameter(CHECKBOX_ACTIVATECMSSERVICE);
              if(value != null && value.equals(CHECKBOX_VALUE))
            	  cmsactive = ExtendedCAServiceInfo.STATUS_ACTIVE; 

              boolean renew = false;
              if(active == ExtendedCAServiceInfo.STATUS_ACTIVE && 
                 request.getParameter(BUTTON_REVOKERENEWOCSPCERTIFICATE) != null){
                 cadatahandler.renewAndRevokeOCSPCertificate(caid);
                 renew=true;
                 ocsprenewed = true;             
                 includefile="choosecapage.jspf"; 
               }
              
              boolean xkmsrenew = false;
              if(xkmsactive == ExtendedCAServiceInfo.STATUS_ACTIVE && 
                 request.getParameter(BUTTON_REVOKERENEWXKMSCERTIFICATE) != null){
                 cadatahandler.renewAndRevokeXKMSCertificate(caid);
                 xkmsrenew=true;
                 xkmsrenewed = true;             
                 includefile="choosecapage.jspf"; 
               }
              
              boolean cmsrenew = false;
              if(cmsactive == ExtendedCAServiceInfo.STATUS_ACTIVE && 
                 request.getParameter(BUTTON_REVOKERENEWCMSCERTIFICATE) != null){
                 cadatahandler.renewAndRevokeCmsCertificate(caid);
                 cmsrenew=true;
                 cmsrenewed = true;             
                 includefile="choosecapage.jspf"; 
               }

	      	  ArrayList extendedcaservices = new ArrayList();
              extendedcaservices.add(
		             new OCSPCAServiceInfo(active, renew));    
              extendedcaservices.add(
 		             new XKMSCAServiceInfo(xkmsactive, xkmsrenew)); 
              extendedcaservices.add(
  		             new CmsCAServiceInfo(cmsactive, cmsrenew)); 

               cainfo = new X509CAInfo(caid, validity,
                                                      catoken, description, 
                                                      crlperiod, crlIssueInterval, crlOverlapTime, deltacrlperiod, crlpublishers, 
                                                      useauthoritykeyidentifier, 
                                                      authoritykeyidentifiercritical,
                                                      usecrlnumber, 
                                                      crlnumbercritical, 
                                                      defaultcrldistpoint,
                                                      defaultcrlissuer,
                                                      defaultocsplocator, cadefinedfreshestcrl,
                                                      finishuser,extendedcaservices,
                                                      useutf8policytext,
                                                      approvalsettings,
                                                      numofreqapprovals,
                                                      useprintablestringsubjectdn,
                                                      useldapdnorder,
                                                      usecrldistpointoncrl,
                                                      crldistpointoncrlcritical,
                                                      true);
             } // if(catype == CAInfo.CATYPE_X509)
            	 
             // Info specific for CVC CA
             if(catype == CAInfo.CATYPE_CVC) {
                 // Edit CVC CA data                            
					// A CVC CA does not have any of the external services OCSP, XKMS, CMS
            		ArrayList extendedcaservices = new ArrayList();
                 
                   // Create the CAInfo to be used for either generating the whole CA or making a request
                   cainfo = new CVCCAInfo(caid, validity, 
                           catoken, description,
                           crlperiod, crlIssueInterval, crlOverlapTime, deltacrlperiod, crlpublishers, 
                           finishuser, extendedcaservices,
                           approvalsettings,
                           numofreqapprovals,
                           true);
             } // if(catype == CAInfo.CATYPE_CVC)
            	 
               if(request.getParameter(BUTTON_SAVE) != null){
                  // Save the CA info but do nothing More
                  cadatahandler.editCA(cainfo);            	   
                  includefile="choosecapage.jspf"; 
               }
          	   // For all other actions we do not save any CA edits before doing what we do, because we need to CA token active
               
               // BUTTON_RECEIVEREQUEST when action is EDIT_CA is actually when you receive a certificate from an external CA as a response from an external CA 
               if(request.getParameter(BUTTON_RECEIVEREQUEST) != null){  
                   filemode = RECIEVERESPONSEMODE;
                   includefile="recievefile.jspf"; 
               }

               if(request.getParameter(BUTTON_RENEWCA) != null){
                   reGenerateKeys = false;
                   if(request.getParameter(CHECKBOX_RENEWKEYS) != null){
                	   reGenerateKeys = request.getParameter(CHECKBOX_RENEWKEYS).equals(CHECKBOX_VALUE);                	   
                   }
                   renewauthenticationcode = request.getParameter(TEXTFIELD_AUTHENTICATIONCODERENEW);
                   int signedby = cadatahandler.getCAInfo(caid).getCAInfo().getSignedBy();
                   if(signedby != CAInfo.SIGNEDBYEXTERNALCA){
                       cadatahandler.renewCA(caid, renewauthenticationcode, reGenerateKeys);
                       carenewed = true;
                   }else{                   
                       includefile="renewexternal.jspf"; 
                   }  
               }
                
             if(request.getParameter(BUTTON_REVOKECA) != null){
                 int revokereason = Integer.parseInt(request.getParameter(SELECT_REVOKEREASONS));
                 cadatahandler.revokeCA(caid, revokereason);                   
                 includefile="choosecapage.jspf"; 
             }
             if(request.getParameter(BUTTON_PUBLISHCA) != null){
                 cadatahandler.publishCA(caid);
                 capublished = true;             
                 includefile="choosecapage.jspf"; 
             }
             // Make Request Button Pushed down, this will create a certificate request but not do anything
             // else with the CA. For creating cross-certificate requests of similar.
             if(request.getParameter(BUTTON_MAKEREQUEST) != null){
                 caname = request.getParameter(HIDDEN_CANAME);
                 cabean.saveRequestInfo(cainfo);                
                 filemode = MAKECROSSREQUESTMODE;
                 includefile="recievefile.jspf"; 
             }             
         } 
       }
      
       if(request.getParameter(BUTTON_CANCEL) != null){
         // Don't save changes.
         includefile="choosecapage.jspf"; 
       }               

     } // if( action.equals(ACTION_EDIT_CA)){
    	
      if( action.equals(ACTION_MAKEREQUEST)){         
       if(!buttoncancel){
         try{
       	   Collection certchain = null;
           byte[] certbytes = FileTools.readInputStreamtoBuffer(file);
           try {
     	       certchain = CertTools.getCertsFromPEM(new ByteArrayInputStream(certbytes));
           } catch (IOException ioe) {
         	  // Maybe it's just a sinlge binary CA cert
         	  Certificate cert = CertTools.getCertfromByteArray(certbytes);
         	  certchain = new ArrayList();
         	  certchain.add(cert);
           }
           try{
             CAInfo cainfo = cabean.getRequestInfo();              
             cadatahandler.createCA(cainfo);                           
             try{ 
               byte[] certreq=cadatahandler.makeRequest(caid, certchain, true, null, false);
               cabean.saveRequestData(certreq);     
               filemode = CERTREQGENMODE;
               includefile = "displayresult.jspf";
             }catch(CATokenOfflineException e){  
        	  includefile="choosecapage.jspf"; 
        	  cadatahandler.removeCA(caid); 
              throw e;
             }catch(EjbcaException e){ 
        	  includefile="choosecapage.jspf"; 
        	  cadatahandler.removeCA(caid); 
              errormessage = e.getMessage(); 
             } catch(Exception e){   
        	  includefile="choosecapage.jspf";
        	  cadatahandler.removeCA(caid); 
        	  errormessage = e.getMessage(); 
             } 
           }catch(CAExistsException caee){
              caexists = true; 
           } 
         }catch(CATokenOfflineException e){  
          throw e;
      }catch(EjbcaException e){ 
          errormessage = e.getMessage(); 
      } catch(CertificateException ce){
    	  errorrecievingfile = true;
      } catch(Exception e){   
          errormessage = e.getMessage(); 
      } 
       }else{
         cabean.saveRequestInfo((CAInfo) null); 
       }
      }

      if( action.equals(ACTION_MAKECROSSREQUEST)){         
          if(!buttoncancel){
              try{
            	  Collection certchain = null;
                  byte[] certbytes = FileTools.readInputStreamtoBuffer(file);
                  try {
            	       certchain = CertTools.getCertsFromPEM(new ByteArrayInputStream(certbytes));
                  } catch (IOException ioe) {
                	  // Maybe it's just a sinlge binary CA cert
                	  Certificate cert = CertTools.getCertfromByteArray(certbytes);
                	  certchain = new ArrayList();
                	  certchain.add(cert);
                  }
                  byte[] certreq = cadatahandler.makeRequest(caid, certchain, false, null, false);
                  cabean.saveRequestData(certreq);     
                  filemode = CERTREQGENMODE;
                  includefile = "displayresult.jspf";
                } catch(CertificateException ce) {
          			includefile="choosecapage.jspf";
        			errorrecievingfile = true;
          		} catch(Exception e){
                  includefile="choosecapage.jspf";
                  errormessage = e.getMessage(); 
                } 
          }
      }
      
      if( action.equals(ACTION_RECEIVERESPONSE)){        
        if(!buttoncancel){
          try{                                                                                     
            if (caid != 0) {                             
              cadatahandler.receiveResponse(caid, file);   
              caactivated = true;
            }           
          }catch(CATokenOfflineException e){  
              throw e;
          }catch(EjbcaException e){ 
              errormessage = e.getMessage(); 
          } catch(ExtCertPathValidatorException e){
        	  errormessage = e.getMessage();  
          } catch(CertificateException e){   
              errorrecievingfile = true; 
          } catch(Exception e){   
        	  errormessage = e.getMessage();
          } 
        }
      }
      
      if( action.equals(ACTION_SIGNREQUEST)){       
          if(!buttoncancel){
            try{           
                byte[] reqbytes = FileTools.readInputStreamtoBuffer(file);
                if (reqbytes != null) {                                    
	               boolean previouskey = false;
	               if(usepreviouskey != null) {
	            	   previouskey = usepreviouskey.equals(CHECKBOX_VALUE);
	               }
	               boolean createlinkcertificate = false;
	               if(createlinkcert != null) {
	            	   createlinkcertificate = createlinkcert.equals(CHECKBOX_VALUE);
	               }
	               byte[] signedreq = cadatahandler.signRequest(caid, reqbytes, previouskey, createlinkcertificate);                                
	               cabean.saveRequestData(signedreq);     
	               filemode = CERTREQGENMODE;
	               includefile = "displayresult.jspf";
                }
            }catch(IOException e){                      
              errorrecievingfile = true; 
            } catch(Exception e){                      
              errormessage = e.getMessage(); 
            } 
          }
      }
      
      if( action.equals(ACTION_PROCESSREQUEST)){       
       if(!buttoncancel){
         try{           
             byte[] reqbytes = FileTools.readInputStreamtoBuffer(file);
             if (reqbytes != null) {
            	 IRequestMessage certreq = org.ejbca.util.RequestMessageUtils.parseRequestMessage(reqbytes);

                 if (certreq != null) {    
                   cabean.saveRequestData(reqbytes);                                
                   processedsubjectdn = certreq.getRequestDN();
                   processrequest = true;
                   includefile="editcapage.jspf";
                 }            	 
             }
         } catch(Exception e){                      
            errorrecievingfile = true;
         } 
       }else{
         cabean.saveRequestData(null);  
       }
      }
      if( action.equals(ACTION_PROCESSREQUEST2)){        
        if(request.getParameter(BUTTON_CANCEL) == null){
         // Create and process CA                          
         caname = request.getParameter(HIDDEN_CANAME);
         catype  = Integer.parseInt(request.getParameter(HIDDEN_CATYPE));
         String subjectdn = request.getParameter(TEXTFIELD_SUBJECTDN);
         try{
             X509Name dummy = CertTools.stringToBcX509Name(subjectdn);
         }catch(Exception e){
           illegaldnoraltname = true;
         }
         
         int certprofileid = 0;
         CertificateProfile certprof = null;
         if(request.getParameter(SELECT_CERTIFICATEPROFILE) != null)
           certprofileid = Integer.parseInt(request.getParameter(SELECT_CERTIFICATEPROFILE));
         int signedby = 0;
         if(request.getParameter(SELECT_SIGNEDBY) != null)
            signedby = Integer.parseInt(request.getParameter(SELECT_SIGNEDBY));
         
         String description = request.getParameter(TEXTFIELD_DESCRIPTION);        
         if(description == null)
           description = "";
         
         final long validity = ValidityDate.encode(request.getParameter(TEXTFIELD_VALIDITY));
         if ( validity<0 ) {
             throw new ParameterError(ejbcawebbean.getText("INVALIDVALIDITYORCERTEND"));
         }

         if(catype != 0 && subjectdn != null && caname != null && 
            certprofileid != 0 && signedby != 0 && validity !=0 ){
        	 CAInfo cainfo = null;

        	 // Parameters common for both X509 and CVC CAs
             ArrayList approvalsettings = new ArrayList(); 
             int numofreqapprovals = 1;
             boolean finishuser = false;
             ArrayList crlpublishers = new ArrayList(); 
             int crlperiod = 0;
             int crlIssueInterval = 0;
             int crlOverlapTime = 10;
             int deltacrlperiod = 0;

             
        	 if(catype == CAInfo.CATYPE_X509){
              // Create a X509 CA
              String subjectaltname = request.getParameter(TEXTFIELD_SUBJECTALTNAME);
              if(subjectaltname == null)
                subjectaltname = ""; 
              else{
                if(!subjectaltname.trim().equals("")){
                   DNFieldExtractor subtest = 
                     new DNFieldExtractor(subjectaltname,DNFieldExtractor.TYPE_SUBJECTALTNAME);                   
                   if(subtest.isIllegal() || subtest.existsOther()){
                     illegaldnoraltname = true;
                   }
                }
              }

              /* Process certificate policies. */
              String policyid = request.getParameter(TEXTFIELD_POLICYID);
              ArrayList policies = new ArrayList();
              certprof = cabean.getCertificateProfile(certprofileid);
			  if (!(policyid == null || policyid.trim().equals(""))){
            	  String[] str = policyid.split("\\s+");
            		if (str.length > 1) {
            			policies.add(new CertificatePolicy(str[0], CertificatePolicy.id_qt_cps, str[1]));
            		} else {
            			policies.add(new CertificatePolicy((policyid.trim()),null,null));
            		}
              }
              if ((certprof.getCertificatePolicies().size() > 0) && (certprof.getCertificatePolicies() != null)) {
            	  policies.addAll(certprof.getCertificatePolicies());
              }

              boolean useauthoritykeyidentifier = false;
              boolean authoritykeyidentifiercritical = false;              

              boolean usecrlnumber = false;
              boolean crlnumbercritical = false;
                                                                      
              boolean useutf8policytext = false;
              boolean useprintablestringsubjectdn = false;
              boolean useldapdnorder = true;
              if (DnComponents.isReverseOrder()) {
                  useldapdnorder = false;            	  
              }
              boolean usecrldistpointoncrl = false;
              boolean crldistpointoncrlcritical = false;
                            
             if(!illegaldnoraltname){
               if(request.getParameter(BUTTON_PROCESSREQUEST) != null){
                 cainfo = new X509CAInfo(subjectdn, caname, SecConst.CA_ACTIVE, new Date(), subjectaltname,
                                                        certprofileid, validity, 
                                                        null, catype, signedby,
                                                        null, null, description, -1, null,
                                                        policies, crlperiod, crlIssueInterval, crlOverlapTime, deltacrlperiod, crlpublishers, 
                                                        useauthoritykeyidentifier, 
                                                        authoritykeyidentifiercritical,
                                                        usecrlnumber, 
                                                        crlnumbercritical, 
                                                        "","","", "", 
                                                        finishuser, 
                                                        new ArrayList(),
                                                        useutf8policytext,
                                                        approvalsettings,
                                                        numofreqapprovals, 
                                                        useprintablestringsubjectdn,
                                                        useldapdnorder,
                                                        usecrldistpointoncrl,
                                                        crldistpointoncrlcritical,
                                                        true);
               }                               
               }
             } // if(catype == CAInfo.CATYPE_X509)
            	 
             if(catype == CAInfo.CATYPE_CVC) {
        		 // A CVC CA does not have any of the external services OCSP, XKMS, CMS
        		 ArrayList extendedcaservices = new ArrayList();

                 if(request.getParameter(BUTTON_MAKEREQUEST) != null){
                     caid = CertTools.stringToBCDNString(subjectdn).hashCode();
                     signedby = CAInfo.SIGNEDBYEXTERNALCA;
                 }

                 // Create the CAInfo to be used for either generating the whole CA or making a request
                 if(!illegaldnoraltname){
                   if(request.getParameter(BUTTON_PROCESSREQUEST) != null){
                     cainfo = new CVCCAInfo(subjectdn, caname, SecConst.CA_ACTIVE, new Date(),
                       certprofileid, validity, 
                       null, catype, signedby,
                       null, null, description, -1, null,
                       crlperiod, crlIssueInterval, crlOverlapTime, deltacrlperiod, crlpublishers, 
                       finishuser, extendedcaservices,
                       approvalsettings,
                       numofreqapprovals,
                       true);
                   }
                 }
               }  // if(catype == CAInfo.CATYPE_CVC)
               if (cainfo != null) {
                   try{
                       byte[] req = cabean.getRequestData(); 
                       IRequestMessage certreq = org.ejbca.util.RequestMessageUtils.parseRequestMessage(req);
                       Certificate result = cadatahandler.processRequest(cainfo, certreq);
                       cabean.saveProcessedCertificate(result);
                       filemode = CERTGENMODE;   
                       includefile="displayresult.jspf";
                   }catch(CAExistsException caee){
                        caexists = true;
                   }                              	   
               }
         }
        } 
      }

      if( action.equals(ACTION_RENEWCA_MAKEREQUEST)){
        if(!buttoncancel){
          try{
           Collection certchain = CertTools.getCertsFromPEM(file);
           // These parameters are set in 'if(FileUpload.isMultipartContent(request)){'            
           //renewauthenticationcode = request.getParameter(HIDDEN_RENEWAUTHCODE);
           //reGenerateKeys = Boolean.valueOf(request.getParameter(HIDDEN_RENEWKEYS)).booleanValue();
           byte[] certreq = cadatahandler.makeRequest(caid, certchain, false, renewauthenticationcode, reGenerateKeys);
           cabean.saveRequestData(certreq);   
               
           filemode = CERTREQGENMODE;
           includefile = "displayresult.jspf";
          }catch(CATokenOfflineException e){  
        	  includefile="choosecapage.jspf"; 
              throw e;
          }catch(EjbcaException e){ 
        	  includefile="choosecapage.jspf"; 
              errormessage = e.getMessage(); 
          } catch(Exception e){   
        	  includefile="choosecapage.jspf"; 
              errorrecievingfile = true; 
          }  
        }else{
          cabean.saveRequestInfo((CAInfo) null); 
        }      
      }
      if( action.equals(ACTION_RENEWCA_RECIEVERESPONSE)){
        if(!buttoncancel){
          try{                                                                                     
            if (caid != 0) {                             
              cadatahandler.receiveResponse(caid, file);   
              carenewed = true;
            }           
          }catch(CATokenOfflineException e){                       
              throw e;
          }catch(EjbcaException e){                       
              errormessage = e.getMessage(); 
          } catch(ExtCertPathValidatorException e){
        	  errormessage = e.getMessage();  
          } catch(Exception e){                       
              errorrecievingfile = true; 
          }  
        }        
      }
      if( action.equals(ACTION_CHOOSE_CATYPE)){
    	  // Change the CA type we are
    	  catype = Integer.parseInt(request.getParameter(SELECT_CATYPE));
          caname = request.getParameter(HIDDEN_CANAME);   
          editca = false;
          processedsubjectdn = request.getParameter(HIDDEN_PROCESSREQUESTDN);
          String processrequeststr = request.getParameter(HIDDEN_PROCESSREQUEST);
          if ( (processrequeststr != null) && (processrequeststr.length() > 0)) {
              processrequest = Boolean.valueOf(processrequeststr).booleanValue();        	  
          } 
          includefile="editcapage.jspf";              
      }
      if( action.equals(ACTION_CHOOSE_CATOKENTYPE)){
        
        catokenpath = request.getParameter(SELECT_CATOKEN);  
        catype = Integer.parseInt(request.getParameter(HIDDEN_CATYPE));
        caname = request.getParameter(HIDDEN_CANAME);   
        if(catokenpath.equals(SoftCAToken.class.getName())){
          catokentype = CATokenInfo.CATOKENTYPE_P12;
        }else{
          catokentype = CATokenInfo.CATOKENTYPE_HSM;
        }
        editca = false;
        includefile="editcapage.jspf";              
      }
      if( action.equals(ACTION_IMPORTCA) ) {
		if( !buttoncancel ) {
	        try {
	        	String caName			= importcaname;
	            String kspwd			= importpassword;
	            InputStream p12file		= file;
	            String alias			= importsigalias;
	            String encryptionAlias	= importencalias;

				java.security.KeyStore ks = java.security.KeyStore.getInstance("PKCS12","BC");
				ks.load(file, kspwd.toCharArray());
				if ( alias.equals("") ) {
					Enumeration aliases = ks.aliases();
		            if ( aliases == null || !aliases.hasMoreElements() ) {
						throw new Exception("This file does not contain any aliases.");
		            } 
		            alias = (String)aliases.nextElement();
		            if ( aliases.hasMoreElements() ) {
			            while (aliases.hasMoreElements()) {
							alias += " " + (String)aliases.nextElement();
						}
						throw new Exception("You have to specify any of the following aliases: " + alias);
					}
		        }
				ByteArrayOutputStream baos = new ByteArrayOutputStream();
	            ks.store(baos, kspwd.toCharArray());
	    		byte[] keystorebytes = baos.toByteArray();
	            if ( encryptionAlias.equals("") ) {
	            	encryptionAlias = null;
	            }
				cadatahandler.importCAFromKeyStore(caName, keystorebytes, kspwd, kspwd, alias, encryptionAlias);
			} catch (Exception e) {
			%> <div style="color: #FF0000;"> <%
				out.println( e.getMessage() );
			%> </div> <%
		        includefile="importca.jspf";              
			}
		}
      } // ACTION_IMPORTCA
      if( action.equals(ACTION_IMPORTCACERT) ) {
		if( !buttoncancel ) {
	        try {
	            // Load PEM
	            cadatahandler.importCACert(importcaname, file);
			} catch (Exception e) {
			%> <div style="color: #FF0000;"> <%
				out.println( e.getMessage() );
			%> </div> <%
		        includefile="importcacert.jspf";
			}
		}
      } // ACTION_IMPORTCACERT
    }
  }catch(CATokenOfflineException ctoe){
    catokenoffline = true;
    includefile="choosecapage.jspf";
  }   


 // Include page
  if( includefile.equals("editcapage.jspf")){ 
%>
   <%@ include file="editcapage.jspf" %>
<%}
  if( includefile.equals("choosecapage.jspf")){ %>
   <%@ include file="choosecapage.jspf" %> 
<%}  
  if( includefile.equals("recievefile.jspf")){ %>
   <%@ include file="recievefile.jspf" %> 
<%} 
  if( includefile.equals("displayresult.jspf")){ %>
   <%@ include file="displayresult.jspf" %> 
<%}
  if( includefile.equals("renewexternal.jspf")){ %>
   <%@ include file="renewexternal.jspf" %> 
<%}
  if( includefile.equals("importca.jspf")){ %>
   <%@ include file="importca.jspf" %> 
<%}
  if( includefile.equals("importcacert.jspf")){ %>
   <%@ include file="importcacert.jspf" %> 
<%}


   // Include Footer 
   String footurl =   globalconfiguration.getFootBanner(); %>
   
  <jsp:include page="<%= footurl %>" />

</body>
</html>
