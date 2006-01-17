<%@ page pageEncoding="ISO-8859-1"%>
<%@page errorPage="/errorpage.jsp" import="java.util.*, java.io.*, org.apache.commons.fileupload.*, org.ejbca.ui.web.admin.configuration.EjbcaWebBean,org.ejbca.core.model.ra.raadmin.GlobalConfiguration, org.ejbca.core.model.SecConst, org.ejbca.util.FileTools, org.ejbca.util.CertTools, org.ejbca.core.model.authorization.AuthorizationDeniedException,
               org.ejbca.ui.web.admin.cainterface.CAInterfaceBean, org.ejbca.core.model.ca.caadmin.CAInfo, org.ejbca.core.model.ca.caadmin.X509CAInfo, org.ejbca.core.model.ca.catoken.CATokenInfo, org.ejbca.core.model.ca.catoken.SoftCATokenInfo, org.ejbca.ui.web.admin.cainterface.CADataHandler,
               org.ejbca.ui.web.admin.rainterface.RevokedInfoView, org.ejbca.ui.web.admin.configuration.InformationMemory, org.bouncycastle.asn1.x509.X509Name, org.ejbca.core.protocol.ExtendedPKCS10CertificationRequest, 
               org.ejbca.core.protocol.PKCS10RequestMessage, org.ejbca.core.model.ca.caadmin.CAExistsException, org.ejbca.core.model.ca.caadmin.CADoesntExistsException, org.ejbca.core.model.ca.catoken.CATokenOfflineException, org.ejbca.core.model.ca.catoken.CATokenAuthenticationFailedException,
               org.ejbca.core.model.ca.caadmin.extendedcaservices.OCSPCAServiceInfo, org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceInfo, org.ejbca.core.model.ca.catoken.HardCATokenManager, org.ejbca.core.model.ca.catoken.AvailableHardCAToken, org.ejbca.core.model.ca.catoken.HardCATokenInfo"%>

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
  static final String ACTION_RECEIVERESPONSE              = "receiveresponse";
  static final String ACTION_PROCESSREQUEST               = "processrequest";
  static final String ACTION_PROCESSREQUEST2              = "processrequest2";
  static final String ACTION_RENEWCA_MAKEREQUEST          = "renewcamakeresponse";  
  static final String ACTION_RENEWCA_RECIEVERESPONSE      = "renewcarecieveresponse";  



  static final String CHECKBOX_VALUE           = "true";

//  Used in choosecapage.jsp
  static final String BUTTON_EDIT_CA                       = "buttoneditca"; 
  static final String BUTTON_DELETE_CA                     = "buttondeleteca";
  static final String BUTTON_CREATE_CA                     = "buttoncreateca"; 
  static final String BUTTON_RENAME_CA                     = "buttonrenameca";
  static final String BUTTON_PROCESSREQUEST                = "buttonprocessrequest";
  

  static final String SELECT_CAS                           = "selectcas";
  static final String TEXTFIELD_CANAME                     = "textfieldcaname";
  static final String HIDDEN_CANAME                        = "hiddencaname";
  static final String HIDDEN_CAID                          = "hiddencaid";
  static final String HIDDEN_CATYPE                        = "hiddencatype";
  static final String HIDDEN_CATOKENPATH                   = "hiddencatokenpath";
  static final String HIDDEN_CATOKENTYPE                   = "hiddencatokentype";
 
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
  static final String BUTTON_GENDEFAULTCRLDISTPOINT     = "checkboxgeneratedefaultcrldistpoint";
  static final String BUTTON_GENDEFAULTOCSPLOCATOR      = "checkbexgeneratedefaultocsplocator";

  static final String TEXTFIELD_SUBJECTDN             = "textfieldsubjectdn";
  static final String TEXTFIELD_SUBJECTALTNAME        = "textfieldsubjectaltname";  
  static final String TEXTFIELD_CRLPERIOD             = "textfieldcrlperiod";
  static final String TEXTFIELD_DESCRIPTION           = "textfielddescription";
  static final String TEXTFIELD_VALIDITY              = "textfieldvalidity";
  static final String TEXTFIELD_POLICYID              = "textfieldpolicyid";
  static final String TEXTFIELD_HARDCATOKENPROPERTIES = "textfieldhardcatokenproperties";
  static final String TEXTFIELD_AUTHENTICATIONCODE    = "textfieldauthenticationcode";
  static final String TEXTFIELD_DEFAULTCRLDISTPOINT   = "textfielddefaultcrldistpoint";
  static final String TEXTFIELD_DEFAULTOCSPLOCATOR    = "textfielddefaultocsplocator";

  static final String CHECKBOX_AUTHORITYKEYIDENTIFIER             = "checkboxauthoritykeyidentifier";
  static final String CHECKBOX_AUTHORITYKEYIDENTIFIERCRITICAL     = "checkboxauthoritykeyidentifiercritical";
  static final String CHECKBOX_USECRLNUMBER                       = "checkboxusecrlnumber";
  static final String CHECKBOX_CRLNUMBERCRITICAL                  = "checkboxcrlnumbercritical";
  static final String CHECKBOX_FINISHUSER                         = "checkboxfinishuser";
  static final String CHECKBOX_ACTIVATEOCSPSERVICE                = "checkboxactivateocspservice";  
  
  static final String HIDDEN_CATOKEN                              = "hiddencatoken";  
  
  static final String SELECT_REVOKEREASONS                        = "selectrevokereasons";
  static final String SELECT_CATYPE                               = "selectcatype";  
  static final String SELECT_CATOKEN                              = "selectcatoken";
  static final String SELECT_SIGNEDBY                             = "selectsignedby";  
  static final String SELECT_KEYSIZE                              = "selectsize";
  static final String SELECT_AVAILABLECRLPUBLISHERS               = "selectavailablecrlpublishers";
  static final String SELECT_CERTIFICATEPROFILE                   = "selectcertificateprofile";
  static final String SELECT_SIGNATUREALGORITHM                   = "selectsignaturealgorithm";

  static final String FILE_RECIEVEFILE                            = "filerecievefile";
  static final String FILE_CACERTFILE                             = "filecacertfile";
  static final String FILE_REQUESTFILE                            = "filerequestfile";   

  static final String CERTSERNO_PARAMETER       = "certsernoparameter"; 

  static final int    MAKEREQUESTMODE     = 0;
  static final int    RECIEVERESPONSEMODE = 1;
  static final int    PROCESSREQUESTMODE  = 2;   
  
  static final int    CERTREQGENMODE      = 0;
  static final int    CERTGENMODE         = 1;
%>
<% 
         
  // Initialize environment
  int caid = 0;
  String caname = null;
  String includefile = "choosecapage.jspf"; 
  String processedsubjectdn = "";
  int catype = CAInfo.CATYPE_X509;  // default
  int catokentype = CATokenInfo.CATOKENTYPE_P12; // default
  String catokenpath = "NONE";

  InputStream file = null;

  boolean  caexists             = false;
  boolean  cadeletefailed       = false;
  boolean  illegaldnoraltname   = false;
  boolean  errorrecievingfile   = false;
  boolean  ocsprenewed          = false;
  boolean  catokenoffline       = false;
  boolean  catokenauthfailed    = false;
  

  GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, "/super_administrator"); 
                                            cabean.initialize(request, ejbcawebbean); 

  CADataHandler cadatahandler = cabean.getCADataHandler(); 
  String THIS_FILENAME            =  globalconfiguration.getCaPath()  + "/editcas/editcas.jsp";
  String action = "";

  final String VIEWCERT_LINK            = globalconfiguration.getBaseUrl() + globalconfiguration.getAdminWebPath() + "viewcertificate.jsp";
  
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
         if(item.getFieldName().equals(BUTTON_CANCEL))
           buttoncancel = true; 
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
    }
    if( action.equals(ACTION_CREATE_CA)){
      if( request.getParameter(BUTTON_CREATE)  != null || request.getParameter(BUTTON_MAKEREQUEST)  != null){
         // Create and save CA                          
         caname = request.getParameter(HIDDEN_CANAME);
          
         CATokenInfo catoken = null;
         catokentype = Integer.parseInt(request.getParameter(HIDDEN_CATOKENTYPE));
         if(catokentype == CATokenInfo.CATOKENTYPE_P12){
           int keysize = Integer.parseInt(request.getParameter(SELECT_KEYSIZE));
           String signalg = request.getParameter(SELECT_SIGNATUREALGORITHM);
           if(keysize == 0 || signalg == null)
             throw new Exception("Error in CATokenData");  
           catoken = new SoftCATokenInfo();
           catoken.setSignatureAlgorithm(signalg);
           ((SoftCATokenInfo) catoken).setKeySize(keysize);              
         } 
         if(catokentype == CATokenInfo.CATOKENTYPE_HSM){
            catokenpath = request.getParameter(HIDDEN_CATOKENPATH);
            String properties = request.getParameter(TEXTFIELD_HARDCATOKENPROPERTIES);
            String signalg = request.getParameter(SELECT_SIGNATUREALGORITHM);
            String authenticationcode = request.getParameter(TEXTFIELD_AUTHENTICATIONCODE);
            if(catokenpath == null || catokenpath == null || signalg == null)
              throw new Exception("Error in CATokenData");  
            catoken = new HardCATokenInfo();           
            ((HardCATokenInfo) catoken).setClassPath(catokenpath);
            ((HardCATokenInfo) catoken).setProperties(properties);
            ((HardCATokenInfo) catoken).setSignatureAlgorithm(signalg);
            ((HardCATokenInfo) catoken).setAuthenticationCode(authenticationcode);
         }

         catype  = Integer.parseInt(request.getParameter(HIDDEN_CATYPE));
         String subjectdn = request.getParameter(TEXTFIELD_SUBJECTDN);
         try{
           X509Name dummy = new X509Name(subjectdn);
         }catch(Exception e){
           illegaldnoraltname = true;
         }
         int certprofileid = 0;
         if(request.getParameter(SELECT_CERTIFICATEPROFILE) != null)
           certprofileid = Integer.parseInt(request.getParameter(SELECT_CERTIFICATEPROFILE));
         int signedby = 0;
         if(request.getParameter(SELECT_SIGNEDBY) != null)
            signedby = Integer.parseInt(request.getParameter(SELECT_SIGNEDBY));
         String description = request.getParameter(TEXTFIELD_DESCRIPTION);        
         if(description == null)
           description = "";
         
         int validity = 0;
         if(request.getParameter(TEXTFIELD_VALIDITY) != null)
           validity = Integer.parseInt(request.getParameter(TEXTFIELD_VALIDITY));  

         if(catoken != null && catype != 0 && subjectdn != null && caname != null 
            && signedby != 0  ){
           if(catype == CAInfo.CATYPE_X509){
              // Create a X509 CA
              String subjectaltname = request.getParameter(TEXTFIELD_SUBJECTALTNAME);             
              if(subjectaltname == null)
                subjectaltname = ""; 
              else{
                if(!subjectaltname.trim().equals("")){
                   org.ejbca.core.model.ra.raadmin.DNFieldExtractor subtest = 
                     new org.ejbca.core.model.ra.raadmin.DNFieldExtractor(subjectaltname,org.ejbca.core.model.ra.raadmin.DNFieldExtractor.TYPE_SUBJECTALTNAME);                   
                   if(subtest.isIllegal() || subtest.existsOther()){
                     illegaldnoraltname = true;
                   }
                }
              }    

              String policyid = request.getParameter(TEXTFIELD_POLICYID);
              if(policyid == null || policyid.trim().equals(""))
                 policyid = null; 

              int crlperiod = Integer.parseInt(request.getParameter(TEXTFIELD_CRLPERIOD));

              boolean useauthoritykeyidentifier = false;
              boolean authoritykeyidentifiercritical = false;
              String value = request.getParameter(CHECKBOX_AUTHORITYKEYIDENTIFIER);
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
             String defaultocsplocator  = request.getParameter(TEXTFIELD_DEFAULTOCSPLOCATOR);
              
             boolean finishuser = false;
             value = request.getParameter(CHECKBOX_FINISHUSER);
             if(value != null)
               finishuser = value.equals(CHECKBOX_VALUE);         

             String[] values = request.getParameterValues(SELECT_AVAILABLECRLPUBLISHERS);
             ArrayList crlpublishers = new ArrayList(); 
             if(values != null){
               for(int i=0; i < values.length; i++){
                  crlpublishers.add(new Integer(values[i]));
               }
             }

             int ocspactive = ExtendedCAServiceInfo.STATUS_INACTIVE;
             value = request.getParameter(CHECKBOX_ACTIVATEOCSPSERVICE);
             if(value != null && value.equals(CHECKBOX_VALUE))
                ocspactive = ExtendedCAServiceInfo.STATUS_ACTIVE;             
              
             if(crlperiod != 0 && !illegaldnoraltname){
               if(request.getParameter(BUTTON_CREATE) != null){           
      
		 // Create and active OSCP CA Service.
		 ArrayList extendedcaservices = new ArrayList();
		 extendedcaservices.add(
		             new OCSPCAServiceInfo(ocspactive,
						  "CN=OCSPSignerCertificate, " + subjectdn,
			     		  "",
						  2048,
						  OCSPCAServiceInfo.KEYALGORITHM_RSA));
                 X509CAInfo x509cainfo = new X509CAInfo(subjectdn, caname, 0, subjectaltname,
                                                        certprofileid, validity, 
                                                        null, catype, signedby,
                                                        null, catoken, description, -1, null,
                                                        policyid, crlperiod, crlpublishers, 
                                                        useauthoritykeyidentifier, 
                                                        authoritykeyidentifiercritical,
                                                        usecrlnumber, 
                                                        crlnumbercritical, 
                                                        defaultcrldistpoint,
                                                        defaultocsplocator,
                                                        finishuser, extendedcaservices);
                 try{
                   cadatahandler.createCA((CAInfo) x509cainfo);
                 }catch(CAExistsException caee){
                    caexists = true; 
                 }catch(CATokenAuthenticationFailedException catfe){
                    catokenauthfailed = true;
                 }
                 includefile="choosecapage.jspf"; 
               }
               if(request.getParameter(BUTTON_MAKEREQUEST) != null){
                 caid = CertTools.stringToBCDNString(subjectdn).hashCode();  
		 // Create and OSCP CA Service.
		 ArrayList extendedcaservices = new ArrayList();
		 extendedcaservices.add(
		             new OCSPCAServiceInfo(ocspactive,
						  "CN=OCSPSignerCertificate, " + subjectdn,
			     		          "",
						  2048,
						  OCSPCAServiceInfo.KEYALGORITHM_RSA));
                 X509CAInfo x509cainfo = new X509CAInfo(subjectdn, caname, caid, subjectaltname,
                                                        certprofileid, validity,
                                                        null, catype, CAInfo.SIGNEDBYEXTERNALCA,
                                                        null, catoken, description, -1, null, 
                                                        policyid, crlperiod, crlpublishers, 
                                                        useauthoritykeyidentifier, 
                                                        authoritykeyidentifiercritical,
                                                        usecrlnumber, 
                                                        crlnumbercritical, 
                                                        defaultcrldistpoint,
                                                        defaultocsplocator,
                                                        finishuser, extendedcaservices);
                 cabean.saveRequestInfo(x509cainfo);                
                 filemode = MAKEREQUESTMODE;
                 includefile="recievefile.jspf"; 
               }
             }                          
           } 
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
          request.getParameter(BUTTON_REVOKERENEWOCSPCERTIFICATE) != null){
         // Create and save CA                          
         caid = Integer.parseInt(request.getParameter(HIDDEN_CAID));
         caname = request.getParameter(HIDDEN_CANAME);
         catype = Integer.parseInt(request.getParameter(HIDDEN_CATYPE));
         
         CATokenInfo catoken = null;
         catokentype = Integer.parseInt(request.getParameter(HIDDEN_CATOKENTYPE));
         if(catokentype == CATokenInfo.CATOKENTYPE_P12){
           catoken = new SoftCATokenInfo();          
         } 
         if(catokentype == CATokenInfo.CATOKENTYPE_HSM){
            String properties = request.getParameter(TEXTFIELD_HARDCATOKENPROPERTIES);
            if(catokenpath == null)
              throw new Exception("Error in CATokenData");  
            catoken = new HardCATokenInfo();                       
            ((HardCATokenInfo) catoken).setProperties(properties);
         }

          
         String description = request.getParameter(TEXTFIELD_DESCRIPTION);        

         int validity = 0;
         if(request.getParameter(TEXTFIELD_VALIDITY) != null)
           validity = Integer.parseInt(request.getParameter(TEXTFIELD_VALIDITY));
            

         if(caid != 0 && description != null && catype !=0 ){
           if(catype == CAInfo.CATYPE_X509){
              // Edit X509 CA data              
              
              int crlperiod = Integer.parseInt(request.getParameter(TEXTFIELD_CRLPERIOD));

              boolean useauthoritykeyidentifier = false;
              boolean authoritykeyidentifiercritical = false;
              String value = request.getParameter(CHECKBOX_AUTHORITYKEYIDENTIFIER);
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
             String defaultocsplocator  = request.getParameter(TEXTFIELD_DEFAULTOCSPLOCATOR);
              
             boolean finishuser = false;
             value = request.getParameter(CHECKBOX_FINISHUSER);
             if(value != null)
               finishuser = value.equals(CHECKBOX_VALUE);         

             String[] values = request.getParameterValues(SELECT_AVAILABLECRLPUBLISHERS);
             ArrayList crlpublishers = new ArrayList(); 
             if(values != null){
                 for(int i=0; i < values.length; i++){
                    crlpublishers.add(new Integer(values[i]));
                 }
              }
              
              // Create extended CA Service updatedata.
              int active = ExtendedCAServiceInfo.STATUS_INACTIVE;
              value = request.getParameter(CHECKBOX_ACTIVATEOCSPSERVICE);
              if(value != null && value.equals(CHECKBOX_VALUE))
                active = ExtendedCAServiceInfo.STATUS_ACTIVE;             

              boolean renew = false;
              if(active == ExtendedCAServiceInfo.STATUS_ACTIVE && 
                 request.getParameter(BUTTON_REVOKERENEWOCSPCERTIFICATE) != null){
                 cadatahandler.revokeOCSPCertificate(caid);
                 renew=true;
                 ocsprenewed = true;             
                 includefile="choosecapage.jspf"; 
               }

	      ArrayList extendedcaservices = new ArrayList();
              extendedcaservices.add(
		             new OCSPCAServiceInfo(active, renew));       

             if(crlperiod != 0){
               X509CAInfo x509cainfo = new X509CAInfo(caid, validity,
                                                      catoken, description, 
                                                      crlperiod, crlpublishers, 
                                                      useauthoritykeyidentifier, 
                                                      authoritykeyidentifiercritical,
                                                      usecrlnumber, 
                                                      crlnumbercritical, 
                                                      defaultcrldistpoint,
                                                      defaultocsplocator,
                                                      finishuser,extendedcaservices);
                 
               cadatahandler.editCA((CAInfo) x509cainfo);
                 

               
               if(request.getParameter(BUTTON_SAVE) != null){
                  // Do nothing More

                  includefile="choosecapage.jspf"; 
               }
               if(request.getParameter(BUTTON_RECEIVEREQUEST) != null){                  
                  filemode = RECIEVERESPONSEMODE;
                  includefile="recievefile.jspf"; 
               }
               if(request.getParameter(BUTTON_RENEWCA) != null){
                 int signedby = cadatahandler.getCAInfo(caid).getCAInfo().getSignedBy();
                 if(signedby != CAInfo.SIGNEDBYEXTERNALCA){
                   cadatahandler.renewCA(caid, null);
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

             }                          
           } 
         } 
       } 
       if(request.getParameter(BUTTON_CANCEL) != null){
         // Don't save changes.
         includefile="choosecapage.jspf"; 
       }               

         
      }
      if( action.equals(ACTION_MAKEREQUEST)){         
       if(!buttoncancel){
         try{
           Collection certchain = CertTools.getCertsFromPEM(file);           
           try{
             CAInfo cainfo = cabean.getRequestInfo();              
             cadatahandler.createCA(cainfo);                           
             ExtendedPKCS10CertificationRequest certreq = null;
             try{ 
               certreq=cadatahandler.makeRequest(caid, certchain, true);
               cabean.savePKCS10RequestData(certreq);     
               filemode = CERTREQGENMODE;
               includefile = "displayresult.jspf";
             }catch(Exception e){  
               cadatahandler.removeCA(caid); 
               errorrecievingfile = true;
               includefile="choosecapage.jspf";  
             }
           }catch(CAExistsException caee){
              caexists = true; 
           } 
         }catch(Exception e){
           errorrecievingfile = true; 
         } 
       }else{
         cabean.saveRequestInfo((CAInfo) null); 
       }
      }

      if( action.equals(ACTION_RECEIVERESPONSE)){        
        if(!buttoncancel){
          try{                                                                                     
            if (caid != 0) {                             
              cadatahandler.receiveResponse(caid, file);   
              caactivated = true;
            }           
          }catch(Exception e){                       
            errorrecievingfile = true; 
          }  
        }
      }
      if( action.equals(ACTION_PROCESSREQUEST)){       
       if(!buttoncancel){
         try{           
           BufferedReader bufRdr = new BufferedReader(new InputStreamReader(file));
           while (bufRdr.ready()) {
            ByteArrayOutputStream ostr = new ByteArrayOutputStream();
            PrintStream opstr = new PrintStream(ostr);
            String temp;
            while ((temp = bufRdr.readLine()) != null){            
              opstr.print(temp + "\n");                
            }  
            opstr.close();                
                                         
            PKCS10RequestMessage certreq = org.ejbca.ui.web.pub.RequestHelper.genPKCS10RequestMessageFromPEM(ostr.toByteArray());
            
             if (certreq != null) {               
               cabean.savePKCS10RequestData(certreq.getCertificationRequest());                                
               processedsubjectdn = certreq.getCertificationRequest().getCertificationRequestInfo().getSubject().toString();
               processrequest = true;
               includefile="editcapage.jspf";
             }
           }
         }catch(Exception e){                      
           errorrecievingfile = true; 
         } 
       }else{
         cabean.savePKCS10RequestData((ExtendedPKCS10CertificationRequest) null);  
       }
      }
      if( action.equals(ACTION_PROCESSREQUEST2)){        
        if(request.getParameter(BUTTON_CANCEL) == null){
         // Create and process CA                          
         caname = request.getParameter(HIDDEN_CANAME);
          
         catype  = Integer.parseInt(request.getParameter(HIDDEN_CATYPE));
         String subjectdn = request.getParameter(TEXTFIELD_SUBJECTDN);
         try{
           X509Name dummy = new X509Name(subjectdn);
         }catch(Exception e){
           illegaldnoraltname = true;
         }
         
         int certprofileid = 0;
         if(request.getParameter(SELECT_CERTIFICATEPROFILE) != null)
           certprofileid = Integer.parseInt(request.getParameter(SELECT_CERTIFICATEPROFILE));
         int signedby = 0;
         if(request.getParameter(SELECT_SIGNEDBY) != null)
            signedby = Integer.parseInt(request.getParameter(SELECT_SIGNEDBY));
         String description = request.getParameter(TEXTFIELD_DESCRIPTION);        
         if(description == null)
           description = "";
         
         int validity = 0;
         if(request.getParameter(TEXTFIELD_VALIDITY) != null)
           validity = Integer.parseInt(request.getParameter(TEXTFIELD_VALIDITY));         

         if(catype != 0 && subjectdn != null && caname != null && 
            certprofileid != 0 && signedby != 0 && validity !=0 ){
           if(catype == CAInfo.CATYPE_X509){
              // Create a X509 CA
              String subjectaltname = request.getParameter(TEXTFIELD_SUBJECTALTNAME);             
              if(subjectaltname == null)
                subjectaltname = ""; 
              else{
                if(!subjectaltname.trim().equals("")){
                   org.ejbca.core.model.ra.raadmin.DNFieldExtractor subtest = 
                     new org.ejbca.core.model.ra.raadmin.DNFieldExtractor(subjectaltname,org.ejbca.core.model.ra.raadmin.DNFieldExtractor.TYPE_SUBJECTALTNAME);                   
                   if(subtest.isIllegal() || subtest.existsOther()){
                     illegaldnoraltname = true;
                   }
                }
              }

              String policyid = request.getParameter(TEXTFIELD_POLICYID);
              if(policyid == null || policyid.trim().equals(""))
                 policyid = null; 

              int crlperiod = 0;

              boolean useauthoritykeyidentifier = false;
              boolean authoritykeyidentifiercritical = false;              

              boolean usecrlnumber = false;
              boolean crlnumbercritical = false;
                                                                      
              boolean finishuser = false;
              ArrayList crlpublishers = new ArrayList(); 
              
             if(!illegaldnoraltname){
               if(request.getParameter(BUTTON_PROCESSREQUEST) != null){
                 X509CAInfo x509cainfo = new X509CAInfo(subjectdn, caname, 0, subjectaltname,
                                                        certprofileid, validity, 
                                                        null, catype, signedby,
                                                        null, null, description, -1, null,
                                                        policyid, crlperiod, crlpublishers, 
                                                        useauthoritykeyidentifier, 
                                                        authoritykeyidentifiercritical,
                                                        usecrlnumber, 
                                                        crlnumbercritical, 
                                                        "","",
                                                        finishuser, 
                                                        new ArrayList());
                 try{
                   ExtendedPKCS10CertificationRequest req = cabean.getPKCS10RequestData(); 
                   java.security.cert.Certificate result = cadatahandler.processRequest(x509cainfo, new PKCS10RequestMessage(req));
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
        } 
      }

      if( action.equals(ACTION_RENEWCA_MAKEREQUEST)){
        if(!buttoncancel){
          try{
           Collection certchain = CertTools.getCertsFromPEM(file);                       
           ExtendedPKCS10CertificationRequest certreq = cadatahandler.makeRequest(caid, certchain, false);
           cabean.savePKCS10RequestData(certreq);   
               
           filemode = CERTREQGENMODE;
           includefile = "displayresult.jspf";
          }catch(Exception e){
           errorrecievingfile = true; 
           includefile="choosecapage.jspf"; 
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
          }catch(Exception e){                       
            errorrecievingfile = true; 
          }  
        }        
      }
      if( action.equals(ACTION_CHOOSE_CATYPE)){
        // Currently not need        
      }
      if( action.equals(ACTION_CHOOSE_CATOKENTYPE)){
        
        catokenpath = request.getParameter(SELECT_CATOKEN);   
        caname = request.getParameter(HIDDEN_CANAME);   
        if(catokenpath.equals("NONE")){
          catokentype = CATokenInfo.CATOKENTYPE_P12;
        }else{
          catokentype = CATokenInfo.CATOKENTYPE_HSM;
        }
        editca = false;
        includefile="editcapage.jspf";              
      }

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


   // Include Footer 
   String footurl =   globalconfiguration.getFootBanner(); %>
   
  <jsp:include page="<%= footurl %>" />

</body>
</html>

