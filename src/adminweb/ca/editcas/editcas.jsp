<html>
<%@page contentType="text/html"%>
<%@page errorPage="/errorpage.jsp" import="java.util.*, se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean,se.anatom.ejbca.ra.raadmin.GlobalConfiguration, se.anatom.ejbca.SecConst, se.anatom.ejbca.authorization.AuthorizationDeniedException,
               se.anatom.ejbca.webdist.cainterface.CAInterfaceBean, se.anatom.ejbca.ca.caadmin.CAInfo, se.anatom.ejbca.ca.caadmin.X509CAInfo, se.anatom.ejbca.ca.caadmin.CATokenInfo, se.anatom.ejbca.ca.caadmin.SoftCATokenInfo, se.anatom.ejbca.webdist.cainterface.CADataHandler,
               se.anatom.ejbca.ca.caadmin.CATokenInfo, se.anatom.ejbca.ca.caadmin.SoftCATokenInfo, se.anatom.ejbca.webdist.webconfiguration.InformationMemory, org.bouncycastle.asn1.x509.X509Name,  
               se.anatom.ejbca.ca.exception.CAExistsException, se.anatom.ejbca.ca.exception.CADoesntExistsException"%>

<jsp:useBean id="ejbcawebbean" scope="session" class="se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean" />
<jsp:useBean id="cabean" scope="session" class="se.anatom.ejbca.webdist.cainterface.CAInterfaceBean" />

<%! // Declarations 
  static final String ACTION                              = "action";
  static final String ACTION_EDIT_CAS                     = "editcas";
  static final String ACTION_EDIT_CA                      = "editca";
  static final String ACTION_CREATE_CA                    = "createca";
  static final String ACTION_CHOOSE_CATYPE                = "choosecatype";
  static final String ACTION_CHOOSE_CATOKENTYPE           = "choosecatokentype";
  static final String ACTION_RECEIVERESPONSE              = "receiveresponse";
  static final String ACTION_PROCESSREQUEST               = "processrequest";
  static final String ACTION_RENEWCA                      = "renewca";


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
  static final String HIDDEN_CATOKENTYPE                   = "hiddencatokentype";
 
// Buttons used in editcapage.jsp
  static final String BUTTON_SAVE              = "buttonsave";
  static final String BUTTON_CREATE            = "buttoncreate";
  static final String BUTTON_CANCEL            = "buttoncancel";
  static final String BUTTON_MAKEREQUEST       = "buttonmakerequest";
  static final String BUTTON_RECEIVEREQUEST    = "buttonreceiverequest";
  static final String BUTTON_RENEWCA           = "buttonrenewca";
  static final String BUTTON_REVOKECA          = "buttonrevokeca";       
 
  static final String TEXTFIELD_SUBJECTDN           = "textfieldsubjectdn";
  static final String TEXTFIELD_SUBJECTALTNAME      = "textfieldsubjectaltname";  
  static final String TEXTFIELD_CRLPERIOD           = "textfieldcrlperiod";
  static final String TEXTFIELD_DESCRIPTION         = "textfielddescription";
  static final String TEXTFIELD_VALIDITY            = "textfieldvalidity";
  static final String TEXTFIELD_POLICYID            = "textfieldpolicyid";

  static final String CHECKBOX_AUTHORITYKEYIDENTIFIER             = "checkboxauthoritykeyidentifier";
  static final String CHECKBOX_AUTHORITYKEYIDENTIFIERCRITICAL     = "checkboxauthoritykeyidentifiercritical";
  static final String CHECKBOX_USECRLNUMBER                       = "checkboxusecrlnumber";
  static final String CHECKBOX_CRLNUMBERCRITICAL                  = "checkboxcrlnumbercritical";
  static final String CHECKBOX_FINISHUSER                         = "checkboxfinishuser";
  
  static final String HIDDEN_CATOKEN                              = "hiddencatoken";

  static final String SELECT_REVOKEREASONS                        = "selectrevokereasons";
  static final String SELECT_CATYPE                               = "selectcatype";  
  static final String SELECT_CATOKEN                              = "selectcatoken";
  static final String SELECT_SIGNEDBY                             = "selectsignedby";  
  static final String SELECT_KEYSIZE                              = "selectsize";
  static final String SELECT_AVAILABLECRLPUBLISHERS               = "selectavailablecrlpublishers";
  static final String SELECT_CERTIFICATEPROFILE                   = "selectcertificateprofile";
  static final String SELECT_SIGNATUREALGORITHM                   = "selectsignaturealgorithm";

  // Declare Language file.

%>
<% 

  // Initialize environment
  int caid = 0;
  String caname = null;
  String includefile = "choosecapage.jsp"; 
  int catype = CAInfo.CATYPE_X509;  // default
  int catokentype = CATokenInfo.CATOKENTYPE_P12; // default

  boolean  caexists             = false;
  boolean  cadeletefailed       = false;
  boolean  illegaldnoraltname   = false;

  GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, "/super_administrator"); 
                                            cabean.initialize(request, ejbcawebbean); 

  CADataHandler cadatahandler = cabean.getCADataHandler(); 
  String THIS_FILENAME            =  globalconfiguration.getCaPath()  + "/editcas/editcas.jsp";
  
  boolean issuperadministrator = false;
  boolean editca = false;

  HashMap caidtonamemap = cabean.getCAIdToNameMap();
  InformationMemory info = ejbcawebbean.getInformationMemory();
%>
 
<head>
  <title><%= globalconfiguration .getEjbcaTitle() %></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>">
  <link rel=STYLESHEET href="<%= ejbcawebbean.getCssFile() %>">
  <script language=javascript src="<%= globalconfiguration .getAdminWebPath() %>ejbcajslib.js"></script>
</head>


<%  // Determine action 
  if( request.getParameter(ACTION) != null){
    if( request.getParameter(ACTION).equals(ACTION_EDIT_CAS)){
      // Actions in the choose CA page.
      if( request.getParameter(BUTTON_EDIT_CA) != null){
          // Display  profilepage.jsp         
         includefile="choosecapage.jsp";
         if(request.getParameter(SELECT_CAS) != null){
           caid = Integer.parseInt(request.getParameter(SELECT_CAS));
           if(caid != 0){             
             editca = true;
             includefile="editcapage.jsp";              
           }
         } 
      }
      if( request.getParameter(BUTTON_DELETE_CA) != null) {
          // Delete profile and display choosecapage. 
          if(request.getParameter(SELECT_CAS) != null){
            caid = Integer.parseInt(request.getParameter(SELECT_CAS));
            if(caid != 0){             
                cadeletefailed = !cadatahandler.removeCA(caid);
            }
          }
          includefile="choosecapage.jsp";             
      }
      if( request.getParameter(BUTTON_RENAME_CA) != null){ 
         // Rename selected profile and display profilespage.
       if(request.getParameter(SELECT_CAS) != null && request.getParameter(TEXTFIELD_CANAME) != null){
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
        includefile="choosecapage.jsp"; 
      }
      if( request.getParameter(BUTTON_CREATE_CA) != null){
         // Add profile and display profilespage.
         includefile="choosecapage.jsp"; 
         caname = request.getParameter(TEXTFIELD_CANAME);
         if(caname != null){
           caname = caname.trim();
           if(!caname.equals("")){             
             editca = false;
             includefile="editcapage.jsp";              
           }      
         }         
      }
      if( request.getParameter(BUTTON_PROCESSREQUEST) != null){
         // TODO Implement process request
         includefile="choosecapage.jsp"; 
      }
    }
    if( request.getParameter(ACTION).equals(ACTION_CREATE_CA)){
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
           // TODO IMPLEMENT HSM FUNCTIONALITY
         }

         catype  = Integer.parseInt(request.getParameter(HIDDEN_CATYPE));
         String subjectdn = request.getParameter(TEXTFIELD_SUBJECTDN);
         try{
           X509Name dummy = new X509Name(subjectdn);
         }catch(Exception e){
           illegaldnoraltname = true;
         }
         int certprofileid = Integer.parseInt(request.getParameter(SELECT_CERTIFICATEPROFILE));
         int signedby = Integer.parseInt(request.getParameter(SELECT_SIGNEDBY));
         String description = request.getParameter(TEXTFIELD_DESCRIPTION);        
         if(description == null)
           description = "";
         int validity = Integer.parseInt(request.getParameter(TEXTFIELD_VALIDITY));

         if(catoken != null && catype != 0 && subjectdn != null && caname != null && 
            certprofileid != 0 && signedby != 0 && validity !=0 ){
           if(catype == CAInfo.CATYPE_X509){
              // Create a X509 CA
              String subjectaltname = request.getParameter(TEXTFIELD_SUBJECTALTNAME);             
              if(subjectaltname == null)
                subjectaltname = ""; 

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
              
             if(crlperiod != 0 && !illegaldnoraltname){
               if(request.getParameter(BUTTON_CREATE) != null){
                 X509CAInfo x509cainfo = new X509CAInfo(subjectdn, caname, 0, subjectaltname,
                                                        certprofileid, validity, 
                                                        null, catype, signedby,
                                                        null, catoken, description, -1, 
                                                        policyid, crlperiod, crlpublishers, 
                                                        useauthoritykeyidentifier, 
                                                        authoritykeyidentifiercritical,
                                                        usecrlnumber, 
                                                        crlnumbercritical, 
                                                        finishuser);
                 try{
                   cadatahandler.createCA((CAInfo) x509cainfo);
                 }catch(CAExistsException caee){
                    caexists = true; 
                 }
               }
               if(request.getParameter(BUTTON_MAKEREQUEST) != null){
                 X509CAInfo x509cainfo = new X509CAInfo(subjectdn, caname, 0, subjectaltname,
                                                        certprofileid, validity,
                                                        null, catype, CAInfo.SIGNEDBYEXTERNALCA,
                                                        null, catoken, description, -1, 
                                                        policyid, crlperiod, crlpublishers, 
                                                        useauthoritykeyidentifier, 
                                                        authoritykeyidentifiercritical,
                                                        usecrlnumber, 
                                                        crlnumbercritical, 
                                                        finishuser);
                 try{
                   cadatahandler.createCA((CAInfo) x509cainfo);
                 }catch(CAExistsException caee){
                    caexists = true; 
                 }
               }
             }                          
           } 
         } 
       } 
       if(request.getParameter(BUTTON_CANCEL) != null){
         // Don't save changes.
       }               

         includefile="choosecapage.jsp"; 
      }
    if( request.getParameter(ACTION).equals(ACTION_EDIT_CA)){
      if( request.getParameter(BUTTON_SAVE)  != null || 
          request.getParameter(BUTTON_RECEIVEREQUEST)  != null || 
          request.getParameter(BUTTON_RENEWCA)  != null ||
          request.getParameter(BUTTON_REVOKECA)  != null){
         // Create and save CA                          
         caid = Integer.parseInt(request.getParameter(HIDDEN_CAID));
         catype = Integer.parseInt(request.getParameter(HIDDEN_CATYPE));
         
         CATokenInfo catoken = null;
         catokentype = Integer.parseInt(request.getParameter(HIDDEN_CATOKENTYPE));
         if(catokentype == CATokenInfo.CATOKENTYPE_P12){
           catoken = new SoftCATokenInfo();          
         } 
         if(catokentype == CATokenInfo.CATOKENTYPE_HSM){
           // TODO IMPLEMENT HSM FUNCTIONALITY
         }

          
         String description = request.getParameter(TEXTFIELD_DESCRIPTION);        

         int validity = Integer.parseInt(request.getParameter(TEXTFIELD_VALIDITY));
            

         if(caid != 0 && description != null && catype !=0 && validity != 0){
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
              
             if(crlperiod != 0){
               X509CAInfo x509cainfo = new X509CAInfo(caid, validity,
                                                      catoken, description, 
                                                      crlperiod, crlpublishers, 
                                                      useauthoritykeyidentifier, 
                                                      authoritykeyidentifiercritical,
                                                      usecrlnumber, 
                                                      crlnumbercritical, 
                                                      finishuser);
                 
               cadatahandler.editCA((CAInfo) x509cainfo);
                 


               if(request.getParameter(BUTTON_SAVE) != null){
                  // Do nothing More
                  includefile="choosecapage.jsp"; 
               }
               if(request.getParameter(BUTTON_RECEIVEREQUEST) != null){
                 // TODO 
               }
               if(request.getParameter(BUTTON_RENEWCA) != null){
                 // TODO 
               }
               if(request.getParameter(BUTTON_REVOKECA) != null){
                 // TODO
               }
             }                          
           } 
         } 
       } 
       if(request.getParameter(BUTTON_CANCEL) != null){
         // Don't save changes.
         includefile="choosecapage.jsp"; 
       }               

         
      }

      if( request.getParameter(ACTION).equals(ACTION_RECEIVERESPONSE)){
        // TODO Implement
      }
      if( request.getParameter(ACTION).equals(ACTION_PROCESSREQUEST)){
        // TODO Implement
      }
      if( request.getParameter(ACTION).equals(ACTION_RENEWCA)){
        // TODO Implement
      }
      if( request.getParameter(ACTION).equals(ACTION_CHOOSE_CATYPE)){
        // Currently not need        
      }
      if( request.getParameter(ACTION).equals(ACTION_CHOOSE_CATOKENTYPE)){
        // TODO Implement
        catokentype = Integer.parseInt(request.getParameter(SELECT_CATOKEN));   
        editca = false;
        includefile="editcapage.jsp";              
      }

    }   


 // Include page
  if( includefile.equals("editcapage.jsp")){ 
%>
   <%@ include file="editcapage.jsp" %>
<%}
  if( includefile.equals("choosecapage.jsp")){ %>
   <%@ include file="choosecapage.jsp" %> 
<%}

   // Include Footer 
   String footurl =   globalconfiguration.getFootBanner(); %>
   
  <jsp:include page="<%= footurl %>" />

</body>
</html>

