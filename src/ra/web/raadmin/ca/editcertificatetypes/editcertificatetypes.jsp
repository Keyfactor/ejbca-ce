<html>
<%@page contentType="text/html"%>
<%@page errorPage="/errorpage.jsp" import="se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean,se.anatom.ejbca.ra.GlobalConfiguration
               ,se.anatom.ejbca.webdist.cainterface.CAInterfaceBean, se.anatom.ejbca.ca.store.certificatetypes.CertificateType, se.anatom.ejbca.webdist.cainterface.CertificateTypeDataHandler, se.anatom.ejbca.webdist.cainterface.CertificateTypeExistsException"%>

<jsp:useBean id="ejbcawebbean" scope="session" class="se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean" />
<jsp:setProperty name="ejbcawebbean" property="*" /> 
<jsp:useBean id="cabean" scope="session" class="se.anatom.ejbca.webdist.cainterface.CAInterfaceBean" />

<%! // Declarations 
  static final String ACTION                           = "action";
  static final String ACTION_EDIT_CERTIFICATETYPES     = "editcertificatetypes";
  static final String ACTION_EDIT_CERTIFICATETYPE      = "editcertificatetype";

  static final String CHECKBOX_VALUE           = CertificateType.TRUE;

//  Used in profiles.jsp
  static final String BUTTON_EDIT_CERTIFICATETYPE      = "buttoneditcertificatetype"; 
  static final String BUTTON_DELETE_CERTIFICATETYPE    = "buttondeletecertificatetype";
  static final String BUTTON_ADD_CERTIFICATETYPE       = "buttonaddcertificatetype"; 
  static final String BUTTON_RENAME_CERTIFICATETYPE    = "buttonrenamecertificatetype";
  static final String BUTTON_CLONE_CERTIFICATETYPE     = "buttonclonecertificatetype";

  static final String SELECT_CERTIFICATETYPE           = "selectcertificatetype";
  static final String TEXTFIELD_CERTIFICATETYPENAME    = "textfieldcertificatetypename";
  static final String HIDDEN_CERTIFICATETYPENAME       = "hiddencertificatetypename";
 
// Buttons used in profile.jsp
  static final String BUTTON_SAVE              = "buttonsave";
  static final String BUTTON_CANCEL            = "buttoncancel";
 
  static final String TEXTFIELD_VALIDITY         = "textfieldvalidity";
  static final String TEXTFIELD_CRLPERIOD        = "textfieldcrlperiod";
  static final String TEXTFIELD_CRLDISTURI       = "textfieldcrldisturi";

  static final String CHECKBOX_BASICCONSTRAINTS                   = "checkboxbasicconstraints";
  static final String CHECKBOX_BASICCONSTRAINTSCRITICAL           = "checkboxbasicconstraintscritical";
  static final String CHECKBOX_KEYUSAGE                           = "checkboxkeyusage";
  static final String CHECKBOX_KEYUSAGECRITICAL                   = "checkboxkeyusagecritical";
  static final String CHECKBOX_SUBJECTKEYIDENTIFIER               = "checkboxsubjectkeyidentifier";
  static final String CHECKBOX_SUBJECTKEYIDENTIFIERCRITICAL       = "checkboxsubjectkeyidentifiercritical";
  static final String CHECKBOX_AUTHORITYKEYIDENTIFIER             = "checkboxauthoritykeyidentifier";
  static final String CHECKBOX_AUTHORITYKEYIDENTIFIERCRITICAL     = "checkboxauthoritykeyidentifiercritical";
  static final String CHECKBOX_CRLNUMBER                          = "checkboxcrlnumber";
  static final String CHECKBOX_CRLNUMBERCRITICAL                  = "checkboxcrlnumbercritical";
  static final String CHECKBOX_SUBJECTALTERNATIVENAME             = "checkboxsubjectalternativename";
  static final String CHECKBOX_SUBJECTALTERNATIVENAMECRITICAL     = "checkboxsubjectalternativenamecritical";
  static final String CHECKBOX_CRLDISTRIBUTIONPOINT               = "checkboxcrldistributionpoint";
  static final String CHECKBOX_CRLDISTRIBUTIONPOINTCRITICAL       = "checkboxcrldistributionpointcritical";
  static final String CHECKBOX_EMAILINDN                          = "checkboxemailindn";
  static final String CHECKBOX_FINISHUSER                         = "checkboxfinishuser";

  static final String SELECT_AVAILABLEBITLENGTHS                  = "selectavailablebitlengths";
  static final String SELECT_KEYUSAGE                             = "selectkeyusage";

  String certificatetype = null;
  // Declare Language file.

%>
<% 

  // Initialize environment
  String includefile = null;
  boolean  triedtoeditfixedcertificatetype   = false;
  boolean  triedtodeletefixedcertificatetype = false;
  boolean  triedtoaddfixedcertificatetype    = false;
  boolean  certificatetypeexists             = false;

  GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request); 

  String THIS_FILENAME            =  globalconfiguration.getCaPath()  + "/editcertificatetypes/editcertificatetypes.jsp";

     
  String[] keyusagetexts = {"DIGITALSIGNATURE","NONREPUDATION", "KEYENCIPHERMENT", "DATAENCIPHERMENT", "KEYAGREEMENT", "KEYCERTSIGN", "CRLSIGN", "ENCIPHERONLY", "DECIPHERONLY" };
int[]    defaultavailablebitlengths = {512,1024,2048,4096};  
%>
 
<head>
  <title><%= globalconfiguration .getEjbcaTitle() %></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>">
  <link rel=STYLESHEET href="<%= ejbcawebbean.getCssFile() %>">
  <script language=javascript src="<%= globalconfiguration .getRaAdminPath() %>ejbcajslib.js"></script>
</head>
<body>

<%  // Determine action 
  if( request.getParameter(ACTION) != null){
    if( request.getParameter(ACTION).equals(ACTION_EDIT_CERTIFICATETYPES)){
      if( request.getParameter(BUTTON_EDIT_CERTIFICATETYPE) != null){
          // Display  profilepage.jsp
         certificatetype = request.getParameter(SELECT_CERTIFICATETYPE);
         if(certificatetype != null){
           if(!certificatetype.trim().equals("")){
             if(!certificatetype.endsWith("(FIXED)")){ 
               includefile="certificatetypepage.jsp"; 
             }else{
                triedtoeditfixedcertificatetype=true;
                certificatetype= null;
             }
           } 
           else{ 
            certificatetype= null;
          } 
        }
        if(certificatetype == null){   
          includefile="certificatetypespage.jsp";     
        }
      }
      if( request.getParameter(BUTTON_DELETE_CERTIFICATETYPE) != null) {
          // Delete profile and display profilespage. 
          certificatetype = request.getParameter(SELECT_CERTIFICATETYPE);
          if(certificatetype != null){
            if(!certificatetype.trim().equals("")){
              if(!certificatetype.endsWith("(FIXED)")){ 
                cabean.removeCertificateType(certificatetype);
              }else{
                triedtodeletefixedcertificatetype=true;
              }
            }
          }
          includefile="certificatetypespage.jsp";             
      }
      if( request.getParameter(BUTTON_RENAME_CERTIFICATETYPE) != null){ 
         // Rename selected profile and display profilespage.
       String newcertificatetypename = request.getParameter(TEXTFIELD_CERTIFICATETYPENAME);
       String oldcertificatetypename = request.getParameter(SELECT_CERTIFICATETYPE);
       if(oldcertificatetypename != null && newcertificatetypename != null){
         if(!newcertificatetypename.trim().equals("") && !oldcertificatetypename.trim().equals("")){
           if(!oldcertificatetypename.endsWith("(FIXED)")){ 
             try{
               cabean.renameCertificateType(oldcertificatetypename.trim(),newcertificatetypename.trim());
             }catch( CertificateTypeExistsException e){
               certificatetypeexists=true;
             }
           }else{
              triedtoeditfixedcertificatetype=true;
           }        
         }
       }      
       includefile="certificatetypespage.jsp"; 
      }
      if( request.getParameter(BUTTON_ADD_CERTIFICATETYPE) != null){
         // Add profile and display profilespage.
         certificatetype = request.getParameter(TEXTFIELD_CERTIFICATETYPENAME);
         if(certificatetype != null){
           if(!certificatetype.trim().equals("")){
             if(!certificatetype.endsWith("(FIXED)")){
               try{
                 cabean.addCertificateType(certificatetype.trim());
               }catch( CertificateTypeExistsException e){
                 certificatetypeexists=true;
               }
             }else{
               triedtoaddfixedcertificatetype=true; 
             }
           }      
         }
         includefile="certificatetypespage.jsp"; 
      }
      if( request.getParameter(BUTTON_CLONE_CERTIFICATETYPE) != null){
         // clone profile and display profilespage.
       String newcertificatetypename = request.getParameter(TEXTFIELD_CERTIFICATETYPENAME);
       String oldcertificatetypename = request.getParameter(SELECT_CERTIFICATETYPE);
       if(oldcertificatetypename != null && newcertificatetypename != null){
         if(!newcertificatetypename.trim().equals("") && !oldcertificatetypename.trim().equals("")){
             if(oldcertificatetypename.endsWith("(FIXED)"))
               oldcertificatetypename = oldcertificatetypename.substring(0,oldcertificatetypename.length()-8);
             try{ 
               cabean.cloneCertificateType(oldcertificatetypename.trim(),newcertificatetypename.trim());
             }catch( CertificateTypeExistsException e){
               certificatetypeexists=true;
             }
         }
       }      
          includefile="certificatetypespage.jsp"; 
      }
    }
    if( request.getParameter(ACTION).equals(ACTION_EDIT_CERTIFICATETYPE)){
         // Display edit access rules page.
       certificatetype = request.getParameter(HIDDEN_CERTIFICATETYPENAME);
       if(certificatetype != null){
         if(!certificatetype.trim().equals("")){
           if(request.getParameter(BUTTON_SAVE) != null){
             CertificateType certificatetypedata = cabean.getCertificateType(certificatetype);
             // Save changes.
       
             String value = request.getParameter(TEXTFIELD_VALIDITY);
             if(value != null){
               value=value.trim();
               if(!value.equals(""))
                 certificatetypedata.setValidity(Long.parseLong(value));
             }
 
             value = request.getParameter(TEXTFIELD_CRLPERIOD);
             if(value != null){
               value=value.trim();
               if(!value.equals(""))
                 certificatetypedata.setCRLPeriod(Long.parseLong(value));
             } 

             boolean use = false;
             value = request.getParameter(CHECKBOX_BASICCONSTRAINTS);
             if(value != null){
                 use = value.equals(CHECKBOX_VALUE);
                 certificatetypedata.setUseBasicConstraints(use);
                 value = request.getParameter(CHECKBOX_BASICCONSTRAINTSCRITICAL); 
                 if(value != null){
                   certificatetypedata.setBasicConstraintsCritical(value.equals(CHECKBOX_VALUE));
                 } 
                 else
                   certificatetypedata.setBasicConstraintsCritical(false);
             }
             else{
                 certificatetypedata.setUseBasicConstraints(false);
                 certificatetypedata.setBasicConstraintsCritical(false); 
             }      
       
             use = false;
             value = request.getParameter(CHECKBOX_KEYUSAGE);
             if(value != null){
                 use = value.equals(CHECKBOX_VALUE);
                 certificatetypedata.setUseKeyUsage(use);
                 value = request.getParameter(CHECKBOX_KEYUSAGECRITICAL); 
                 if(value != null)
                   certificatetypedata.setKeyUsageCritical(value.equals(CHECKBOX_VALUE)); 
                 else
                   certificatetypedata.setKeyUsageCritical(false); 
             }  
             else{
                 certificatetypedata.setUseKeyUsage(false);
                 certificatetypedata.setKeyUsageCritical(false); 
             }
    
             use = false;
             value = request.getParameter(CHECKBOX_SUBJECTKEYIDENTIFIER);
             if(value != null){
                 use = value.equals(CHECKBOX_VALUE);
                 certificatetypedata.setUseSubjectKeyIdentifier(use);
                 value = request.getParameter(CHECKBOX_SUBJECTKEYIDENTIFIERCRITICAL); 
                 if(value != null)
                   certificatetypedata.setSubjectKeyIdentifierCritical(value.equals(CHECKBOX_VALUE)); 
                 else
                   certificatetypedata.setSubjectKeyIdentifierCritical(false); 
             }
             else{
                 certificatetypedata.setUseSubjectKeyIdentifier(false);
                 certificatetypedata.setSubjectKeyIdentifierCritical(false); 
             }

             use = false;
             value = request.getParameter(CHECKBOX_AUTHORITYKEYIDENTIFIER);
             if(value != null){
                 use = value.equals(CHECKBOX_VALUE);
                 certificatetypedata.setUseAuthorityKeyIdentifier(use);
                 value = request.getParameter(CHECKBOX_AUTHORITYKEYIDENTIFIERCRITICAL); 
                 if(value != null)
                   certificatetypedata.setAuthorityKeyIdentifierCritical(value.equals(CHECKBOX_VALUE)); 
                 else
                   certificatetypedata.setAuthorityKeyIdentifierCritical(false); 
             }
             else{
                 certificatetypedata.setUseAuthorityKeyIdentifier(false);
                 certificatetypedata.setAuthorityKeyIdentifierCritical(false); 
             }

             use = false;
             value = request.getParameter(CHECKBOX_CRLNUMBER);
             if(value != null){
                 use = value.equals(CHECKBOX_VALUE);
                 certificatetypedata.setUseCRLNumber(use);
                 value = request.getParameter(CHECKBOX_CRLNUMBERCRITICAL); 
                 if(value != null)
                   certificatetypedata.setCRLNumberCritical(value.equals(CHECKBOX_VALUE)); 
                 else
                   certificatetypedata.setCRLNumberCritical(false); 
             }
             else{
                 certificatetypedata.setUseCRLNumber(false);
                 certificatetypedata.setCRLNumberCritical(false); 
             }

             use = false;
             value = request.getParameter(CHECKBOX_SUBJECTALTERNATIVENAME);
             if(value != null){
                 use = value.equals(CHECKBOX_VALUE);
                 certificatetypedata.setUseSubjectAlternativeName(use);
                 value = request.getParameter(CHECKBOX_SUBJECTALTERNATIVENAMECRITICAL); 
                 if(value != null)
                   certificatetypedata.setSubjectAlternativeNameCritical(value.equals(CHECKBOX_VALUE)); 
                 else
                   certificatetypedata.setSubjectAlternativeNameCritical(false); 
             }
             else{
                 certificatetypedata.setUseSubjectAlternativeName(false);
                 certificatetypedata.setSubjectAlternativeNameCritical(false); 
             }

             use = false;
             value = request.getParameter(CHECKBOX_CRLDISTRIBUTIONPOINT);
             if(value != null){
                 use = value.equals(CHECKBOX_VALUE);
                 certificatetypedata.setUseCRLDistributionPoint(use);
                 value = request.getParameter(CHECKBOX_CRLDISTRIBUTIONPOINTCRITICAL); 
                 if(value != null)
                   certificatetypedata.setCRLDistributionPointCritical(value.equals(CHECKBOX_VALUE)); 
                 else
                   certificatetypedata.setCRLDistributionPointCritical(false); 

                 value = request.getParameter(TEXTFIELD_CRLDISTURI);
                 if(value != null){
                   value=value.trim();
                   certificatetypedata.setCRLDistributionPointURI(value);
                 } 
             }
             else{
                 certificatetypedata.setUseCRLDistributionPoint(false);
                 certificatetypedata.setCRLDistributionPointCritical(false); 
                 certificatetypedata.setCRLDistributionPointURI("");
             } 


             value = request.getParameter(CHECKBOX_EMAILINDN);
             if(value != null){
                 use = value.equals(CHECKBOX_VALUE);
                 certificatetypedata.setEmailInDN(use);
             }
             else{
                 certificatetypedata.setEmailInDN(false);
             }

             value = request.getParameter(CHECKBOX_FINISHUSER);
             if(value != null){
                 use = value.equals(CHECKBOX_VALUE);
                 certificatetypedata.setFinishUser(use);
             } 
             else{
                 certificatetypedata.setFinishUser(false);
             }
              String[] values = request.getParameterValues(SELECT_AVAILABLEBITLENGTHS); 
              if(values != null){
                int[] abl = new int[values.length];
                for(int i=0; i< values.length;i++){
                  abl[i] = Integer.parseInt(values[i]);
                }
                certificatetypedata.setAvailableBitLengths(abl);
              }



              values = request.getParameterValues(SELECT_KEYUSAGE);
              boolean[] ku = new boolean[ keyusagetexts.length]; 
              if(values != null){
                 for(int i=0; i < values.length; i++){
                    ku[Integer.parseInt(values[i])] = true;
                 }
              }
              certificatetypedata.setKeyUsage(ku);             
              

              cabean.changeCertificateType(certificatetype,certificatetypedata);
           }
           if(request.getParameter(BUTTON_CANCEL) != null){
              // Don't save changes.
           }
             includefile="certificatetypespage.jsp";
         }
      }
    }
  }
  else{ 
    // Display main user group editing page. 
          includefile="certificatetypespage.jsp"; 

  }
 // Include page
  if( includefile.equals("certificatetypepage.jsp")){ %>
   <%@ include file="certificatetypepage.jsp" %>
<%}
  if( includefile.equals("certificatetypespage.jsp")){ %>
   <%@ include file="certificatetypespage.jsp" %> 
<%}

   // Include Footer 
   String footurl =   globalconfiguration.getFootBanner(); %>
   
  <jsp:include page="<%= footurl %>" />

</body>
</html>
