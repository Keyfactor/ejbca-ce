<html>
<%@page contentType="text/html"%>
<%@page errorPage="/errorpage.jsp" import="java.util.ArrayList, se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean,se.anatom.ejbca.ra.GlobalConfiguration, se.anatom.ejbca.SecConst
               ,se.anatom.ejbca.webdist.cainterface.CAInterfaceBean, se.anatom.ejbca.ca.store.certificateprofiles.CertificateProfile, se.anatom.ejbca.webdist.cainterface.CertificateProfileDataHandler, se.anatom.ejbca.webdist.cainterface.CertificateProfileExistsException"%>

<jsp:useBean id="ejbcawebbean" scope="session" class="se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean" />
<jsp:setProperty name="ejbcawebbean" property="*" /> 
<jsp:useBean id="cabean" scope="session" class="se.anatom.ejbca.webdist.cainterface.CAInterfaceBean" />

<%! // Declarations 
  static final String ACTION                              = "action";
  static final String ACTION_EDIT_CERTIFICATEPROFILES     = "editcertificateprofiles";
  static final String ACTION_EDIT_CERTIFICATEPROFILE      = "editcertificateprofile";

  static final String CHECKBOX_VALUE           = CertificateProfile.TRUE;

//  Used in profiles.jsp
  static final String BUTTON_EDIT_CERTIFICATEPROFILES      = "buttoneditcertificateprofile"; 
  static final String BUTTON_DELETE_CERTIFICATEPROFILES    = "buttondeletecertificateprofile";
  static final String BUTTON_ADD_CERTIFICATEPROFILES       = "buttonaddcertificateprofile"; 
  static final String BUTTON_RENAME_CERTIFICATEPROFILES    = "buttonrenamecertificateprofile";
  static final String BUTTON_CLONE_CERTIFICATEPROFILES     = "buttonclonecertificateprofile";

  static final String SELECT_CERTIFICATEPROFILES           = "selectcertificateprofile";
  static final String TEXTFIELD_CERTIFICATEPROFILESNAME    = "textfieldcertificateprofilename";
  static final String HIDDEN_CERTIFICATEPROFILENAME        = "hiddencertificateprofilename";
 
// Buttons used in profile.jsp
  static final String BUTTON_SAVE              = "buttonsave";
  static final String BUTTON_CANCEL            = "buttoncancel";
 
  static final String TEXTFIELD_VALIDITY            = "textfieldvalidity";
  static final String TEXTFIELD_CRLDISTURI          = "textfieldcrldisturi";
  static final String TEXTFIELD_CERTIFICATEPOLICYID = "textfieldcertificatepolicyid";

  static final String CHECKBOX_BASICCONSTRAINTS                   = "checkboxbasicconstraints";
  static final String CHECKBOX_BASICCONSTRAINTSCRITICAL           = "checkboxbasicconstraintscritical";
  static final String CHECKBOX_KEYUSAGE                           = "checkboxkeyusage";
  static final String CHECKBOX_KEYUSAGECRITICAL                   = "checkboxkeyusagecritical";
  static final String CHECKBOX_SUBJECTKEYIDENTIFIER               = "checkboxsubjectkeyidentifier";
  static final String CHECKBOX_SUBJECTKEYIDENTIFIERCRITICAL       = "checkboxsubjectkeyidentifiercritical";
  static final String CHECKBOX_AUTHORITYKEYIDENTIFIER             = "checkboxauthoritykeyidentifier";
  static final String CHECKBOX_AUTHORITYKEYIDENTIFIERCRITICAL     = "checkboxauthoritykeyidentifiercritical";
  static final String CHECKBOX_SUBJECTALTERNATIVENAME             = "checkboxsubjectalternativename";
  static final String CHECKBOX_SUBJECTALTERNATIVENAMECRITICAL     = "checkboxsubjectalternativenamecritical";
  static final String CHECKBOX_CRLDISTRIBUTIONPOINT               = "checkboxcrldistributionpoint";
  static final String CHECKBOX_CRLDISTRIBUTIONPOINTCRITICAL       = "checkboxcrldistributionpointcritical";
  static final String CHECKBOX_USECERTIFICATEPOLICIES             = "checkusecertificatepolicies";
  static final String CHECKBOX_CERTIFICATEPOLICIESCRITICAL        = "checkcertificatepoliciescritical";
  static final String CHECKBOX_ALLOWKEYUSAGEOVERRIDE              = "checkallowkeyusageoverride";
  static final String CHECKBOX_USEEXTENDEDKEYUSAGE                = "checkuseextendedkeyusage";
  static final String CHECKBOX_EXTENDEDKEYUSAGECRITICAL           = "checkboxextendedkeyusagecritical";

  static final String SELECT_AVAILABLEBITLENGTHS                  = "selectavailablebitlengths";
  static final String SELECT_KEYUSAGE                             = "selectkeyusage";
  static final String SELECT_EXTENDEDKEYUSAGE                     = "selectextendedkeyusage";
  static final String SELECT_TYPE                                 = "selecttype";


  // Declare Language file.

%>
<% 

  // Initialize environment
  String certprofile = null;
  String includefile = "certificateprofilespage.jsp"; 
  boolean  triedtoeditfixedcertificateprofile   = false;
  boolean  triedtodeletefixedcertificateprofile = false;
  boolean  triedtoaddfixedcertificateprofile    = false;
  boolean  certificateprofileexists             = false;
  boolean  certificateprofiledeletefailed       = false;

  GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, "/ca_functionallity/edit_certificate_profiles"); 
                                            cabean.initialize(request); 

  String THIS_FILENAME            =  globalconfiguration.getCaPath()  + "/editcertificateprofiles/editcertificateprofiles.jsp";

     
  String[] keyusagetexts = {"DIGITALSIGNATURE","NONREPUDATION", "KEYENCIPHERMENT", "DATAENCIPHERMENT", "KEYAGREEMENT", "KEYCERTSIGN", "CRLSIGN", "ENCIPHERONLY", "DECIPHERONLY" };
  String[] extendedkeyusagetexts = {"ANYEXTENDEDKEYUSAGE","SERVERAUTH", "CLIENTAUTH", 
                                    "CODESIGNING", "EMAILPROTECTION", "IPSECENDSYSTEM", 
                                    "IPSECTUNNEL", "IPSECUSER", "TIMESTAMPING" };
int[]    defaultavailablebitlengths = {512,1024,2048,4096};  
%>
 
<head>
  <title><%= globalconfiguration .getEjbcaTitle() %></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>">
  <link rel=STYLESHEET href="<%= ejbcawebbean.getCssFile() %>">
  <script language=javascript src="<%= globalconfiguration .getAdminWebPath() %>ejbcajslib.js"></script>
</head>
<body>

<%  // Determine action 
  if( request.getParameter(ACTION) != null){
    if( request.getParameter(ACTION).equals(ACTION_EDIT_CERTIFICATEPROFILES)){
      if( request.getParameter(BUTTON_EDIT_CERTIFICATEPROFILES) != null){
          // Display  profilepage.jsp
         certprofile = request.getParameter(SELECT_CERTIFICATEPROFILES);
         if(certprofile != null){
           if(!certprofile.trim().equals("")){
             if(!certprofile.endsWith("(FIXED)")){ 
               includefile="certificateprofilepage.jsp"; 
             }else{
                triedtoeditfixedcertificateprofile=true;
                certprofile= null;
             }
           } 
           else{ 
            certprofile= null;
          } 
        }
        if(certprofile == null){   
          includefile="certificateprofilespage.jsp";     
        }
      }
      if( request.getParameter(BUTTON_DELETE_CERTIFICATEPROFILES) != null) {
          // Delete profile and display profilespage. 
          certprofile = request.getParameter(SELECT_CERTIFICATEPROFILES);
          if(certprofile != null){
            if(!certprofile.trim().equals("")){
              if(!certprofile.endsWith("(FIXED)")){ 
                certificateprofiledeletefailed = !cabean.removeCertificateProfile(certprofile);
              }else{
                triedtodeletefixedcertificateprofile=true;
              }
            }
          }
          includefile="certificateprofilespage.jsp";             
      }
      if( request.getParameter(BUTTON_RENAME_CERTIFICATEPROFILES) != null){ 
         // Rename selected profile and display profilespage.
       String newcertificateprofilename = request.getParameter(TEXTFIELD_CERTIFICATEPROFILESNAME);
       String oldcertificateprofilename = request.getParameter(SELECT_CERTIFICATEPROFILES);
       if(oldcertificateprofilename != null && newcertificateprofilename != null){
         if(!newcertificateprofilename.trim().equals("") && !oldcertificateprofilename.trim().equals("")){
           if(!oldcertificateprofilename.endsWith("(FIXED)")){ 
             try{
               cabean.renameCertificateProfile(oldcertificateprofilename.trim(),newcertificateprofilename.trim());
             }catch( CertificateProfileExistsException e){
               certificateprofileexists=true;
             }
           }else{
              triedtoeditfixedcertificateprofile=true;
           }        
         }
       }      
       includefile="certificateprofilespage.jsp"; 
      }
      if( request.getParameter(BUTTON_ADD_CERTIFICATEPROFILES) != null){
         // Add profile and display profilespage.
         certprofile = request.getParameter(TEXTFIELD_CERTIFICATEPROFILESNAME);
         if(certprofile != null){
           if(!certprofile.trim().equals("")){
             if(!certprofile.endsWith("(FIXED)")){
               try{
                 cabean.addCertificateProfile(certprofile.trim());
               }catch( CertificateProfileExistsException e){
                 certificateprofileexists=true;
               }
             }else{
               triedtoaddfixedcertificateprofile=true; 
             }
           }      
         }
         includefile="certificateprofilespage.jsp"; 
      }
      if( request.getParameter(BUTTON_CLONE_CERTIFICATEPROFILES) != null){
         // clone profile and display profilespage.
       String newcertificateprofilename = request.getParameter(TEXTFIELD_CERTIFICATEPROFILESNAME);
       String oldcertificateprofilename = request.getParameter(SELECT_CERTIFICATEPROFILES);
       if(oldcertificateprofilename != null && newcertificateprofilename != null){
         if(!newcertificateprofilename.trim().equals("") && !oldcertificateprofilename.trim().equals("")){
             if(oldcertificateprofilename.endsWith("(FIXED)"))
               oldcertificateprofilename = oldcertificateprofilename.substring(0,oldcertificateprofilename.length()-8);
             try{ 
               cabean.cloneCertificateProfile(oldcertificateprofilename.trim(),newcertificateprofilename.trim());
             }catch( CertificateProfileExistsException e){
               certificateprofileexists=true;
             }
         }
       }      
          includefile="certificateprofilespage.jsp"; 
      }
    }
    if( request.getParameter(ACTION).equals(ACTION_EDIT_CERTIFICATEPROFILE)){
         // Display edit access rules page.
       certprofile = request.getParameter(HIDDEN_CERTIFICATEPROFILENAME);
       if(certprofile != null){
         if(!certprofile.trim().equals("")){
           if(request.getParameter(BUTTON_SAVE) != null){
             CertificateProfile certificateprofiledata = cabean.getCertificateProfile(certprofile);
             // Save changes.
       
             String value = request.getParameter(TEXTFIELD_VALIDITY);
             if(value != null){
               value=value.trim();
               if(!value.equals(""))
                 certificateprofiledata.setValidity(Long.parseLong(value));
             }
  

             boolean use = false;
             value = request.getParameter(CHECKBOX_BASICCONSTRAINTS);
             if(value != null){
                 use = value.equals(CHECKBOX_VALUE);
                 certificateprofiledata.setUseBasicConstraints(use);
                 value = request.getParameter(CHECKBOX_BASICCONSTRAINTSCRITICAL); 
                 if(value != null){
                   certificateprofiledata.setBasicConstraintsCritical(value.equals(CHECKBOX_VALUE));
                 } 
                 else
                   certificateprofiledata.setBasicConstraintsCritical(false);
             }
             else{
                 certificateprofiledata.setUseBasicConstraints(false);
                 certificateprofiledata.setBasicConstraintsCritical(false); 
             }      
       
             use = false;
             value = request.getParameter(CHECKBOX_KEYUSAGE);
             if(value != null){
                 use = value.equals(CHECKBOX_VALUE);
                 certificateprofiledata.setUseKeyUsage(use);
                 value = request.getParameter(CHECKBOX_KEYUSAGECRITICAL); 
                 if(value != null)
                   certificateprofiledata.setKeyUsageCritical(value.equals(CHECKBOX_VALUE)); 
                 else
                   certificateprofiledata.setKeyUsageCritical(false); 
             }  
             else{
                 certificateprofiledata.setUseKeyUsage(false);
                 certificateprofiledata.setKeyUsageCritical(false); 
             }
    
             use = false;
             value = request.getParameter(CHECKBOX_SUBJECTKEYIDENTIFIER);
             if(value != null){
                 use = value.equals(CHECKBOX_VALUE);
                 certificateprofiledata.setUseSubjectKeyIdentifier(use);
                 value = request.getParameter(CHECKBOX_SUBJECTKEYIDENTIFIERCRITICAL); 
                 if(value != null)
                   certificateprofiledata.setSubjectKeyIdentifierCritical(value.equals(CHECKBOX_VALUE)); 
                 else
                   certificateprofiledata.setSubjectKeyIdentifierCritical(false); 
             }
             else{
                 certificateprofiledata.setUseSubjectKeyIdentifier(false);
                 certificateprofiledata.setSubjectKeyIdentifierCritical(false); 
             }

             use = false;
             value = request.getParameter(CHECKBOX_AUTHORITYKEYIDENTIFIER);
             if(value != null){
                 use = value.equals(CHECKBOX_VALUE);
                 certificateprofiledata.setUseAuthorityKeyIdentifier(use);
                 value = request.getParameter(CHECKBOX_AUTHORITYKEYIDENTIFIERCRITICAL); 
                 if(value != null)
                   certificateprofiledata.setAuthorityKeyIdentifierCritical(value.equals(CHECKBOX_VALUE)); 
                 else
                   certificateprofiledata.setAuthorityKeyIdentifierCritical(false); 
             }
             else{
                 certificateprofiledata.setUseAuthorityKeyIdentifier(false);
                 certificateprofiledata.setAuthorityKeyIdentifierCritical(false); 
             }

             use = false;
             value = request.getParameter(CHECKBOX_SUBJECTALTERNATIVENAME);
             if(value != null){
                 use = value.equals(CHECKBOX_VALUE);
                 certificateprofiledata.setUseSubjectAlternativeName(use);
                 value = request.getParameter(CHECKBOX_SUBJECTALTERNATIVENAMECRITICAL); 
                 if(value != null)
                   certificateprofiledata.setSubjectAlternativeNameCritical(value.equals(CHECKBOX_VALUE)); 
                 else
                   certificateprofiledata.setSubjectAlternativeNameCritical(false); 
             }
             else{
                 certificateprofiledata.setUseSubjectAlternativeName(false);
                 certificateprofiledata.setSubjectAlternativeNameCritical(false); 
             }

             use = false;
             value = request.getParameter(CHECKBOX_CRLDISTRIBUTIONPOINT);
             if(value != null){
                 use = value.equals(CHECKBOX_VALUE);
                 certificateprofiledata.setUseCRLDistributionPoint(use);
                 value = request.getParameter(CHECKBOX_CRLDISTRIBUTIONPOINTCRITICAL); 
                 if(value != null)
                   certificateprofiledata.setCRLDistributionPointCritical(value.equals(CHECKBOX_VALUE)); 
                 else
                   certificateprofiledata.setCRLDistributionPointCritical(false); 

                 value = request.getParameter(TEXTFIELD_CRLDISTURI);
                 if(value != null){
                   value=value.trim();
                   certificateprofiledata.setCRLDistributionPointURI(value);
                 } 
             }
             else{
                 certificateprofiledata.setUseCRLDistributionPoint(false);
                 certificateprofiledata.setCRLDistributionPointCritical(false); 
                 certificateprofiledata.setCRLDistributionPointURI("");
             } 

             use = false;
             value = request.getParameter(CHECKBOX_USECERTIFICATEPOLICIES);
             if(value != null){
                 use = value.equals(CHECKBOX_VALUE);
                 certificateprofiledata.setUseCertificatePolicies(use);
                 value = request.getParameter(CHECKBOX_CERTIFICATEPOLICIESCRITICAL); 
                 if(value != null)
                   certificateprofiledata.setCertificatePoliciesCritical(value.equals(CHECKBOX_VALUE)); 
                 else
                   certificateprofiledata.setCertificatePoliciesCritical(false); 

                 value = request.getParameter(TEXTFIELD_CERTIFICATEPOLICYID);
                 if(value != null){
                   value=value.trim();
                   certificateprofiledata.setCertificatePolicyId(value);
                 } 
             }
             else{
                 certificateprofiledata.setUseCertificatePolicies(false);
                 certificateprofiledata.setCertificatePoliciesCritical(false); 
                 certificateprofiledata.setCertificatePolicyId("");
             } 

              String[] values = request.getParameterValues(SELECT_AVAILABLEBITLENGTHS); 
              if(values != null){
                int[] abl = new int[values.length];
                for(int i=0; i< values.length;i++){
                  abl[i] = Integer.parseInt(values[i]);
                }
                certificateprofiledata.setAvailableBitLengths(abl);
              }



              values = request.getParameterValues(SELECT_KEYUSAGE);
              boolean[] ku = new boolean[ keyusagetexts.length]; 
              if(values != null){
                 for(int i=0; i < values.length; i++){
                    ku[Integer.parseInt(values[i])] = true;
                 }
              }
              certificateprofiledata.setKeyUsage(ku);      
 
             value = request.getParameter(CHECKBOX_USEEXTENDEDKEYUSAGE);
             if(value != null && value.equals(CHECKBOX_VALUE)){
               certificateprofiledata.setUseExtendedKeyUsage(true); 
               value = request.getParameter(CHECKBOX_EXTENDEDKEYUSAGECRITICAL); 
               if(value != null){
                 certificateprofiledata.setExtendedKeyUsageCritical(value.equals(CHECKBOX_VALUE));
               } 
               values = request.getParameterValues(SELECT_EXTENDEDKEYUSAGE);
               ArrayList eku = new ArrayList(); 
                if(values != null){
                   for(int i=0; i < values.length; i++){
                      eku.add(new Integer(values[i]));
                   }
                }
                certificateprofiledata.setExtendedKeyUsage(eku);    
              }
              else{
                certificateprofiledata.setUseExtendedKeyUsage(false); 
                certificateprofiledata.setExtendedKeyUsageCritical(false); 
                certificateprofiledata.setExtendedKeyUsage(new ArrayList());        
              }

              value = request.getParameter(SELECT_TYPE);
              int type  = CertificateProfile.TYPE_ENDENTITY;
              if(value != null){
                type = Integer.parseInt(value);
              }
              certificateprofiledata.setType(type);    
              
              value = request.getParameter(CHECKBOX_ALLOWKEYUSAGEOVERRIDE);
              if(value != null){
                 use = value.equals(CHECKBOX_VALUE);
                 certificateprofiledata.setAllowKeyUsageOverride(use);
              }
              else
                 certificateprofiledata.setAllowKeyUsageOverride(false);

              cabean.changeCertificateProfile(certprofile,certificateprofiledata);
           }
           if(request.getParameter(BUTTON_CANCEL) != null){
              // Don't save changes.
           }
             includefile="certificateprofilespage.jsp";
         }
      }
    }
  }

 // Include page
  if( includefile.equals("certificateprofilepage.jsp")){ 
%>
   <%@ include file="certificateprofilepage.jsp" %>
<%}
  if( includefile.equals("certificateprofilespage.jsp")){ %>
   <%@ include file="certificateprofilespage.jsp" %> 
<%}

   // Include Footer 
   String footurl =   globalconfiguration.getFootBanner(); %>
   
  <jsp:include page="<%= footurl %>" />

</body>
</html>
