<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ page pageEncoding="ISO-8859-1"%>
<% response.setContentType("text/html; charset="+org.ejbca.config.WebConfiguration.getWebContentEncoding()); %>
<%@page errorPage="/errorpage.jsp" import="java.util.*, org.ejbca.ui.web.admin.configuration.EjbcaWebBean,org.ejbca.config.GlobalConfiguration, org.ejbca.core.model.SecConst, org.cesecore.authorization.AuthorizationDeniedException,
    org.ejbca.ui.web.RequestHelper,org.ejbca.ui.web.admin.cainterface.CAInterfaceBean, org.cesecore.certificates.certificateprofile.CertificateProfile, org.ejbca.ui.web.admin.cainterface.CertificateProfileDataHandler, 
               org.cesecore.certificates.certificateprofile.CertificateProfileExistsException, org.cesecore.certificates.certificateprofile.CertificateProfileConstants, org.ejbca.ui.web.CertificateView, org.cesecore.certificates.util.DNFieldExtractor, org.cesecore.certificates.util.DnComponents, 
               org.cesecore.certificates.certificate.certextensions.CertificateExtensionFactory, org.cesecore.certificates.certificate.certextensions.AvailableCertificateExtension, org.cesecore.certificates.certificateprofile.CertificatePolicy,
               org.cesecore.certificates.ca.CAInfo, org.cesecore.util.ValidityDate, org.ejbca.ui.web.ParameterException, org.cesecore.certificates.util.AlgorithmConstants,
               org.cesecore.certificates.certificate.CertificateConstants, org.ejbca.core.model.authorization.AccessRulesConstants"%>
<%@page import="org.cesecore.util.YearMonthDayTime"%>
<html>
<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />
<jsp:useBean id="cabean" scope="session" class="org.ejbca.ui.web.admin.cainterface.CAInterfaceBean" />

<%! // Declarations 
  static final String ACTION                              = "action";
  static final String ACTION_EDIT_CERTIFICATEPROFILES     = "editcertificateprofiles";
  static final String ACTION_EDIT_CERTIFICATEPROFILE      = "editcertificateprofile";

  static final String INHERITFROMCA = "inheritfromca";

  static final String CHECKBOX_VALUE           = CertificateProfile.TRUE;

//  Used in profiles.jsp
  static final String BUTTON_EDIT_CERTIFICATEPROFILES      = "buttoneditcertificateprofile"; 
  static final String BUTTON_DELETE_CERTIFICATEPROFILES    = "buttondeletecertificateprofile";
  static final String BUTTON_ADD_CERTIFICATEPROFILES       = "buttonaddcertificateprofile"; 
  static final String BUTTON_RENAME_CERTIFICATEPROFILES    = "buttonrenamecertificateprofile";
  static final String BUTTON_CLONE_CERTIFICATEPROFILES     = "buttonclonecertificateprofile";

  static final String BUTTON_ADD_POLICY                    = "buttonaddpolicy";
  static final String BUTTON_DELETE_POLICY                 = "buttondeletepolicy";
  static final String BUTTON_ADD_CAISSUERURI               = "buttonaddcaissueruri";
  static final String BUTTON_DELETE_CAISSUERURI            = "buttondeletecaissueruri";

  static final String SELECT_CERTIFICATEPROFILES           = "selectcertificateprofile";
  static final String TEXTFIELD_CERTIFICATEPROFILESNAME    = "textfieldcertificateprofilename";
  static final String HIDDEN_CERTIFICATEPROFILENAME        = "hiddencertificateprofilename";
 
// Buttons used in profile.jsp
  static final String BUTTON_SAVE              = "buttonsave";
  static final String BUTTON_CANCEL            = "buttoncancel";
 
  static final String TEXTFIELD_VALIDITY               = "textfieldvalidity";
  static final String TEXTFIELD_CRLDISTURI             = "textfieldcrldisturi";
  static final String TEXTFIELD_CRLISSUER              = "textfieldcrlissuer";
  static final String TEXTFIELD_FRESHESTCRLURI         = "textfieldfreshestcrluri";

  static final String TEXTFIELD_CERTIFICATEPOLICYID    = "textfieldcertificatepolicyid";
  static final String TEXTFIELD_POLICYNOTICE_CPSURL    = "textfielpolicynoticedcpsurl";
  static final String TEXTAREA_POLICYNOTICE_UNOTICE    = "textareapolicynoticeunotice";

  static final String TEXTFIELD_CAISSUERURI            = "textfieldcaissueruri";
  static final String TEXTFIELD_OCSPSERVICELOCATOR     = "textfieldocspservicelocatoruri";
  static final String TEXTFIELD_CNPOSTFIX              = "textfieldcnpostfix";
  static final String TEXTFIELD_PATHLENGTHCONSTRAINT   = "textfieldpathlengthconstraint";
  static final String TEXTFIELD_QCSSEMANTICSID         = "textfieldqcsemanticsid";
  static final String TEXTFIELD_QCSTATEMENTRANAME      = "textfieldqcstatementraname";
  static final String TEXTFIELD_QCETSIVALUELIMIT       = "textfieldqcetsivaluelimit";
  static final String TEXTFIELD_QCETSIRETENTIONPERIOD  = "textfieldqcetsiretentionperiod";
  static final String TEXTFIELD_QCETSIVALUELIMITEXP    = "textfieldqcetsivaluelimitexp";
  static final String TEXTFIELD_QCETSIVALUELIMITCUR    = "textfieldqcetsivaluelimitcur";
  static final String TEXTFIELD_QCCUSTOMSTRINGOID      = "textfieldqccustomstringoid";
  static final String TEXTFIELD_QCCUSTOMSTRINGTEXT     = "textfieldqccustomstringtext";
  static final String TEXTFIELD_PRIVKEYUSAGEPERIODSTARTOFFSET     = "textfieldprivkeyusageperiodstartoffset";
  static final String TEXTFIELD_PRIVKEYUSAGEPERIODLENGTH          = "textfieldprivkeyusageperiodlength";
  
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
  static final String CHECKBOX_SUBJECTDIRATTRIBUTES               = "checksubjectdirattributes";
  static final String CHECKBOX_CRLDISTRIBUTIONPOINT               = "checkboxcrldistributionpoint";
  static final String CHECKBOX_USEDEFAULTCRLDISTRIBUTIONPOINT     = "checkboxusedefaultcrldistributionpoint";
  static final String CHECKBOX_CRLDISTRIBUTIONPOINTCRITICAL       = "checkboxcrldistributionpointcritical";
  static final String CHECKBOX_USECERTIFICATEPOLICIES             = "checkusecertificatepolicies";
  static final String CHECKBOX_USEFRESHESTCRL                     = "checkboxusefreshestcrl";
  static final String CHECKBOX_USECADEFINEDFRESHESTCRL            = "checkboxusecadefinedfreshestcrl";
  static final String CHECKBOX_CERTIFICATEPOLICIESCRITICAL        = "checkcertificatepoliciescritical";
  static final String CHECKBOX_ALLOWDNOVERRIDE                    = "checkallowdnoverride";
  static final String CHECKBOX_ALLOWCERTSERIALNUMBEROVERRIDE      = "allowcertserialnumberoverride";
  static final String CHECKBOX_ALLOWEXTENSIONOVERRIDE             = "checkallowextensionoverride";
  static final String CHECKBOX_ALLOWVALIDITYOVERRIDE              = "checkallowvalidityoverride";
  static final String CHECKBOX_ALLOWKEYUSAGEOVERRIDE              = "checkallowkeyusageoverride";
  static final String CHECKBOX_ALLOWBACKDATEDREVOCATION           = "checkallowbackdatedrevokation";
  static final String CHECKBOX_USEEXTENDEDKEYUSAGE                = "checkuseextendedkeyusage";
  static final String CHECKBOX_EXTENDEDKEYUSAGECRITICAL           = "checkboxextendedkeyusagecritical";
  static final String CHECKBOX_USEOCSPNOCHECK                     = "checkuseocspnocheck";
  static final String CHECKBOX_USEAUTHORITYINFORMATIONACCESS      = "checkuseauthorityinformationaccess";
  static final String CHECKBOX_USEDEFAULTOCSPSERVICELOCALTOR      = "checkusedefaultocspservicelocator";
  static final String CHECKBOX_USELDAPDNORDER                      = "checkuseldapdnorder";
  static final String CHECKBOX_USEMSTEMPLATE                      = "checkusemstemplate";
  static final String CHECKBOX_USECARDNUMBER                      = "checkusecardnumber";
  static final String CHECKBOX_USECNPOSTFIX                       = "checkusecnpostfix";
  static final String CHECKBOX_USESUBJECTDNSUBSET                 = "checkusesubjectdnsubset";
  static final String CHECKBOX_USESUBJECTALTNAMESUBSET            = "checkusesubjectaltnamesubset";
  static final String CHECKBOX_USEPATHLENGTHCONSTRAINT            = "checkusepathlengthconstraint";
  static final String CHECKBOX_USEQCSTATEMENT                     = "checkuseqcstatement";
  static final String CHECKBOX_QCSTATEMENTCRITICAL                = "checkqcstatementcritical";
  static final String CHECKBOX_USEPKIXQCSYNTAXV2                  = "checkpkixqcsyntaxv2";
  static final String CHECKBOX_USEQCETSIQCCOMPLIANCE              = "checkqcetsiqcompliance";
  static final String CHECKBOX_USEQCETSIVALUELIMIT                = "checkqcetsivaluelimit";
  static final String CHECKBOX_USEQCETSIRETENTIONPERIOD           = "checkqcetsiretentionperiod";
  static final String CHECKBOX_USEQCETSISIGNATUREDEVICE           = "checkqcetsisignaturedevice";
  static final String CHECKBOX_USEQCCUSTOMSTRING                  = "checkqccustomstring";
  static final String CHECKBOX_USEPRIVKEYUSAGEPERIODNOTBEFORE	  = "checkboxuseprivkeyusageperiodnotbefore";
  static final String CHECKBOX_USEPRIVKEYUSAGEPERIODNOTAFTER	  = "checkboxuseprivkeyusageperiodnotafter";

  static final String SELECT_AVAILABLEBITLENGTHS                  = "selectavailablebitlengths";
  static final String SELECT_KEYUSAGE                             = "selectkeyusage";
  static final String SELECT_EXTENDEDKEYUSAGE                     = "selectextendedkeyusage";
  static final String SELECT_CVCACCESSRIGHTS                      = "selectcvcaccessrights";
  static final String SELECT_TYPE                                 = "selecttype";
  static final String SELECT_AVAILABLECAS                         = "selectavailablecas";
  static final String SELECT_AVAILABLEPUBLISHERS                  = "selectavailablepublishers";
  static final String SELECT_MSTEMPLATE                           = "selectmstemplate";
  static final String SELECT_SIGNATUREALGORITHM                   = "selectsignaturealgorithm";
  static final String SELECT_SUBJECTDNSUBSET                      = "selectsubjectdnsubset";
  static final String SELECT_SUBJECTALTNAMESUBSET                 = "selectsubjectaltnamesubset";
  static final String SELECT_USEDCERTIFICATEEXTENSIONS            = "selectusedcertificateextensions";
  static final String SELECT_APPROVALSETTINGS                     = "selectapprovalsettings";
  static final String SELECT_NUMOFREQUIREDAPPROVALS               = "selectnumofrequiredapprovals";

  // Declare Language file.
%>
<% 

  // Initialize environment
  String certprofile = null;
  String includefile = "certificateprofilespage.jspf"; 
  boolean  triedtoeditfixedcertificateprofile   = false;
  boolean  triedtodeletefixedcertificateprofile = false;
  boolean  triedtoaddfixedcertificateprofile    = false;
  boolean  certificateprofileexists             = false;
  boolean  certificateProfileDeletionFailed = false;
  List<String> servicesContainingCertificateProfile = new ArrayList<String>();
  long numberOfEndEntitiesContainingCertificateProfile = 0;
  List<String> endEntitiesContainingCertificateProfile = new ArrayList<String>();
  List<String> endEntityProfilesContainingCertificateProfile = new ArrayList<String>();
  List<String> hardTokenProfilesContainingCertificateProfile = new ArrayList<String>();
  List<String> casUsingCertificateProfile = new ArrayList<String>();

  GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, AccessRulesConstants.ROLE_ADMINISTRATOR, AccessRulesConstants.REGULAR_EDITCERTIFICATEPROFILES); 
                                            cabean.initialize(ejbcawebbean); 

  String THIS_FILENAME            =  globalconfiguration.getCaPath()  + "/editcertificateprofiles/editcertificateprofiles.jsp";
  
  boolean issuperadministrator = false;
  try{
    issuperadministrator = ejbcawebbean.isAuthorizedNoLog("/super_administrator");
  }catch(AuthorizationDeniedException ade){}   

  String[] keyusagetexts = CertificateView.KEYUSAGETEXTS;
  int[] defaultavailablebitlengths = CertificateProfile.DEFAULTBITLENGTHS;
%>
 
<head>
  <title><c:out value="<%= globalconfiguration.getEjbcaTitle() %>" /></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>" />
  <link rel="stylesheet" type="text/css" href="<%= ejbcawebbean.getCssFile() %>" />
  <script type="text/javascript" src="<%= globalconfiguration .getAdminWebPath() %>ejbcajslib.js"></script>
</head>

<body>

<%
	// Determine action 
  RequestHelper.setDefaultCharacterEncoding(request);
  if( request.getParameter(ACTION) != null){
    if( request.getParameter(ACTION).equals(ACTION_EDIT_CERTIFICATEPROFILES)){
      if( request.getParameter(BUTTON_EDIT_CERTIFICATEPROFILES) != null){
          // Display  profilepage.jsp
         certprofile = request.getParameter(SELECT_CERTIFICATEPROFILES);
         if(certprofile != null){
           // clear any stored temporary certificate profile
           cabean.setTempCertificateProfile(null);
           if(!certprofile.trim().equals("")){
             if(!certprofile.endsWith("(FIXED)")){ 
               includefile="certificateprofilepage.jspf"; 
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
          includefile="certificateprofilespage.jspf";     
        }
      }
      if( request.getParameter(BUTTON_DELETE_CERTIFICATEPROFILES) != null) {
          // Delete profile and display profilespage. 
          certprofile = request.getParameter(SELECT_CERTIFICATEPROFILES);
          if(certprofile != null){
            if(!certprofile.trim().equals("")){
              if(!certprofile.endsWith("(FIXED)")){ 
                  servicesContainingCertificateProfile = cabean.getServicesUsingCertificateProfile(certprofile); 
                  numberOfEndEntitiesContainingCertificateProfile = cabean.countEndEntitiesUsingCertificateProfile(certprofile);
                  //Don't query for end entities of their number exceeds 1000
                  if(numberOfEndEntitiesContainingCertificateProfile > 0 && numberOfEndEntitiesContainingCertificateProfile < 1000) {
                      endEntitiesContainingCertificateProfile = cabean.getEndEntitiesUsingCertificateProfile(certprofile);
                  }
                  endEntityProfilesContainingCertificateProfile = cabean.getEndEntityProfilesUsingCertificateProfile(certprofile);
      		      hardTokenProfilesContainingCertificateProfile = cabean.getHardTokenTokensUsingCertificateProfile(certprofile);
      		      casUsingCertificateProfile = cabean.getCaUsingCertificateProfile(certprofile);
      		      if( !servicesContainingCertificateProfile.isEmpty() 
      		       || numberOfEndEntitiesContainingCertificateProfile > 0
      		       || !endEntityProfilesContainingCertificateProfile.isEmpty()
      		       || !hardTokenProfilesContainingCertificateProfile.isEmpty()
      		       || !casUsingCertificateProfile.isEmpty()) {
      		          certificateProfileDeletionFailed = true;
      		    } else {
      		        cabean.removeCertificateProfile(certprofile);
      		    }
              }else{
                triedtodeletefixedcertificateprofile=true;
              }
            }
          }
          includefile="certificateprofilespage.jspf";             
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
       includefile="certificateprofilespage.jspf"; 
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
         includefile="certificateprofilespage.jspf"; 
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
          includefile="certificateprofilespage.jspf"; 
      }
    }
    if( request.getParameter(ACTION).equals(ACTION_EDIT_CERTIFICATEPROFILE)){
         // Display edit access rules page.
       certprofile = request.getParameter(HIDDEN_CERTIFICATEPROFILENAME);
       if(certprofile != null){
         if(!certprofile.trim().equals("")){

             CertificateProfile certprofiledata = cabean.getTempCertificateProfile();
             if(certprofiledata == null) {
                 certprofiledata = cabean.getCertificateProfile(certprofile);
             }
             CertificateProfile certificateprofiledata = (CertificateProfile) certprofiledata.clone();
       
             String value = request.getParameter(TEXTFIELD_VALIDITY).trim();
             if ( value!=null && value.length()>0 ){
                 final long validity = ValidityDate.encode(value);
                 if ( validity<0 ) {
                     throw new ParameterException(ejbcawebbean.getText("INVALIDVALIDITYORCERTEND"));
                 }
                 certificateprofiledata.setValidity(validity);
             }
  
             boolean use = false;
             value = request.getParameter(CHECKBOX_ALLOWVALIDITYOVERRIDE);
             if(value != null){
                use = value.equals(CHECKBOX_VALUE);
                certificateprofiledata.setAllowValidityOverride(use);
             } else {
                certificateprofiledata.setAllowValidityOverride(false);
             }
             
             value = request.getParameter(CHECKBOX_ALLOWEXTENSIONOVERRIDE);
             if(value != null){
                use = value.equals(CHECKBOX_VALUE);
                certificateprofiledata.setAllowExtensionOverride(use);
             } else {
                certificateprofiledata.setAllowExtensionOverride(false);
             }

             value = request.getParameter(CHECKBOX_ALLOWDNOVERRIDE);
             if(value != null){
                use = value.equals(CHECKBOX_VALUE);
                certificateprofiledata.setAllowDNOverride(use);
             } else {
                certificateprofiledata.setAllowDNOverride(false);
             }

             value = request.getParameter(CHECKBOX_ALLOWCERTSERIALNUMBEROVERRIDE);
             if( value!=null && cabean.isUniqueIndexForSerialNumber() ){
                use = value.equals(CHECKBOX_VALUE);
                certificateprofiledata.setAllowCertSerialNumberOverride(use);
             } else {
                certificateprofiledata.setAllowCertSerialNumberOverride(false);
             }

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
             value = request.getParameter(CHECKBOX_USEPATHLENGTHCONSTRAINT);
             if(value != null){
                 use = value.equals(CHECKBOX_VALUE);
                 certificateprofiledata.setUsePathLengthConstraint(use);
                 value = request.getParameter(TEXTFIELD_PATHLENGTHCONSTRAINT); 
                 if(value != null){
                   certificateprofiledata.setPathLengthConstraint(Integer.parseInt(value));
                 } 
             }
             else{
                 certificateprofiledata.setUsePathLengthConstraint(false);
                 certificateprofiledata.setPathLengthConstraint(0); 
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

             value = request.getParameter(CHECKBOX_SUBJECTDIRATTRIBUTES);
             if(value != null){                  
                  certificateprofiledata.setUseSubjectDirAttributes(value.equals(CHECKBOX_VALUE));
             } else {
                 certificateprofiledata.setUseSubjectDirAttributes(false);
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
                   
                 value = request.getParameter(CHECKBOX_USEDEFAULTCRLDISTRIBUTIONPOINT); 
                 if(value != null)
                   certificateprofiledata.setUseDefaultCRLDistributionPoint(value.equals(CHECKBOX_VALUE)); 
                 else
                   certificateprofiledata.setUseDefaultCRLDistributionPoint(false); 
                   
                 value = request.getParameter(TEXTFIELD_CRLDISTURI);
                 if(value != null && !certificateprofiledata.getUseDefaultCRLDistributionPoint()){
                   value=value.trim();
                   certificateprofiledata.setCRLDistributionPointURI(value);
                 } 
                 value = request.getParameter(TEXTFIELD_CRLISSUER);
                 if(value != null && !certificateprofiledata.getUseDefaultCRLDistributionPoint()){
                   value=value.trim();
                   certificateprofiledata.setCRLIssuer(value);
                 } 
                 
             }
             else{
                 certificateprofiledata.setUseCRLDistributionPoint(false);
                 certificateprofiledata.setCRLDistributionPointCritical(false); 
                 certificateprofiledata.setCRLDistributionPointURI("");
             } 

             use = false;
             value = request.getParameter(CHECKBOX_USECERTIFICATEPOLICIES);
             if(value != null) {
                 use = value.equals(CHECKBOX_VALUE);
                 certificateprofiledata.setUseCertificatePolicies(use);
                 value = request.getParameter(CHECKBOX_CERTIFICATEPOLICIESCRITICAL); 
                 if(value != null) {
		   certificateprofiledata.setCertificatePoliciesCritical(value.equals(CHECKBOX_VALUE)); 
                 } else {
			 certificateprofiledata.setCertificatePoliciesCritical(false); 
		 }

		 value = request.getParameter(TEXTFIELD_CERTIFICATEPOLICYID);
		 String userNotice = request.getParameter(TEXTAREA_POLICYNOTICE_UNOTICE);
		 String cpsUri = request.getParameter(TEXTFIELD_POLICYNOTICE_CPSURL);
                 if ( (value != null) && (value.trim().length() > 0) ) {
                   boolean added = false;
                   if (userNotice != null) {
                     userNotice = userNotice.trim();
                     if (userNotice.length() > 0) {
                       certificateprofiledata.addCertificatePolicy(new CertificatePolicy(value.trim(), CertificatePolicy.id_qt_unotice, userNotice));
                       added = true;
                     }
                   }
                   if (cpsUri != null) {
                     cpsUri = cpsUri.trim();
                     if (cpsUri.length() > 0) {
                       certificateprofiledata.addCertificatePolicy(new CertificatePolicy(value.trim(), CertificatePolicy.id_qt_cps, cpsUri));
                       added = true;
                     }
                   }
                   if (!added) {
                     certificateprofiledata.addCertificatePolicy(new CertificatePolicy(value.trim(), null, null));
                   }
                 }
             } else {
                 certificateprofiledata.setUseCertificatePolicies(false);
                 certificateprofiledata.setCertificatePoliciesCritical(false); 
                 certificateprofiledata.setCertificatePolicies(null);
             } 

              String[] values = request.getParameterValues(SELECT_AVAILABLEBITLENGTHS); 
              if(values != null){
                int[] abl = new int[values.length];
                for(int i=0; i< values.length;i++){
                  abl[i] = Integer.parseInt(values[i]);
                }
                certificateprofiledata.setAvailableBitLengths(abl);
              }

              value = request.getParameter(SELECT_SIGNATUREALGORITHM);
              value = value.trim();
              if(value != null) {
                  if(value.equals(INHERITFROMCA)) {
                      certificateprofiledata.setSignatureAlgorithm(null);
                  } else {
                      certificateprofiledata.setSignatureAlgorithm(value);
                  }
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
               if(value != null)
                 certificateprofiledata.setExtendedKeyUsageCritical(value.equals(CHECKBOX_VALUE));
               else
                 certificateprofiledata.setExtendedKeyUsageCritical(false);
                 
               values = request.getParameterValues(SELECT_EXTENDEDKEYUSAGE);
               ArrayList eku = new ArrayList(); 
                if(values != null){
                   for(int i=0; i < values.length; i++){
                      eku.add(values[i]);
                   }
                }
                certificateprofiledata.setExtendedKeyUsage(eku);    
              }
              else{
                certificateprofiledata.setUseExtendedKeyUsage(false); 
                certificateprofiledata.setExtendedKeyUsageCritical(false); 
                certificateprofiledata.setExtendedKeyUsage(new ArrayList());        
              }

              value = request.getParameter(SELECT_CVCACCESSRIGHTS);
              int ar  = CertificateProfile.CVC_ACCESS_DG3DG4;
              if(value != null){
                ar = Integer.parseInt(value);
              }
              certificateprofiledata.setCVCAccessRights(ar);    

              value = request.getParameter(SELECT_TYPE);
              int type  = CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER;
              if(value != null){
                type = Integer.parseInt(value);
              }
              certificateprofiledata.setType(type);    
              
              value = request.getParameter(CHECKBOX_ALLOWKEYUSAGEOVERRIDE);
              if(value != null){
                 use = value.equals(CHECKBOX_VALUE);
                 certificateprofiledata.setAllowKeyUsageOverride(use);
              } else {
                 certificateprofiledata.setAllowKeyUsageOverride(false);
              }
              {
            	  final String v = request.getParameter(CHECKBOX_ALLOWBACKDATEDREVOCATION);
            	  certificateprofiledata.setAllowBackdatedRevocation( v!=null && v.equals(CHECKBOX_VALUE) );
              }
              values = request.getParameterValues(SELECT_AVAILABLECAS);
              ArrayList availablecas = new ArrayList(); 
              if(values != null){
                 for(int i=0; i < values.length; i++){
                    if(Integer.parseInt(values[i]) == CertificateProfile.ANYCA){
                      availablecas = new ArrayList();
                      availablecas.add(Integer.valueOf(CertificateProfile.ANYCA));
                      break;  
                    }
                    availablecas.add(Integer.valueOf(values[i]));
                 }
              }
              certificateprofiledata.setAvailableCAs(availablecas);

              values = request.getParameterValues(SELECT_AVAILABLEPUBLISHERS);
              ArrayList availablepublishers = new ArrayList(); 
              if(values != null){
                 for(int i=0; i < values.length; i++){
                    availablepublishers.add(Integer.valueOf(values[i]));
                 }
              }
              certificateprofiledata.setPublisherList(availablepublishers);

              use = false;
              value = request.getParameter(CHECKBOX_USEOCSPNOCHECK);
              if(value != null){
                  use = value.equals(CHECKBOX_VALUE);
                  certificateprofiledata.setUseOcspNoCheck(use);
              }
              else{
                  certificateprofiledata.setUseOcspNoCheck(false);
              }

              /* Authority Information Access extension */
              use = false;
              value = request.getParameter(CHECKBOX_USEAUTHORITYINFORMATIONACCESS);
              if(value != null){
           		  use = value.equals(CHECKBOX_VALUE);
                  certificateprofiledata.setUseAuthorityInformationAccess(use);
                  // Ocsp service locator
                  value = request.getParameter(CHECKBOX_USEDEFAULTOCSPSERVICELOCALTOR);
                  if(value != null){
                    certificateprofiledata.setUseDefaultOCSPServiceLocator(value.equals(CHECKBOX_VALUE));
                  }else{
                    certificateprofiledata.setUseDefaultOCSPServiceLocator(false);
                  }          
                  
                  value = request.getParameter(TEXTFIELD_OCSPSERVICELOCATOR);
                  if(value != null && !certificateprofiledata.getUseDefaultOCSPServiceLocator()){
                    value=value.trim();
                    certificateprofiledata.setOCSPServiceLocatorURI(value);
                  } 
                  // CA issuers
                  value = request.getParameter(TEXTFIELD_CAISSUERURI);
               	  if( value != null ) {
                 	  certificateprofiledata.addCaIssuer(value);
               	  } 
           	  } else {
            	  certificateprofiledata.setUseAuthorityInformationAccess(false);
               	  certificateprofiledata.setCaIssuers(null);
                  certificateprofiledata.setOCSPServiceLocatorURI("");
           	  }
             
             /* Freshest CRL extension */
             use = false;
             value = request.getParameter(CHECKBOX_USEFRESHESTCRL);
             if(value != null){
                 use = value.equals(CHECKBOX_VALUE);
                 certificateprofiledata.setUseFreshestCRL(use);

                 value = request.getParameter(CHECKBOX_USECADEFINEDFRESHESTCRL);
                 if(value != null){
                   certificateprofiledata.setUseCADefinedFreshestCRL(value.equals(CHECKBOX_VALUE));
                 }else{
                   certificateprofiledata.setUseCADefinedFreshestCRL(false);
                 }          
                  
                 value = request.getParameter(TEXTFIELD_FRESHESTCRLURI);
                 if(value != null && !certificateprofiledata.getUseCADefinedFreshestCRL()){
                   value=value.trim();
                   certificateprofiledata.setFreshestCRLURI(value);
                 } 
             }
             else{
                 certificateprofiledata.setUseFreshestCRL(false);                 
                 certificateprofiledata.setFreshestCRLURI("");
             }

             /* Use LDAP DN oder */
             use = false;
             value = request.getParameter(CHECKBOX_USELDAPDNORDER);
             if(value != null){
                 use = value.equals(CHECKBOX_VALUE);
                 certificateprofiledata.setUseLdapDnOrder(use);
             } else{
                 certificateprofiledata.setUseLdapDnOrder(false);                 
             }

             /* MS Domain controller extension */
             use = false;
             value = request.getParameter(CHECKBOX_USEMSTEMPLATE);
             if(value != null){
                 use = value.equals(CHECKBOX_VALUE);
                 certificateprofiledata.setUseMicrosoftTemplate(use);

                 value = request.getParameter(SELECT_MSTEMPLATE);
                 if(value != null){
                   value=value.trim();
                   certificateprofiledata.setMicrosoftTemplate(value);
                 } 
             }
             else{
                 certificateprofiledata.setUseMicrosoftTemplate(false);                 
                 certificateprofiledata.setMicrosoftTemplate("");
             }
             
             use = false; 
             value = request.getParameter(CHECKBOX_USECARDNUMBER);
             if(value != null) {
            	 use = value.equals(CHECKBOX_VALUE);
            	 certificateprofiledata.setUseCardNumber(use);
             }
             else {
            	 certificateprofiledata.setUseCardNumber(false);
             }

             use = false;
             value = request.getParameter(CHECKBOX_USECNPOSTFIX);
             if(value != null){
                 use = value.equals(CHECKBOX_VALUE);
                 certificateprofiledata.setUseCNPostfix(use);

                 value = request.getParameter(TEXTFIELD_CNPOSTFIX);
                 if(value != null){
                   certificateprofiledata.setCNPostfix(value);
                 } 
             }
             else{
                 certificateprofiledata.setUseCNPostfix(false);                 
                 certificateprofiledata.setCNPostfix("");
             }
             
             use = false;
             value = request.getParameter(CHECKBOX_USESUBJECTDNSUBSET);
             if(value != null){
                 use = value.equals(CHECKBOX_VALUE);
                 certificateprofiledata.setUseSubjectDNSubSet(use);

                 values = request.getParameterValues(SELECT_SUBJECTDNSUBSET);
                 if(values != null){
                     ArrayList usefields = new ArrayList();
                     for(int i=0;i< values.length;i++){
                         usefields.add(Integer.valueOf(values[i]));	
                     }                     
                     certificateprofiledata.setSubjectDNSubSet(usefields);
                 }
             }
             else{
                 certificateprofiledata.setUseSubjectDNSubSet(false);                 
                 certificateprofiledata.setSubjectDNSubSet(new ArrayList());
             }
             
             use = false;
             value = request.getParameter(CHECKBOX_USESUBJECTALTNAMESUBSET);
             if(value != null){
                 use = value.equals(CHECKBOX_VALUE);
                 certificateprofiledata.setUseSubjectAltNameSubSet(use);

                 values = request.getParameterValues(SELECT_SUBJECTALTNAMESUBSET);
                 if(values != null){
                     ArrayList usefields = new ArrayList();
                     for(int i=0;i< values.length;i++){
                         usefields.add(Integer.valueOf(values[i]));	
                     }                     
                     certificateprofiledata.setSubjectAltNameSubSet(usefields);
                 }
             }
             else{
                 certificateprofiledata.setUseSubjectAltNameSubSet(false);                 
                 certificateprofiledata.setSubjectAltNameSubSet(new ArrayList());
             }
             
             values = request.getParameterValues(SELECT_USEDCERTIFICATEEXTENSIONS);
             if(values != null){
                ArrayList useextensions = new ArrayList();
                for(int i=0;i< values.length;i++){
                  useextensions.add(Integer.valueOf(values[i]));	
                }                     
                certificateprofiledata.setUsedCertificateExtensions(useextensions);
             } else {
            	 // Make sure we remove everything if there is something there
                 ArrayList useextensions = new ArrayList();
                 certificateprofiledata.setUsedCertificateExtensions(useextensions);
             }
             
             // PrivateKeyUsagePeriod extension
             value = request.getParameter(CHECKBOX_USEPRIVKEYUSAGEPERIODNOTBEFORE);
             if (value != null) {
                 use = value.equals(CHECKBOX_VALUE);
                 certificateprofiledata.setUsePrivateKeyUsagePeriodNotBefore(use);
                 if (use) {
		             value = request.getParameter(TEXTFIELD_PRIVKEYUSAGEPERIODSTARTOFFSET);
		             if (value != null) {
		             	value = value.trim();
		             	if (value.length() > 0) {
		                 	final long validity = ValidityDate.encode(value);
		                 	if (validity < 0) {
		                 	    throw new ParameterException(ejbcawebbean.getText("INVALIDPRIVKEYSTARTOFFSET"));
		                 	}
		                 	certificateprofiledata.setPrivateKeyUsagePeriodStartOffset(validity * 24 * 3600);
		                }
		             }
		         }
             } else {
             	certificateprofiledata.setUsePrivateKeyUsagePeriodNotBefore(false);
         	 }
             
             value = request.getParameter(CHECKBOX_USEPRIVKEYUSAGEPERIODNOTAFTER);
             if (value != null) {
                 use = value.equals(CHECKBOX_VALUE);
                 certificateprofiledata.setUsePrivateKeyUsagePeriodNotAfter(use);
                 if (use) {
		             value = request.getParameter(TEXTFIELD_PRIVKEYUSAGEPERIODLENGTH);
		             if (value != null) {
		             	value = value.trim();
		             	if (value.length() > 0) {
			                 final long validity = ValidityDate.encode(value);
			                 if (validity < 0) {
			                     throw new ParameterException(ejbcawebbean.getText("INVALIDPRIVKEYPERIOD"));
			                 }
			                 certificateprofiledata.setPrivateKeyUsagePeriodLength(validity * 24 * 3600);
		                }
		             }
		         }
             } else {
             	certificateprofiledata.setUsePrivateKeyUsagePeriodNotAfter(false);
         	 }
             
             certificateprofiledata.setUseQCStatement(false);
             certificateprofiledata.setQCStatementCritical(false);
             certificateprofiledata.setUsePkixQCSyntaxV2(false);
             certificateprofiledata.setUseQCEtsiQCCompliance(false);
             certificateprofiledata.setUseQCEtsiSignatureDevice(false);
             certificateprofiledata.setUseQCEtsiValueLimit(false);
             certificateprofiledata.setUseQCEtsiRetentionPeriod(false);
             certificateprofiledata.setQCSemanticsId("");
             certificateprofiledata.setQCStatementRAName("");
             certificateprofiledata.setQCEtsiValueLimit(0);
             certificateprofiledata.setQCEtsiValueLimitExp(0);
             certificateprofiledata.setQCEtsiValueLimitCurrency("");
             certificateprofiledata.setQCEtsiRetentionPeriod(0);
             certificateprofiledata.setUseQCCustomString(false);
             certificateprofiledata.setQCCustomStringOid("");
             certificateprofiledata.setQCCustomStringText("");
             
             value = request.getParameter(CHECKBOX_USEQCSTATEMENT);
             if(value != null){                  
                  certificateprofiledata.setUseQCStatement(value.equals(CHECKBOX_VALUE));
                  
                  if(certificateprofiledata.getUseQCStatement()){
                     value = request.getParameter(CHECKBOX_QCSTATEMENTCRITICAL);
                     if(value != null) {
                       certificateprofiledata.setQCStatementCritical(value.equals(CHECKBOX_VALUE));
                     }
                     value = request.getParameter(CHECKBOX_USEPKIXQCSYNTAXV2);
                     if(value != null) {
                       certificateprofiledata.setUsePkixQCSyntaxV2(value.equals(CHECKBOX_VALUE));
                     }
                     value = request.getParameter(CHECKBOX_USEQCETSIQCCOMPLIANCE);
                     if(value != null) {
                       certificateprofiledata.setUseQCEtsiQCCompliance(value.equals(CHECKBOX_VALUE));
                     }
                     value = request.getParameter(CHECKBOX_USEQCETSISIGNATUREDEVICE);
                     if(value != null) {
                       certificateprofiledata.setUseQCEtsiSignatureDevice(value.equals(CHECKBOX_VALUE));
                     }
                     value = request.getParameter(CHECKBOX_USEQCETSIVALUELIMIT);
                     if(value != null) {
                       certificateprofiledata.setUseQCEtsiValueLimit(value.equals(CHECKBOX_VALUE));
                       certificateprofiledata.setQCEtsiValueLimit(Integer.valueOf(request.getParameter(TEXTFIELD_QCETSIVALUELIMIT)).intValue());
                       certificateprofiledata.setQCEtsiValueLimitExp(Integer.valueOf(request.getParameter(TEXTFIELD_QCETSIVALUELIMITEXP)).intValue());  
                       certificateprofiledata.setQCEtsiValueLimitCurrency(request.getParameter(TEXTFIELD_QCETSIVALUELIMITCUR));                                                                    
                     }                     
                     value = request.getParameter(CHECKBOX_USEQCETSIRETENTIONPERIOD);
                     if(value != null) {
                       certificateprofiledata.setUseQCEtsiRetentionPeriod(value.equals(CHECKBOX_VALUE));
                       certificateprofiledata.setQCEtsiRetentionPeriod(Integer.valueOf(request.getParameter(TEXTFIELD_QCETSIRETENTIONPERIOD)).intValue());
                     }                     
                     value = request.getParameter(CHECKBOX_USEQCCUSTOMSTRING);
                     if(value != null) {
                       certificateprofiledata.setUseQCCustomString(value.equals(CHECKBOX_VALUE));
                       certificateprofiledata.setQCCustomStringOid(request.getParameter(TEXTFIELD_QCCUSTOMSTRINGOID));
                       certificateprofiledata.setQCCustomStringText(request.getParameter(TEXTFIELD_QCCUSTOMSTRINGTEXT));  
                     }                     
                     certificateprofiledata.setQCSemanticsId(request.getParameter(TEXTFIELD_QCSSEMANTICSID));
                     certificateprofiledata.setQCStatementRAName(request.getParameter(TEXTFIELD_QCSTATEMENTRANAME));
                  }
             }
             
             values = request.getParameterValues(SELECT_APPROVALSETTINGS);
             ArrayList approvalsettings = new ArrayList(); 
             if(values != null){
               for(int i=0; i < values.length; i++){
            	   approvalsettings.add(Integer.valueOf(values[i]));
               }
             }
			certificateprofiledata.setApprovalSettings(approvalsettings);
			value = request.getParameter(SELECT_NUMOFREQUIREDAPPROVALS);
			int numofreqapprovals = 1;
			if(value != null){
			 numofreqapprovals = Integer.parseInt(value);
			}
			certificateprofiledata.setNumOfReqApprovals(numofreqapprovals);
             
           /*
            * Save changes.
            */
           if(request.getParameter(BUTTON_SAVE) != null) {
               cabean.changeCertificateProfile(certprofile, certificateprofiledata);
               cabean.setTempCertificateProfile(null);
               includefile="certificateprofilespage.jspf";
           }
             /*
             * Add policy.
              */
             if(request.getParameter(BUTTON_ADD_POLICY) != null) {
  	             cabean.setTempCertificateProfile(certificateprofiledata);
                 includefile = "certificateprofilepage.jspf";
             }

             /*
              * Remove policy.
              */
             if(certificateprofiledata.getCertificatePolicies() != null) {
                 boolean removed = false;
                 for(int i = 0; i < certificateprofiledata.getCertificatePolicies().size(); i++) {
                     value = request.getParameter(BUTTON_DELETE_POLICY + i);
                     if(value != null) {
                         removed = true;
                         String policyId = request.getParameter(TEXTFIELD_CERTIFICATEPOLICYID + i);
                         if (policyId != null) {
                           policyId = policyId.trim();
                         }
                         String userNotice = request.getParameter(TEXTAREA_POLICYNOTICE_UNOTICE + i);
                         if ( (userNotice != null) && (userNotice.trim().length() > 0) ) {
                           userNotice = userNotice.trim();
                           CertificatePolicy policy =
                             new CertificatePolicy(policyId,    // policyID
                                                   CertificatePolicy.id_qt_unotice,  // policyQualifier UserNotice
                                                   userNotice);     // user notice text
                           certificateprofiledata.removeCertificatePolicy(policy);
                         }
                         String cpsUri = request.getParameter(TEXTFIELD_POLICYNOTICE_CPSURL + i);
                         if ( (cpsUri != null) && (cpsUri.trim().length() > 0) ) {
                           cpsUri = cpsUri.trim();
                           CertificatePolicy policy =
                             new CertificatePolicy(policyId,    // policyID
                                                   CertificatePolicy.id_qt_cps,  // policyQualifier CPS URI
                                                   cpsUri);     // cps uri
                           certificateprofiledata.removeCertificatePolicy(policy);
                         }
                         if ( ((userNotice == null) || (userNotice.trim().length() == 0)) && 
                              ((cpsUri == null) || (cpsUri.trim().length() == 0)) && 
                              (policyId != null) ) {
                             CertificatePolicy policy =
                               new CertificatePolicy(policyId, null, null);
                             certificateprofiledata.removeCertificatePolicy(policy);                           
                         }
                                               
                         cabean.setTempCertificateProfile(certificateprofiledata);
                     }
                 }         
                 if (removed) {
                   includefile = "certificateprofilepage.jspf";
                 }
             }
             
             /*
              * Add caIssuer URI.
              */
             if(request.getParameter(BUTTON_ADD_CAISSUERURI) != null) {
    	           cabean.setTempCertificateProfile(certificateprofiledata);
                 includefile = "certificateprofilepage.jspf";
             }

             /*
              * Remove caIssuer URI.
              */
             if(certificateprofiledata.getCaIssuers() != null) {
               for(int i = 0; i < certificateprofiledata.getCaIssuers().size(); i++) {
                   value = request.getParameter(BUTTON_DELETE_CAISSUERURI + i);
                   if(value != null) {
                       certificateprofiledata.removeCaIssuer(request.getParameter(TEXTFIELD_CAISSUERURI + i));                                                 
                       cabean.setTempCertificateProfile(certificateprofiledata);
                       includefile = "certificateprofilepage.jspf";
                   }
               }         
             }

           
           if(request.getParameter(BUTTON_CANCEL) != null){
              // Don't save changes.
              cabean.setTempCertificateProfile(null);
              includefile="certificateprofilespage.jspf";
           }
           if(includefile == null ) {
                 includefile="certificateprofilespage.jspf";
           }
         }
      }
    }
  }

 // Include page
  if( includefile.equals("certificateprofilepage.jspf")){
%>
   <%@ include file="certificateprofilepage.jspf" %>
<%}
  if( includefile.equals("certificateprofilespage.jspf")){ %>
   <%@ include file="certificateprofilespage.jspf" %> 
<%}

   // Include Footer 
   String footurl =   globalconfiguration.getFootBanner(); %>
   
  <jsp:include page="<%= footurl %>" />

</body>
</html>
