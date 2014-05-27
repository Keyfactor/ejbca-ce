<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ page pageEncoding="ISO-8859-1"%>
<% response.setContentType("text/html; charset="+org.ejbca.config.WebConfiguration.getWebContentEncoding()); %>
<%@page errorPage="/errorpage.jsp" import="java.util.*, java.util.Map.Entry, org.ejbca.ui.web.admin.configuration.EjbcaWebBean,org.ejbca.config.GlobalConfiguration, org.ejbca.core.model.SecConst, org.cesecore.authorization.AuthorizationDeniedException,
    org.ejbca.ui.web.RequestHelper,org.ejbca.ui.web.admin.cainterface.CAInterfaceBean, org.cesecore.certificates.certificateprofile.CertificateProfile, org.ejbca.ui.web.admin.cainterface.CertificateProfileDataHandler, 
               org.cesecore.certificates.certificateprofile.CertificateProfileExistsException, org.cesecore.certificates.certificateprofile.CertificateProfileConstants, org.ejbca.ui.web.CertificateView, org.cesecore.certificates.util.DNFieldExtractor, org.cesecore.certificates.util.DnComponents, 
               org.cesecore.certificates.certificate.certextensions.CertificateExtensionFactory, org.cesecore.certificates.certificate.certextensions.AvailableCertificateExtension, org.cesecore.certificates.certificateprofile.CertificatePolicy,
               org.cesecore.certificates.ca.CAInfo, org.cesecore.util.ValidityDate, org.ejbca.ui.web.ParameterException, org.cesecore.certificates.util.AlgorithmConstants,
               org.cesecore.certificates.certificate.CertificateConstants, org.ejbca.core.model.authorization.AccessRulesConstants, org.cesecore.certificates.certificatetransparency.CertificateTransparencyFactory, org.cesecore.certificates.certificatetransparency.CTLogInfo,
               org.ejbca.cvc.AccessRightAuthTerm"%>
<%@page import="org.cesecore.util.YearMonthDayTime"%>
<html>
<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />
<jsp:useBean id="cabean" scope="session" class="org.ejbca.ui.web.admin.cainterface.CAInterfaceBean" />
<%!
  static final String ACTION="action";
  static final String ACTION_EDIT_CPS="editcertificateprofiles";
  static final String ACTION_EDIT_CP="editcertificateprofile";
  static final String ACTION_IMPORT_EXPORT="importexportprofiles";
  static final String INHERITFROMCA="inheritfromca";
  static final String CB_VALUE= CertificateProfile.TRUE;
  static final String BUTTON_EDIT_CERTIFICATEPROFILES="buttoneditcertificateprofile";
  static final String BUTTON_DELETE_CERTIFICATEPROFILES="buttondeletecertificateprofile";
  static final String BUTTON_ADD_CERTIFICATEPROFILES="buttonaddcertificateprofile";
  static final String BUTTON_RENAME_CERTIFICATEPROFILES="buttonrenamecertificateprofile";
  static final String BUTTON_CLONE_CERTIFICATEPROFILES="buttonclonecertificateprofile";
  static final String BUTTON_ADD_POLICY="buttonaddpolicy";
  static final String BUTTON_DELETE_POLICY="buttondeletepolicy";
  static final String BUTTON_ADD_CAISSUERURI="buttonaddcaissueruri";
  static final String BUTTON_DELETE_CAISSUERURI="buttondeletecaissueruri";
  static final String BUTTON_IMPORT_PROFILES="buttonimportprofiles";
  static final String BUTTON_EXPORT_PROFILES="buttonexportprofiles";
  static final String SELECT_CERTIFICATEPROFILES="selectcertificateprofile";
  static final String TEXTFIELD_CERTIFICATEPROFILESNAME="textfieldcertificateprofilename";
  static final String TEXTFIELD_EXPORT_DESTINATION	="textfieldexportdestination";
  static final String HIDDEN_CERTIFICATEPROFILENAME="hiddencertificateprofilename";
  static final String FILE_IMPORTFILE="fileimportfile";
  static final String BUTTON_SAVE="buttonsave";
  static final String BUTTON_CANCEL="buttoncancel";
  static final String TEXTFIELD_VALIDITY="textfieldvalidity";
  static final String TEXTFIELD_CRLDISTURI="textfieldcrldisturi";
  static final String TEXTFIELD_CRLISSUER="textfieldcrlissuer";
  static final String TEXTFIELD_FRESHESTCRLURI="textfieldfreshestcrluri";
  static final String TEXTFIELD_CERTIFICATEPOLICYID="textfieldcertificatepolicyid";
  static final String TEXTFIELD_POLICYNOTICE_CPSURL="textfielpolicynoticedcpsurl";
  static final String TEXTAREA_POLICYNOTICE_UNOTICE="textareapolicynoticeunotice";
  static final String TEXTFIELD_CAISSUERURI="textfieldcaissueruri";
  static final String TEXTFIELD_OCSPSERVICELOCATOR="textfieldocspservicelocatoruri";
  static final String TEXTFIELD_CNPOSTFIX="textfieldcnpostfix";
  static final String TEXTFIELD_PATHLENGTHCONSTRAINT="textfieldpathlengthconstraint";
  static final String TEXTFIELD_QCSSEMANTICSID="textfieldqcsemanticsid";
  static final String TEXTFIELD_QCSTATEMENTRANAME="textfieldqcstatementraname";
  static final String TEXTFIELD_QCETSIVALUELIMIT="textfieldqcetsivaluelimit";
  static final String TEXTFIELD_QCETSIRETENTIONPERIOD="textfieldqcetsiretentionperiod";
  static final String TEXTFIELD_QCETSIVALUELIMITEXP="textfieldqcetsivaluelimitexp";
  static final String TEXTFIELD_QCETSIVALUELIMITCUR="textfieldqcetsivaluelimitcur";
  static final String TEXTFIELD_QCCUSTOMSTRINGOID="textfieldqccustomstringoid";
  static final String TEXTFIELD_QCCUSTOMSTRINGTEXT="textfieldqccustomstringtext";
  static final String TEXTFIELD_PRIVKEYUSAGEPERIODSTARTOFFSET="textfieldprivkeyusageperiodstartoffset";
  static final String TEXTFIELD_PRIVKEYUSAGEPERIODLENGTH="textfieldprivkeyusageperiodlength";
  static final String TEXTFIELD_CTMINSCTS="textfieldctminscts";
  static final String TEXTFIELD_CTMAXSCTS="textfieldctmaxscts";
  static final String TEXTFIELD_CTMAXRETRIES="textfieldctmaxretries";
  static final String TEXTFIELD_DOCUMENTTYPE="textfielddocumenttype";
  static final String CB_BASICCONSTRAINTS="cbbasicconstraints";
  static final String CB_BASICCONSTRAINTSCRITICAL="cbbasicconstraintscritical";
  static final String CB_KEYUSAGE="cbkeyusage";
  static final String CB_KEYUSAGECRITICAL="cbkeyusagecritical";
  static final String CB_SUBJECTKEYIDENTIFIER="cbsubjectkeyidentifier";
  static final String CB_SUBJECTKEYIDENTIFIERCRITICAL="cbsubjectkeyidentifiercritical";
  static final String CB_AUTHORITYKEYIDENTIFIER="cbauthoritykeyidentifier";
  static final String CB_AUTHORITYKEYIDENTIFIERCRITICAL="cbauthoritykeyidentifiercritical";
  static final String CB_SUBJECTALTERNATIVENAME="cbsubjectalternativename";
  static final String CB_SUBJECTALTERNATIVENAMECRITICAL="cbsubjectalternativenamecritical";
  static final String CB_ISSUERALTERNATIVENAME="cbissueralternativename";
  static final String CB_ISSUERALTERNATIVENAMECRITICAL="cbissueralternativenamecritical";
  static final String CB_USEDOCUMENTTYPE="cbusedocumenttype";
  static final String CB_DOCUMENTTYPECRITICAL="cbdocumenttypecritical";
  static final String CB_SUBJECTDIRATTRIBUTES="checksubjectdirattributes";
  static final String CB_NAMECONSTRAINTS="checknameconstraints";
  static final String CB_NAMECONSTRAINTSCRITICAL="checknameconstraintscritical";
  static final String CB_CRLDISTRIBUTIONPOINT="cbcrldistributionpoint";
  static final String CB_USEDEFAULTCRLDISTRIBUTIONPOINT="cbusedefaultcrldistributionpoint";
  static final String CB_CRLDISTRIBUTIONPOINTCRITICAL="cbcrldistributionpointcritical";
  static final String CB_USECERTIFICATEPOLICIES="checkusecertificatepolicies";
  static final String CB_USEFRESHESTCRL="cbusefreshestcrl";
  static final String CB_USECADEFINEDFRESHESTCRL="cbusecadefinedfreshestcrl";
  static final String CB_CERTIFICATEPOLICIESCRITICAL="checkcertificatepoliciescritical";
  static final String CB_ALLOWDNOVERRIDE="checkallowdnoverride";
  static final String CB_ALLOWCERTSERIALNUMBEROVERRIDE="allowcertserialnumberoverride";
  static final String CB_ALLOWEXTENSIONOVERRIDE="checkallowextensionoverride";
  static final String CB_ALLOWVALIDITYOVERRIDE="checkallowvalidityoverride";
  static final String CB_ALLOWKEYUSAGEOVERRIDE="checkallowkeyusageoverride";
  static final String CB_ALLOWBACKDATEDREVOCATION="checkallowbackdatedrevokation";
  static final String CB_USEEXTENDEDKEYUSAGE="checkuseextendedkeyusage";
  static final String CB_EXTENDEDKEYUSAGECRITICAL="cbextendedkeyusagecritical";
  static final String CB_USEOCSPNOCHECK="checkuseocspnocheck";
  static final String CB_USEAUTHORITYINFORMATIONACCESS="checkuseauthorityinformationaccess";
  static final String CB_USEDEFAULTOCSPSERVICELOCALTOR="checkusedefaultocspservicelocator";
  static final String CB_USELDAPDNORDER="checkuseldapdnorder";
  static final String CB_USEMSTEMPLATE="checkusemstemplate";
  static final String CB_USECARDNUMBER="checkusecardnumber";
  static final String CB_USECNPOSTFIX="checkusecnpostfix";
  static final String CB_USESUBJECTDNSUBSET="checkusesubjectdnsubset";
  static final String CB_USESUBJECTALTNAMESUBSET="checkusesubjectaltnamesubset";
  static final String CB_USEPATHLENGTHCONSTRAINT="checkusepathlengthconstraint";
  static final String CB_USEQCSTATEMENT="checkuseqcstatement";
  static final String CB_QCSTATEMENTCRITICAL="checkqcstatementcritical";
  static final String CB_USEPKIXQCSYNTAXV2="checkpkixqcsyntaxv2";
  static final String CB_USEQCETSIQCCOMPLIANCE="checkqcetsiqcompliance";
  static final String CB_USEQCETSIVALUELIMIT="checkqcetsivaluelimit";
  static final String CB_USEQCETSIRETENTIONPERIOD="checkqcetsiretentionperiod";
  static final String CB_USEQCETSISIGNATUREDEVICE="checkqcetsisignaturedevice";
  static final String CB_USEQCCUSTOMSTRING="checkqccustomstring";
  static final String CB_USEPRIVKEYUSAGEPERIODNOTBEFORE="cbuseprivkeyusageperiodnotbefore";
  static final String CB_USEPRIVKEYUSAGEPERIODNOTAFTER="cbuseprivkeyusageperiodnotafter";
  static final String CB_USECERTIFICATETRANSPARENCYINCERTS="cbusecertificatetransparencyincerts";
  static final String CB_USECERTIFICATETRANSPARENCYINOCSP="cbusecertificatetransparencyinocsp";
  static final String SELECT_AVAILABLEBITLENGTHS="selectavailablebitlengths";
  static final String SELECT_KEYUSAGE="selectkeyusage";
  static final String SELECT_EXTENDEDKEYUSAGE="selectextendedkeyusage";
  static final String SELECT_CVCTERMTYPE="selectcvctermtype";
  static final String SELECT_CVCSIGNTERMDVTYPE="selectcvcsigntermdvtype";
  static final String SELECT_CVCACCESSRIGHTS="selectcvcaccessrights";
  static final String SELECT_TYPE="selecttype";
  static final String SELECT_AVAILABLECAS="selectavailablecas";
  static final String SELECT_AVAILABLEPUBLISHERS="selectavailablepublishers";
  static final String SELECT_MSTEMPLATE="selectmstemplate";
  static final String SELECT_SIGNATUREALGORITHM="selectsignaturealgorithm";
  static final String SELECT_SUBJECTDNSUBSET="selectsubjectdnsubset";
  static final String SELECT_SUBJECTALTNAMESUBSET="selectsubjectaltnamesubset";
  static final String SELECT_USEDCERTIFICATEEXTENSIONS="selectusedcertificateextensions";
  static final String SELECT_APPROVALSETTINGS="selectapprovalsettings";
  static final String SELECT_NUMOFREQUIREDAPPROVALS="selectnumofrequiredapprovals";
  static final String SELECT_CTLOGS="selectctlogs";
%>
<%
  String cp=null;
  String includefile="certificateprofilespage.jspf";
  boolean triedtoeditfixcp=false;
  boolean triedtodeletefixcp=false;
  boolean triedtoaddfixcp=false;
  boolean cpexists=false;
  boolean cpDeleteFailed=false;
  List<String> servicesWithCP=new ArrayList<String>();
  long numEEsWithCP=0;
  List<String> eentitiesWithCP=new ArrayList<String>();
  List<String> eepsWithCP=new ArrayList<String>();
  List<String> htpsWithCP=new ArrayList<String>();
  List<String> casWithCP=new ArrayList<String>();
  GlobalConfiguration globalconfiguration=ejbcawebbean.initialize(request,AccessRulesConstants.ROLE_ADMINISTRATOR,AccessRulesConstants.REGULAR_EDITCERTIFICATEPROFILES);
  cabean.initialize(ejbcawebbean);
  String THIS_FILENAME=globalconfiguration.getCaPath()+"/editcertificateprofiles/editcertificateprofiles.jsp";
  boolean issuperadministrator=false;
  try{
    issuperadministrator=ejbcawebbean.isAuthorizedNoLog("/super_administrator");
  }catch(AuthorizationDeniedException ade){}
  String[] keyusagetexts=CertificateView.KEYUSAGETEXTS;
  int[] defaultavailablebitlengths=CertificateProfile.DEFAULTBITLENGTHS;
%>
<head>
  <title><c:out value="<%=globalconfiguration.getEjbcaTitle()%>" /></title>
  <base href="<%=ejbcawebbean.getBaseUrl()%>"/>
  <link rel="stylesheet" type="text/css" href="<%=ejbcawebbean.getCssFile()%>"/>
  <script type="text/javascript" src="<%=globalconfiguration.getAdminWebPath()%>ejbcajslib.js"></script>
</head>
<body>
<%
  RequestHelper.setDefaultCharacterEncoding(request);
  Map<String,String> requestMap=new HashMap<String,String>();
  byte[] filebuffer=cabean.parseRequestParameters(request,requestMap);
  String action=null;
  action=requestMap.get(ACTION);
  if(action!=null){
    if(action.equals(ACTION_EDIT_CPS)){
	  cp=request.getParameter(SELECT_CERTIFICATEPROFILES);
	  servicesWithCP=cabean.getServicesUsingCertificateProfile(cp);
	  numEEsWithCP=cabean.countEndEntitiesUsingCertificateProfile(cp);
	  if(numEEsWithCP>0&&numEEsWithCP<1000){
	    eentitiesWithCP=cabean.getEndEntitiesUsingCertificateProfile(cp);
	  }
	  eepsWithCP=cabean.getEndEntityProfilesUsingCertificateProfile(cp);
	  htpsWithCP=cabean.getHardTokenTokensUsingCertificateProfile(cp);
	  casWithCP=cabean.getCaUsingCertificateProfile(cp);
      if(request.getParameter(BUTTON_EDIT_CERTIFICATEPROFILES)!=null){
        if(cp!=null){
          cabean.setTempCertificateProfile(null);
          if(!cabean.cpNameEmpty(cp)){
            if(!cabean.cpFixed(cp)){
              includefile="certificateprofilepage.jspf";
            }else{
              triedtoeditfixcp=true;
              cp=null;
           	}
          }else{
            cp=null;
          }
        }
        if(cp==null){
          includefile="certificateprofilespage.jspf";
        }
      }
      if(request.getParameter(BUTTON_DELETE_CERTIFICATEPROFILES)!=null) {
        if(!cabean.cpNameEmpty(cp)){
          if(!cabean.cpFixed(cp)){
			if(!cabean.canDeleteCertProfile(cp,numEEsWithCP)){
      		  cpDeleteFailed=true;
      		}else{
      		  cabean.removeCertificateProfile(cp);
      		}
          }else{
            triedtodeletefixcp=true;
          }
        }
        includefile="certificateprofilespage.jspf";
      }
      if(request.getParameter(BUTTON_RENAME_CERTIFICATEPROFILES)!=null){
        String newcpname=request.getParameter(TEXTFIELD_CERTIFICATEPROFILESNAME);
       	String oldcpname=cp;
       	if(!cabean.cpNameEmpty(oldcpname)&&!cabean.cpNameEmpty(newcpname)){
          if(!cabean.cpFixed(oldcpname)){
            try{
              cabean.renameCertificateProfile(oldcpname.trim(),newcpname.trim());
            }catch(CertificateProfileExistsException e){
              cpexists=true;
            }
          }else{
            triedtoeditfixcp=true;
          }
       	}
       	includefile="certificateprofilespage.jspf";
      }
      if(request.getParameter(BUTTON_ADD_CERTIFICATEPROFILES)!=null){
        cp=request.getParameter(TEXTFIELD_CERTIFICATEPROFILESNAME);
        if(!cabean.cpNameEmpty(cp)){
          if(!cabean.cpFixed(cp)){
            try{
              cabean.addCertificateProfile(cp.trim());
            }catch(CertificateProfileExistsException e){cpexists=true;}
          }else{
            triedtoaddfixcp=true;
          }
        }
        includefile="certificateprofilespage.jspf";
      }
      if(request.getParameter(BUTTON_CLONE_CERTIFICATEPROFILES)!=null){
        String newcpname=request.getParameter(TEXTFIELD_CERTIFICATEPROFILESNAME);
       	String oldcpname=cp;
       	if(!cabean.cpNameEmpty(oldcpname)&&!cabean.cpNameEmpty(newcpname)){
          if(cabean.cpFixed(oldcpname)){
            oldcpname=oldcpname.substring(0,oldcpname.length()-8);
          }
          try{
            cabean.cloneCertificateProfile(oldcpname.trim(),newcpname.trim());
          }catch(CertificateProfileExistsException e){
            cpexists=true;
          }
       	}
        includefile="certificateprofilespage.jspf";
      }
    }
  	if(action.equals(ACTION_IMPORT_EXPORT)){
  	  try{
  	    if(requestMap.get(BUTTON_IMPORT_PROFILES)!=null){cabean.importProfilesFromZip(filebuffer);}
  	    if(requestMap.get(BUTTON_EXPORT_PROFILES)!=null){cabean.exportProfiles(requestMap.get(TEXTFIELD_EXPORT_DESTINATION));}
  	  }catch(Exception e){%><div style="color: #FF0000;"><c:out value="<%=e.getMessage()%>"/></div><%}
  	}
    if(action.equals(ACTION_EDIT_CP)){
      cp=request.getParameter(HIDDEN_CERTIFICATEPROFILENAME);
      if(!cabean.cpNameEmpty(cp)){
        CertificateProfile certprofiledata=cabean.getTempCertificateProfile();
        if(certprofiledata==null){
          certprofiledata=cabean.getCertificateProfile(cp);
        }
        CertificateProfile cpd=(CertificateProfile) certprofiledata.clone();
        String value=request.getParameter(TEXTFIELD_VALIDITY).trim();
        if(value!=null&&value.length()>0){
          final long validity=ValidityDate.encode(value);
          if(validity<0){
            throw new ParameterException(ejbcawebbean.getText("INVALIDVALIDITYORCERTEND"));
          }
          cpd.setValidity(validity);
        }
        boolean use=false;
        value=request.getParameter(CB_ALLOWVALIDITYOVERRIDE);
        if(value!=null){
          use=value.equals(CB_VALUE);
          cpd.setAllowValidityOverride(use);
        }else{
          cpd.setAllowValidityOverride(false);
        }     					
        value=request.getParameter(CB_ALLOWEXTENSIONOVERRIDE);
        if(value!=null){
          use=value.equals(CB_VALUE);
          cpd.setAllowExtensionOverride(use);
        }else{
          cpd.setAllowExtensionOverride(false);
        }
        value=request.getParameter(CB_ALLOWDNOVERRIDE);
        if(value!=null){
          use=value.equals(CB_VALUE);
          cpd.setAllowDNOverride(use);
        }else{
          cpd.setAllowDNOverride(false);
        }
        value=request.getParameter(CB_ALLOWCERTSERIALNUMBEROVERRIDE);
        if(value!=null&&cabean.isUniqueIndexForSerialNumber()){
          use=value.equals(CB_VALUE);
          cpd.setAllowCertSerialNumberOverride(use);
        }else{
          cpd.setAllowCertSerialNumberOverride(false);
        }
        value=request.getParameter(CB_BASICCONSTRAINTS);
        if(value!=null){
          use=value.equals(CB_VALUE);
          cpd.setUseBasicConstraints(use);
          value=request.getParameter(CB_BASICCONSTRAINTSCRITICAL);
          if(value!=null){
            cpd.setBasicConstraintsCritical(value.equals(CB_VALUE));
          }else{
            cpd.setBasicConstraintsCritical(false);
          }
        }else{
          cpd.setUseBasicConstraints(false);
          cpd.setBasicConstraintsCritical(false);
        }
        use=false;
        value=request.getParameter(CB_USEPATHLENGTHCONSTRAINT);
        if(value!=null){
          use=value.equals(CB_VALUE);
          cpd.setUsePathLengthConstraint(use);
          value=request.getParameter(TEXTFIELD_PATHLENGTHCONSTRAINT);
          if(value!=null){
            cpd.setPathLengthConstraint(Integer.parseInt(value));
          }
        }else{
          cpd.setUsePathLengthConstraint(false);
          cpd.setPathLengthConstraint(0); 
        }
        use=false;
        value=request.getParameter(CB_KEYUSAGE);
        if(value!=null){
          use=value.equals(CB_VALUE);
          cpd.setUseKeyUsage(use);
          value=request.getParameter(CB_KEYUSAGECRITICAL);
          if(value!=null)
            cpd.setKeyUsageCritical(value.equals(CB_VALUE));
          else
            cpd.setKeyUsageCritical(false);
        }else{
          cpd.setUseKeyUsage(false);
          cpd.setKeyUsageCritical(false);
        }
        use=false;
        value=request.getParameter(CB_SUBJECTKEYIDENTIFIER);
        if(value!=null){
          use=value.equals(CB_VALUE);
          cpd.setUseSubjectKeyIdentifier(use);
          value=request.getParameter(CB_SUBJECTKEYIDENTIFIERCRITICAL);
          if(value!=null)
            cpd.setSubjectKeyIdentifierCritical(value.equals(CB_VALUE));
          else
            cpd.setSubjectKeyIdentifierCritical(false);
        }else{
          cpd.setUseSubjectKeyIdentifier(false);
          cpd.setSubjectKeyIdentifierCritical(false);
        }
        use=false;
        value=request.getParameter(CB_AUTHORITYKEYIDENTIFIER);
        if(value!=null){
          use=value.equals(CB_VALUE);
          cpd.setUseAuthorityKeyIdentifier(use);
          value=request.getParameter(CB_AUTHORITYKEYIDENTIFIERCRITICAL); 
          if(value!=null)
            cpd.setAuthorityKeyIdentifierCritical(value.equals(CB_VALUE));
          else
            cpd.setAuthorityKeyIdentifierCritical(false);
        }else{
          cpd.setUseAuthorityKeyIdentifier(false);
          cpd.setAuthorityKeyIdentifierCritical(false);
        }
        use = false;
        value = request.getParameter(CB_SUBJECTALTERNATIVENAME);
        if(value!=null){
          use=value.equals(CB_VALUE);
          cpd.setUseSubjectAlternativeName(use);
          value=request.getParameter(CB_SUBJECTALTERNATIVENAMECRITICAL);
          if(value!=null)
            cpd.setSubjectAlternativeNameCritical(value.equals(CB_VALUE));
          else
            cpd.setSubjectAlternativeNameCritical(false);
        }else{
          cpd.setUseSubjectAlternativeName(false);
          cpd.setSubjectAlternativeNameCritical(false);
        }
        use=false;
        value=request.getParameter(CB_ISSUERALTERNATIVENAME);
        if(value!=null){
          use=value.equals(CB_VALUE);
          cpd.setUseIssuerAlternativeName(use);
          value=request.getParameter(CB_ISSUERALTERNATIVENAMECRITICAL);
          if(value!=null)
            cpd.setIssuerAlternativeNameCritical(value.equals(CB_VALUE));
          else
            cpd.setIssuerAlternativeNameCritical(false);
        }else{
          cpd.setUseIssuerAlternativeName(false);
          cpd.setIssuerAlternativeNameCritical(false);
        }
        use=false;
        value=request.getParameter(CB_USEDOCUMENTTYPE);
        if(value!=null){
          use=value.equals(CB_VALUE);
          cpd.setUseDocumentTypeList(use);
          value=request.getParameter(CB_DOCUMENTTYPECRITICAL);
          if(value!=null)
            cpd.setDocumentTypeListCritical(value.equals(CB_VALUE));
          else
            cpd.setDocumentTypeListCritical(false);
          value=request.getParameter(TEXTFIELD_DOCUMENTTYPE);
          if(use&&value!=null)
            cpd.setDocumentTypeList(cabean.getListFromString(value));
          else
            cpd.setDocumentTypeList(new ArrayList<String>());
        }else{
          cpd.setUseDocumentTypeList(false);
          cpd.setDocumentTypeListCritical(false);
          cpd.setDocumentTypeList(new ArrayList<String>());
        }
        value=request.getParameter(CB_SUBJECTDIRATTRIBUTES);
        if(value!=null){
          cpd.setUseSubjectDirAttributes(value.equals(CB_VALUE));
        }else{
          cpd.setUseSubjectDirAttributes(false);
        }
        value=request.getParameter(CB_NAMECONSTRAINTS);
        if(value!=null){
          cpd.setUseNameConstraints(value.equals(CB_VALUE));
          value=request.getParameter(CB_NAMECONSTRAINTSCRITICAL);
          if(value!=null)
            cpd.setNameConstraintsCritical(value.equals(CB_VALUE));
          else
            cpd.setNameConstraintsCritical(false);
        } else {
          cpd.setUseNameConstraints(false);
          cpd.setNameConstraintsCritical(false);
        }
        use=false;
        value=request.getParameter(CB_CRLDISTRIBUTIONPOINT);
        if(value!=null){
          use=value.equals(CB_VALUE);
          cpd.setUseCRLDistributionPoint(use);
          value=request.getParameter(CB_CRLDISTRIBUTIONPOINTCRITICAL);
          if(value!=null)
            cpd.setCRLDistributionPointCritical(value.equals(CB_VALUE));
          else
            cpd.setCRLDistributionPointCritical(false);
          value=request.getParameter(CB_USEDEFAULTCRLDISTRIBUTIONPOINT);
          if(value!=null)
            cpd.setUseDefaultCRLDistributionPoint(value.equals(CB_VALUE));
          else
            cpd.setUseDefaultCRLDistributionPoint(false);
          value=request.getParameter(TEXTFIELD_CRLDISTURI);
          if(value!=null&&!cpd.getUseDefaultCRLDistributionPoint()){
            value=value.trim();
            cpd.setCRLDistributionPointURI(value);
          }
          value=request.getParameter(TEXTFIELD_CRLISSUER);
          if(value!=null&&!cpd.getUseDefaultCRLDistributionPoint()){
            value=value.trim();
            cpd.setCRLIssuer(value);
          }
        }else{
          cpd.setUseCRLDistributionPoint(false);
          cpd.setCRLDistributionPointCritical(false);
          cpd.setCRLDistributionPointURI("");
        }
        use=false;
        value=request.getParameter(CB_USECERTIFICATEPOLICIES);
        if(value!=null) {
          use=value.equals(CB_VALUE);
          cpd.setUseCertificatePolicies(use);
          value=request.getParameter(CB_CERTIFICATEPOLICIESCRITICAL);
          if(value!=null){
		    cpd.setCertificatePoliciesCritical(value.equals(CB_VALUE));
          }else{
			cpd.setCertificatePoliciesCritical(false);
          }
		  value=request.getParameter(TEXTFIELD_CERTIFICATEPOLICYID);
		  String userNotice=request.getParameter(TEXTAREA_POLICYNOTICE_UNOTICE);
		  String cpsUri=request.getParameter(TEXTFIELD_POLICYNOTICE_CPSURL);
          if((value!=null)&&(value.trim().length()>0)){
            boolean added=false;
            if(userNotice!=null){
              userNotice=userNotice.trim();
              if(userNotice.length()>0){
                cpd.addCertificatePolicy(new CertificatePolicy(value.trim(),CertificatePolicy.id_qt_unotice,userNotice));
                added=true;
              }
            }
            if(cpsUri!=null){
              cpsUri=cpsUri.trim();
              if(cpsUri.length()>0){
                cpd.addCertificatePolicy(new CertificatePolicy(value.trim(),CertificatePolicy.id_qt_cps,cpsUri));
                added=true;
              }
            }
            if(!added){
              cpd.addCertificatePolicy(new CertificatePolicy(value.trim(),null,null));
            }
          }
        }else{
          cpd.setUseCertificatePolicies(false);
          cpd.setCertificatePoliciesCritical(false);
          cpd.setCertificatePolicies(null);
        }
        String[] values=request.getParameterValues(SELECT_AVAILABLEBITLENGTHS);
        if(values!=null){
          int[] abl=new int[values.length];
          for(int i=0;i<values.length;i++){
            abl[i]=Integer.parseInt(values[i]);
          }
          cpd.setAvailableBitLengths(abl);
        }
        value=request.getParameter(SELECT_SIGNATUREALGORITHM);
        value=value.trim();
        if(value!=null){
          if(value.equals(INHERITFROMCA)){
            cpd.setSignatureAlgorithm(null);
          }else{
            cpd.setSignatureAlgorithm(value);
          }
        }
        values=request.getParameterValues(SELECT_KEYUSAGE);
        boolean[] ku=new boolean[keyusagetexts.length];
        if(values!=null){
          for(int i=0;i<values.length;i++){
            ku[Integer.parseInt(values[i])]=true;
          }
        }
        cpd.setKeyUsage(ku);
        value=request.getParameter(CB_USEEXTENDEDKEYUSAGE);
        if(value!=null&&value.equals(CB_VALUE)){
          cpd.setUseExtendedKeyUsage(true);
          value=request.getParameter(CB_EXTENDEDKEYUSAGECRITICAL);
          if(value!=null)
            cpd.setExtendedKeyUsageCritical(value.equals(CB_VALUE));
          else
            cpd.setExtendedKeyUsageCritical(false);
          values=request.getParameterValues(SELECT_EXTENDEDKEYUSAGE);
          ArrayList eku=new ArrayList();
          if(values!=null){
            for(int i=0;i<values.length;i++){
              eku.add(values[i]);
            }
          }
          cpd.setExtendedKeyUsage(eku);
        }else{
          cpd.setUseExtendedKeyUsage(false);
          cpd.setExtendedKeyUsageCritical(false);
          cpd.setExtendedKeyUsage(new ArrayList());
        }
        value=request.getParameter(SELECT_CVCTERMTYPE);
        int termtype=CertificateProfile.CVC_TERMTYPE_IS;
        if(value!=null){
          termtype=Integer.parseInt(value);
        }
        cpd.setCVCTerminalType(termtype);                        
        value=request.getParameter(SELECT_CVCSIGNTERMDVTYPE);
        int dvtype=CertificateProfile.CVC_SIGNTERM_DV_AB;
        if(value!=null){
          dvtype=Integer.parseInt(value);
        }
        cpd.setCVCSignTermDVType(dvtype);
        switch(termtype){
          case CertificateProfile.CVC_TERMTYPE_IS:
          case CertificateProfile.CVC_TERMTYPE_ST:
            values=request.getParameterValues(SELECT_CVCACCESSRIGHTS);
            if(values==null){values=new String[0];}
            int ar=0;
            for(int i=0;i<values.length;i++){
              int bit=Integer.parseInt(values[i]);
              boolean isIS=(termtype==CertificateProfile.CVC_TERMTYPE_IS);
              if((isIS&&(bit==CertificateProfile.CVC_ACCESS_DG3||bit==CertificateProfile.CVC_ACCESS_DG4))||
            		  (!isIS&&(bit==CertificateProfile.CVC_ACCESS_SIGN||bit==CertificateProfile.CVC_ACCESS_QUALSIGN))){
                ar|=bit;
              }
            }
            cpd.setCVCAccessRights(ar);
            cpd.setCVCLongAccessRights(null);
            break;
          case CertificateProfile.CVC_TERMTYPE_AT:
            values=request.getParameterValues(SELECT_CVCACCESSRIGHTS);
            if(values==null){values=new String[0];}
            AccessRightAuthTerm atrights=new AccessRightAuthTerm();
            for(int i=0;i<values.length;i++){
              atrights.setFlag(Integer.parseInt(values[i]),true);
            }
            cpd.setCVCAccessRights(0);
            cpd.setCVCLongAccessRights(atrights.getEncoded());
            break;
        }
        value=request.getParameter(SELECT_TYPE);
        int type=CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER;
        if(value!=null){
          type=Integer.parseInt(value);
        }
        cpd.setType(type);
		value=request.getParameter(CB_ALLOWKEYUSAGEOVERRIDE);
        if(value!=null){
          use=value.equals(CB_VALUE);
          cpd.setAllowKeyUsageOverride(use);
        }else{
          cpd.setAllowKeyUsageOverride(false);
        }
        {
          final String v=request.getParameter(CB_ALLOWBACKDATEDREVOCATION);
          cpd.setAllowBackdatedRevocation(v!=null&&v.equals(CB_VALUE) );
        }
        values=request.getParameterValues(SELECT_AVAILABLECAS);
        ArrayList availablecas=new ArrayList();
        if(values!=null){
          for(int i=0;i<values.length;i++){
            if(Integer.parseInt(values[i])==CertificateProfile.ANYCA){
              availablecas=new ArrayList();
              availablecas.add(Integer.valueOf(CertificateProfile.ANYCA));
              break;
            }
            availablecas.add(Integer.valueOf(values[i]));
          }
        }
        cpd.setAvailableCAs(availablecas);
        values=request.getParameterValues(SELECT_AVAILABLEPUBLISHERS);
        ArrayList availablepublishers=new ArrayList();
        if(values!=null){
          for(int i=0;i< values.length;i++){
            availablepublishers.add(Integer.valueOf(values[i]));
          }
        }
        cpd.setPublisherList(availablepublishers);
        use=false;
        value=request.getParameter(CB_USEOCSPNOCHECK);
        if(value!=null){
          use=value.equals(CB_VALUE);
          cpd.setUseOcspNoCheck(use);
        }else{
          cpd.setUseOcspNoCheck(false);
        }
        use=false;
        value=request.getParameter(CB_USEAUTHORITYINFORMATIONACCESS);
        if(value!=null){
          use=value.equals(CB_VALUE);
          cpd.setUseAuthorityInformationAccess(use);
          value=request.getParameter(CB_USEDEFAULTOCSPSERVICELOCALTOR);
          if(value!=null){
            cpd.setUseDefaultOCSPServiceLocator(value.equals(CB_VALUE));
          }else{
            cpd.setUseDefaultOCSPServiceLocator(false);
          }
          value=request.getParameter(TEXTFIELD_OCSPSERVICELOCATOR);
          if(value!=null&&!cpd.getUseDefaultOCSPServiceLocator()){
            value=value.trim();
            cpd.setOCSPServiceLocatorURI(value);
          }
          value=request.getParameter(TEXTFIELD_CAISSUERURI);
          if(value!=null){
            cpd.addCaIssuer(value);
          }
        }else{
          cpd.setUseAuthorityInformationAccess(false);
          cpd.setCaIssuers(null);
          cpd.setOCSPServiceLocatorURI("");
        }
        use=false;
        value=request.getParameter(CB_USEFRESHESTCRL);
        if(value!=null){
          use=value.equals(CB_VALUE);
          cpd.setUseFreshestCRL(use);
          value=request.getParameter(CB_USECADEFINEDFRESHESTCRL);
          if(value!=null){
            cpd.setUseCADefinedFreshestCRL(value.equals(CB_VALUE));
          }else{
            cpd.setUseCADefinedFreshestCRL(false);
          }
          value=request.getParameter(TEXTFIELD_FRESHESTCRLURI);
          if(value!=null&&!cpd.getUseCADefinedFreshestCRL()){
            value=value.trim();
            cpd.setFreshestCRLURI(value);
          }
        }else{
          cpd.setUseFreshestCRL(false);                 
          cpd.setFreshestCRLURI("");
        }
        use=false;
        value=request.getParameter(CB_USELDAPDNORDER);
        if(value!=null){
          use=value.equals(CB_VALUE);
          cpd.setUseLdapDnOrder(use);
        }else{
          cpd.setUseLdapDnOrder(false);
        }
        use=false;
        value=request.getParameter(CB_USEMSTEMPLATE);
        if(value!=null){
          use=value.equals(CB_VALUE);
          cpd.setUseMicrosoftTemplate(use);
          value=request.getParameter(SELECT_MSTEMPLATE);
          if(value!=null){
            value=value.trim();
            cpd.setMicrosoftTemplate(value);
          }
        }else{
          cpd.setUseMicrosoftTemplate(false);
          cpd.setMicrosoftTemplate("");
        }
        use=false;
        value=request.getParameter(CB_USECARDNUMBER);
        if(value!=null) {
          use=value.equals(CB_VALUE);
          cpd.setUseCardNumber(use);
        }else{
          cpd.setUseCardNumber(false);
        }
        use=false;
        value=request.getParameter(CB_USECNPOSTFIX);
        if(value!=null){
          use=value.equals(CB_VALUE);
          cpd.setUseCNPostfix(use);
          value=request.getParameter(TEXTFIELD_CNPOSTFIX);
          if(value!=null){
            cpd.setCNPostfix(value);
          }
        }else{
          cpd.setUseCNPostfix(false);
          cpd.setCNPostfix("");
        }
        use=false;
        value=request.getParameter(CB_USESUBJECTDNSUBSET);
        if(value!=null){
          use=value.equals(CB_VALUE);
          cpd.setUseSubjectDNSubSet(use);
          values=request.getParameterValues(SELECT_SUBJECTDNSUBSET);
          if(values!=null){
            ArrayList usefields=new ArrayList();
            for(int i=0;i<values.length;i++){
              usefields.add(Integer.valueOf(values[i]));
            }
            cpd.setSubjectDNSubSet(usefields);
          }
        }else{
          cpd.setUseSubjectDNSubSet(false);
          cpd.setSubjectDNSubSet(new ArrayList());
        }
        use=false;
        value=request.getParameter(CB_USESUBJECTALTNAMESUBSET);
        if(value!=null){
          use=value.equals(CB_VALUE);
          cpd.setUseSubjectAltNameSubSet(use);
          values=request.getParameterValues(SELECT_SUBJECTALTNAMESUBSET);
          if(values!=null){
            ArrayList usefields=new ArrayList();
            for(int i=0;i<values.length;i++){
              usefields.add(Integer.valueOf(values[i]));
            }
            cpd.setSubjectAltNameSubSet(usefields);
          }
        }else{
          cpd.setUseSubjectAltNameSubSet(false);
          cpd.setSubjectAltNameSubSet(new ArrayList());
        }
        values=request.getParameterValues(SELECT_USEDCERTIFICATEEXTENSIONS);
        if(values!=null){
          ArrayList useextensions=new ArrayList();
          for(int i=0;i<values.length;i++){
            useextensions.add(Integer.valueOf(values[i]));
          }
          cpd.setUsedCertificateExtensions(useextensions);
        }else{
          ArrayList useextensions=new ArrayList();
          cpd.setUsedCertificateExtensions(useextensions);
        }
        value=request.getParameter(CB_USEPRIVKEYUSAGEPERIODNOTBEFORE);
        if(value!=null) {
          use=value.equals(CB_VALUE);
          cpd.setUsePrivateKeyUsagePeriodNotBefore(use);
          if(use){
		    value=request.getParameter(TEXTFIELD_PRIVKEYUSAGEPERIODSTARTOFFSET);
		    if(value!=null){
		      value=value.trim();
		      if(value.length()>0){
		        final long validity=ValidityDate.encode(value);
		        if(validity<0) {
		          throw new ParameterException(ejbcawebbean.getText("INVALIDPRIVKEYSTARTOFFSET"));
		        }
		        cpd.setPrivateKeyUsagePeriodStartOffset(validity*24*3600);
		      }
		    }
          }
        }else{
          cpd.setUsePrivateKeyUsagePeriodNotBefore(false);
        }
        value=request.getParameter(CB_USEPRIVKEYUSAGEPERIODNOTAFTER);
        if(value!=null){
          use=value.equals(CB_VALUE);
          cpd.setUsePrivateKeyUsagePeriodNotAfter(use);
          if(use){
		    value=request.getParameter(TEXTFIELD_PRIVKEYUSAGEPERIODLENGTH);
		    if(value!=null){
		      value=value.trim();
		      if(value.length()>0){
			    final long validity=ValidityDate.encode(value);
			    if(validity<0){
			      throw new ParameterException(ejbcawebbean.getText("INVALIDPRIVKEYPERIOD"));
			    }
			    cpd.setPrivateKeyUsagePeriodLength(validity*24*3600);
		      }
		    }
          }
        }else{
          cpd.setUsePrivateKeyUsagePeriodNotAfter(false);
        }
        cpd.setUseQCStatement(false);
        cpd.setQCStatementCritical(false);
        cpd.setUsePkixQCSyntaxV2(false);
        cpd.setUseQCEtsiQCCompliance(false);
        cpd.setUseQCEtsiSignatureDevice(false);
        cpd.setUseQCEtsiValueLimit(false);
        cpd.setUseQCEtsiRetentionPeriod(false);
        cpd.setQCSemanticsId("");
        cpd.setQCStatementRAName("");
        cpd.setQCEtsiValueLimit(0);
        cpd.setQCEtsiValueLimitExp(0);
        cpd.setQCEtsiValueLimitCurrency("");
        cpd.setQCEtsiRetentionPeriod(0);
        cpd.setUseQCCustomString(false);
        cpd.setQCCustomStringOid("");
        cpd.setQCCustomStringText("");
        value=request.getParameter(CB_USEQCSTATEMENT);
        if(value!=null){
          cpd.setUseQCStatement(value.equals(CB_VALUE));
          if(cpd.getUseQCStatement()){
            value=request.getParameter(CB_QCSTATEMENTCRITICAL);
            if(value!=null) {
              cpd.setQCStatementCritical(value.equals(CB_VALUE));
            }
            value=request.getParameter(CB_USEPKIXQCSYNTAXV2);
            if(value!=null) {
              cpd.setUsePkixQCSyntaxV2(value.equals(CB_VALUE));
            }
            value=request.getParameter(CB_USEQCETSIQCCOMPLIANCE);
            if(value!=null) {
              cpd.setUseQCEtsiQCCompliance(value.equals(CB_VALUE));
            }
            value=request.getParameter(CB_USEQCETSISIGNATUREDEVICE);
            if(value!=null) {
              cpd.setUseQCEtsiSignatureDevice(value.equals(CB_VALUE));
            }
            value=request.getParameter(CB_USEQCETSIVALUELIMIT);
            if(value!=null) {
              cpd.setUseQCEtsiValueLimit(value.equals(CB_VALUE));
              cpd.setQCEtsiValueLimit(Integer.valueOf(request.getParameter(TEXTFIELD_QCETSIVALUELIMIT)).intValue());
              cpd.setQCEtsiValueLimitExp(Integer.valueOf(request.getParameter(TEXTFIELD_QCETSIVALUELIMITEXP)).intValue());
              cpd.setQCEtsiValueLimitCurrency(request.getParameter(TEXTFIELD_QCETSIVALUELIMITCUR));
            }
            value=request.getParameter(CB_USEQCETSIRETENTIONPERIOD);
            if(value!=null) {
              cpd.setUseQCEtsiRetentionPeriod(value.equals(CB_VALUE));
              cpd.setQCEtsiRetentionPeriod(Integer.valueOf(request.getParameter(TEXTFIELD_QCETSIRETENTIONPERIOD)).intValue());
            }
            value=request.getParameter(CB_USEQCCUSTOMSTRING);
            if(value!=null) {
              cpd.setUseQCCustomString(value.equals(CB_VALUE));
              cpd.setQCCustomStringOid(request.getParameter(TEXTFIELD_QCCUSTOMSTRINGOID));
              cpd.setQCCustomStringText(request.getParameter(TEXTFIELD_QCCUSTOMSTRINGTEXT));
            }
            cpd.setQCSemanticsId(request.getParameter(TEXTFIELD_QCSSEMANTICSID));
            cpd.setQCStatementRAName(request.getParameter(TEXTFIELD_QCSTATEMENTRANAME));
          }
        }
        boolean useCTInCerts=false;
        value=request.getParameter(CB_USECERTIFICATETRANSPARENCYINCERTS);
        if(value!=null){useCTInCerts=value.equals(CB_VALUE);}
        boolean useCTInOCSP=false;
        value=request.getParameter(CB_USECERTIFICATETRANSPARENCYINOCSP);
        if(value!=null){useCTInOCSP=value.equals(CB_VALUE);}
        cpd.setUseCertificateTransparencyInCerts(useCTInCerts);
        cpd.setUseCertificateTransparencyInOCSP(useCTInOCSP);
        if(useCTInCerts||useCTInOCSP){
          values=request.getParameterValues(SELECT_CTLOGS);
          Set<Integer> enabledLogs=new LinkedHashSet<Integer>();
          if(values!=null){
            for(String selected:values){
              enabledLogs.add(Integer.valueOf(selected));
            }
          }
          cpd.setEnabledCTLogs(enabledLogs);
          int minSCTs=Integer.parseInt(request.getParameter(TEXTFIELD_CTMINSCTS));
          if (minSCTs>enabledLogs.size()) {
            throw new ParameterException(ejbcawebbean.getText("TOOMANYREQUIREDCTLOGS"));
          }
          cpd.setCTMinSCTs(minSCTs);
          cpd.setCTMaxSCTs(Integer.parseInt(request.getParameter(TEXTFIELD_CTMAXSCTS)));
          cpd.setCTMaxRetries(Integer.parseInt(request.getParameter(TEXTFIELD_CTMAXRETRIES)));
        }
        values=request.getParameterValues(SELECT_APPROVALSETTINGS);
        ArrayList approvalsettings=new ArrayList();
        if(values!=null){
          for(int i=0;i<values.length;i++){
            approvalsettings.add(Integer.valueOf(values[i]));
          }
        }
		cpd.setApprovalSettings(approvalsettings);
		value=request.getParameter(SELECT_NUMOFREQUIREDAPPROVALS);
		int numofreqapprovals=1;
		if(value!=null){
		  numofreqapprovals=Integer.parseInt(value);
		}
		cpd.setNumOfReqApprovals(numofreqapprovals);
        if(request.getParameter(BUTTON_SAVE)!=null){
          cabean.changeCertificateProfile(cp,cpd);
          cabean.setTempCertificateProfile(null);
          includefile="certificateprofilespage.jspf";
        }
        if(request.getParameter(BUTTON_ADD_POLICY)!=null){
  	      cabean.setTempCertificateProfile(cpd);
          includefile="certificateprofilepage.jspf";
        }
        if(cpd.getCertificatePolicies()!=null){
          boolean removed=false;
          for(int i=0;i<cpd.getCertificatePolicies().size();i++){
            value=request.getParameter(BUTTON_DELETE_POLICY+i);
            if(value!=null){
              removed=true;
              String policyId=request.getParameter(TEXTFIELD_CERTIFICATEPOLICYID+i);
              if(policyId!=null){
                policyId=policyId.trim();
              }
              String userNotice=request.getParameter(TEXTAREA_POLICYNOTICE_UNOTICE+i);
              if ((userNotice!=null)&&(userNotice.trim().length()>0)){
                userNotice=userNotice.trim();
                CertificatePolicy policy=new CertificatePolicy(policyId,CertificatePolicy.id_qt_unotice,userNotice);
                cpd.removeCertificatePolicy(policy);
              }
              String cpsUri=request.getParameter(TEXTFIELD_POLICYNOTICE_CPSURL+i);
              if((cpsUri!=null)&&(cpsUri.trim().length()>0)){
                cpsUri=cpsUri.trim();
                CertificatePolicy policy=new CertificatePolicy(policyId,CertificatePolicy.id_qt_cps,cpsUri);
                cpd.removeCertificatePolicy(policy);
              }
              if(((userNotice==null)||(userNotice.trim().length()==0))&&
                  ((cpsUri==null)||(cpsUri.trim().length()==0))&&(policyId!=null)){
                CertificatePolicy policy=new CertificatePolicy(policyId,null,null);
                cpd.removeCertificatePolicy(policy);
              }
              cabean.setTempCertificateProfile(cpd);
            }
          }
          if(removed){
            includefile="certificateprofilepage.jspf";
          }
        }
        if(request.getParameter(BUTTON_ADD_CAISSUERURI)!=null){
    	  cabean.setTempCertificateProfile(cpd);
          includefile="certificateprofilepage.jspf";
        }
        if(cpd.getCaIssuers()!=null){
          for(int i=0;i<cpd.getCaIssuers().size();i++){
            value=request.getParameter(BUTTON_DELETE_CAISSUERURI+i);
            if(value!=null){
              cpd.removeCaIssuer(request.getParameter(TEXTFIELD_CAISSUERURI+i));
              cabean.setTempCertificateProfile(cpd);
              includefile="certificateprofilepage.jspf";
            }
          }
        }
        if(request.getParameter(BUTTON_CANCEL)!=null){
          cabean.setTempCertificateProfile(null);
          includefile="certificateprofilespage.jspf";
        }
        if(includefile==null){
          includefile="certificateprofilespage.jspf";
        }
      }
    }
  }
  if(includefile.equals("certificateprofilepage.jspf")){
%>
   <%@ include file="certificateprofilepage.jspf" %>
<%}
  if(includefile.equals("certificateprofilespage.jspf")){ %>
   <%@ include file="certificateprofilespage.jspf" %>
<%}
   String footurl=globalconfiguration.getFootBanner();%>
  <jsp:include page="<%=footurl%>"/>
</body>
</html>