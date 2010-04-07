/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
 
package org.ejbca.core.model.ca.certificateprofiles;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.ejbca.config.ExtendedKeyUsageConfiguration;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.UpgradeableDataHashMap;
import org.ejbca.util.CertTools;
import org.ejbca.util.dn.DNFieldExtractor;

/**
 * CertificateProfile is a basic class used to customize a certificate
 * configuration or be inherited by fixed certificate profiles.
 *
 * @version $Id$
 */
public class CertificateProfile extends UpgradeableDataHashMap implements Serializable, Cloneable {
    private static final Logger log = Logger.getLogger(CertificateProfile.class);
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    // Default Values
    public static final float LATEST_VERSION = (float) 34.0;

    /**
     * Determines if a de-serialized file is compatible with this class.
     *
     * Maintainers must change this value if and only if the new version
     * of this class is not compatible with old versions. See Sun docs
     * for <a href=http://java.sun.com/products/jdk/1.1/docs/guide
     * /serialization/spec/version.doc.html> details. </a>
     *
     */
    private static final long serialVersionUID = -8069608639716545206L;

    /** KeyUsage constants */
    public static final int DIGITALSIGNATURE = 0;
    public static final int NONREPUDIATION   = 1;
    public static final int KEYENCIPHERMENT  = 2;
    public static final int DATAENCIPHERMENT = 3;
    public static final int KEYAGREEMENT     = 4;
    public static final int KEYCERTSIGN      = 5;
    public static final int CRLSIGN          = 6;
    public static final int ENCIPHERONLY     = 7;
    public static final int DECIPHERONLY     = 8;

    /** Returns a List<String> of all extended key usage oids, as strings */
    public static List getAllExtendedKeyUsageOIDStrings() {
    	return ExtendedKeyUsageConfiguration.getExtendedKeyUsageOids();
    }
    /** Returns a Map<String, String> that maps oid string to displayable/translatable text strings */
    public static Map getAllExtendedKeyUsageTexts() {
    	return ExtendedKeyUsageConfiguration.getExtendedKeyUsageOidsAndNames();
    }

	/** Microsoft Template Constants */
	public static final String MSTEMPL_DOMAINCONTROLLER  = "DomainController";
	
	public static final String[] AVAILABLE_MSTEMPLATES = {MSTEMPL_DOMAINCONTROLLER};
    
    public static final String TRUE  = "true";
    public static final String FALSE = "false";

    public static final int TYPE_ENDENTITY  = SecConst.CERTTYPE_ENDENTITY;
    public static final int TYPE_SUBCA      = SecConst.CERTTYPE_SUBCA;
    public static final int TYPE_ROOTCA     = SecConst.CERTTYPE_ROOTCA;
    public static final int NUMBER_OF_TYPES = 3;

    /** Determines the access rights in CV Certificates. CV Certificates is used by EU EAC ePassports and
     * is issued by a CVC CA. DG3 is access to fingerprints and DG4 access to iris.
     */
    public static final int CVC_ACCESS_NONE = 0;
    public static final int CVC_ACCESS_DG3 = 1;
    public static final int CVC_ACCESS_DG4 = 2;
    public static final int CVC_ACCESS_DG3DG4 = 3;
    
    /** Supported certificate versions. */
    public static final String VERSION_X509V3 = "X509v3";
    public static final String CERTIFICATEPROFILENAME =  "CUSTOM";
    
    /** Constant indicating that any CA can be used with this certificate profile.*/
    public static final int ANYCA = -1;

    /** Constant holding the default available bit lengths for certificate profiles */
    public static final int[] DEFAULTBITLENGTHS= {0,192,239,256,384,512,1024,2048,4096};
    
    // Profile fields
    protected static final String CERTVERSION                    = "certversion";
    protected static final String VALIDITY                       = "validity";
    protected static final String ALLOWVALIDITYOVERRIDE          = "allowvalidityoverride";
    protected static final String ALLOWKEYUSAGEOVERRIDE          = "allowkeyusageoverride";
    protected static final String ALLOWEXTENSIONOVERRIDE         = "allowextensionoverride";
    protected static final String ALLOWDNOVERRIDE                = "allowdnoverride";
    protected static final String AVAILABLEBITLENGTHS            = "availablebitlengths";
    protected static final String MINIMUMAVAILABLEBITLENGTH      = "minimumavailablebitlength";
    protected static final String MAXIMUMAVAILABLEBITLENGTH      = "maximumavailablebitlength";
    public    static final String TYPE                           = "type";
    protected static final String AVAILABLECAS                   = "availablecas";
    protected static final String USEDPUBLISHERS                 = "usedpublishers";         
	protected static final String USECNPOSTFIX                   = "usecnpostfix";
	protected static final String CNPOSTFIX                      = "cnpostfix";	
	protected static final String USESUBJECTDNSUBSET             = "usesubjectdnsubset";
	protected static final String SUBJECTDNSUBSET                = "subjectdnsubset";
	protected static final String USESUBJECTALTNAMESUBSET        = "usesubjectaltnamesubset";
	protected static final String SUBJECTALTNAMESUBSET           = "subjectaltnamesubset";
    protected static final String USEDCERTIFICATEEXTENSIONS      = "usedcertificateextensions";
    protected static final String APPROVALSETTINGS				 = "approvalsettings";
    protected static final String NUMOFREQAPPROVALS				 = "numofreqapprovals";
    protected static final String SIGNATUREALGORITHM             = "signaturealgorithm";
    //
    // CRL extensions
    protected static final String USECRLNUMBER                   = "usecrlnumber";
    protected static final String CRLNUMBERCRITICAL              = "crlnumbercritical";
    protected static final String USECRLDISTRIBUTIONPOINTONCRL   = "usecrldistributionpointoncrl";
    //
    // Certificate extensions
    protected static final String USEBASICCONSTRAINTS            = "usebasicconstrants";
    protected static final String BASICCONSTRAINTSCRITICAL       = "basicconstraintscritical";
	protected static final String USEPATHLENGTHCONSTRAINT        = "usepathlengthconstraint";
	protected static final String PATHLENGTHCONSTRAINT           = "pathlengthconstraint";
    protected static final String USEKEYUSAGE                    = "usekeyusage";
    protected static final String KEYUSAGECRITICAL               = "keyusagecritical";
    protected static final String KEYUSAGE                       = "keyusage";
    protected static final String USESUBJECTKEYIDENTIFIER        = "usesubjectkeyidentifier";
    protected static final String SUBJECTKEYIDENTIFIERCRITICAL   = "subjectkeyidentifiercritical";
    protected static final String USEAUTHORITYKEYIDENTIFIER      = "useauthoritykeyidentifier";
    protected static final String AUTHORITYKEYIDENTIFIERCRITICAL = "authoritykeyidentifiercritical";
    protected static final String USESUBJECTALTERNATIVENAME      = "usesubjectalternativename";
    protected static final String SUBJECTALTERNATIVENAMECRITICAL = "subjectalternativenamecritical";
    protected static final String USECRLDISTRIBUTIONPOINT        = "usecrldistributionpoint";
    protected static final String USEDEFAULTCRLDISTRIBUTIONPOINT = "usedefaultcrldistributionpoint";
    protected static final String CRLDISTRIBUTIONPOINTCRITICAL   = "crldistributionpointcritical";
    protected static final String CRLDISTRIBUTIONPOINTURI        = "crldistributionpointuri";
    protected static final String CRLISSUER                      = "crlissuer";
    protected static final String USEFRESHESTCRL                 = "usefreshestcrl";
    protected static final String USECADEFINEDFRESHESTCRL        = "usecadefinedfreshestcrl";
    protected static final String FRESHESTCRLURI                 = "freshestcrluri";    
    protected static final String USECERTIFICATEPOLICIES         = "usecertificatepolicies";
    protected static final String CERTIFICATEPOLICIESCRITICAL    = "certificatepoliciescritical";
    /** Policy containing oid, User Notice and Cps Url */
    protected static final String CERTIFICATE_POLICIES           = "certificatepolicies";
    protected static final String USEEXTENDEDKEYUSAGE            = "useextendedkeyusage";
    protected static final String EXTENDEDKEYUSAGE               = "extendedkeyusage";
    protected static final String EXTENDEDKEYUSAGECRITICAL       = "extendedkeyusagecritical";
    protected static final String USEOCSPNOCHECK                 = "useocspnocheck";
    protected static final String USEAUTHORITYINFORMATIONACCESS  = "useauthorityinformationaccess";
	protected static final String USEOCSPSERVICELOCATOR          = "useocspservicelocator";
	protected static final String USEDEFAULTOCSPSERVICELOCATOR   = "usedefaultocspservicelocator";	
	protected static final String OCSPSERVICELOCATORURI          = "ocspservicelocatoruri";
    protected static final String USECAISSUERS                   = "usecaissuersuri";
    protected static final String CAISSUERS                      = "caissuers";
    protected static final String USELDAPDNORDER                 = "useldapdnorder";
    protected static final String USEMICROSOFTTEMPLATE           = "usemicrosofttemplate";
	protected static final String MICROSOFTTEMPLATE              = "microsofttemplate";
	protected static final String USECARDNUMBER                 = "usecardnumber";
    protected static final String USEQCSTATEMENT                 = "useqcstatement";
    protected static final String USEPKIXQCSYNTAXV2              = "usepkixqcsyntaxv2";
    protected static final String QCSTATEMENTCRITICAL            = "useqcstatementcritical";
    protected static final String QCSTATEMENTRANAME              = "useqcstatementraname";
    protected static final String QCSSEMANTICSID                 = "useqcsematicsid";
    protected static final String USEQCETSIQCCOMPLIANCE          = "useqcetsiqccompliance";
    protected static final String USEQCETSIVALUELIMIT            = "useqcetsivaluelimit";
    protected static final String QCETSIVALUELIMIT               = "qcetsivaluelimit";
    protected static final String QCETSIVALUELIMITEXP            = "qcetsivaluelimitexp";
    protected static final String QCETSIVALUELIMITCURRENCY       = "qcetsivaluelimitcurrency";
    protected static final String USEQCETSIRETENTIONPERIOD       = "useqcetsiretentionperiod";
    protected static final String QCETSIRETENTIONPERIOD          = "qcetsiretentionperiod";
    protected static final String USEQCETSISIGNATUREDEVICE       = "useqcetsisignaturedevice";
    protected static final String USEQCCUSTOMSTRING              = "useqccustomstring";
    protected static final String QCCUSTOMSTRINGOID              = "qccustomstringoid";
    protected static final String QCCUSTOMSTRINGTEXT             = "qccustomstringtext";
    protected static final String USESUBJECTDIRATTRIBUTES        = "usesubjectdirattributes";
    protected static final String CVCACCESSRIGHTS                = "cvcaccessrights";
    
    /** OID for creating Smartcard Number Certificate Extension
     *  SEIS Cardnumber Extension according to SS 614330/31 */
    public static final String OID_CARDNUMBER= "1.2.752.34.2.1";

    /** Constants holding the use properties for certificate extensions */
    protected static final HashMap useStandardCertificateExtensions = new HashMap();
    {
    	useStandardCertificateExtensions.put(USEBASICCONSTRAINTS,X509Extensions.BasicConstraints.getId());
    	useStandardCertificateExtensions.put(USEKEYUSAGE,X509Extensions.KeyUsage.getId());
    	useStandardCertificateExtensions.put(USESUBJECTKEYIDENTIFIER,X509Extensions.SubjectKeyIdentifier.getId());
    	useStandardCertificateExtensions.put(USEAUTHORITYKEYIDENTIFIER,X509Extensions.AuthorityKeyIdentifier.getId());
    	useStandardCertificateExtensions.put(USESUBJECTALTERNATIVENAME,X509Extensions.SubjectAlternativeName.getId());
    	useStandardCertificateExtensions.put(USECRLDISTRIBUTIONPOINT,X509Extensions.CRLDistributionPoints.getId());
    	useStandardCertificateExtensions.put(USEFRESHESTCRL,X509Extensions.FreshestCRL.getId());
    	useStandardCertificateExtensions.put(USECERTIFICATEPOLICIES,X509Extensions.CertificatePolicies.getId());
    	useStandardCertificateExtensions.put(USEEXTENDEDKEYUSAGE,X509Extensions.ExtendedKeyUsage.getId());
    	useStandardCertificateExtensions.put(USEQCSTATEMENT,X509Extensions.QCStatements.getId());
    	useStandardCertificateExtensions.put(USESUBJECTDIRATTRIBUTES,X509Extensions.SubjectDirectoryAttributes.getId());
    	useStandardCertificateExtensions.put(USEAUTHORITYINFORMATIONACCESS,X509Extensions.AuthorityInfoAccess.getId());
    	useStandardCertificateExtensions.put(USEOCSPNOCHECK,OCSPObjectIdentifiers.id_pkix_ocsp_nocheck.getId());
    	useStandardCertificateExtensions.put(USEMICROSOFTTEMPLATE,CertTools.OID_MSTEMPLATE);
    	useStandardCertificateExtensions.put(USECARDNUMBER, OID_CARDNUMBER);
    }

    // Old values used to upgrade from v22 to v23
    protected static final String CERTIFICATEPOLICYID            = "certificatepolicyid";
    /** Policy Notice Url to CPS field alias in the data structure */
    protected static final String POLICY_NOTICE_CPS_URL 		 = "policynoticecpsurl";    
    /** Policy Notice User Notice field alias in the data structure */
    protected static final String POLICY_NOTICE_UNOTICE_TEXT 	 = "policynoticeunoticetext";

    // Public Methods

    /**
     * Creates a new instance of CertificateProfile
     * 
     * These settings are general for all sub-profiles, only differing values are overridden
     * in the sub-profiles. If changing any present value here you must therefore go through all
     * sub-profiles and add an override there.
     * I.e. only add new values here, don't change any present settings.
     */
    public CertificateProfile() {
      setCertificateVersion(VERSION_X509V3);
      setValidity(730);
      setAllowValidityOverride(false);
      
      setAllowExtensionOverride(false);
      
      setAllowDNOverride(false);

      setUseBasicConstraints(true);
      setBasicConstraintsCritical(true);

      setUseSubjectKeyIdentifier(true);
      setSubjectKeyIdentifierCritical(false);

      setUseAuthorityKeyIdentifier(true);
      setAuthorityKeyIdentifierCritical(false);

      setUseSubjectAlternativeName(true);
      setSubjectAlternativeNameCritical(false);

      setUseCRLDistributionPoint(false);
      setUseDefaultCRLDistributionPoint(false);
      setCRLDistributionPointCritical(false);
      setCRLDistributionPointURI("");
      setUseCRLDistributionPointOnCRL(false);
      setUseFreshestCRL(false);
      setUseCADefinedFreshestCRL(false);
      setFreshestCRLURI("");

      setUseCertificatePolicies(false);
      setCertificatePoliciesCritical(false);
      ArrayList policies = new ArrayList();
      setCertificatePolicies(policies);

      setType(TYPE_ENDENTITY);

      
      setAvailableBitLengths(DEFAULTBITLENGTHS);

      setUseKeyUsage(true);
      setKeyUsage(new boolean[9]);
      setAllowKeyUsageOverride(false);
      setKeyUsageCritical(true);

      setUseExtendedKeyUsage(false);
      setExtendedKeyUsage(new ArrayList());
      setExtendedKeyUsageCritical(false);

      ArrayList availablecas = new ArrayList();
      availablecas.add(new Integer(ANYCA));
      setAvailableCAs(availablecas);
      
      setPublisherList(new ArrayList());

      setUseCaIssuers(false);
      setCaIssuers(new ArrayList());

      setUseOcspNoCheck(false);
	  setUseOCSPServiceLocator(false);	  
	  setUseDefaultOCSPServiceLocator(false);
	  setOCSPServiceLocatorURI("");

	  setUseLdapDnOrder(true);	  

	  setUseMicrosoftTemplate(false);	
	  setMicrosoftTemplate("");
	  setUseCardNumber(false);
	  
	  setUseCNPostfix(false);
	  setCNPostfix("");
	  
	  setUseSubjectDNSubSet(false);
	  setSubjectDNSubSet(new ArrayList());
	  setUseSubjectAltNameSubSet(false);
	  setSubjectAltNameSubSet(new ArrayList());
	  
	  setUsePathLengthConstraint(false);
	  setPathLengthConstraint(0);
	  
      setUseQCStatement(false);
      setUsePkixQCSyntaxV2(false);
      setQCStatementCritical(false);
      setQCStatementRAName(null);
      setQCSemanticsId(null);
      setUseQCEtsiQCCompliance(false);
      setUseQCEtsiSignatureDevice(false);
      setUseQCEtsiValueLimit(false);
      setQCEtsiValueLimit(0);
      setQCEtsiValueLimitExp(0);
      setQCEtsiValueLimitCurrency(null);
      setUseQCEtsiRetentionPeriod(false);
      setQCEtsiRetentionPeriod(0);
      setUseQCCustomString(false);
      setQCCustomStringOid(null);
      setQCCustomStringText(null);
      
      setUseSubjectDirAttributes(false);
      setUseAuthorityInformationAccess(false);
      setUseCRLDistributionPointOnCRL(false);
      setUseOcspNoCheck(false);
      setUseFreshestCRL(false);
      
      // Default to have access to fingerprint and iris
      setCVCAccessRights(CertificateProfile.CVC_ACCESS_DG3DG4);
      
      setUsedCertificateExtensions(new ArrayList());
      
      setNumOfReqApprovals(1);
      setApprovalSettings(Collections.EMPTY_LIST);
    }



	// Public Methods.
    /** Returns the version of the certificate, should be one of the VERSION_ constants defined in CertificateProfile class. */
    public String getCertificateVersion(){return (String) data.get(CERTVERSION);}
	/**
	* Returns the version of the certificate, should be one of the VERSION_ constants defined in
	* CertificateProfile class.
	*/
    public void setCertificateVersion(String version){data.put(CERTVERSION,version);}

    public long getValidity(){return ((Long)data.get(VALIDITY)).longValue();}
    public void setValidity(long validity) { data.put(VALIDITY,new Long(validity));}

    /**
     * If validity override is allowed, a certificate can have a shorter validity than the one specefied in
     * the certificate profile, but never longer. A certificate created with validity override can hava a
     * starting point in the future.
     * @return true if validity override is allowed
     */
    public boolean getAllowValidityOverride(){ return ((Boolean)data.get(ALLOWVALIDITYOVERRIDE)).booleanValue(); }
    /**
     * If validity override is allowed, a certificate can have a shorter validity than the one specefied in
     * the certificate profile, but never longer. A certificate created with validity override can hava a
     * starting point in the future.
     */
    public void setAllowValidityOverride(boolean allowvalidityoverride) {data.put(ALLOWVALIDITYOVERRIDE, Boolean.valueOf(allowvalidityoverride));}

    /** If extension override is allowed, the X509 certificate extension created in a certificate can
     * come from the request sent by the user. If the request contains an extension than will be used instead of the one defined in the profile.
     * If the request does not contain an extension, the one defined in the profile will be used.
     */
    public boolean getAllowExtensionOverride(){ 
    	Object d = data.get(ALLOWEXTENSIONOVERRIDE);
    	if (d == null) {
    		return false;
    	}
    	return ((Boolean)d).booleanValue(); 
    }
    /** @see #getAllowExtensionOverride() */
    public void setAllowExtensionOverride(boolean allowextensionoverride) {data.put(ALLOWEXTENSIONOVERRIDE, Boolean.valueOf(allowextensionoverride));}

    /** If DN override is allowed, the X509 subject DN extension created in a certificate can
     * come directly from the request sent by the user. This is instead of the normal way where the user's registered DN is used.
     */
    public boolean getAllowDNOverride(){ 
    	Object d = data.get(ALLOWDNOVERRIDE);
    	if (d == null) {
    		return false;
    	}
    	return ((Boolean)d).booleanValue(); 
    }
    /** @see #getAllowDNOverride() */
    public void setAllowDNOverride(boolean allowdnoverride) {data.put(ALLOWDNOVERRIDE, Boolean.valueOf(allowdnoverride));}

    public boolean getUseBasicConstraints(){ return ((Boolean)data.get(USEBASICCONSTRAINTS)).booleanValue(); }
    public void setUseBasicConstraints(boolean usebasicconstraints) {data.put(USEBASICCONSTRAINTS, Boolean.valueOf(usebasicconstraints));}

    public boolean getBasicConstraintsCritical(){ return ((Boolean) data.get(BASICCONSTRAINTSCRITICAL)).booleanValue(); }
    public void setBasicConstraintsCritical(boolean basicconstraintscritical) { data.put(BASICCONSTRAINTSCRITICAL, Boolean.valueOf(basicconstraintscritical));}

    public boolean getUseKeyUsage(){ return ((Boolean) data.get(USEKEYUSAGE)).booleanValue(); }
    public void setUseKeyUsage(boolean usekeyusage) { data.put(USEKEYUSAGE, Boolean.valueOf(usekeyusage));}

    public boolean getKeyUsageCritical(){ return ((Boolean) data.get(KEYUSAGECRITICAL)).booleanValue(); }
    public void setKeyUsageCritical(boolean keyusagecritical) { data.put(KEYUSAGECRITICAL, Boolean.valueOf(keyusagecritical));}

    public boolean getUseSubjectKeyIdentifier(){ return ((Boolean) data.get(USESUBJECTKEYIDENTIFIER)).booleanValue(); }
    public void setUseSubjectKeyIdentifier(boolean usesubjectkeyidentifier) { data.put(USESUBJECTKEYIDENTIFIER, Boolean.valueOf(usesubjectkeyidentifier));}

    public boolean getSubjectKeyIdentifierCritical(){ return ((Boolean) data.get(SUBJECTKEYIDENTIFIERCRITICAL)).booleanValue(); }
    public void setSubjectKeyIdentifierCritical(boolean subjectkeyidentifiercritical) { data.put(SUBJECTKEYIDENTIFIERCRITICAL, Boolean.valueOf(subjectkeyidentifiercritical));}

    public boolean getUseAuthorityKeyIdentifier(){ return ((Boolean) data.get(USEAUTHORITYKEYIDENTIFIER)).booleanValue(); }
    public void setUseAuthorityKeyIdentifier(boolean useauthoritykeyidentifier) { data.put(USEAUTHORITYKEYIDENTIFIER, Boolean.valueOf(useauthoritykeyidentifier));}

    public boolean getAuthorityKeyIdentifierCritical(){ return ((Boolean) data.get(AUTHORITYKEYIDENTIFIERCRITICAL)).booleanValue(); }
    public void setAuthorityKeyIdentifierCritical(boolean authoritykeyidentifiercritical) { data.put(AUTHORITYKEYIDENTIFIERCRITICAL, Boolean.valueOf(authoritykeyidentifiercritical));}

    public boolean getUseSubjectAlternativeName(){ return ((Boolean) data.get(USESUBJECTALTERNATIVENAME)).booleanValue(); }
    public void setUseSubjectAlternativeName(boolean usesubjectalternativename) { data.put(USESUBJECTALTERNATIVENAME, Boolean.valueOf(usesubjectalternativename));}

    public boolean getSubjectAlternativeNameCritical(){ return ((Boolean) data.get(SUBJECTALTERNATIVENAMECRITICAL)).booleanValue(); }
    public void setSubjectAlternativeNameCritical(boolean subjectalternativenamecritical) { data.put(SUBJECTALTERNATIVENAMECRITICAL, Boolean.valueOf(subjectalternativenamecritical));}

    public boolean getUseCRLDistributionPoint(){ return ((Boolean) data.get(USECRLDISTRIBUTIONPOINT)).booleanValue(); }
    public void setUseCRLDistributionPoint(boolean usecrldistributionpoint) { data.put(USECRLDISTRIBUTIONPOINT, Boolean.valueOf(usecrldistributionpoint));}

    public boolean getUseDefaultCRLDistributionPoint(){ return ((Boolean) data.get(USEDEFAULTCRLDISTRIBUTIONPOINT)).booleanValue(); }
    public void setUseDefaultCRLDistributionPoint(boolean usedefaultcrldistributionpoint) { data.put(USEDEFAULTCRLDISTRIBUTIONPOINT, Boolean.valueOf(usedefaultcrldistributionpoint));}
    
    public boolean getCRLDistributionPointCritical(){ return ((Boolean) data.get(CRLDISTRIBUTIONPOINTCRITICAL)).booleanValue(); }
    public void setCRLDistributionPointCritical(boolean crldistributionpointcritical) { data.put(CRLDISTRIBUTIONPOINTCRITICAL, Boolean.valueOf(crldistributionpointcritical));}

    public String getCRLDistributionPointURI(){ return (String) data.get(CRLDISTRIBUTIONPOINTURI); }
    public void setCRLDistributionPointURI(String crldistributionpointuri) {
      if(crldistributionpointuri==null) {
        data.put(CRLDISTRIBUTIONPOINTURI,"");
      } else {
        data.put(CRLDISTRIBUTIONPOINTURI,crldistributionpointuri);
      }
    }
    public String getCRLIssuer(){ return (String) data.get(CRLISSUER); }
    public void setCRLIssuer(String crlissuer) {
      if(crlissuer==null) {
        data.put(CRLISSUER,"");
      } else {
        data.put(CRLISSUER,crlissuer);
      }
    }

    public boolean getUseFreshestCRL() {
        Object obj = data.get(USEFRESHESTCRL);
        if(obj == null) {
            return false;
        } else {
            return ((Boolean) obj).booleanValue();
        }
    }
    
    public boolean getUseCRLDistributionPointOnCRL(){
    	Object obj = data.get(USECRLDISTRIBUTIONPOINTONCRL);
    	if(obj == null) {
    		return false;
    	} else {
    		return ((Boolean) obj).booleanValue();
    	}
    }

    public void setUseCRLDistributionPointOnCRL(boolean usecrldistributionpointoncrl) {
    	data.put(USECRLDISTRIBUTIONPOINTONCRL, Boolean.valueOf(usecrldistributionpointoncrl));
    }

    public void setUseFreshestCRL(boolean usefreshestcrl) {
        data.put(USEFRESHESTCRL, Boolean.valueOf(usefreshestcrl));
    }
    
    public boolean getUseCADefinedFreshestCRL(){
        Object obj = data.get(USECADEFINEDFRESHESTCRL);
        if(obj == null) {
            return false;
        } else {
            return ((Boolean) obj).booleanValue();
        }
    }
    
    public void setUseCADefinedFreshestCRL(boolean usecadefinedfreshestcrl) {
        data.put(USECADEFINEDFRESHESTCRL, Boolean.valueOf(usecadefinedfreshestcrl));
    }
    
    public String getFreshestCRLURI() {
        return ((String) data.get(FRESHESTCRLURI));
    }
    
    public void setFreshestCRLURI(String freshestcrluri) {
        if (freshestcrluri == null) {
            data.put(FRESHESTCRLURI, "");
        } else {
            data.put(FRESHESTCRLURI, freshestcrluri);
        }
    }
    
    public boolean getUseCertificatePolicies() { return ((Boolean) data.get(USECERTIFICATEPOLICIES)).booleanValue(); }
    public void  setUseCertificatePolicies(boolean usecertificatepolicies) { data.put(USECERTIFICATEPOLICIES, Boolean.valueOf(usecertificatepolicies));}
    public boolean getCertificatePoliciesCritical() { return ((Boolean) data.get(CERTIFICATEPOLICIESCRITICAL)).booleanValue(); }
    public void  setCertificatePoliciesCritical(boolean certificatepoliciescritical) { data.put(CERTIFICATEPOLICIESCRITICAL, Boolean.valueOf(certificatepoliciescritical));}
    public List getCertificatePolicies() {
    	List l = (List)data.get(CERTIFICATE_POLICIES);
    	if (l == null) {
    		l = new ArrayList();
    	}
    	return l;
    }

    public void addCertificatePolicy(CertificatePolicy policy) {
    	if (data.get(CERTIFICATE_POLICIES) == null) {
    		setCertificatePolicies(new ArrayList());
    	}
    	((List) data.get(CERTIFICATE_POLICIES)).add(policy);
    }

    public void setCertificatePolicies(List policies) {
    	if (policies == null) {
    		data.put(CERTIFICATE_POLICIES, new ArrayList(0));
    	} else {
    		data.put(CERTIFICATE_POLICIES, policies);
    	}
    }

    public void removeCertificatePolicy(CertificatePolicy policy) {
    	if (data.get(CERTIFICATE_POLICIES) != null) {
    		((List) data.get(CERTIFICATE_POLICIES)).remove(policy);
    	}
    }

    public int getType(){ return ((Integer) data.get(TYPE)).intValue(); }
    public void setType(int type){ data.put(TYPE, new Integer(type)); }
    public boolean isTypeCA() { return ((Integer) data.get(TYPE)).intValue() == TYPE_SUBCA; }
    public boolean isTypeRootCA() { return ((Integer) data.get(TYPE)).intValue() == TYPE_ROOTCA; }
    public boolean isTypeEndEntity() { return ((Integer) data.get(TYPE)).intValue() == TYPE_ENDENTITY; }

    public int[] getAvailableBitLengths(){
      ArrayList availablebitlengths = (ArrayList) data.get(AVAILABLEBITLENGTHS);
      int[] returnval = new int[availablebitlengths.size()];

      for(int i=0; i < availablebitlengths.size(); i++){
        returnval[i] = ((Integer) availablebitlengths.get(i)).intValue();
      }

      return returnval;
    }

    public void setAvailableBitLengths(int[] availablebitlengths){
      ArrayList availbitlengths = new ArrayList(availablebitlengths.length);

      int minimumavailablebitlength = 99999999;
      int maximumavailablebitlength = 0;

      for(int i=0;i< availablebitlengths.length;i++){
        if( availablebitlengths[i] > maximumavailablebitlength) {
          maximumavailablebitlength = availablebitlengths[i];
        }
        if( availablebitlengths[i] < minimumavailablebitlength) {
          minimumavailablebitlength = availablebitlengths[i];
        }
        availbitlengths.add(new Integer(availablebitlengths[i]));
      }
      data.put(AVAILABLEBITLENGTHS, availbitlengths);
      data.put(MINIMUMAVAILABLEBITLENGTH, new Integer(minimumavailablebitlength));
      data.put(MAXIMUMAVAILABLEBITLENGTH, new Integer(maximumavailablebitlength));
    }

    public int getMinimumAvailableBitLength(){return ((Integer) data.get(MINIMUMAVAILABLEBITLENGTH)).intValue();}
    public int getMaximumAvailableBitLength(){return ((Integer) data.get(MAXIMUMAVAILABLEBITLENGTH)).intValue();}

    /**
     * Returns the chosen algorithm to be used for signing the certificates or
     * null if it is to be inherited from the CA (i.e., it is the same as the
     * algorithm used to sign the CA certificate).
     *
     * @see org.ejbca.core.model.AlgorithmConstants.AVAILABLE_SIGALGS
     * @return JCE identifier for the signature algorithm or null if it is to
     * be inherited from the CA (i.e., it is the same as the algorithm used to
     * sign the CA certificate).
     */
    public String getSignatureAlgorithm(){
        // If it's null, it is inherited from issuing CA.
        return (String) data.get(SIGNATUREALGORITHM);
    }

    /**
     * Sets the algorithm to be used for signing the certificates. A null value
     * means that the signature algorithm is to be inherited from the CA (i.e.,
     * it is the same as the algorithm used to sign the CA certificate).
     *
     * @param signAlg JCE identifier for the signature algorithm or null if it
     * is to be inherited from the CA (i.e., it is the same as the algorithm
     * used to sign the CA certificate).
     * @see org.ejbca.core.model.AlgorithmConstants.AVAILABLE_SIGALGS
     */
    public void setSignatureAlgorithm(String signAlg){
        data.put(SIGNATUREALGORITHM, signAlg);
    }

    public boolean[] getKeyUsage(){
      ArrayList keyusage = (ArrayList) data.get(KEYUSAGE);
      boolean[] returnval = new boolean[keyusage.size()];

      for(int i=0; i < keyusage.size(); i++){
        returnval[i] = ((Boolean) keyusage.get(i)).booleanValue();
      }

      return returnval;
    }

    public boolean getKeyUsage(int keyusageconstant){
      return ((Boolean) ((ArrayList) data.get(KEYUSAGE)).get(keyusageconstant)).booleanValue();
    }

    public void setKeyUsage(boolean[] keyusage){
      ArrayList keyuse = new ArrayList(keyusage.length);

      for(int i=0;i< keyusage.length;i++){
        keyuse.add(Boolean.valueOf(keyusage[i]));
      }
      data.put(KEYUSAGE, keyuse);
    }

    public void setKeyUsage(int keyusageconstant, boolean value){
      ((ArrayList) data.get(KEYUSAGE)).set(keyusageconstant, Boolean.valueOf(value));
    }

    public void setAllowKeyUsageOverride(boolean override) {
        data.put(ALLOWKEYUSAGEOVERRIDE, Boolean.valueOf(override));
    }
    public boolean getAllowKeyUsageOverride() {
        return ((Boolean) data.get(ALLOWKEYUSAGEOVERRIDE)).booleanValue();
    }

    public void setUseExtendedKeyUsage(boolean use) {
        data.put(USEEXTENDEDKEYUSAGE, Boolean.valueOf(use));
    }
    public boolean getUseExtendedKeyUsage() {
        return ((Boolean) data.get(USEEXTENDEDKEYUSAGE)).booleanValue();
    }

    public void setExtendedKeyUsageCritical(boolean critical) {
        data.put(EXTENDEDKEYUSAGECRITICAL, Boolean.valueOf(critical));
    }
    public boolean getExtendedKeyUsageCritical() {
        return ((Boolean) data.get(EXTENDEDKEYUSAGECRITICAL)).booleanValue();
    }
    /**
     * Extended Key Usage is an arraylist of oid Strings.
     */
    public void setExtendedKeyUsage(ArrayList extendedkeyusage) {
        data.put(EXTENDEDKEYUSAGE, extendedkeyusage);
    }
    /** Only used for JUnit testing */
    protected ArrayList getExtendedKeyUsageArray() {
    	return (ArrayList) data.get(EXTENDEDKEYUSAGE);    	
    }
    /**
     * Extended Key Usage is an arraylist of Strings with eku oids.
     */
    public ArrayList getExtendedKeyUsageOids(){
    	return getExtendedKeyUsageAsOIDStrings(false);
    }
    private ArrayList getExtendedKeyUsageAsOIDStrings(boolean fromupgrade){
    	ArrayList returnval = new ArrayList();
    	ArrayList eku = (ArrayList) data.get(EXTENDEDKEYUSAGE);
    	if ((eku != null) && (eku.size() > 0)) {
        	Object o = eku.get(0);
    		// This is a test for backwards compatibility for the older type of extended key usage
    		if (o instanceof String) {
    			// This is the new extended key usage in the profile, simply return the array with oids
    			returnval = eku;
    		} else {
            	Iterator i = eku.iterator();
            	List oids = getAllExtendedKeyUsageOIDStrings();
            	while(i.hasNext()) {
            		// We fell through to this conversion from Integer to String, which we should not have to 
            		// if upgrade() had done it's job. This is an error!
            		if (!fromupgrade) {
            			log.error("We're forced to convert between old extended key usage format and new. This is an error that we handle so it should work for now. It should be reported as we can not guarantee that it will work in the future. "+getVersion());
            		}
            		int index = ((Integer)i.next()).intValue();
            		returnval.add(oids.get(index));
            	}    		    			
    		}
    	}
    	return returnval;
    }

    public boolean getUseLdapDnOrder(){
    	boolean ret = true; // Default value is true here
    	Object o = data.get(USELDAPDNORDER);
    	if (o != null) {
    		ret = ((Boolean)o).booleanValue();
    	}
    	return ret;	
    }
    
    public void setUseLdapDnOrder(boolean use){
    	data.put(USELDAPDNORDER, Boolean.valueOf(use));	
    }

    public boolean getUseMicrosoftTemplate(){
    	return ((Boolean) data.get(USEMICROSOFTTEMPLATE)).booleanValue();	
    }
    
    public void setUseMicrosoftTemplate(boolean use){
    	data.put(USEMICROSOFTTEMPLATE, Boolean.valueOf(use));	
    }

    public String getMicrosoftTemplate(){
    	return (String) data.get(MICROSOFTTEMPLATE);	
    }
    
    public void setMicrosoftTemplate(String mstemplate){
    	data.put(MICROSOFTTEMPLATE, mstemplate);	
    }
    
    public boolean getUseCardNumber() {
    	return ((Boolean) data.get(USECARDNUMBER)).booleanValue();
    }
    
    public void setUseCardNumber(boolean use) {
    	data.put(USECARDNUMBER, Boolean.valueOf(use));
    }
    
    public boolean getUseCNPostfix(){
    	return ((Boolean) data.get(USECNPOSTFIX)).booleanValue();	
    }
    
    public void setUseCNPostfix(boolean use) {
		data.put(USECNPOSTFIX, Boolean.valueOf(use));			
	}
    
    public String getCNPostfix(){
    	return (String) data.get(CNPOSTFIX);	
    }
    
    public void setCNPostfix(String cnpostfix) {
		data.put(CNPOSTFIX, cnpostfix);	
		
	}
	
    public boolean getUseSubjectDNSubSet(){
    	return ((Boolean) data.get(USESUBJECTDNSUBSET)).booleanValue();	
    }
    
    public void setUseSubjectDNSubSet(boolean use) {
		data.put(USESUBJECTDNSUBSET, Boolean.valueOf(use));			
	}
    
    /**
     * Returns a collection of Integer (DNFieldExtractor constants) indicating
     * which subject dn fields that should be used in certificate.
     * 
     */
    public Collection getSubjectDNSubSet(){
    	return (Collection) data.get(SUBJECTDNSUBSET);	
    }

    /**
     * Should contain a collection of Integer (DNFieldExtractor constants) indicating
     * which subject dn fields that should be used in certificate.
     * 
     */
    public void setSubjectDNSubSet(Collection subjectdns) {
		data.put(SUBJECTDNSUBSET, subjectdns);	
		
	}

    /**
     * Method taking a full user dn and returns a DN only containing the 
     * DN fields specified in the subjectdn sub set array.
     * 
     * @param dn
     * @return a subset of original DN
     */
    
    public String createSubjectDNSubSet(String dn){
    	DNFieldExtractor extractor = new DNFieldExtractor(dn,DNFieldExtractor.TYPE_SUBJECTDN);    	
    	return constructUserData(extractor, getSubjectDNSubSet(), true);
    }
    
    public boolean getUseSubjectAltNameSubSet(){
    	return ((Boolean) data.get(USESUBJECTALTNAMESUBSET)).booleanValue();	
    }
    
    public void setUseSubjectAltNameSubSet(boolean use) {
		data.put(USESUBJECTALTNAMESUBSET, Boolean.valueOf(use));			
	}

    /**
     * Returns a collection of Integer (DNFieldExtractor constants) indicating
     * which subject altnames fields that should be used in certificate.
     * 
     */
    public Collection getSubjectAltNameSubSet(){
    	return (Collection) data.get(SUBJECTALTNAMESUBSET);	
    }
    
    /**
     * Returns a collection of Integer (DNFieldExtractor constants) indicating
     * which subject altnames fields that should be used in certificate.
     * 
     */
    public void setSubjectAltNameSubSet(Collection subjectaltnames) {
		data.put(SUBJECTALTNAMESUBSET, subjectaltnames);	
		
	}

    
    /**
     * Method taking a full user dn and returns a AltName only containing the 
     * AltName fields specified in the subjectaltname sub set array.
     * 
     * @param dn
     * @return a subset of original DN
     */
    public String createSubjectAltNameSubSet(String subjectaltname){
    	DNFieldExtractor extractor = new DNFieldExtractor(subjectaltname,DNFieldExtractor.TYPE_SUBJECTALTNAME);    	
    	return constructUserData(extractor, getSubjectAltNameSubSet(), false);
    }
    
    /**
     * Help method converting a full DN or Subject Alt Name to one usng only specified fields
     * @param extractor 
     * @param usefields
     * @return
     */
    protected String constructUserData(DNFieldExtractor extractor, Collection usefields, boolean subjectdn){
        String retval = "";
                       
        if(usefields instanceof List){
          Collections.sort((List) usefields);
        }
        Iterator iter = usefields.iterator(); 
        String dnField = null;
        while(iter.hasNext()){
        	Integer next = (Integer) iter.next();
        	dnField = extractor.getFieldString(next.intValue());
        	if (StringUtils.isNotEmpty(dnField)) {
            	if(retval.length() == 0) {
              	  retval += dnField; // first item, don't start with a comma
            	} else {
              	  retval += "," + dnField;
            	}
        	}
        }
        log.debug("CertificateProfile: constructed DN or AltName: " + retval );
        return retval;	
      }
      
    
    /**
     * Returns a Collections of caids (Integer), indicating which CAs the profile should
     * be applicable to.
     *
     * If it contains the constant ANYCA then the profile is applicable to all CAs
     */
    public Collection getAvailableCAs(){
      return (Collection) data.get(AVAILABLECAS);   
    }
    
    /**
     * Saves the CertificateProfile's list of CAs the cert profile is applicable to.
     *
     * @param availablecas a Collection of caids (Integer)
     */
    
    public void setAvailableCAs(Collection availablecas){
      data.put(AVAILABLECAS, availablecas);   
    }
    
    public boolean isApplicableToAnyCA(){
    	return ((Collection) data.get(AVAILABLECAS)).contains(new Integer(ANYCA));
    }
    
    /**
     * Returns a Collection of publisher id's (Integer) indicating which publishers a certificate
     * created with this profile should be published to.
     * Never returns null.
     */
    
    public Collection getPublisherList(){
    	Object o = data.get(USEDPUBLISHERS);
    	if (o == null) {
    		o = new ArrayList();
    	}
    	return (Collection)o;   
    }
    
    /**
     * Saves the CertificateProfile's list of publishers that certificates created with this profile 
     * should be published to.
     *
     * @param publishers a Collection of publisherids (Integer)
     */ 
    
    public void setPublisherList(Collection publisher){
      data.put(USEDPUBLISHERS, publisher);   
    }   
    	
    /**
     * Method indicating that Path Length Constain should be used in the BasicConstaint
     * 
     */
    public boolean getUsePathLengthConstraint(){
    	return ((Boolean) data.get(USEPATHLENGTHCONSTRAINT)).booleanValue();	
    }
    
    /**
     * Method indicating that Path Length Constain should be used in the BasicConstaint
     * 
     */
    public void setUsePathLengthConstraint(boolean use) {
		data.put(USEPATHLENGTHCONSTRAINT, Boolean.valueOf(use));			
	}
    
    public int getPathLengthConstraint(){
    	return ((Integer) data.get(PATHLENGTHCONSTRAINT)).intValue();	
    }
    
  
    public void setPathLengthConstraint(int pathlength) {
		data.put(PATHLENGTHCONSTRAINT, new Integer(pathlength));			
	}   

    /**
	 * @deprecated setUseAuthorityInformationAccess in combination with getOCSPServiceLocator and getCaIssuer instead
     * @param use
     */
    public void setUseCaIssuers(boolean use) {
        data.put(USECAISSUERS, Boolean.valueOf(use));
    }

    /**
	 * @deprecated setUseAuthorityInformationAccess in combination with getOCSPServiceLocator and getCaIssuer instead
     * @return
     */
    public boolean getUseCaIssuers() {
        if(data.get(USECAISSUERS) == null) {
            return false; 
        } else {
            return ((Boolean) data.get(USECAISSUERS)).booleanValue();
        }
    }

    public void setCaIssuers(List caIssuers) {
        data.put(CAISSUERS, caIssuers);
    }

    public void addCaIssuer(String caIssuer) {
    	caIssuer = caIssuer.trim();
    	if ( caIssuer.length()<1 ) {
    		return;
    	}
        if (data.get(CAISSUERS) == null) {
            List caIssuers = new ArrayList();
            caIssuers.add(caIssuer);
            this.setCaIssuers(caIssuers);
        } else {
            ((List) data.get(CAISSUERS)).add(caIssuer);
        }
    }

    public List getCaIssuers() {
        if(data.get(CAISSUERS) == null) {
            return new ArrayList(); 
        } else {
            return (List) data.get(CAISSUERS);
        }
    }

    public void removeCaIssuer(String caIssuer) {
        if (data.get(CAISSUERS) != null) {
            ((List) data.get(CAISSUERS)).remove(caIssuer);
        }
    }

    public boolean getUseOcspNoCheck() {
        if(data.get(USEOCSPNOCHECK) == null) {
            return false; 
        } else {
            return ((Boolean) data.get(USEOCSPNOCHECK)).booleanValue();
        }
    }

    public void setUseOcspNoCheck(boolean useocspnocheck) {
        data.put(USEOCSPNOCHECK, Boolean.valueOf(useocspnocheck));
    }

    public boolean getUseAuthorityInformationAccess(){ return ((Boolean) data.get(USEAUTHORITYINFORMATIONACCESS)).booleanValue(); }
	public void setUseAuthorityInformationAccess(boolean useauthorityinformationaccess) { data.put(USEAUTHORITYINFORMATIONACCESS, Boolean.valueOf(useauthorityinformationaccess));}

	/** @deprecated setUseAuthorityInformationAccess in combination with getOCSPServiceLocator and getCaIssuer instead */
	public boolean getUseOCSPServiceLocator(){ return ((Boolean) data.get(USEOCSPSERVICELOCATOR)).booleanValue(); }
	/** @deprecated setUseAuthorityInformationAccess in combination with getOCSPServiceLocator and getCaIssuer instead */
	public void setUseOCSPServiceLocator(boolean useocspservicelocator) { data.put(USEOCSPSERVICELOCATOR, Boolean.valueOf(useocspservicelocator));}
    
	public boolean getUseDefaultOCSPServiceLocator(){ return ((Boolean) data.get(USEDEFAULTOCSPSERVICELOCATOR)).booleanValue(); }
	public void setUseDefaultOCSPServiceLocator(boolean usedefaultocspservicelocator) { data.put(USEDEFAULTOCSPSERVICELOCATOR, Boolean.valueOf(usedefaultocspservicelocator));}

	public String getOCSPServiceLocatorURI(){ return (String) data.get(OCSPSERVICELOCATORURI); }
	public void setOCSPServiceLocatorURI(String ocspservicelocatoruri) {
	  if(ocspservicelocatoruri==null) {
		data.put(OCSPSERVICELOCATORURI,"");
	  } else {
		data.put(OCSPSERVICELOCATORURI,ocspservicelocatoruri);
	  }
	}

    public boolean getUseQCStatement(){ return ((Boolean) data.get(USEQCSTATEMENT)).booleanValue(); }
    public void setUseQCStatement(boolean useqcstatement) { data.put(USEQCSTATEMENT, Boolean.valueOf(useqcstatement));}
    public boolean getUsePkixQCSyntaxV2(){ return ((Boolean) data.get(USEPKIXQCSYNTAXV2)).booleanValue(); }
    public void setUsePkixQCSyntaxV2(boolean pkixqcsyntaxv2) { data.put(USEPKIXQCSYNTAXV2, Boolean.valueOf(pkixqcsyntaxv2));}
    public boolean getQCStatementCritical() { return ((Boolean) data.get(QCSTATEMENTCRITICAL)).booleanValue(); }
    public void  setQCStatementCritical(boolean qcstatementcritical) { data.put(QCSTATEMENTCRITICAL, Boolean.valueOf(qcstatementcritical));}

    public String getQCStatementRAName(){ return (String) data.get(QCSTATEMENTRANAME); }
    public void setQCStatementRAName(String qcstatementraname) {
      if(qcstatementraname==null) {
        data.put(QCSTATEMENTRANAME,"");
      } else {
        data.put(QCSTATEMENTRANAME,qcstatementraname);
      }
    }
    public String getQCSemanticsId(){ return (String) data.get(QCSSEMANTICSID); }
    public void setQCSemanticsId(String qcsemanticsid) {
      if(qcsemanticsid==null) {
        data.put(QCSSEMANTICSID,"");
      } else {
        data.put(QCSSEMANTICSID,qcsemanticsid);
      }
    }
    public boolean getUseQCEtsiQCCompliance(){ return ((Boolean) data.get(USEQCETSIQCCOMPLIANCE)).booleanValue(); }
    public void setUseQCEtsiQCCompliance(boolean useqcetsiqccompliance) { data.put(USEQCETSIQCCOMPLIANCE, Boolean.valueOf(useqcetsiqccompliance));}
    public boolean getUseQCEtsiValueLimit(){ return ((Boolean) data.get(USEQCETSIVALUELIMIT)).booleanValue(); }
    public void setUseQCEtsiValueLimit(boolean useqcetsivaluelimit) { data.put(USEQCETSIVALUELIMIT, Boolean.valueOf(useqcetsivaluelimit));}
    public int getQCEtsiValueLimit(){return ((Integer) data.get(QCETSIVALUELIMIT)).intValue();}
    public void setQCEtsiValueLimit(int qcetsivaluelimit){data.put(QCETSIVALUELIMIT, new Integer(qcetsivaluelimit));}
    public int getQCEtsiValueLimitExp(){return ((Integer) data.get(QCETSIVALUELIMITEXP)).intValue();}
    public void setQCEtsiValueLimitExp(int qcetsivaluelimitexp){data.put(QCETSIVALUELIMITEXP, new Integer(qcetsivaluelimitexp));}
    public String getQCEtsiValueLimitCurrency(){ return (String) data.get(QCETSIVALUELIMITCURRENCY); }
    public void setQCEtsiValueLimitCurrency(String qcetsicaluelimitcurrency) {
      if(qcetsicaluelimitcurrency==null) {
        data.put(QCETSIVALUELIMITCURRENCY,"");
      } else {
        data.put(QCETSIVALUELIMITCURRENCY,qcetsicaluelimitcurrency);
      }
    }
    public boolean getUseQCEtsiRetentionPeriod(){ return ((Boolean) data.get(USEQCETSIRETENTIONPERIOD)).booleanValue(); }
    public void setUseQCEtsiRetentionPeriod(boolean useqcetsiretentionperiod) { data.put(USEQCETSIRETENTIONPERIOD, Boolean.valueOf(useqcetsiretentionperiod));}
    public int getQCEtsiRetentionPeriod(){return ((Integer) data.get(QCETSIRETENTIONPERIOD)).intValue();}
    public void setQCEtsiRetentionPeriod(int qcetsiretentionperiod){data.put(QCETSIRETENTIONPERIOD, new Integer(qcetsiretentionperiod));}
    public boolean getUseQCEtsiSignatureDevice(){ return ((Boolean) data.get(USEQCETSISIGNATUREDEVICE)).booleanValue(); }
    public void setUseQCEtsiSignatureDevice(boolean useqcetsisignaturedevice) { data.put(USEQCETSISIGNATUREDEVICE, Boolean.valueOf(useqcetsisignaturedevice));}

    public boolean getUseQCCustomString(){ return ((Boolean) data.get(USEQCCUSTOMSTRING)).booleanValue(); }
    public void setUseQCCustomString(boolean useqccustomstring) { data.put(USEQCCUSTOMSTRING, Boolean.valueOf(useqccustomstring));}
    public String getQCCustomStringOid(){ return (String) data.get(QCCUSTOMSTRINGOID); }
    public void setQCCustomStringOid(String qccustomstringoid) {
      if(qccustomstringoid==null) {
        data.put(QCCUSTOMSTRINGOID,"");
      } else {
        data.put(QCCUSTOMSTRINGOID,qccustomstringoid);
      }
    }
    public String getQCCustomStringText(){ return (String) data.get(QCCUSTOMSTRINGTEXT); }
    public void setQCCustomStringText(String qccustomstringtext) {
      if(qccustomstringtext==null) {
        data.put(QCCUSTOMSTRINGTEXT,"");
      } else {
        data.put(QCCUSTOMSTRINGTEXT,qccustomstringtext);
      }
    }

    public boolean getUseSubjectDirAttributes(){ return ((Boolean) data.get(USESUBJECTDIRATTRIBUTES)).booleanValue(); }
    public void setUseSubjectDirAttributes(boolean use) { data.put(USESUBJECTDIRATTRIBUTES, Boolean.valueOf(use));}

    public int getCVCAccessRights(){ 
    	if(data.get(CVCACCESSRIGHTS) == null){
    		return CertificateProfile.CVC_ACCESS_NONE;
    	}
    	return ((Integer) data.get(CVCACCESSRIGHTS)).intValue(); 
    }
    public void setCVCAccessRights(int access) { data.put(CVCACCESSRIGHTS, Integer.valueOf(access));}

    /**
     * Method returning a list of (Integers) of ids of
     * used CUSTOM certificate extensions. I.e. those custom certificate extensions selected for 
     * this profile. Never null.
     * 
     * Autoupgradable method
     */
    public List getUsedCertificateExtensions(){ 
    	if(data.get(USEDCERTIFICATEEXTENSIONS) == null){
    		return new ArrayList();
    	}
    	
    	return (List) data.get(USEDCERTIFICATEEXTENSIONS); 
    }

    /**
     * Method setting a list of used certificate extensions
     * a list of Integers containing CertificateExtension Id is expected
     * @param usedCertificateExtensions
     */
    public void setUsedCertificateExtensions(List usedCertificateExtensions) {
      if(usedCertificateExtensions==null) {
        data.put(USEDCERTIFICATEEXTENSIONS,new ArrayList());
      } else {
        data.put(USEDCERTIFICATEEXTENSIONS,usedCertificateExtensions);
      }
    }

    /** Function that looks up in the profile all certificate extensions that we should use
     * if the value si that we should use it, the oid for this extension is returned in the list
     * @return List of oid Strings for standard certificate extensions that should be used
     */
    public List getUsedStandardCertificateExtensions() {
    	ArrayList ret = new ArrayList();
    	Iterator iter = useStandardCertificateExtensions.keySet().iterator();
    	while (iter.hasNext()) {
    		String s = (String)iter.next();
            if ( (data.get(s) != null) && ((Boolean)data.get(s)).booleanValue() ) {
                ret.add(useStandardCertificateExtensions.get(s)); 
                log.debug("Using standard certificate extension: "+s);
            } else {
            	log.debug("Not using standard certificate extensions: "+s);
            }
    	}
    	return ret;
    }
    
    /**
	 * Returns a collection of Integers (CAInfo.REQ_APPROVAL_ constants) of which
	 * action that requires approvals, default none 
	 * 
	 * Never null
	 */
	public Collection getApprovalSettings() {
		return (Collection) data.get(APPROVALSETTINGS);
	}
	
	/**
	 * Collection of Integers (CAInfo.REQ_APPROVAL_ constants) of which
	 * action that requires approvals
	 */
	public void setApprovalSettings(Collection approvalSettings) {
		data.put(APPROVALSETTINGS, approvalSettings);
	}
	
	/**
	 * Returns the number of different administrators that needs to approve
	 * an action, default 1.
	 */
	public int getNumOfReqApprovals() {
		return ((Integer) data.get(NUMOFREQAPPROVALS)).intValue();
	}
	
	/**
	 * The number of different administrators that needs to approve
	 */
	public void setNumOfReqApprovals(int numOfReqApprovals) {
		data.put(NUMOFREQAPPROVALS, new Integer(numOfReqApprovals));
	}
	
	/**
	 * Returns true if the action requires approvals.
	 * @param action, on of the CAInfo.REQ_APPROVAL_ constants
	 */
	public boolean isApprovalRequired(int action){
		Collection approvalSettings = (Collection) data.get(APPROVALSETTINGS);
		return approvalSettings.contains(new Integer(action));
	}

    public Object clone() throws CloneNotSupportedException {
      CertificateProfile clone = new CertificateProfile();
      HashMap clonedata = (HashMap) clone.saveData();

      Iterator i = (data.keySet()).iterator();
      while(i.hasNext()){
        Object key = i.next();
        clonedata.put(key, data.get(key));
      }

      clone.loadData(clonedata);
      return clone;
    }

    /** Implementation of UpgradableDataHashMap function getLatestVersion */
    public float getLatestVersion(){
       return LATEST_VERSION;
    }
    /**
     * Function setting the current version of the class data.
     * Used for JUnit testing
     */
    protected void setVersion(float version) {
        data.put(VERSION, Float.valueOf(version));
    }

    /** 
     * Implementation of UpgradableDataHashMap function upgrade. 
     */
    public void upgrade(){
    	if (log.isTraceEnabled()) {
            log.trace(">upgrade: "+getLatestVersion()+", "+getVersion());    		
    	}
    	if(Float.compare(getLatestVersion(), getVersion()) != 0) {
            // New version of the class, upgrade
			String msg = intres.getLocalizedMessage("certprofile.upgrade", new Float(getVersion()));
            log.info(msg);

            if(data.get(ALLOWKEYUSAGEOVERRIDE) == null) {
                data.put(ALLOWKEYUSAGEOVERRIDE, Boolean.TRUE);
            }
            if(data.get(USEEXTENDEDKEYUSAGE) == null) {
                data.put(USEEXTENDEDKEYUSAGE, Boolean.FALSE);
            }
            if(data.get(EXTENDEDKEYUSAGE) == null) {
                data.put(EXTENDEDKEYUSAGE, new ArrayList());
            }
            if(data.get(EXTENDEDKEYUSAGECRITICAL) == null) {
                data.put(EXTENDEDKEYUSAGECRITICAL, Boolean.FALSE);
            }
            if(data.get(AVAILABLECAS) == null) {
                ArrayList availablecas = new ArrayList();
                availablecas.add(new Integer(ANYCA));
                data.put(AVAILABLECAS, availablecas);
            }
            if(data.get(USEDPUBLISHERS) == null) {
                data.put(USEDPUBLISHERS, new ArrayList());   
            }            
            if(data.get(USEOCSPSERVICELOCATOR) == null) {
                // setUseOCSPServiceLocator(false);            
                data.put(USEOCSPSERVICELOCATOR, Boolean.valueOf(false));
                setOCSPServiceLocatorURI("");
            }
            
            if(data.get(USEMICROSOFTTEMPLATE) == null){
                setUseMicrosoftTemplate(false);            
                setMicrosoftTemplate("");
            } 
            
            if(data.get(USECNPOSTFIX) == null){
          	  setUseCNPostfix(false);
        	  setCNPostfix("");
            } 
            
            if(data.get(USESUBJECTDNSUBSET) == null){
          	  setUseSubjectDNSubSet(false);
        	  setSubjectDNSubSet(new ArrayList());
        	  setUseSubjectAltNameSubSet(false);
        	  setSubjectAltNameSubSet(new ArrayList());
            }
            
            if(data.get(USEPATHLENGTHCONSTRAINT) == null){
            	setUsePathLengthConstraint(false);
            	setPathLengthConstraint(0);
            }
            
            if(data.get(USEQCSTATEMENT) == null){
                setUseQCStatement(false);
                setUsePkixQCSyntaxV2(false);
                setQCStatementCritical(false);
                setQCStatementRAName(null);
                setQCSemanticsId(null);
                setUseQCEtsiQCCompliance(false);
                setUseQCEtsiSignatureDevice(false);
                setUseQCEtsiValueLimit(false);
                setUseQCEtsiRetentionPeriod(false);
                setQCEtsiRetentionPeriod(0);
                setQCEtsiValueLimit(0);
                setQCEtsiValueLimitExp(0);
                setQCEtsiValueLimitCurrency(null);
            }
            
            if(data.get(USEDEFAULTCRLDISTRIBUTIONPOINT) == null){
            	setUseDefaultCRLDistributionPoint(false);
            	setUseDefaultOCSPServiceLocator(false);
            }
            
            if (data.get(USEQCCUSTOMSTRING) == null) {
            	setUseQCCustomString(false);
            	setQCCustomStringOid(null);
            	setQCCustomStringText(null);
            }
            if (data.get(USESUBJECTDIRATTRIBUTES) == null) {
            	setUseSubjectDirAttributes(false);
            }
            if(data.get(ALLOWVALIDITYOVERRIDE) == null) {
                setAllowValidityOverride(false);
            }
            
            if(data.get(CRLISSUER) == null) {
                setCRLIssuer(null); // v20
            }
            
            if(data.get(USEOCSPNOCHECK) == null) {
                setUseOcspNoCheck(false); // v21
            }
            if(data.get(USEFRESHESTCRL) == null) {
                setUseFreshestCRL(false); // v22
                setUseCADefinedFreshestCRL(false);
                setFreshestCRLURI(null);
            }
            
            if (data.get(CERTIFICATE_POLICIES) == null) { // v23
            	if (data.get(CERTIFICATEPOLICYID) != null) {
            		String ids = (String)data.get(CERTIFICATEPOLICYID);
            		String unotice = null;
            		String cpsuri = null;
                	if (data.get(POLICY_NOTICE_UNOTICE_TEXT) != null) {
                		unotice = (String)data.get(POLICY_NOTICE_UNOTICE_TEXT);
                	}
                	if (data.get(POLICY_NOTICE_CPS_URL) != null) {
                		cpsuri = (String)data.get(POLICY_NOTICE_CPS_URL);
                	}
                	// Only the first policy could have user notice and cpsuri in the old scheme
                    StringTokenizer tokenizer = new StringTokenizer(ids, ";", false);
                    if (tokenizer.hasMoreTokens()) {
                    	String id = tokenizer.nextToken();
                    	CertificatePolicy newpolicy = null;
                    	if (StringUtils.isNotEmpty(unotice)) {
                        	newpolicy = new CertificatePolicy(id, CertificatePolicy.id_qt_unotice, unotice);
                        	addCertificatePolicy(newpolicy);
                    	}
                    	if (StringUtils.isNotEmpty(cpsuri)) {
                        	newpolicy = new CertificatePolicy(id, CertificatePolicy.id_qt_cps, cpsuri);
                        	addCertificatePolicy(newpolicy);                    		
                    	} 
                    	// If it was a lonely policy id
                    	if (newpolicy == null) {
                        	newpolicy = new CertificatePolicy(id, null, null);
                        	addCertificatePolicy(newpolicy);                    		                    		                    		
                    	}
                    }
                    while (tokenizer.hasMoreTokens()) {
                    	String id = tokenizer.nextToken();
                    	CertificatePolicy newpolicy = new CertificatePolicy(id, null, null);
                    	addCertificatePolicy(newpolicy);                    	
                    }
            	}
            }

            if(data.get(USECRLDISTRIBUTIONPOINTONCRL) == null) {
            	setUseCRLDistributionPointOnCRL(false); // v24
            }
            if(data.get(USECAISSUERS) == null) {
            	//setUseCaIssuers(false); // v24
            	data.put(USECAISSUERS, Boolean.valueOf(false)); // v24
            	setCaIssuers(new ArrayList());
            }
            if ( (data.get(USEOCSPSERVICELOCATOR) != null) || (data.get(USECAISSUERS) != null) ) {
            	boolean ocsp = false;
            	if ((data.get(USEOCSPSERVICELOCATOR) != null)) {
            		ocsp = ((Boolean) data.get(USEOCSPSERVICELOCATOR)).booleanValue();
            	}
            	boolean caissuers = false;
            	if ((data.get(USECAISSUERS) != null)) {
            		caissuers = ((Boolean) data.get(USECAISSUERS)).booleanValue();
            	}
            	if (ocsp || caissuers) {
            		setUseAuthorityInformationAccess(true); // v25
            	}
            } else {
            	setUseAuthorityInformationAccess(false);
            }

            if (data.get(ALLOWEXTENSIONOVERRIDE) == null) {
            	setAllowExtensionOverride(false); // v26
            } 

            if (data.get(USEQCETSIRETENTIONPERIOD) == null) {
            	setUseQCEtsiRetentionPeriod(false); // v27
            	setQCEtsiRetentionPeriod(0);
            }

            if (data.get(CVCACCESSRIGHTS) == null) {
            	setCVCAccessRights(CertificateProfile.CVC_ACCESS_NONE); // v28
            }

            if (data.get(USELDAPDNORDER) == null) {
            	setUseLdapDnOrder(true); // v29, default value is true
            } 

            if(data.get(USECARDNUMBER) == null) { //v30, default value is false
            	setUseCardNumber(false);            
            } 

            if (data.get(ALLOWDNOVERRIDE) == null) {
            	setAllowDNOverride(false); // v31
            } 

            if(Float.compare((float)32.0, getVersion()) > 0) { // v32
            	// Extended key usage storage changed from ArrayList of Integers to an ArrayList of Strings.
            	setExtendedKeyUsage(getExtendedKeyUsageAsOIDStrings(true));
            }
            
            if (data.get(NUMOFREQAPPROVALS) == null) { // v 33
            	setNumOfReqApprovals(1);
            }
            if (data.get(APPROVALSETTINGS) == null) { // v 33
            	setApprovalSettings(Collections.EMPTY_LIST);
            }

            if (data.get(SIGNATUREALGORITHM) == null) { // v 34
                setSignatureAlgorithm(null);
            }

            data.put(VERSION, new Float(LATEST_VERSION));
    	}
    	log.trace("<upgrade");
    }
    
}
