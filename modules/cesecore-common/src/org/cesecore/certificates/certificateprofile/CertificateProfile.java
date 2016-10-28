/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.certificateprofile;

import java.io.Serializable;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map.Entry;
import java.util.Set;
import java.util.StringTokenizer;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.certificates.util.DNFieldExtractor;
import org.cesecore.certificates.util.DnComponents;
import org.cesecore.internal.InternalResources;
import org.cesecore.internal.UpgradeableDataHashMap;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
import org.cesecore.util.ValidityDate;

/**
 * CertificateProfile is a basic class used to customize a certificate configuration or be inherited by fixed certificate profiles.
 * 
 * @version $Id$
 */
public class CertificateProfile extends UpgradeableDataHashMap implements Serializable, Cloneable {
    private static final Logger log = Logger.getLogger(CertificateProfile.class);
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    // Public Constants
    public static final float LATEST_VERSION = (float) 43.0;

    public static final String ROOTCAPROFILENAME = "ROOTCA";
    public static final String SUBCAPROFILENAME = "SUBCA";
    public static final String ENDUSERPROFILENAME = "ENDUSER";
    public static final String OCSPSIGNERPROFILENAME = "OCSPSIGNER";
    public static final String SERVERPROFILENAME = "SERVER";
    public static final String HARDTOKENAUTHPROFILENAME = "HARDTOKEN_AUTH";
    public static final String HARDTOKENAUTHENCPROFILENAME = "HARDTOKEN_AUTHENC";
    public static final String HARDTOKENENCPROFILENAME = "HARDTOKEN_ENC";
    public static final String HARDTOKENSIGNPROFILENAME = "HARDTOKEN_SIGN";

    public static final List<String> FIXED_PROFILENAMES = new ArrayList<>();
    static {
        FIXED_PROFILENAMES.add(ROOTCAPROFILENAME);
        FIXED_PROFILENAMES.add(SUBCAPROFILENAME);
        FIXED_PROFILENAMES.add(ENDUSERPROFILENAME);
        FIXED_PROFILENAMES.add(OCSPSIGNERPROFILENAME);
        FIXED_PROFILENAMES.add(SERVERPROFILENAME);
        FIXED_PROFILENAMES.add(HARDTOKENAUTHPROFILENAME);
        FIXED_PROFILENAMES.add(HARDTOKENAUTHENCPROFILENAME);
        FIXED_PROFILENAMES.add(HARDTOKENENCPROFILENAME);
        FIXED_PROFILENAMES.add(HARDTOKENSIGNPROFILENAME);
    }

    /**
     * Determines if a de-serialized file is compatible with this class.
     * 
     * Maintainers must change this value if and only if the new version of this class is not compatible with old versions. See Sun docs for <a
     * href=http://java.sun.com/products/jdk/1.1/docs/guide /serialization/spec/version.doc.html> details. </a>
     * 
     */
    private static final long serialVersionUID = -8069608639716545206L;



    /** Microsoft Template Constants */
    public static final String MSTEMPL_DOMAINCONTROLLER = "DomainController";

    public static final String[] AVAILABLE_MSTEMPLATES = { MSTEMPL_DOMAINCONTROLLER };

    public static final String TRUE = "true";
    public static final String FALSE = "false";

    /**
     * Determines the access rights in CV Certificates. CV Certificates is used by EU EAC ePassports and is issued by a CVC CA. DG3 is access to
     * fingerprints and DG4 access to iris.
     */
    public static final int CVC_ACCESS_NONE = 0;
    public static final int CVC_ACCESS_DG3 = 1;
    public static final int CVC_ACCESS_DG4 = 2;
    public static final int CVC_ACCESS_DG3DG4 = 3;
    // For signature terminals (defined in version 2.10 of the EAC specification)
    public static final int CVC_ACCESS_SIGN = 16;
    public static final int CVC_ACCESS_QUALSIGN = 32;
    public static final int CVC_ACCESS_SIGN_AND_QUALSIGN = 48;
    
    /**
     * CVC terminal types. Controls which set of roles and access rights are available.
     */
    public static final int CVC_TERMTYPE_IS = 0;
    /** Authentication terminal */
    public static final int CVC_TERMTYPE_AT = 1;
    /** Signature terminal */
    public static final int CVC_TERMTYPE_ST = 2;
    
    /** Accreditation Body DV for signature terminals. ABs accredits CSPs */
    public static final int CVC_SIGNTERM_DV_AB = 0;
    /** Certification Service Provider DV for signature terminals */
    public static final int CVC_SIGNTERM_DV_CSP = 1;

    /** Supported certificate versions. */
    public static final String VERSION_X509V3 = "X509v3";
    public static final String CUSTOMPROFILENAME = "CUSTOM";

    /** Constant indicating that any CA can be used with this certificate profile. */
    public static final int ANYCA = -1;
    /** Constant indicating that any elliptic curve may be used with this profile. */
    public static final String ANY_EC_CURVE = "ANY_EC_CURVE";

    /** Constant holding the default available bit lengths for certificate profiles */
    public static final int[] DEFAULTBITLENGTHS = { 0, 192, 224, 239, 256, 384, 512, 521, 1024, 1536, 2048, 3072, 4096, 6144, 8192 };
    public static final byte[] DEFAULT_CVC_RIGHTS_AT = { 0, 0, 0, 0, 0 };

    // Profile fields
    protected static final String CERTVERSION = "certversion";
    protected static final String VALIDITY = "validity";
    protected static final String ALLOWVALIDITYOVERRIDE = "allowvalidityoverride";
    protected static final String ALLOWKEYUSAGEOVERRIDE = "allowkeyusageoverride";
    protected static final String ALLOWBACKDATEDREVOCATION = "allowbackdatedrevokation";
    protected static final String ALLOWEXTENSIONOVERRIDE = "allowextensionoverride";
    protected static final String ALLOWDNOVERRIDE = "allowdnoverride";
    protected static final String ALLOWDNOVERRIDEBYEEI = "allowdnoverridebyeei";
    protected static final String ALLOWCERTSNOVERIDE = "allowcertsnoverride";
    protected static final String AVAILABLEKEYALGORITHMS = "availablekeyalgorithms";
    protected static final String AVAILABLEECCURVES = "availableeccurves";
    protected static final String AVAILABLEBITLENGTHS = "availablebitlengths";
    protected static final String MINIMUMAVAILABLEBITLENGTH = "minimumavailablebitlength";
    protected static final String MAXIMUMAVAILABLEBITLENGTH = "maximumavailablebitlength";
    public static final String TYPE = "type";
    protected static final String AVAILABLECAS = "availablecas";
    protected static final String USEDPUBLISHERS = "usedpublishers";
    protected static final String USECNPOSTFIX = "usecnpostfix";
    protected static final String CNPOSTFIX = "cnpostfix";
    protected static final String USESUBJECTDNSUBSET = "usesubjectdnsubset";
    protected static final String SUBJECTDNSUBSET = "subjectdnsubset";
    protected static final String USESUBJECTALTNAMESUBSET = "usesubjectaltnamesubset";
    protected static final String SUBJECTALTNAMESUBSET = "subjectaltnamesubset";
    protected static final String USEDCERTIFICATEEXTENSIONS = "usedcertificateextensions";
    protected static final String APPROVALSETTINGS = "approvalsettings";
    /**
     * @deprecated since 6.6.0, use the appropriate approval profile instead
     * Needed for a while in order to be able to import old statedumps from 6.5 and earlier
     */
    @Deprecated
    public static final String NUMOFREQAPPROVALS = "numofreqapprovals";
    protected static final String APPROVALPROFILE = "approvalProfile";
    protected static final String SIGNATUREALGORITHM = "signaturealgorithm";
    protected static final String USECERTIFICATESTORAGE = "usecertificatestorage";
    protected static final String STORECERTIFICATEDATA = "storecertificatedata";
    protected static final String STORESUBJECTALTNAME = "storesubjectaltname";
    //
    // CRL extensions
    protected static final String USECRLNUMBER = "usecrlnumber";
    protected static final String CRLNUMBERCRITICAL = "crlnumbercritical";
    protected static final String USECRLDISTRIBUTIONPOINTONCRL = "usecrldistributionpointoncrl";
    //
    // Certificate extensions
    protected static final String USEBASICCONSTRAINTS = "usebasicconstrants";
    protected static final String BASICCONSTRAINTSCRITICAL = "basicconstraintscritical";
    protected static final String USEPATHLENGTHCONSTRAINT = "usepathlengthconstraint";
    protected static final String PATHLENGTHCONSTRAINT = "pathlengthconstraint";
    protected static final String USEKEYUSAGE = "usekeyusage";
    protected static final String KEYUSAGECRITICAL = "keyusagecritical";
    protected static final String KEYUSAGE = "keyusage";
    protected static final String USESUBJECTKEYIDENTIFIER = "usesubjectkeyidentifier";
    protected static final String SUBJECTKEYIDENTIFIERCRITICAL = "subjectkeyidentifiercritical";
    protected static final String USEAUTHORITYKEYIDENTIFIER = "useauthoritykeyidentifier";
    protected static final String AUTHORITYKEYIDENTIFIERCRITICAL = "authoritykeyidentifiercritical";
    protected static final String USESUBJECTALTERNATIVENAME = "usesubjectalternativename";
    protected static final String SUBJECTALTERNATIVENAMECRITICAL = "subjectalternativenamecritical";
    protected static final String USEISSUERALTERNATIVENAME = "useissueralternativename";
    protected static final String ISSUERALTERNATIVENAMECRITICAL = "issueralternativenamecritical";
    protected static final String USECRLDISTRIBUTIONPOINT = "usecrldistributionpoint";
    protected static final String USEDEFAULTCRLDISTRIBUTIONPOINT = "usedefaultcrldistributionpoint";
    protected static final String CRLDISTRIBUTIONPOINTCRITICAL = "crldistributionpointcritical";
    protected static final String CRLDISTRIBUTIONPOINTURI = "crldistributionpointuri";
    protected static final String CRLISSUER = "crlissuer";
    protected static final String USEFRESHESTCRL = "usefreshestcrl";
    protected static final String USECADEFINEDFRESHESTCRL = "usecadefinedfreshestcrl";
    protected static final String FRESHESTCRLURI = "freshestcrluri";
    protected static final String USECERTIFICATEPOLICIES = "usecertificatepolicies";
    protected static final String CERTIFICATEPOLICIESCRITICAL = "certificatepoliciescritical";
    /** Policy containing oid, User Notice and Cps Url */
    protected static final String CERTIFICATE_POLICIES = "certificatepolicies";
    protected static final String USEEXTENDEDKEYUSAGE = "useextendedkeyusage";
    protected static final String EXTENDEDKEYUSAGE = "extendedkeyusage";
    protected static final String EXTENDEDKEYUSAGECRITICAL = "extendedkeyusagecritical";
    protected static final String USEDOCUMENTTYPELIST = "usedocumenttypelist";
    protected static final String DOCUMENTTYPELISTCRITICAL = "documenttypelistcritical";
    protected static final String DOCUMENTTYPELIST = "documenttypelist";
    protected static final String USEOCSPNOCHECK = "useocspnocheck";
    protected static final String USEAUTHORITYINFORMATIONACCESS = "useauthorityinformationaccess";
    protected static final String USEOCSPSERVICELOCATOR = "useocspservicelocator";
    protected static final String USEDEFAULTCAISSUER = "usedefaultcaissuer";
    protected static final String USEDEFAULTOCSPSERVICELOCATOR = "usedefaultocspservicelocator";
    protected static final String OCSPSERVICELOCATORURI = "ocspservicelocatoruri";
    protected static final String USECAISSUERS = "usecaissuersuri";
    protected static final String CAISSUERS = "caissuers";
    protected static final String USELDAPDNORDER = "useldapdnorder";
    protected static final String USEMICROSOFTTEMPLATE = "usemicrosofttemplate";
    protected static final String MICROSOFTTEMPLATE = "microsofttemplate";
    protected static final String USECARDNUMBER = "usecardnumber";
    protected static final String USEQCSTATEMENT = "useqcstatement";
    protected static final String USEPKIXQCSYNTAXV2 = "usepkixqcsyntaxv2";
    protected static final String QCSTATEMENTCRITICAL = "useqcstatementcritical";
    protected static final String QCSTATEMENTRANAME = "useqcstatementraname";
    protected static final String QCSSEMANTICSID = "useqcsematicsid";
    protected static final String USEQCETSIQCCOMPLIANCE = "useqcetsiqccompliance";
    protected static final String USEQCETSIVALUELIMIT = "useqcetsivaluelimit";
    protected static final String QCETSIVALUELIMIT = "qcetsivaluelimit";
    protected static final String QCETSIVALUELIMITEXP = "qcetsivaluelimitexp";
    protected static final String QCETSIVALUELIMITCURRENCY = "qcetsivaluelimitcurrency";
    protected static final String USEQCETSIRETENTIONPERIOD = "useqcetsiretentionperiod";
    protected static final String QCETSIRETENTIONPERIOD = "qcetsiretentionperiod";
    protected static final String USEQCETSISIGNATUREDEVICE = "useqcetsisignaturedevice";
    protected static final String USEQCETSITYPE = "useqcetsitype";
    protected static final String QCETSITYPE = "qcetsitype";
    protected static final String QCETSIPDS = "qcetsipds";
    @Deprecated
    protected static final String QCETSIPDSURL = "qcetsipdsurl";
    @Deprecated
    protected static final String QCETSIPDSLANG = "qcetsipdslang";
    protected static final String USEQCCUSTOMSTRING = "useqccustomstring";
    protected static final String QCCUSTOMSTRINGOID = "qccustomstringoid";
    protected static final String QCCUSTOMSTRINGTEXT = "qccustomstringtext";
    protected static final String USENAMECONSTRAINTS = "usenameconstraints";
    protected static final String NAMECONSTRAINTSCRITICAL = "nameconstraintscritical";
    protected static final String USESUBJECTDIRATTRIBUTES = "usesubjectdirattributes";
    protected static final String CVCTERMINALTYPE = "cvctermtype";
    protected static final String CVCACCESSRIGHTS = "cvcaccessrights";
    protected static final String CVCLONGACCESSRIGHTS = "cvclongaccessrights";
    protected static final String CVCSIGNTERMDVTYPE = "cvcsigntermdvtype";
    protected static final String USEPRIVKEYUSAGEPERIOD          = "useprivkeyusageperiod";
    protected static final String USEPRIVKEYUSAGEPERIODNOTBEFORE = "useprivkeyusageperiodnotbefore";
    protected static final String USEPRIVKEYUSAGEPERIODNOTAFTER  = "useprivkeyusageperiodnotafter";
    protected static final String PRIVKEYUSAGEPERIODSTARTOFFSET  = "privkeyusageperiodstartoffset";
    protected static final String PRIVKEYUSAGEPERIODLENGTH           = "privkeyusageperiodlength";
    protected static final String USECERTIFICATETRANSPARENCYINCERTS = "usecertificatetransparencyincerts";
    protected static final String USECERTIFICATETRANSPARENCYINOCSP  = "usecertificatetransparencyinocsp";
    protected static final String USECERTIFICATETRANSPARENCYINPUBLISHERS  = "usecertificatetransparencyinpublisher";
    protected static final String CTSUBMITEXISTING  = "ctsubmitexisting";
    protected static final String CTLOGS = "ctlogs";
    protected static final String CTMINSCTS = "ctminscts";
    protected static final String CTMAXSCTS = "ctmaxscts";
    protected static final String CTMINSCTSOCSP = "ctminsctsocsp";
    protected static final String CTMAXSCTSOCSP = "ctmaxsctsocsp";
    protected static final String CTMAXRETRIES = "ctmaxretries";
    protected static final String USERSINGLEACTIVECERTIFICATECONSTRAINT = "usesingleactivecertificateconstraint";
    protected static final String USECUSTOMDNORDER = "usecustomdnorder";
    protected static final String CUSTOMDNORDER = "customdnorder";
    

    /**
     * OID for creating Smartcard Number Certificate Extension SEIS Cardnumber Extension according to SS 614330/31
     */
    public static final String OID_CARDNUMBER = "1.2.752.34.2.1";

    /** Constants holding the use properties for certificate extensions */
    protected static final HashMap<String, String> useStandardCertificateExtensions = new HashMap<>();
    {
        useStandardCertificateExtensions.put(USEBASICCONSTRAINTS, Extension.basicConstraints.getId());
        useStandardCertificateExtensions.put(USEKEYUSAGE, Extension.keyUsage.getId());
        useStandardCertificateExtensions.put(USESUBJECTKEYIDENTIFIER, Extension.subjectKeyIdentifier.getId());
        useStandardCertificateExtensions.put(USEAUTHORITYKEYIDENTIFIER, Extension.authorityKeyIdentifier.getId());
        useStandardCertificateExtensions.put(USESUBJECTALTERNATIVENAME, Extension.subjectAlternativeName.getId());
        useStandardCertificateExtensions.put(USEISSUERALTERNATIVENAME, Extension.issuerAlternativeName.getId());
        useStandardCertificateExtensions.put(USECRLDISTRIBUTIONPOINT, Extension.cRLDistributionPoints.getId());
        useStandardCertificateExtensions.put(USEFRESHESTCRL, Extension.freshestCRL.getId());
        useStandardCertificateExtensions.put(USECERTIFICATEPOLICIES, Extension.certificatePolicies.getId());
        useStandardCertificateExtensions.put(USEEXTENDEDKEYUSAGE, Extension.extendedKeyUsage.getId());
        useStandardCertificateExtensions.put(USEDOCUMENTTYPELIST, "2.23.136.1.1.6.2");
        useStandardCertificateExtensions.put(USEQCSTATEMENT, Extension.qCStatements.getId());
        useStandardCertificateExtensions.put(USENAMECONSTRAINTS, Extension.nameConstraints.getId());
        useStandardCertificateExtensions.put(USESUBJECTDIRATTRIBUTES, Extension.subjectDirectoryAttributes.getId());
        useStandardCertificateExtensions.put(USEAUTHORITYINFORMATIONACCESS, Extension.authorityInfoAccess.getId());
        useStandardCertificateExtensions.put(USEPRIVKEYUSAGEPERIOD, Extension.privateKeyUsagePeriod.getId());
        useStandardCertificateExtensions.put(USEOCSPNOCHECK, OCSPObjectIdentifiers.id_pkix_ocsp_nocheck.getId());
        useStandardCertificateExtensions.put(USEMICROSOFTTEMPLATE, CertTools.OID_MSTEMPLATE);
        useStandardCertificateExtensions.put(USECARDNUMBER, OID_CARDNUMBER);
    }

    // Old values used to upgrade from v22 to v23
    protected static final String CERTIFICATEPOLICYID = "certificatepolicyid";
    /** Policy Notice Url to CPS field alias in the data structure */
    protected static final String POLICY_NOTICE_CPS_URL = "policynoticecpsurl";
    /** Policy Notice User Notice field alias in the data structure */
    protected static final String POLICY_NOTICE_UNOTICE_TEXT = "policynoticeunoticetext";

    // Public Methods

    /**
     * Creates a new instance of CertificateProfile. The default contructor creates a basic CertificateProfile
     * that is the same as an End User certificateProfile, except that there are _no_ key usages. this means that a certificate
     * issued with a default profile should not be usable for anything. Should be used for testing and where you want to create your own
     * CertificateProfile for specific purposes.
     * 
     */
    public CertificateProfile() {
        setCommonDefaults();
    }
    
    /**
     * Creates a new instance of CertificateProfile
     * 
     * These settings are general for all sub-profiles, only differing values are overridden in the sub-profiles. If changing any present value here
     * you must therefore go through all sub-profiles and add an override there. I.e. only add new values here, don't change any present settings.
     * 
     * @param type
     *            one of CertificateProfileConstants.CERTPROFILE_FIXED_XX, for example CertificateConstants.CERTPROFILE_NO_PROFILE, CERTPROFILE_NO_ENDUSER, etc
     */
    public CertificateProfile(int type) {
        setCommonDefaults();
        setDefaultValues(type);
    }

    private void setCommonDefaults() {
        setType(CertificateConstants.CERTTYPE_ENDENTITY);
        setCertificateVersion(VERSION_X509V3);
        setValidity(730);
        setAllowValidityOverride(false);

        setAllowExtensionOverride(false);

        setAllowDNOverride(false);
        setAllowDNOverrideByEndEntityInformation(false);
        setAllowBackdatedRevocation(false);
        setUseCertificateStorage(true);
        setStoreCertificateData(true);
        setStoreSubjectAlternativeName(true); // New profiles created after EJBCA 6.6.0 will store SAN by default

        setUseBasicConstraints(true);
        setBasicConstraintsCritical(true);

        setUseSubjectKeyIdentifier(true);
        setSubjectKeyIdentifierCritical(false);

        setUseAuthorityKeyIdentifier(true);
        setAuthorityKeyIdentifierCritical(false);

        setUseSubjectAlternativeName(true);
        setSubjectAlternativeNameCritical(false);
        
        setUseIssuerAlternativeName(true);
        setIssuerAlternativeNameCritical(false);

        setUseCRLDistributionPoint(false);
        setUseDefaultCRLDistributionPoint(false);
        setCRLDistributionPointCritical(false);
        setCRLDistributionPointURI("");
        setUseCRLDistributionPointOnCRL(false);
        setUseFreshestCRL(false);
        setUseCADefinedFreshestCRL(false);
        setFreshestCRLURI("");
        setCRLIssuer(null);

        setUseCertificatePolicies(false);
        setCertificatePoliciesCritical(false);
        ArrayList<CertificatePolicy> policies = new ArrayList<>();
        setCertificatePolicies(policies);

        setAvailableKeyAlgorithmsAsList(getAvailableKeyAlgorithmsAvailable());
        setAvailableEcCurvesAsList(Arrays.asList(ANY_EC_CURVE));
        setAvailableBitLengths(DEFAULTBITLENGTHS);
        setSignatureAlgorithm(null);

        setUseKeyUsage(true);
        setKeyUsage(new boolean[9]);
        setAllowKeyUsageOverride(false);
        setKeyUsageCritical(true);

        setUseExtendedKeyUsage(false);
        setExtendedKeyUsage(new ArrayList<String>());
        setExtendedKeyUsageCritical(false);
        
        setUseDocumentTypeList(false);
        setDocumentTypeListCritical(false);
        setDocumentTypeList(new ArrayList<String>());

        ArrayList<Integer> availablecas = new ArrayList<>();
        availablecas.add(Integer.valueOf(ANYCA));
        setAvailableCAs(availablecas);

        setPublisherList(new ArrayList<Integer>());

        setUseOcspNoCheck(false);

        setUseLdapDnOrder(true);
        setUseCustomDnOrder(false);

        setUseMicrosoftTemplate(false);
        setMicrosoftTemplate("");
        setUseCardNumber(false);

        setUseCNPostfix(false);
        setCNPostfix("");

        setUseSubjectDNSubSet(false);
        setSubjectDNSubSet(new ArrayList<String>());
        setUseSubjectAltNameSubSet(false);
        setSubjectAltNameSubSet(new ArrayList<Integer>());

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
        setQCEtsiPds(null);
        setQCEtsiType(null);
        
        setUseCertificateTransparencyInCerts(false);
        setUseCertificateTransparencyInOCSP(false);
        setUseCertificateTransparencyInPublishers(false);

        setUseSubjectDirAttributes(false);
        setUseNameConstraints(false);
        setUseAuthorityInformationAccess(false);
        setCaIssuers(new ArrayList<String>());
        setUseDefaultCAIssuer(false);
        setUseDefaultOCSPServiceLocator(false);
        setOCSPServiceLocatorURI("");

        // Default to have access to fingerprint and iris
        setCVCAccessRights(CertificateProfile.CVC_ACCESS_DG3DG4);

        setUsedCertificateExtensions(new ArrayList<Integer>());
        List<Integer> emptyList = Collections.emptyList();
        setApprovalSettings(emptyList);
        setApprovalProfileID(-1);
        
     // PrivateKeyUsagePeriod extension
        setUsePrivateKeyUsagePeriodNotBefore(false);
        setUsePrivateKeyUsagePeriodNotAfter(false);
        setPrivateKeyUsagePeriodStartOffset(0);
        setPrivateKeyUsagePeriodLength(getValidity() * 24 * 3600);
        
        setSingleActiveCertificateConstraint(false);
    }

    /**
     * @param type
     *            one of CertificateProfileConstants.CERTPROFILE_FIXED_XX, for example CertificateConstants.CERTPROFILE_FIXED_ROOTCA
     */

    private void setDefaultValues(int type) {
        if (type == CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA) {
            setType(CertificateConstants.CERTTYPE_ROOTCA);
            setAllowValidityOverride(true);
            setUseKeyUsage(true);
            setKeyUsage(new boolean[9]);
            setKeyUsage(CertificateConstants.DIGITALSIGNATURE, true);
            setKeyUsage(CertificateConstants.KEYCERTSIGN, true);
            setKeyUsage(CertificateConstants.CRLSIGN, true);
            setKeyUsageCritical(true);
            setValidity(25 * 365 + 7); // Default validity for this profile is 25 years including 6 or 7 leap days
        } else if (type == CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA) {
            setType(CertificateConstants.CERTTYPE_SUBCA);
            setAllowValidityOverride(true);
            setUseKeyUsage(true);
            setKeyUsage(new boolean[9]);
            setKeyUsage(CertificateConstants.DIGITALSIGNATURE, true);
            setKeyUsage(CertificateConstants.KEYCERTSIGN, true);
            setKeyUsage(CertificateConstants.CRLSIGN, true);
            setKeyUsageCritical(true);
            setValidity(25 * 365 + 7); // Default validity for this profile is 25 years including 6 or 7 leap days
        } else if (type == CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER) {
            setType(CertificateConstants.CERTTYPE_ENDENTITY);
            // Standard key usages for end users are: digitalSignature | nonRepudiation, and/or (keyEncipherment or keyAgreement)
            // Default key usage is digitalSignature | nonRepudiation | keyEncipherment
            // Create an array for KeyUsage according to X509Certificate.getKeyUsage()
            setUseKeyUsage(true);
            setKeyUsage(new boolean[9]);
            setKeyUsage(CertificateConstants.DIGITALSIGNATURE, true);
            setKeyUsage(CertificateConstants.NONREPUDIATION, true);
            setKeyUsage(CertificateConstants.KEYENCIPHERMENT, true);
            setKeyUsageCritical(true);
            setUseExtendedKeyUsage(true);
            ArrayList<String> eku = new ArrayList<>();
            eku.add(KeyPurposeId.id_kp_clientAuth.getId());
            eku.add(KeyPurposeId.id_kp_emailProtection.getId());
            setExtendedKeyUsage(eku);
            setExtendedKeyUsageCritical(false);
        } else if (type == CertificateProfileConstants.CERTPROFILE_FIXED_OCSPSIGNER) {
            setType(CertificateConstants.CERTTYPE_ENDENTITY);
            // Default key usage for an OCSP signer is digitalSignature
            // Create an array for KeyUsage acoording to X509Certificate.getKeyUsage()
            setUseKeyUsage(true);
            setKeyUsage(new boolean[9]);
            setKeyUsage(CertificateConstants.DIGITALSIGNATURE, true);
            setKeyUsageCritical(true);
            setUseExtendedKeyUsage(true);
            ArrayList<String> eku = new ArrayList<>();
            eku.add(KeyPurposeId.id_kp_OCSPSigning.getId());
            setExtendedKeyUsage(eku);
            setExtendedKeyUsageCritical(false);
            setUseOcspNoCheck(true);
        } else if (type == CertificateProfileConstants.CERTPROFILE_FIXED_SERVER) {
            setType(CertificateConstants.CERTTYPE_ENDENTITY);
            // Standard key usages for server are: digitalSignature | (keyEncipherment or keyAgreement)
            // Default key usage is digitalSignature | keyEncipherment
            // Create an array for KeyUsage acoording to X509Certificate.getKeyUsage()
            setUseKeyUsage(true);
            setKeyUsage(new boolean[9]);
            setKeyUsage(CertificateConstants.DIGITALSIGNATURE, true);
            setKeyUsage(CertificateConstants.KEYENCIPHERMENT, true);
            setKeyUsageCritical(true);
            setUseExtendedKeyUsage(true);
            ArrayList<String> eku = new ArrayList<>();
            eku.add(KeyPurposeId.id_kp_serverAuth.getId());
            setExtendedKeyUsage(eku);
            setExtendedKeyUsageCritical(false);
        } else if (type == CertificateProfileConstants.CERTPROFILE_FIXED_HARDTOKENAUTH) {
            setType(CertificateConstants.CERTTYPE_ENDENTITY);
            setUseKeyUsage(true);
            setKeyUsage(new boolean[9]);
            setKeyUsage(CertificateConstants.DIGITALSIGNATURE, true);
            setKeyUsageCritical(true);
            setUseExtendedKeyUsage(true);
            ArrayList<String> eku = new ArrayList<>();
            eku.add(KeyPurposeId.id_kp_clientAuth.getId());
            eku.add(KeyPurposeId.id_kp_smartcardlogon.getId());
            setExtendedKeyUsage(eku);
            setExtendedKeyUsageCritical(false);
        } else if (type == CertificateProfileConstants.CERTPROFILE_FIXED_HARDTOKENAUTHENC) {
            setType(CertificateConstants.CERTTYPE_ENDENTITY);
            setUseKeyUsage(true);
            setKeyUsage(new boolean[9]);
            setKeyUsage(CertificateConstants.KEYENCIPHERMENT, true);
            setKeyUsage(CertificateConstants.DIGITALSIGNATURE, true);
            setKeyUsageCritical(true);
            setUseExtendedKeyUsage(true);
            ArrayList<String> eku = new ArrayList<>();
            eku.add(KeyPurposeId.id_kp_clientAuth.getId());
            eku.add(KeyPurposeId.id_kp_emailProtection.getId());
            eku.add(KeyPurposeId.id_kp_smartcardlogon.getId());
            setExtendedKeyUsage(eku);
            setExtendedKeyUsageCritical(false);
        } else if (type == CertificateProfileConstants.CERTPROFILE_FIXED_HARDTOKENENC) {
            setType(CertificateConstants.CERTTYPE_ENDENTITY);
            setUseKeyUsage(true);
            setKeyUsage(new boolean[9]);
            setKeyUsage(CertificateConstants.KEYENCIPHERMENT, true);
            setKeyUsageCritical(true);
            setUseExtendedKeyUsage(true);
            ArrayList<String> eku = new ArrayList<>();
            eku.add(KeyPurposeId.id_kp_emailProtection.getId());
            setExtendedKeyUsage(eku);
            setExtendedKeyUsageCritical(false);
        } else if (type == CertificateProfileConstants.CERTPROFILE_FIXED_HARDTOKENSIGN) {
            setType(CertificateConstants.CERTTYPE_ENDENTITY);
            setUseKeyUsage(true);
            setKeyUsage(new boolean[9]);
            setKeyUsage(CertificateConstants.NONREPUDIATION, true);
            setKeyUsageCritical(true);
            setUseExtendedKeyUsage(true);
            ArrayList<String> eku = new ArrayList<>();
            eku.add(KeyPurposeId.id_kp_emailProtection.getId());
            setExtendedKeyUsage(eku);
            setExtendedKeyUsageCritical(false);
        }
    }

    // Public Methods.
    /** Returns the version of the certificate, should be one of the VERSION_ constants defined in CertificateProfile class. */
    public String getCertificateVersion() {
        return (String) data.get(CERTVERSION);
    }

    /**
     * Returns the version of the certificate, should be one of the VERSION_ constants defined in CertificateProfile class.
     */
    public void setCertificateVersion(String version) {
        data.put(CERTVERSION, version);
    }

    /** 
     * @see ValidityDate#getDate(long, java.util.Date)
     * @return a long that is used to provide the end date of certificates for this profile, interpreted by ValidityDate#getDate
     */
    public long getValidity() {
        return ((Long) data.get(VALIDITY)).longValue();
    }

    /** 
     * @see ValidityDate#getDate(long, java.util.Date)
     * @param validity a long that is used to provide the end date of certificates for this profile, interpreted by ValidityDate#getDate
     */
    public void setValidity(long validity) {
        data.put(VALIDITY, Long.valueOf(validity));
    }

    /**
     * If validity override is allowed, a certificate can have a shorter validity than the one specified in the certificate profile, but never longer.
     * A certificate created with validity override can hava a starting point in the future.
     * 
     * @return true if validity override is allowed
     */
    public boolean getAllowValidityOverride() {
        return ((Boolean) data.get(ALLOWVALIDITYOVERRIDE)).booleanValue();
    }

    /**
     * If validity override is allowed, a certificate can have a shorter validity than the one specified in the certificate profile, but never longer.
     * A certificate created with validity override can hava a starting point in the future.
     */
    public void setAllowValidityOverride(boolean allowvalidityoverride) {
        data.put(ALLOWVALIDITYOVERRIDE, Boolean.valueOf(allowvalidityoverride));
    }

    /**
     * If extension override is allowed, the X509 certificate extension created in a certificate can come from the request sent by the user. If the
     * request contains an extension than will be used instead of the one defined in the profile. If the request does not contain an extension, the
     * one defined in the profile will be used.
     */
    public boolean getAllowExtensionOverride() {
        Object d = data.get(ALLOWEXTENSIONOVERRIDE);
        if (d == null) {
            return false;
        }
        return ((Boolean) d).booleanValue();
    }

    /** @see #getAllowExtensionOverride() */
    public void setAllowExtensionOverride(boolean allowextensionoverride) {
        data.put(ALLOWEXTENSIONOVERRIDE, Boolean.valueOf(allowextensionoverride));
    }

    /**
     * If DN override is allowed, the X509 subject DN extension created in a certificate can
     * come directly from the CSR in the request sent by the user. This is instead of the normal way where the user's
     * registered DN is used.
     */
    public boolean getAllowDNOverride() {
        Object d = data.get(ALLOWDNOVERRIDE);
        if (d == null) {
            return false;
        }
        return ((Boolean) d).booleanValue();
    }

    /** @see #getAllowDNOverride() */
    public void setAllowDNOverride(boolean allowdnoverride) {
        data.put(ALLOWDNOVERRIDE, Boolean.valueOf(allowdnoverride));
    }

    /**
     * If DN override by End Entity Information is allowed, the X509 subject DN extension created in a certificate can
     * come directly from the request meta information sent by the user. This is instead of the normal way where the
     * user's registered DN is used.
     */
    public boolean getAllowDNOverrideByEndEntityInformation() {
        Object d = data.get(ALLOWDNOVERRIDEBYEEI);
        if (d == null) {
            return false;
        }
        return ((Boolean) d).booleanValue();
    }

    /** @see #getAllowDNOverrideByEndEntityInformation() */
    public void setAllowDNOverrideByEndEntityInformation(final boolean value) {
        data.put(ALLOWDNOVERRIDEBYEEI, Boolean.valueOf(value));
    }

    /**
     * If override is allowed the serial number could be specified.
     * 
     * @return true if allowed
     */
    public boolean getAllowCertSerialNumberOverride() {
        Object d = data.get(ALLOWCERTSNOVERIDE);
        if (d == null) {
            return false;
        }
        return ((Boolean) d).booleanValue();
    }

    /**
     * @see #getAllowDNOverride()
     * @param allowdnoverride
     *            new value
     */
    public void setAllowCertSerialNumberOverride(boolean allowdnoverride) {
        data.put(ALLOWCERTSNOVERIDE, Boolean.valueOf(allowdnoverride));
    }

    public boolean getUseBasicConstraints() {
        return ((Boolean) data.get(USEBASICCONSTRAINTS)).booleanValue();
    }

    public void setUseBasicConstraints(boolean usebasicconstraints) {
        data.put(USEBASICCONSTRAINTS, Boolean.valueOf(usebasicconstraints));
    }

    public boolean getBasicConstraintsCritical() {
        return ((Boolean) data.get(BASICCONSTRAINTSCRITICAL)).booleanValue();
    }

    public void setBasicConstraintsCritical(boolean basicconstraintscritical) {
        data.put(BASICCONSTRAINTSCRITICAL, Boolean.valueOf(basicconstraintscritical));
    }

    public boolean getUseKeyUsage() {
        return ((Boolean) data.get(USEKEYUSAGE)).booleanValue();
    }

    public void setUseKeyUsage(boolean usekeyusage) {
        data.put(USEKEYUSAGE, Boolean.valueOf(usekeyusage));
    }

    public boolean getKeyUsageCritical() {
        return ((Boolean) data.get(KEYUSAGECRITICAL)).booleanValue();
    }

    public void setKeyUsageCritical(boolean keyusagecritical) {
        data.put(KEYUSAGECRITICAL, Boolean.valueOf(keyusagecritical));
    }

    public boolean getUseSubjectKeyIdentifier() {
        return ((Boolean) data.get(USESUBJECTKEYIDENTIFIER)).booleanValue();
    }

    public void setUseSubjectKeyIdentifier(boolean usesubjectkeyidentifier) {
        data.put(USESUBJECTKEYIDENTIFIER, Boolean.valueOf(usesubjectkeyidentifier));
    }

    public boolean getSubjectKeyIdentifierCritical() {
        return ((Boolean) data.get(SUBJECTKEYIDENTIFIERCRITICAL)).booleanValue();
    }

    public void setSubjectKeyIdentifierCritical(boolean subjectkeyidentifiercritical) {
        data.put(SUBJECTKEYIDENTIFIERCRITICAL, Boolean.valueOf(subjectkeyidentifiercritical));
    }

    public boolean getUseAuthorityKeyIdentifier() {
        return ((Boolean) data.get(USEAUTHORITYKEYIDENTIFIER)).booleanValue();
    }

    public void setUseAuthorityKeyIdentifier(boolean useauthoritykeyidentifier) {
        data.put(USEAUTHORITYKEYIDENTIFIER, Boolean.valueOf(useauthoritykeyidentifier));
    }

    public boolean getAuthorityKeyIdentifierCritical() {
        return ((Boolean) data.get(AUTHORITYKEYIDENTIFIERCRITICAL)).booleanValue();
    }

    public void setAuthorityKeyIdentifierCritical(boolean authoritykeyidentifiercritical) {
        data.put(AUTHORITYKEYIDENTIFIERCRITICAL, Boolean.valueOf(authoritykeyidentifiercritical));
    }

    public boolean getUseSubjectAlternativeName() {
        return ((Boolean) data.get(USESUBJECTALTERNATIVENAME)).booleanValue();
    }

    public void setUseSubjectAlternativeName(boolean usesubjectalternativename) {
        data.put(USESUBJECTALTERNATIVENAME, Boolean.valueOf(usesubjectalternativename));
    }
    
    public boolean getStoreCertificateData() {
        // Lazy upgrade for profiles created prior to EJBCA 6.2.10
        final Boolean value = (Boolean) data.get(STORECERTIFICATEDATA);
        if (value == null) {
            // Default for existing profiles is true
            setStoreCertificateData(true);
            return true;
        } else {
            return value.booleanValue();
        }
    }
    
    public void setStoreCertificateData(boolean storeCertificateData) {
        data.put(STORECERTIFICATEDATA, Boolean.valueOf(storeCertificateData));
    }

    /** @return true if the CertificateData.subjectAltName column should be populated. */
    public boolean getStoreSubjectAlternativeName() {
        // Lazy upgrade for profiles created prior to EJBCA 6.6.0
        final Boolean value = (Boolean) data.get(STORESUBJECTALTNAME);
        if (value == null) {
            // Old profiles created before EJBCA 6.6.0 will not store SAN by default.
            setStoreSubjectAlternativeName(false);
            return false;
        } else {
            return value.booleanValue();
        }
    }
    
    public void setStoreSubjectAlternativeName(final boolean storeSubjectAlternativeName) {
        data.put(STORESUBJECTALTNAME, Boolean.valueOf(storeSubjectAlternativeName));
    }

    public boolean getSubjectAlternativeNameCritical() {
        return ((Boolean) data.get(SUBJECTALTERNATIVENAMECRITICAL)).booleanValue();
    }

    public void setSubjectAlternativeNameCritical(boolean subjectalternativenamecritical) {
        data.put(SUBJECTALTERNATIVENAMECRITICAL, Boolean.valueOf(subjectalternativenamecritical));
    }
    
    public boolean getUseIssuerAlternativeName() {
        return ((Boolean) data.get(USEISSUERALTERNATIVENAME)).booleanValue();
    }

    public void setUseIssuerAlternativeName(boolean useissueralternativename) {
        data.put(USEISSUERALTERNATIVENAME, Boolean.valueOf(useissueralternativename));
    }

    public boolean getIssuerAlternativeNameCritical() {
        return ((Boolean) data.get(ISSUERALTERNATIVENAMECRITICAL)).booleanValue();
    }

    public void setIssuerAlternativeNameCritical(boolean issueralternativenamecritical) {
        data.put(ISSUERALTERNATIVENAMECRITICAL, Boolean.valueOf(issueralternativenamecritical));
    }

    public boolean getUseCRLDistributionPoint() {
        return ((Boolean) data.get(USECRLDISTRIBUTIONPOINT)).booleanValue();
    }

    public void setUseCRLDistributionPoint(boolean usecrldistributionpoint) {
        data.put(USECRLDISTRIBUTIONPOINT, Boolean.valueOf(usecrldistributionpoint));
    }

    public boolean getUseDefaultCRLDistributionPoint() {
        return ((Boolean) data.get(USEDEFAULTCRLDISTRIBUTIONPOINT)).booleanValue();
    }

    public void setUseDefaultCRLDistributionPoint(boolean usedefaultcrldistributionpoint) {
        data.put(USEDEFAULTCRLDISTRIBUTIONPOINT, Boolean.valueOf(usedefaultcrldistributionpoint));
    }

    public boolean getCRLDistributionPointCritical() {
        return ((Boolean) data.get(CRLDISTRIBUTIONPOINTCRITICAL)).booleanValue();
    }

    public void setCRLDistributionPointCritical(boolean crldistributionpointcritical) {
        data.put(CRLDISTRIBUTIONPOINTCRITICAL, Boolean.valueOf(crldistributionpointcritical));
    }

    public String getCRLDistributionPointURI() {
        return (String) data.get(CRLDISTRIBUTIONPOINTURI);
    }

    public void setCRLDistributionPointURI(String crldistributionpointuri) {
        if (crldistributionpointuri == null) {
            data.put(CRLDISTRIBUTIONPOINTURI, "");
        } else {
            data.put(CRLDISTRIBUTIONPOINTURI, crldistributionpointuri);
        }
    }

    public String getCRLIssuer() {
        return (String) data.get(CRLISSUER);
    }

    public void setCRLIssuer(String crlissuer) {
        if (crlissuer == null) {
            data.put(CRLISSUER, "");
        } else {
            data.put(CRLISSUER, crlissuer);
        }
    }

    public boolean getUseFreshestCRL() {
        Object obj = data.get(USEFRESHESTCRL);
        if (obj == null) {
            return false;
        } else {
            return ((Boolean) obj).booleanValue();
        }
    }

    public boolean getUseCRLDistributionPointOnCRL() {
        Object obj = data.get(USECRLDISTRIBUTIONPOINTONCRL);
        if (obj == null) {
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

    public boolean getUseCADefinedFreshestCRL() {
        Object obj = data.get(USECADEFINEDFRESHESTCRL);
        if (obj == null) {
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

    public boolean getUseCertificatePolicies() {
        return ((Boolean) data.get(USECERTIFICATEPOLICIES)).booleanValue();
    }

    public void setUseCertificatePolicies(boolean usecertificatepolicies) {
        data.put(USECERTIFICATEPOLICIES, Boolean.valueOf(usecertificatepolicies));
    }
    
    public boolean getUseCertificateStorage() {
        //Lazy upgrade for profiles created prior to EJBCA 6.2.10
        Boolean value = (Boolean) data.get(USECERTIFICATESTORAGE);
        if (value == null) {
            //Default is true
            setUseCertificateStorage(true);
            return true;
        } else {
            return value.booleanValue();
        }
    }
    
    public void setUseCertificateStorage(boolean useCertificateStorage) {
        data.put(USECERTIFICATESTORAGE, Boolean.valueOf(useCertificateStorage));
    }

    public boolean getCertificatePoliciesCritical() {
        return ((Boolean) data.get(CERTIFICATEPOLICIESCRITICAL)).booleanValue();
    }

    public void setCertificatePoliciesCritical(boolean certificatepoliciescritical) {
        data.put(CERTIFICATEPOLICIESCRITICAL, Boolean.valueOf(certificatepoliciescritical));
    }

    public List<CertificatePolicy> getCertificatePolicies() {
        @SuppressWarnings("unchecked")
        List<CertificatePolicy> l = (List<CertificatePolicy>) data.get(CERTIFICATE_POLICIES);
        if (l == null) {
            l = new ArrayList<CertificatePolicy>();
        } else {
            // Check class name, because we changed this in EJBCA 5 and need to support older versions in the database for 100% upgrade
            if (l.size() > 0) {
                try {
                    // Don't remove the unused test object
                    CertificatePolicy test = l.get(0); // NOPMD: we need to actually get the text object, otherwise the cast will not be tried
                    test.getPolicyID();
                } catch (ClassCastException e) {
                    if (log.isDebugEnabled()) {
                        log.debug("CertificatePolicy in profile is old class name (< EJBCA 5), post-upgrade has not been run. Converting in code to return new class type.");
                    }
                    @SuppressWarnings("unchecked")
                    List<Object> oldl = (List<Object>) data.get(CERTIFICATE_POLICIES);
                    // In worst case they can have mixed old and new classes, therefore we use a "normal" iterator so we can verify the cast
                    l = new ArrayList<CertificatePolicy>();
                    for (int i = 0; i < oldl.size(); i++) {
                        try {
                            org.ejbca.core.model.ca.certificateprofiles.CertificatePolicy oldPol = (org.ejbca.core.model.ca.certificateprofiles.CertificatePolicy)oldl.get(i);                            
                            CertificatePolicy newPol = new CertificatePolicy(oldPol.getPolicyID(), oldPol.getQualifierId(), oldPol.getQualifier());
                            if (log.isTraceEnabled()) {
                                log.trace("Adding converted policy");
                            }
                            l.add(newPol);
                        } catch (ClassCastException e2) {
                            // This was already a new class, there are mixed policies here...
                            CertificatePolicy newPol = (CertificatePolicy)oldl.get(i);                            
                            if (log.isTraceEnabled()) {
                                log.trace("Adding non-converted policy");
                            }
                            l.add(newPol);
                        }                        
                    }
                }
            }
        }
        return l;
    }

    @SuppressWarnings("unchecked")
    public void addCertificatePolicy(CertificatePolicy policy) {
        if (data.get(CERTIFICATE_POLICIES) == null) {
            setCertificatePolicies(new ArrayList<CertificatePolicy>());
        }
        ((List<CertificatePolicy>) data.get(CERTIFICATE_POLICIES)).add(policy);
    }

    public void setCertificatePolicies(List<CertificatePolicy> policies) {
        if (policies == null) {
            data.put(CERTIFICATE_POLICIES, new ArrayList<CertificatePolicy>(0));
        } else {
            data.put(CERTIFICATE_POLICIES, policies);
        }
    }

    @SuppressWarnings("unchecked")
    public void removeCertificatePolicy(CertificatePolicy policy) {
        if (data.get(CERTIFICATE_POLICIES) != null) {
            ((List<CertificatePolicy>) data.get(CERTIFICATE_POLICIES)).remove(policy);
        }
    }

    /** Type is used when setting BasicConstraints, i.e. to determine if it is a CA or an end entity 
     * @see CertificateConstants.CERTTYPE_ROOTCA, etc
     */
    public int getType() {
        return ((Integer) data.get(TYPE)).intValue();
    }

    /** Type is used when setting BasicConstraints, i.e. to determine if it is a CA or an end entity 
     * @see CertificateConstants.CERTTYPE_ROOTCA, etc
     */
    public void setType(int type) {
        data.put(TYPE, Integer.valueOf(type));
    }

    public boolean isTypeSubCA() {
        return ((Integer) data.get(TYPE)).intValue() == CertificateConstants.CERTTYPE_SUBCA;
    }

    public boolean isTypeRootCA() {
        return ((Integer) data.get(TYPE)).intValue() == CertificateConstants.CERTTYPE_ROOTCA;
    }

    public boolean isTypeEndEntity() {
        return ((Integer) data.get(TYPE)).intValue() == CertificateConstants.CERTTYPE_ENDENTITY;
    }

    public String[] getAvailableKeyAlgorithms() {
        final List<String> availableKeyAlgorithms = getAvailableKeyAlgorithmsAsList();
        return availableKeyAlgorithms.toArray(new String[availableKeyAlgorithms.size()]);
    }
    @SuppressWarnings("unchecked")
    public List<String> getAvailableKeyAlgorithmsAsList() {
        return (ArrayList<String>) data.get(AVAILABLEKEYALGORITHMS);
    }
    public void setAvailableKeyAlgorithms(final String[] availableKeyAlgorithms) {
        setAvailableKeyAlgorithmsAsList(Arrays.asList(availableKeyAlgorithms));
    }
    public void setAvailableKeyAlgorithmsAsList(final List<String> availableKeyAlgorithms) {
        data.put(AVAILABLEKEYALGORITHMS, new ArrayList<>(availableKeyAlgorithms));
    }
    public List<String> getAvailableKeyAlgorithmsAvailable() {
        return AlgorithmTools.getAvailableKeyAlgorithms();
    }

    public String[] getAvailableEcCurves() {
        final List<String> availableEcCurves = getAvailableEcCurvesAsList();
        return availableEcCurves.toArray(new String[availableEcCurves.size()]);
    }
    @SuppressWarnings("unchecked")
    public List<String> getAvailableEcCurvesAsList() {
        return (ArrayList<String>) data.get(AVAILABLEECCURVES);
    }
    public void setAvailableEcCurves(final String[] availableEcCurves) {
        setAvailableEcCurvesAsList(Arrays.asList(availableEcCurves));
    }
    public void setAvailableEcCurvesAsList(final List<String> availableEcCurves) {
        data.put(AVAILABLEECCURVES, new ArrayList<>(availableEcCurves));
    }

	public int[] getAvailableBitLengths() {
        final List<Integer> availablebitlengths = getAvailableBitLengthsAsList();
        final int[] returnval = new int[availablebitlengths.size()];
        for (int i = 0; i < availablebitlengths.size(); i++) {
            returnval[i] = availablebitlengths.get(i).intValue();
        }
        return returnval;
    }
    @SuppressWarnings("unchecked")
    public List<Integer> getAvailableBitLengthsAsList() {
        return (ArrayList<Integer>) data.get(AVAILABLEBITLENGTHS);
    }

    public void setAvailableBitLengths(List<Integer> availablebitlengths) {
        // Strange values here, but it makes the <> below work for sure
        int minimumavailablebitlength = 99999999;
        int maximumavailablebitlength = 0;

        for (int i = 0; i < availablebitlengths.size(); i++) {
            if (availablebitlengths.get(i) > maximumavailablebitlength) {
                maximumavailablebitlength = availablebitlengths.get(i);
            }
            if (availablebitlengths.get(i) < minimumavailablebitlength) {
                minimumavailablebitlength = availablebitlengths.get(i);
            }
        }
        data.put(AVAILABLEBITLENGTHS, availablebitlengths);        
        data.put(MINIMUMAVAILABLEBITLENGTH, Integer.valueOf(minimumavailablebitlength));
        data.put(MAXIMUMAVAILABLEBITLENGTH, Integer.valueOf(maximumavailablebitlength));        
    }

    public void setAvailableBitLengths(int[] availablebitlengths) {
        ArrayList<Integer> availbitlengths = new ArrayList<>(availablebitlengths.length);

        for (int i = 0; i < availablebitlengths.length; i++) {
            availbitlengths.add(Integer.valueOf(availablebitlengths[i]));
        }
        setAvailableBitLengths(availbitlengths);
    }

    public int getMinimumAvailableBitLength() {
        return ((Integer) data.get(MINIMUMAVAILABLEBITLENGTH)).intValue();
    }

    public int getMaximumAvailableBitLength() {
        return ((Integer) data.get(MAXIMUMAVAILABLEBITLENGTH)).intValue();
    }

    /**
     * Returns the chosen algorithm to be used for signing the certificates or null if it is to be inherited from the CA (i.e., it is the same as the
     * algorithm used to sign the CA certificate).
     * 
     * @see org.cesecore.certificates.util.core.model.AlgorithmConstants.AVAILABLE_SIGALGS
     * @return JCE identifier for the signature algorithm or null if it is to be inherited from the CA (i.e., it is the same as the algorithm used to
     *         sign the CA certificate).
     */
    public String getSignatureAlgorithm() {
        // If it's null, it is inherited from issuing CA.
        return (String) data.get(SIGNATUREALGORITHM);
    }

    /**
     * Sets the algorithm to be used for signing the certificates. A null value means that the signature algorithm is to be inherited from the CA
     * (i.e., it is the same as the algorithm used to sign the CA certificate).
     * 
     * @param signAlg
     *            JCE identifier for the signature algorithm or null if it is to be inherited from the CA (i.e., it is the same as the algorithm used
     *            to sign the CA certificate).
     * @see org.cesecore.certificates.util.core.model.AlgorithmConstants.AVAILABLE_SIGALGS
     */
    public void setSignatureAlgorithm(String signAlg) {
        data.put(SIGNATUREALGORITHM, signAlg);
    }

    public boolean[] getKeyUsage() {
        @SuppressWarnings("unchecked")
        ArrayList<Boolean> keyusage = (ArrayList<Boolean>) data.get(KEYUSAGE);
        boolean[] returnval = new boolean[keyusage.size()];
        for (int i = 0; i < keyusage.size(); i++) {
            returnval[i] = keyusage.get(i).booleanValue();
        }
        return returnval;
    }

    /**
     * @param keyusageconstant
     *            from CertificateConstants.DIGITALSIGNATURE etc
     * @return true or false if the key usage is set or not.
     */
    @SuppressWarnings("unchecked")
    public boolean getKeyUsage(int keyusageconstant) {
        return ((ArrayList<Boolean>) data.get(KEYUSAGE)).get(keyusageconstant).booleanValue();
    }

    public void setKeyUsage(boolean[] keyusage) {
        ArrayList<Boolean> keyuse = new ArrayList<Boolean>(keyusage.length);

        for (int i = 0; i < keyusage.length; i++) {
            keyuse.add(Boolean.valueOf(keyusage[i]));
        }
        data.put(KEYUSAGE, keyuse);
    }

    /**
     * @param keyusageconstant
     *            from CertificateConstants.DIGITALSIGNATURE etc
     * @param value
     *            true or false if the key usage is set or not.
     */
    @SuppressWarnings("unchecked")
    public void setKeyUsage(int keyusageconstant, boolean value) {
        ((ArrayList<Boolean>) data.get(KEYUSAGE)).set(keyusageconstant, Boolean.valueOf(value));
    }

    public void setAllowKeyUsageOverride(boolean override) {
        data.put(ALLOWKEYUSAGEOVERRIDE, Boolean.valueOf(override));
    }

    public boolean getAllowKeyUsageOverride() {
        return ((Boolean) data.get(ALLOWKEYUSAGEOVERRIDE)).booleanValue();
    }

    public void setAllowBackdatedRevocation(boolean override) {
        this.data.put(ALLOWBACKDATEDREVOCATION, Boolean.valueOf(override));
    }
    public boolean getAllowBackdatedRevocation() {
        final Object value = this.data.get(ALLOWBACKDATEDREVOCATION);
        return value!=null && value instanceof Boolean && ((Boolean)value).booleanValue();
    }

    public void setUseDocumentTypeList(boolean use) {
        data.put(USEDOCUMENTTYPELIST, Boolean.valueOf(use));
    }
    
    public boolean getUseDocumentTypeList() {
        return ((Boolean) data.get(USEDOCUMENTTYPELIST)).booleanValue();
    }
    
    public void setDocumentTypeListCritical(boolean critical) {
        data.put(DOCUMENTTYPELISTCRITICAL, Boolean.valueOf(critical));
    }
    
    public boolean getDocumentTypeListCritical() {
        return ((Boolean) data.get(DOCUMENTTYPELISTCRITICAL)).booleanValue();
    }

    public void setDocumentTypeList(ArrayList<String> docTypes) {
        data.put(DOCUMENTTYPELIST, docTypes);
    }
    
    @SuppressWarnings("unchecked")
    public ArrayList<String> getDocumentTypeList() {
        return (ArrayList<String>) data.get(DOCUMENTTYPELIST);
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
     * Extended Key Usage is an arraylist of oid Strings. Usually oids comes from KeyPurposeId in BC.
     */
    public void setExtendedKeyUsage(ArrayList<String> extendedkeyusage) {
        data.put(EXTENDEDKEYUSAGE, extendedkeyusage);
    }

    /**
     * Extended Key Usage is an arraylist of Strings with eku oids.
     */
    @SuppressWarnings("unchecked")
    public ArrayList<String> getExtendedKeyUsageOids() {
        return (ArrayList<String>) data.get(EXTENDEDKEYUSAGE);
    }
    public void setExtendedKeyUsageOids(final ArrayList<String> extendedKeyUsageOids) {
        setExtendedKeyUsage(extendedKeyUsageOids);
    }

    public void setUseCustomDnOrder(boolean use) {
        data.put(USECUSTOMDNORDER, Boolean.valueOf(use));
    }

    public boolean getUseCustomDnOrder() {
        boolean ret = false; // Default value is false here
        Object o = data.get(USECUSTOMDNORDER);
        if (o != null) {
            ret = ((Boolean) o).booleanValue();
        }
        return ret;
    }

    /** Custom DN order is an ArrayList of DN strings
     * @see DnComponents
     * @return ArrayList of Strings or an empty ArrayList
     */
    @SuppressWarnings("unchecked")
    public ArrayList<String> getCustomDnOrder() {
        if (data.get(CUSTOMDNORDER) == null) {
            return new ArrayList<>();
        }
        return (ArrayList<String>) data.get(CUSTOMDNORDER);
    }

    public void setCustomDnOrder(final ArrayList<String> dnOrder) {
        data.put(CUSTOMDNORDER, dnOrder);
    }
    
    public boolean getUseLdapDnOrder() {
        boolean ret = true; // Default value is true here
        Object o = data.get(USELDAPDNORDER);
        if (o != null) {
            ret = ((Boolean) o).booleanValue();
        }
        return ret;
    }

    public void setUseLdapDnOrder(boolean use) {
        data.put(USELDAPDNORDER, Boolean.valueOf(use));
    }

    public boolean getUseMicrosoftTemplate() {
        return ((Boolean) data.get(USEMICROSOFTTEMPLATE)).booleanValue();
    }

    public void setUseMicrosoftTemplate(boolean use) {
        data.put(USEMICROSOFTTEMPLATE, Boolean.valueOf(use));
    }

    public String getMicrosoftTemplate() {
        return (String) data.get(MICROSOFTTEMPLATE);
    }

    public void setMicrosoftTemplate(String mstemplate) {
        data.put(MICROSOFTTEMPLATE, mstemplate);
    }

    public boolean getUseCardNumber() {
        return ((Boolean) data.get(USECARDNUMBER)).booleanValue();
    }

    public void setUseCardNumber(boolean use) {
        data.put(USECARDNUMBER, Boolean.valueOf(use));
    }

    public boolean getUseCNPostfix() {
        return ((Boolean) data.get(USECNPOSTFIX)).booleanValue();
    }

    public void setUseCNPostfix(boolean use) {
        data.put(USECNPOSTFIX, Boolean.valueOf(use));
    }

    public String getCNPostfix() {
        return (String) data.get(CNPOSTFIX);
    }

    public void setCNPostfix(String cnpostfix) {
        data.put(CNPOSTFIX, cnpostfix);

    }

    public boolean getUseSubjectDNSubSet() {
        return ((Boolean) data.get(USESUBJECTDNSUBSET)).booleanValue();
    }

    public void setUseSubjectDNSubSet(boolean use) {
        data.put(USESUBJECTDNSUBSET, Boolean.valueOf(use));
    }

    /**
     * Returns a List of Integer (DNFieldExtractor constants) indicating which subject dn fields that should be used in certificate.
     * 
     */
    @SuppressWarnings("unchecked")
    public List<Integer> getSubjectDNSubSet() {
        return (List<Integer>) data.get(SUBJECTDNSUBSET);
    }

    /**
     * Should contain a collection of Integer (DNFieldExtractor constants) indicating which subject dn fields that should be used in certificate.
     * 
     * Will come in as a list of string from the GUI, because JSP doesn't always care about type safety.
     * 
     */
    public void setSubjectDNSubSet(List<String> subjectdns) {
        List<Integer> convertedList = new ArrayList<>();
        for(String value : subjectdns) {
            convertedList.add(Integer.valueOf(value));
        }
        data.put(SUBJECTDNSUBSET, convertedList);

    }
    
    /**
     * Method taking a full user dn and returns a DN only containing the DN fields specified in the subjectdn sub set array.
     * 
     * @param dn
     * @return a subset of original DN
     */

    public String createSubjectDNSubSet(String dn) {
        DNFieldExtractor extractor = new DNFieldExtractor(dn, DNFieldExtractor.TYPE_SUBJECTDN);
        return constructUserData(extractor, getSubjectDNSubSet(), true);
    }

    public boolean getUseSubjectAltNameSubSet() {
        return ((Boolean) data.get(USESUBJECTALTNAMESUBSET)).booleanValue();
    }

    public void setUseSubjectAltNameSubSet(boolean use) {
        data.put(USESUBJECTALTNAMESUBSET, Boolean.valueOf(use));
    }

    /**
     * Returns a List of Integer (DNFieldExtractor constants) indicating which subject altnames fields that should be used in certificate.
     * 
     */
    @SuppressWarnings("unchecked")
    public List<Integer> getSubjectAltNameSubSet() {
        return (List<Integer>) data.get(SUBJECTALTNAMESUBSET);
    }

    /**
     * Sets a List of Integer (DNFieldExtractor constants) indicating which subject altnames fields that should be used in certificate.
     * 
     */
    public void setSubjectAltNameSubSet(List<Integer> subjectaltnames) {
        data.put(SUBJECTALTNAMESUBSET, subjectaltnames);

    }

    /**
     * Method taking a full user dn and returns a AltName only containing the AltName fields specified in the subjectaltname sub set array.
     * 
     * @param dn
     * @return a subset of original DN
     */
    public String createSubjectAltNameSubSet(String subjectaltname) {
        DNFieldExtractor extractor = new DNFieldExtractor(subjectaltname, DNFieldExtractor.TYPE_SUBJECTALTNAME);
        return constructUserData(extractor, getSubjectAltNameSubSet(), false);
    }

    /**
     * Help method converting a full DN or Subject Alt Name to one usng only specified fields
     * 
     * @param extractor
     * @param usefields
     * @return
     */
    protected static String constructUserData(DNFieldExtractor extractor, Collection<Integer> usefields, boolean subjectdn) {
        String retval = "";

        if (usefields instanceof List<?>) {
            Collections.sort((List<Integer>) usefields);
        }
        String dnField = null;
        for (Integer next : usefields) {
            dnField = extractor.getFieldString(next.intValue());
            if (StringUtils.isNotEmpty(dnField)) {
                if (retval.length() == 0) {
                    retval += dnField; // first item, don't start with a comma
                } else {
                    retval += "," + dnField;
                }
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("CertificateProfile: constructed DN or AltName: " + retval);
        }
        return retval;
    }

    /**
     * Returns a List of caids (Integer), indicating which CAs the profile should be applicable to.
     * 
     * If it contains the constant ANYCA then the profile is applicable to all CAs
     */
    @SuppressWarnings("unchecked")
    public List<Integer> getAvailableCAs() {
        return (List<Integer>) data.get(AVAILABLECAS);
    }

    /**
     * Saves the CertificateProfile's list of CAs the cert profile is applicable to.
     * 
     * @param availablecas
     *            a List of caids (Integer)
     */

    public void setAvailableCAs(List<Integer> availablecas) {
        data.put(AVAILABLECAS, availablecas);
    }

    @SuppressWarnings("unchecked")
    public boolean isApplicableToAnyCA() {
        return ((List<Integer>) data.get(AVAILABLECAS)).contains(Integer.valueOf(ANYCA));
    }

    /**
     * Returns a List of publisher id's (Integer) indicating which publishers a certificate created with this profile should be published to.
     * Never returns null.
     */
    @SuppressWarnings("unchecked")
    public List<Integer> getPublisherList() {
        Object o = data.get(USEDPUBLISHERS);
        if (o == null) {
            o = new ArrayList<Integer>();
        }
        return (List<Integer>) o;
    }

    /**
     * Saves the CertificateProfile's list of publishers that certificates created with this profile should be published to.
     * 
     * @param publishers
     *            a List<Integer> of publisher Ids
     */

    public void setPublisherList(List<Integer> publisher) {
        data.put(USEDPUBLISHERS, publisher);
    }

    /**
     * Method indicating that Path Length Constraint should be used in the BasicConstaint
     */
    public boolean getUsePathLengthConstraint() {
        return ((Boolean) data.get(USEPATHLENGTHCONSTRAINT)).booleanValue();
    }

    /**
     * Method indicating that Path Length Constraint should be used in the BasicConstaint
     */
    public void setUsePathLengthConstraint(boolean use) {
        data.put(USEPATHLENGTHCONSTRAINT, Boolean.valueOf(use));
    }

    public int getPathLengthConstraint() {
        return ((Integer) data.get(PATHLENGTHCONSTRAINT)).intValue();
    }

    public void setPathLengthConstraint(int pathlength) {
        data.put(PATHLENGTHCONSTRAINT, Integer.valueOf(pathlength));
    }

    public void setCaIssuers(List<String> caIssuers) {
        data.put(CAISSUERS, caIssuers);
    }

    @SuppressWarnings("unchecked")
    public void addCaIssuer(String caIssuer) {
        caIssuer = caIssuer.trim();
        if (caIssuer.length() < 1) {
            return;
        }
        if (data.get(CAISSUERS) == null) {
            List<String> caIssuers = new ArrayList<>();
            caIssuers.add(caIssuer);
            this.setCaIssuers(caIssuers);
        } else {
            ((List<String>) data.get(CAISSUERS)).add(caIssuer);
        }
    }

    @SuppressWarnings("unchecked")
    public List<String> getCaIssuers() {
        if (data.get(CAISSUERS) == null) {
            return new ArrayList<>();
        } else {
            return (List<String>) data.get(CAISSUERS);
        }
    }

    public void removeCaIssuer(String caIssuer) {
        if (data.get(CAISSUERS) != null) {
            ((List<?>) data.get(CAISSUERS)).remove(caIssuer);
        }
    }

    public boolean getUseOcspNoCheck() {
        if (data.get(USEOCSPNOCHECK) == null) {
            return false;
        } else {
            return ((Boolean) data.get(USEOCSPNOCHECK)).booleanValue();
        }
    }

    public void setUseOcspNoCheck(boolean useocspnocheck) {
        data.put(USEOCSPNOCHECK, Boolean.valueOf(useocspnocheck));
    }

    public boolean getUseAuthorityInformationAccess() {
        return ((Boolean) data.get(USEAUTHORITYINFORMATIONACCESS)).booleanValue();
    }

    public void setUseAuthorityInformationAccess(boolean useauthorityinformationaccess) {
        data.put(USEAUTHORITYINFORMATIONACCESS, Boolean.valueOf(useauthorityinformationaccess));
    }

    public boolean getUseDefaultCAIssuer() {
        return ((Boolean) data.get(USEDEFAULTCAISSUER)).booleanValue();
    }

    public void setUseDefaultCAIssuer(boolean usedefaultcaissuer) {
        data.put(USEDEFAULTCAISSUER, Boolean.valueOf(usedefaultcaissuer));
    }
    
    public boolean getUseDefaultOCSPServiceLocator() {
        return ((Boolean) data.get(USEDEFAULTOCSPSERVICELOCATOR)).booleanValue();
    }

    public void setUseDefaultOCSPServiceLocator(boolean usedefaultocspservicelocator) {
        data.put(USEDEFAULTOCSPSERVICELOCATOR, Boolean.valueOf(usedefaultocspservicelocator));
    }

    public String getOCSPServiceLocatorURI() {
        return (String) data.get(OCSPSERVICELOCATORURI);
    }

    public void setOCSPServiceLocatorURI(String ocspservicelocatoruri) {
        if (ocspservicelocatoruri == null) {
            data.put(OCSPSERVICELOCATORURI, "");
        } else {
            data.put(OCSPSERVICELOCATORURI, ocspservicelocatoruri);
        }
    }

    public boolean getUseQCStatement() {
        return ((Boolean) data.get(USEQCSTATEMENT)).booleanValue();
    }

    public void setUseQCStatement(boolean useqcstatement) {
        data.put(USEQCSTATEMENT, Boolean.valueOf(useqcstatement));
    }

    public boolean getUsePkixQCSyntaxV2() {
        return ((Boolean) data.get(USEPKIXQCSYNTAXV2)).booleanValue();
    }

    public void setUsePkixQCSyntaxV2(boolean pkixqcsyntaxv2) {
        data.put(USEPKIXQCSYNTAXV2, Boolean.valueOf(pkixqcsyntaxv2));
    }

    public boolean getQCStatementCritical() {
        return ((Boolean) data.get(QCSTATEMENTCRITICAL)).booleanValue();
    }

    public void setQCStatementCritical(boolean qcstatementcritical) {
        data.put(QCSTATEMENTCRITICAL, Boolean.valueOf(qcstatementcritical));
    }

    /** @return String with RAName or empty string */
    public String getQCStatementRAName() {
        return (String) data.get(QCSTATEMENTRANAME);
    }

    public void setQCStatementRAName(String qcstatementraname) {
        if (qcstatementraname == null) {
            data.put(QCSTATEMENTRANAME, "");
        } else {
            data.put(QCSTATEMENTRANAME, qcstatementraname);
        }
    }

    /** @return String with SemanticsId or empty string */
    public String getQCSemanticsId() {
        return (String) data.get(QCSSEMANTICSID);
    }

    public void setQCSemanticsId(String qcsemanticsid) {
        if (qcsemanticsid == null) {
            data.put(QCSSEMANTICSID, "");
        } else {
            data.put(QCSSEMANTICSID, qcsemanticsid);
        }
    }

    public boolean getUseQCEtsiQCCompliance() {
        return ((Boolean) data.get(USEQCETSIQCCOMPLIANCE)).booleanValue();
    }

    public void setUseQCEtsiQCCompliance(boolean useqcetsiqccompliance) {
        data.put(USEQCETSIQCCOMPLIANCE, Boolean.valueOf(useqcetsiqccompliance));
    }

    public boolean getUseQCEtsiValueLimit() {
        return ((Boolean) data.get(USEQCETSIVALUELIMIT)).booleanValue();
    }

    public void setUseQCEtsiValueLimit(boolean useqcetsivaluelimit) {
        data.put(USEQCETSIVALUELIMIT, Boolean.valueOf(useqcetsivaluelimit));
    }

    public int getQCEtsiValueLimit() {
        return ((Integer) data.get(QCETSIVALUELIMIT)).intValue();
    }

    public void setQCEtsiValueLimit(int qcetsivaluelimit) {
        data.put(QCETSIVALUELIMIT, Integer.valueOf(qcetsivaluelimit));
    }

    public int getQCEtsiValueLimitExp() {
        return ((Integer) data.get(QCETSIVALUELIMITEXP)).intValue();
    }

    public void setQCEtsiValueLimitExp(int qcetsivaluelimitexp) {
        data.put(QCETSIVALUELIMITEXP, Integer.valueOf(qcetsivaluelimitexp));
    }

    /** @return String with Currency or empty string */
    public String getQCEtsiValueLimitCurrency() {
        return (String) data.get(QCETSIVALUELIMITCURRENCY);
    }

    public void setQCEtsiValueLimitCurrency(String qcetsivaluelimitcurrency) {
        if (qcetsivaluelimitcurrency == null) {
            data.put(QCETSIVALUELIMITCURRENCY, "");
        } else {
            data.put(QCETSIVALUELIMITCURRENCY, qcetsivaluelimitcurrency);
        }
    }

    public boolean getUseQCEtsiRetentionPeriod() {
        return ((Boolean) data.get(USEQCETSIRETENTIONPERIOD)).booleanValue();
    }

    public void setUseQCEtsiRetentionPeriod(boolean useqcetsiretentionperiod) {
        data.put(USEQCETSIRETENTIONPERIOD, Boolean.valueOf(useqcetsiretentionperiod));
    }

    public int getQCEtsiRetentionPeriod() {
        return ((Integer) data.get(QCETSIRETENTIONPERIOD)).intValue();
    }

    public void setQCEtsiRetentionPeriod(int qcetsiretentionperiod) {
        data.put(QCETSIRETENTIONPERIOD, Integer.valueOf(qcetsiretentionperiod));
    }

    public boolean getUseQCEtsiSignatureDevice() {
        return ((Boolean) data.get(USEQCETSISIGNATUREDEVICE)).booleanValue();
    }

    public void setUseQCEtsiSignatureDevice(boolean useqcetsisignaturedevice) {
        data.put(USEQCETSISIGNATUREDEVICE, Boolean.valueOf(useqcetsisignaturedevice));
    }

    /** @return String with Type OID or null (or empty string) if it's not to be used (EN 319 412-05)
     * 0.4.0.1862.1.6.1 = id-etsi-qct-esign
     * 0.4.0.1862.1.6.2 = id-etsi-qct-eseal
     * 0.4.0.1862.1.6.3 = id-etsi-qct-web
     */
    public String getQCEtsiType() {
        return (String) data.get(QCETSITYPE);
    }
    public void setQCEtsiType(String qcetsitype) {
        data.put(QCETSITYPE, qcetsitype);
    }

    /**
     * Returns the PKI Disclosure Statements (EN 319 412-05) used in this profile, or null if none are present.
     */
    @SuppressWarnings("unchecked")
    public List<PKIDisclosureStatement> getQCEtsiPds() {
        List<PKIDisclosureStatement> result = null;
        List<PKIDisclosureStatement> pdsList = (List<PKIDisclosureStatement>)data.get(QCETSIPDS);
        if (pdsList == null) {
            // EJBCA 6.6.0 or older
            // TODO move this code into the upgrade() method
            final String url = (String) data.get(QCETSIPDSURL);
            final String lang = (String) data.get(QCETSIPDSLANG);
            if (url != null) {
                result = new ArrayList<>();
                result.add(new PKIDisclosureStatement(url, lang));
            }
        } else if (!pdsList.isEmpty()) {
            // EJBCA 6.6.1 and newer
            result = new ArrayList<>(pdsList.size());
            try {
                for (final PKIDisclosureStatement pds : pdsList) {
                    result.add((PKIDisclosureStatement) pds.clone());
                }
            } catch (CloneNotSupportedException e) {
                throw new IllegalStateException(e);
            }
        }
        return result;
    }
    
    /**
     * Sets the PKI Disclosure Statements (EN 319 412-05).
     * Both null and empty lists are interpreted as an "none". 
     */
    public void setQCEtsiPds(final List<PKIDisclosureStatement> pds) {
        if (pds == null || pds.isEmpty()) { // never store an empty list
            data.put(QCETSIPDS, null);
        } else {
            data.put(QCETSIPDS, new ArrayList<>(pds));
        }
        // These were used by EJBCA <= 6.6.0
        // TODO move this code into the upgrade() method
        data.remove(QCETSIPDSURL);
        data.remove(QCETSIPDSLANG);
    }
    
    public boolean getUseQCCustomString() {
        return ((Boolean) data.get(USEQCCUSTOMSTRING)).booleanValue();
    }

    public void setUseQCCustomString(boolean useqccustomstring) {
        data.put(USEQCCUSTOMSTRING, Boolean.valueOf(useqccustomstring));
    }

    /** @return String with oid or empty string */
    public String getQCCustomStringOid() {
        return (String) data.get(QCCUSTOMSTRINGOID);
    }

    public void setQCCustomStringOid(String qccustomstringoid) {
        if (qccustomstringoid == null) {
            data.put(QCCUSTOMSTRINGOID, "");
        } else {
            data.put(QCCUSTOMSTRINGOID, qccustomstringoid);
        }
    }

    /** @return String with custom text or empty string */
    public String getQCCustomStringText() {
        return (String) data.get(QCCUSTOMSTRINGTEXT);
    }

    public void setQCCustomStringText(String qccustomstringtext) {
        if (qccustomstringtext == null) {
            data.put(QCCUSTOMSTRINGTEXT, "");
        } else {
            data.put(QCCUSTOMSTRINGTEXT, qccustomstringtext);
        }
    }
    
    public boolean getUseNameConstraints() {
        Boolean b = (Boolean) data.get(USENAMECONSTRAINTS);
        return b != null && b.booleanValue();
    }

    public void setUseNameConstraints(boolean use) {
        data.put(USENAMECONSTRAINTS, Boolean.valueOf(use));
    }
    
    public boolean getNameConstraintsCritical() {
        Boolean b = (Boolean) data.get(NAMECONSTRAINTSCRITICAL);
        return b != null && b.booleanValue();
    }

    public void setNameConstraintsCritical(boolean use) {
        data.put(NAMECONSTRAINTSCRITICAL, Boolean.valueOf(use));
    }

    public boolean getUseSubjectDirAttributes() {
        return ((Boolean) data.get(USESUBJECTDIRATTRIBUTES)).booleanValue();
    }

    public void setUseSubjectDirAttributes(boolean use) {
        data.put(USESUBJECTDIRATTRIBUTES, Boolean.valueOf(use));
    }
    
    public void setSingleActiveCertificateConstraint(final boolean enabled) {
        data.put(USERSINGLEACTIVECERTIFICATECONSTRAINT, Boolean.valueOf(enabled));
    }
    
    public boolean isSingleActiveCertificateConstraint() {
        Object constraintObject = data.get(USERSINGLEACTIVECERTIFICATECONSTRAINT);
        if(constraintObject == null) {
            //For upgrading from versions prior to 6.3.1
            setSingleActiveCertificateConstraint(false);
            return false;
        } else {
            return ((Boolean) data.get(USERSINGLEACTIVECERTIFICATECONSTRAINT)).booleanValue();
        }
    }

    
    /**
     * Returns which type of terminals are used in this ca/certificate hierarchy.
     * The values correspond to the id-roles-1/2/3 OIDs. 
     */
    public int getCVCTerminalType() {
        if (data.get(CVCTERMINALTYPE) == null) {
            return CertificateProfile.CVC_TERMTYPE_IS;
        }
        return ((Integer) data.get(CVCTERMINALTYPE)).intValue();
    }

    public void setCVCTerminalType(int termtype) {
        data.put(CVCTERMINALTYPE, Integer.valueOf(termtype));
    }

    public int getCVCAccessRights() {
        if (data.get(CVCACCESSRIGHTS) == null) {
            return CertificateProfile.CVC_ACCESS_NONE;
        }
        return ((Integer) data.get(CVCACCESSRIGHTS)).intValue();
    }

    public void setCVCAccessRights(int access) {
        data.put(CVCACCESSRIGHTS, Integer.valueOf(access));
    }
    
    /**
     * Used for bitmasks that don't fit in an int.
     * E.g. the 5-byte bitmask for Authentication Terminals
     */
    public byte[] getCVCLongAccessRights() {
        if (data.get(CVCLONGACCESSRIGHTS) == null) {
            return null;
        }
        @SuppressWarnings("unchecked")
        List<Byte> rightsList = (List<Byte>)data.get(CVCLONGACCESSRIGHTS);
        return ArrayUtils.toPrimitive(rightsList.toArray(new Byte[0]));
    }

    public void setCVCLongAccessRights(byte[] access) {
        if (access == null) {
            data.put(CVCLONGACCESSRIGHTS, null);
        } else {
            // Convert to List<Byte> since byte[] doesn't work with database protection
            data.put(CVCLONGACCESSRIGHTS, new ArrayList<Byte>(Arrays.asList(ArrayUtils.toObject(access))));
        }
    }
    
    public int getCVCSignTermDVType() {
        if (data.get(CVCSIGNTERMDVTYPE) == null) {
            return CertificateProfile.CVC_SIGNTERM_DV_CSP;
        }
        return ((Integer) data.get(CVCSIGNTERMDVTYPE)).intValue();
    }

    public void setCVCSignTermDVType(int type) {
        data.put(CVCSIGNTERMDVTYPE, Integer.valueOf(type));
    }

    /**
     * Method returning a list of (Integers) of ids of used CUSTOM certificate extensions. I.e. those custom certificate extensions selected for this
     * profile. Never null.
     * 
     * Autoupgradable method
     */
    @SuppressWarnings("unchecked")
    public List<Integer> getUsedCertificateExtensions() {
        if (data.get(USEDCERTIFICATEEXTENSIONS) == null) {
            return new ArrayList<>();
        }
        return (List<Integer>) data.get(USEDCERTIFICATEEXTENSIONS);
    }

    /**
     * Method setting a list of used certificate extensions a list of Integers containing CertificateExtension Id is expected
     * 
     * @param usedCertificateExtensions
     */
    public void setUsedCertificateExtensions(List<Integer> usedCertificateExtensions) {
        if (usedCertificateExtensions == null) {
            data.put(USEDCERTIFICATEEXTENSIONS, new ArrayList<Integer>());
        } else {
            data.put(USEDCERTIFICATEEXTENSIONS, usedCertificateExtensions);
        }
    }

    /**
     * Function that looks up in the profile all certificate extensions that we should use if the value is that we should use it, the oid for this
     * extension is returned in the list
     * 
     * @return List of oid Strings for standard certificate extensions that should be used
     */
    public List<String> getUsedStandardCertificateExtensions() {
        ArrayList<String> ret = new ArrayList<>();
        Iterator<String> iter = useStandardCertificateExtensions.keySet().iterator();
        while (iter.hasNext()) {
            String s = iter.next();
            if ((data.get(s) != null) && ((Boolean) data.get(s)).booleanValue()) {
                ret.add(useStandardCertificateExtensions.get(s));
                if (log.isDebugEnabled()) {
                    log.debug("Using standard certificate extension: " + s);
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Not using standard certificate extensions: " + s);
                }
            }
        }
        return ret;
    }

    /**
     * Returns a List of Integers (CAInfo.REQ_APPROVAL_ constants) of which action that requires approvals, default none
     * 
     * Never null
     */
    @SuppressWarnings("unchecked")
    public List<Integer> getApprovalSettings() {
        return (List<Integer>) data.get(APPROVALSETTINGS);
    }

    /**
     * List of Integers (CAInfo.REQ_APPROVAL_ constants) of which action that requires approvals
     */
    public void setApprovalSettings(List<Integer> approvalSettings) {
        data.put(APPROVALSETTINGS, approvalSettings);
    }

    /**
     * Returns the number of different administrators that needs to approve an action, default 1.
     * 
     * @deprecated since 6.6.0, use the appropriate approval profile instead
     * Needed for a while in order to be able to import old statedumps from 6.5 and earlier
     */
    @Deprecated
    public int getNumOfReqApprovals() {
        Integer result = (Integer) data.get(NUMOFREQAPPROVALS);
        if(result != null) {
            return result.intValue();
        } else {
            return 1;
        }
    }

    /**
     * The number of different administrators that needs to approve
     * 
     * @deprecated since 6.6.0, use the appropriate approval profile instead
     * Needed for a while in order to be able to import old statedumps from 6.5 and earlier
     */
    @Deprecated
    public void setNumOfReqApprovals(int numOfReqApprovals) {
        data.put(NUMOFREQAPPROVALS, Integer.valueOf(numOfReqApprovals));
    }

    /**
     * Returns the id of the approval profile. ID -1 means  that no approval profile was set
     */
    public int getApprovalProfileID() {
        return ((Integer) data.get(APPROVALPROFILE)).intValue();
    }

    /**
     * The ID of an approval profile
     */
    public void setApprovalProfileID(int approvalProfileID) {
        data.put(APPROVALPROFILE, Integer.valueOf(approvalProfileID));
    }

    

    /**
     * Returns true if the action requires approvals.
     * 
     * @param action
     *            , on of the CAInfo.REQ_APPROVAL_ constants
     */
    @SuppressWarnings("unchecked")
    public boolean isApprovalRequired(int action) {
        Collection<Integer> approvalSettings = (Collection<Integer>) data.get(APPROVALSETTINGS);
        return approvalSettings.contains(Integer.valueOf(action));
    }

    /**
     * @return If the PrivateKeyUsagePeriod extension should be used and with the notBefore component.
     */
    public boolean isUsePrivateKeyUsagePeriodNotBefore() {
        if (data.get(USEPRIVKEYUSAGEPERIODNOTAFTER) == null) {
            return false;
        }
        return ((Boolean) data.get(USEPRIVKEYUSAGEPERIODNOTBEFORE)).booleanValue();
    }

    /**
     * Sets if the PrivateKeyUsagePeriod extension should be used and with 
     * the notBefore component.
     * Setting this to true means that there will be an PrivateKeyUsagePeriod 
     * extension and that it also at least will contain an notBefore component.
     * Setting this to false means that the extension will not contain an
     * notBefore component. In that case if there will be an extension depends 
     * on if {@link #isUsePrivateKeyUsagePeriodNotAfter()} is true.
     * 
     * @param use True if the notBefore component should be used.
     */
    public void setUsePrivateKeyUsagePeriodNotBefore(final boolean use) {
            data.put(USEPRIVKEYUSAGEPERIODNOTBEFORE, use);
            data.put(USEPRIVKEYUSAGEPERIOD, use || isUsePrivateKeyUsagePeriodNotAfter());
    }
    
    /**
     * @return If the PrivateKeyUsagePeriod extension should be used and with the notAfter component.
     */
    public boolean isUsePrivateKeyUsagePeriodNotAfter() {
        if (data.get(USEPRIVKEYUSAGEPERIODNOTAFTER) == null) {
            return false;
        }
        return ((Boolean) data.get(USEPRIVKEYUSAGEPERIODNOTAFTER)).booleanValue();
    }
    
    /**
     * Sets if the PrivateKeyUsagePeriod extension should be used and with 
     * the notAfter component.
     * Setting this to true means that there will be an PrivateKeyUsagePeriod 
     * extension and that it also at least will contain an notAfter component.
     * Setting this to false means that the extension will not contain an
     * notAfter component. In that case if there will be an extension depends 
     * on if {@link #isUsePrivateKeyUsagePeriodNotBefore()} is true.
     * 
     * @param use True if the notAfter component should be used.
     */
    public void setUsePrivateKeyUsagePeriodNotAfter(final boolean use) {
            data.put(USEPRIVKEYUSAGEPERIODNOTAFTER, use);
            data.put(USEPRIVKEYUSAGEPERIOD, use || isUsePrivateKeyUsagePeriodNotBefore());
    }
    
    /**
     * @return How long (in seconds) after the certificate's notBefore date the 
     * PrivateKeyUsagePeriod's notBefore date should be.
     */
    public long getPrivateKeyUsagePeriodStartOffset() {
            return ((Long) data.get(PRIVKEYUSAGEPERIODSTARTOFFSET)).longValue();
    }
    
    /**
     * Sets how long (in seconds) after the certificate's notBefore date the PrivateKeyUsagePeriod's notBefore date should be.
     * 
     * @param start Offset from certificate issuance.
     */
    public void setPrivateKeyUsagePeriodStartOffset(final long start) {
        data.put(PRIVKEYUSAGEPERIODSTARTOFFSET, start);
    }

    /**
     * @return The private key usage period (private key validity) length (in seconds).
     */
    public long getPrivateKeyUsagePeriodLength() {
        return ((Long) data.get(PRIVKEYUSAGEPERIODLENGTH)).longValue();
    }

    /**
     * Sets the private key usage period (private key validity) length (in seconds).
     * 
     * @param validity The length.
     */
    public void setPrivateKeyUsagePeriodLength(final long validity) {
        data.put(PRIVKEYUSAGEPERIODLENGTH, validity);
    }
    
    /**
     * Whether Certificate Transparency (CT) should be used when generating new certificates. CT is specified in RFC 6962
     */
    public boolean isUseCertificateTransparencyInCerts() {
        if (data.get(USECERTIFICATETRANSPARENCYINCERTS) == null) {
            return false;
        }
        return ((Boolean)data.get(USECERTIFICATETRANSPARENCYINCERTS)).booleanValue();
    }
    
    public void setUseCertificateTransparencyInCerts(boolean use) {
        data.put(USECERTIFICATETRANSPARENCYINCERTS, use);
    }
    
    /**
     * Whether Certificate Transparency (CT) should be used in OCSP responses. CT is specified in RFC 6962
     */
    public boolean isUseCertificateTransparencyInOCSP() {
        if (data.get(USECERTIFICATETRANSPARENCYINOCSP) == null) {
            return false;
        }
        return ((Boolean)data.get(USECERTIFICATETRANSPARENCYINOCSP)).booleanValue();
    }
    
    public void setUseCertificateTransparencyInOCSP(boolean use) {
        data.put(USECERTIFICATETRANSPARENCYINOCSP, use);
    }
    
    /**
     * Whether Certificate Transparency (CT) should be used in publishers.
     * You have to create a publisher and enable it in the profile also!
     */
    public boolean isUseCertificateTransparencyInPublishers() {
        if (data.get(USECERTIFICATETRANSPARENCYINPUBLISHERS) == null) {
            // Default to being enabled if CT in OCSP was enabled
            return isUseCertificateTransparencyInOCSP();
        }
        return ((Boolean)data.get(USECERTIFICATETRANSPARENCYINPUBLISHERS)).booleanValue();
    }
    
    public void setUseCertificateTransparencyInPublishers(boolean use) {
        data.put(USECERTIFICATETRANSPARENCYINPUBLISHERS, use);
    }
    
    /**
     * Whether existing certificates should be submitted by the CT publisher and the CT OCSP extension class.
     */
    public boolean isUseCTSubmitExisting() {
        if (data.get(CTSUBMITEXISTING) == null) {
            return true;
        }
        return ((Boolean)data.get(CTSUBMITEXISTING)).booleanValue();
    }
    
    public void setUseCTSubmitExisting(boolean use) {
        data.put(CTSUBMITEXISTING, use);
    }
    
    /**
     * Gets the IDs of the CT logs that are activated in this profile.
     */
    @SuppressWarnings("unchecked")
    public Set<Integer> getEnabledCTLogs() {
        if (data.get(CTLOGS) == null) {
            return new LinkedHashSet<>();
        }
        
        return (Set<Integer>)data.get(CTLOGS);
    }
    
    public void setEnabledCTLogs(Set<Integer> logIds) {
        data.put(CTLOGS, new LinkedHashSet<>(logIds));
    }
    
    /**
     * Number of CT logs to require an SCT from, or it will be considered an error.
     * If zero, CT is completely optional and ignored if no log servers can be contacted.
     * This value is used for certificates and publishers. For OCSP responses, see CertificateProfile#getCTMinSCTsOCSP
     */
    public int getCTMinSCTs() {
        if (data.get(CTMINSCTS) == null) {
            return 1;
        }
        return (Integer)data.get(CTMINSCTS);
    }
    
    public void setCTMinSCTs(int minSCTs) {
        data.put(CTMINSCTS, minSCTs);
    }
    
    /**
     * @see CertificateProfile#getCTMinSCTs
     */
    public int getCTMinSCTsOCSP() {
        if (data.get(CTMINSCTSOCSP) == null) {
            return getCTMinSCTs();
        }
        return (Integer)data.get(CTMINSCTSOCSP);
    }
    
    public void setCTMinSCTsOCSP(int minSCTsOCSP) {
        data.put(CTMINSCTSOCSP, minSCTsOCSP);
    }
    
    /**
     * After the maximum number of SCTs have been received EJBCA will stop contacting log servers.
     * This value is for certificates. For OCSP responses, see CertificateProfile#getCTMaxSCTsOCSP.
     * For publishers, certificates are submitted to all enabled logs.
     */
    public int getCTMaxSCTs() {
        if (data.get(CTMAXSCTS) == null) {
            return 1;
        }
        return (Integer)data.get(CTMAXSCTS);
    }
    
    public void setCTMaxSCTs(int maxSCTs) {
        data.put(CTMAXSCTS, maxSCTs);
    }
    
    /**
     * @see CertificateProfile#getCTMaxSCTs
     */
    public int getCTMaxSCTsOCSP() {
        if (data.get(CTMAXSCTSOCSP) == null) {
            return getCTMaxSCTs();
        }
        return (Integer)data.get(CTMAXSCTSOCSP);
    }
    
    public void setCTMaxSCTsOCSP(int maxSCTsOCSP) {
        data.put(CTMAXSCTSOCSP, maxSCTsOCSP);
    }
    
    /** Number of times to retry connecting to a Certificate Transparency log */
    public int getCTMaxRetries() {
        if (data.get(CTMAXRETRIES) == null) {
            return 0;
        }
        return (Integer)data.get(CTMAXRETRIES);
    }
    
    public void setCTMaxRetries(int numRetries) {
        data.put(CTMAXRETRIES, numRetries);
    }
    
    /**
     * Checks that a public key fulfills the policy in the CertificateProfile
     * 
     * @param publicKey PublicKey to verify
     * @throws IllegalKeyException if the PublicKey does not fulfill policy in CertificateProfile
     */
    public void verifyKey(final PublicKey publicKey) throws IllegalKeyException {
        final String keyAlgorithm = AlgorithmTools.getKeyAlgorithm(publicKey);
        final int keyLength = KeyTools.getKeyLength(publicKey);
        if (log.isDebugEnabled()) {
            log.debug("KeyAlgorithm: " + keyAlgorithm + " KeyLength: " + keyLength);
        }
        // Verify that the key algorithm is compliant with the certificate profile
        if (!getAvailableKeyAlgorithmsAsList().contains(keyAlgorithm)) {
            throw new IllegalKeyException(intres.getLocalizedMessage("createcert.illegalkeyalgorithm", keyAlgorithm));
        }
        if (AlgorithmConstants.KEYALGORITHM_ECDSA.equals(keyAlgorithm)) {
            final List<String> availableEcCurves = getAvailableEcCurvesAsList();
            final String keySpecification = AlgorithmTools.getKeySpecification(publicKey);
            for (final String ecNamedCurveAlias : AlgorithmTools.getEcKeySpecAliases(keySpecification)) {
                if (availableEcCurves.contains(ecNamedCurveAlias)) {
                    // Curve is allowed, so we don't check key strength
                    return;
                }
            }
            if (!availableEcCurves.contains(ANY_EC_CURVE)) {
                // Curve will never be allowed by bit length check
                throw new IllegalKeyException(intres.getLocalizedMessage("createcert.illegaleccurve", keySpecification));
            }
        }
        // Verify key length that it is compliant with certificate profile
        if (keyLength == -1) {
            throw new IllegalKeyException(intres.getLocalizedMessage("createcert.unsupportedkeytype", publicKey.getClass().getName()));
        }
        if ((keyLength < (getMinimumAvailableBitLength() - 1)) || (keyLength > (getMaximumAvailableBitLength()))) {
            throw new IllegalKeyException(intres.getLocalizedMessage("createcert.illegalkeylength", Integer.valueOf(keyLength)));
        }
    }

    @Override
    public CertificateProfile clone() throws CloneNotSupportedException {
        final CertificateProfile clone = new CertificateProfile(0);
        // We need to make a deep copy of the hashmap here
        clone.data = new LinkedHashMap<>(data.size());
        for (final Entry<Object,Object> entry : data.entrySet()) {
                Object value = entry.getValue();
                if (value instanceof ArrayList<?>) {
                        // We need to make a clone of this object, but the stored immutables can still be referenced
                        value = ((ArrayList<?>)value).clone();
                }
                clone.data.put(entry.getKey(), value);
        }
        return clone;
    }

    /** Implementation of UpgradableDataHashMap function getLatestVersion */
    @Override
    public float getLatestVersion() {
        return LATEST_VERSION;
    }

    /**
     * Function setting the current version of the class data. Used for JUnit testing
     */
    protected void setVersion(float version) {
        data.put(VERSION, Float.valueOf(version));
    }

    /**
     * Implementation of UpgradableDataHashMap function upgrade.
     */
    @Override
    public void upgrade() {
        if (log.isTraceEnabled()) {
            log.trace(">upgrade: " + getLatestVersion() + ", " + getVersion());
        }
        if (Float.compare(getLatestVersion(), getVersion()) != 0) {
            // New version of the class, upgrade
            String msg = intres.getLocalizedMessage("certprofile.upgrade", new Float(getVersion()));
            log.info(msg);

            if (data.get(ALLOWKEYUSAGEOVERRIDE) == null) {
                data.put(ALLOWKEYUSAGEOVERRIDE, Boolean.TRUE);
            }
            if (data.get(USEEXTENDEDKEYUSAGE) == null) {
                data.put(USEEXTENDEDKEYUSAGE, Boolean.FALSE);
            }
            if (data.get(EXTENDEDKEYUSAGE) == null) {
                data.put(EXTENDEDKEYUSAGE, new ArrayList<String>());
            }
            if (data.get(EXTENDEDKEYUSAGECRITICAL) == null) {
                data.put(EXTENDEDKEYUSAGECRITICAL, Boolean.FALSE);
            }
            if (data.get(AVAILABLECAS) == null) {
                ArrayList<Integer> availablecas = new ArrayList<>();
                availablecas.add(Integer.valueOf(ANYCA));
                data.put(AVAILABLECAS, availablecas);
            }
            if (data.get(USEDPUBLISHERS) == null) {
                data.put(USEDPUBLISHERS, new ArrayList<Integer>());
            }
            if ( (data.get(USEOCSPSERVICELOCATOR) == null) && (data.get(USEAUTHORITYINFORMATIONACCESS) == null) ) {
                // Only set this flag if we have not already set the new flag USEAUTHORITYINFORMATIONACCESS
                // setUseOCSPServiceLocator(false);
                data.put(USEOCSPSERVICELOCATOR, Boolean.FALSE);
                setOCSPServiceLocatorURI("");
            }

            if (data.get(USEMICROSOFTTEMPLATE) == null) {
                setUseMicrosoftTemplate(false);
                setMicrosoftTemplate("");
            }

            if (data.get(USECNPOSTFIX) == null) {
                setUseCNPostfix(false);
                setCNPostfix("");
            }

            if (data.get(USESUBJECTDNSUBSET) == null) {
                setUseSubjectDNSubSet(false);
                setSubjectDNSubSet(new ArrayList<String>());
                setUseSubjectAltNameSubSet(false);
                setSubjectAltNameSubSet(new ArrayList<Integer>());
            }

            if (data.get(USEPATHLENGTHCONSTRAINT) == null) {
                setUsePathLengthConstraint(false);
                setPathLengthConstraint(0);
            }

            if (data.get(USEQCSTATEMENT) == null) {
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

            if (data.get(USEDEFAULTCRLDISTRIBUTIONPOINT) == null) {
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
            if (data.get(ALLOWVALIDITYOVERRIDE) == null) {
                setAllowValidityOverride(false);
            }

            if (data.get(CRLISSUER) == null) {
                setCRLIssuer(null); // v20
            }

            if (data.get(USEOCSPNOCHECK) == null) {
                setUseOcspNoCheck(false); // v21
            }
            if (data.get(USEFRESHESTCRL) == null) {
                setUseFreshestCRL(false); // v22
                setUseCADefinedFreshestCRL(false);
                setFreshestCRLURI(null);
            }

            if (data.get(CERTIFICATE_POLICIES) == null) { // v23
                if (data.get(CERTIFICATEPOLICYID) != null) {
                    String ids = (String) data.get(CERTIFICATEPOLICYID);
                    String unotice = null;
                    String cpsuri = null;
                    if (data.get(POLICY_NOTICE_UNOTICE_TEXT) != null) {
                        unotice = (String) data.get(POLICY_NOTICE_UNOTICE_TEXT);
                    }
                    if (data.get(POLICY_NOTICE_CPS_URL) != null) {
                        cpsuri = (String) data.get(POLICY_NOTICE_CPS_URL);
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

            if (data.get(USECRLDISTRIBUTIONPOINTONCRL) == null) {
                setUseCRLDistributionPointOnCRL(false); // v24
            }
            if ( (data.get(USECAISSUERS) == null) && (data.get(USEAUTHORITYINFORMATIONACCESS) == null) ) {
                // Only set this flag if we have not already set the new flag USEAUTHORITYINFORMATIONACCESS
                // setUseCaIssuers(false); // v24
                data.put(USECAISSUERS, Boolean.FALSE); // v24
                setCaIssuers(new ArrayList<String>());
            }
            if ( ((data.get(USEOCSPSERVICELOCATOR) != null) || (data.get(USECAISSUERS) != null)) && (data.get(USEAUTHORITYINFORMATIONACCESS) == null) ) {
                // Only do this if we have not already set the new flag USEAUTHORITYINFORMATIONACCESS
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
                } else {
                    setUseAuthorityInformationAccess(false); // v25
                }
            } else if (data.get(USEAUTHORITYINFORMATIONACCESS) == null) {
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

            if (data.get(USECARDNUMBER) == null) { // v30, default value is false
                setUseCardNumber(false);
            }

            if (data.get(ALLOWDNOVERRIDE) == null) {
                setAllowDNOverride(false); // v31
            }

            if (data.get(NUMOFREQAPPROVALS) == null) { // v 33
                setNumOfReqApprovals(1);
            }
            if (data.get(APPROVALSETTINGS) == null) { // v 33
                setApprovalSettings(new ArrayList<Integer>());
            }

            if (data.get(SIGNATUREALGORITHM) == null) { // v 34
                setSignatureAlgorithm(null);
            }

            if (data.get(USEPRIVKEYUSAGEPERIODNOTBEFORE) == null) { // v 35
                setUsePrivateKeyUsagePeriodNotBefore(false);
            }
            if (data.get(USEPRIVKEYUSAGEPERIODNOTAFTER) == null) { // v 35
                setUsePrivateKeyUsagePeriodNotAfter(false);
            }
            if (data.get(PRIVKEYUSAGEPERIODSTARTOFFSET) == null) { // v 35
                setPrivateKeyUsagePeriodStartOffset(0);
            }
            if (data.get(PRIVKEYUSAGEPERIODLENGTH) == null) { // v 35
                setPrivateKeyUsagePeriodLength(getValidity() * 24 * 3600);
            }
            if(data.get(USEISSUERALTERNATIVENAME) == null) { // v 36
                setUseIssuerAlternativeName(false);
            }
            if(data.get(ISSUERALTERNATIVENAMECRITICAL) == null) { // v 36
                setIssuerAlternativeNameCritical(false);
            }
            if(data.get(USEDOCUMENTTYPELIST) == null) { // v 37
                setUseDocumentTypeList(false);
            }
            if(data.get(DOCUMENTTYPELISTCRITICAL) == null) { // v 37
                setDocumentTypeListCritical(false);
            }
            if(data.get(DOCUMENTTYPELIST) == null) { // v 37
            	setDocumentTypeList(new ArrayList<String>());
            }
            if(data.get(AVAILABLEKEYALGORITHMS) == null) { // v 39
                // Make some intelligent guesses what key algorithm this profile is used for
                final List<String> availableKeyAlgorithms = getAvailableKeyAlgorithmsAvailable();
                if (getMinimumAvailableBitLength()>521) {
                    availableKeyAlgorithms.remove(AlgorithmConstants.KEYALGORITHM_ECDSA);
                    availableKeyAlgorithms.remove(AlgorithmConstants.KEYALGORITHM_DSTU4145);
                    availableKeyAlgorithms.remove(AlgorithmConstants.KEYALGORITHM_ECGOST3410);
                }
                if (getMinimumAvailableBitLength()>1024 || getMaximumAvailableBitLength()<1024) {
                    availableKeyAlgorithms.remove(AlgorithmConstants.KEYALGORITHM_DSA);
                }
                if (getMaximumAvailableBitLength()<1024) {
                    availableKeyAlgorithms.remove(AlgorithmConstants.KEYALGORITHM_RSA);
                }
                setAvailableKeyAlgorithmsAsList(availableKeyAlgorithms);
            }
            if (data.get(AVAILABLEECCURVES) == null) { // v 40
               setAvailableEcCurves(new String[]{ ANY_EC_CURVE }); 
            }
            if(data.get(APPROVALPROFILE) == null) { // v41
                setApprovalProfileID(-1);
            }
            // v42. ETSI QC Type and PDS specified in EN 319 412-05.
            // Nothing to set though, since null values means to not use the new values
            
            if (data.get(USEDEFAULTCAISSUER) == null) {
                setUseDefaultCAIssuer(false); // v43
            }
            
            data.put(VERSION, new Float(LATEST_VERSION));
        }
        log.trace("<upgrade");
    }
}
