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
package org.cesecore.certificates.ca;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.SimpleTimeZone;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.icao.ICAOObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameStyle;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuingDistributionPoint;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.BufferingContentSigner;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.ErrorCode;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAService;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceTypes;
import org.cesecore.certificates.ca.internal.CertificateValidity;
import org.cesecore.certificates.ca.internal.RequestAndPublicKeySelector;
import org.cesecore.certificates.ca.internal.SernoGeneratorRandom;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificate.certextensions.AvailableCustomCertificateExtensionsConfiguration;
import org.cesecore.certificates.certificate.certextensions.CertificateExtension;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionFactory;
import org.cesecore.certificates.certificate.certextensions.CustomCertificateExtension;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificateprofile.CertificatePolicy;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificatetransparency.CTLogException;
import org.cesecore.certificates.certificatetransparency.CTLogInfo;
import org.cesecore.certificates.certificatetransparency.CertificateTransparency;
import org.cesecore.certificates.certificatetransparency.CertificateTransparencyFactory;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.certificates.ocsp.SHA1DigestCalculator;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.certificates.util.dn.DNFieldsUtil;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.internal.InternalResources;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.IllegalCryptoTokenException;
import org.cesecore.keys.token.NullCryptoToken;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.keys.validation.IssuancePhase;
import org.cesecore.keys.validation.ValidationException;
import org.cesecore.util.CeSecoreNameStyle;
import org.cesecore.util.CertTools;
import org.cesecore.util.PrintableStringNameStyle;
import org.cesecore.util.SimpleTime;
import org.cesecore.util.StringTools;

/**
 * X509CA is a implementation of a CA and holds data specific for Certificate and CRL generation according to the X509 standard.
 *
 * @version $Id$
 */
public class X509CA extends CA implements Serializable {

    private static final long serialVersionUID = -2882572653108530258L;

    private static final Logger log = Logger.getLogger(X509CA.class);

    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    /** Version of this class, if this is increased the upgrade() method will be called automatically */
    public static final float LATEST_VERSION = 23;

    // protected fields for properties specific to this type of CA.
    protected static final String POLICIES = "policies";
    protected static final String SUBJECTALTNAME = "subjectaltname";
    protected static final String USEAUTHORITYKEYIDENTIFIER = "useauthoritykeyidentifier";
    protected static final String AUTHORITYKEYIDENTIFIERCRITICAL = "authoritykeyidentifiercritical";
    protected static final String AUTHORITY_INFORMATION_ACCESS = "authorityinformationaccess";
    protected static final String CERTIFICATE_AIA_DEFAULT_CA_ISSUER_URI = "certificateaiadefaultcaissueruri";
    protected static final String USECRLNUMBER = "usecrlnumber";
    protected static final String CRLNUMBERCRITICAL = "crlnumbercritical";
    protected static final String DEFAULTCRLDISTPOINT = "defaultcrldistpoint";
    protected static final String DEFAULTCRLISSUER = "defaultcrlissuer";
    protected static final String DEFAULTOCSPSERVICELOCATOR = "defaultocspservicelocator";
    protected static final String CADEFINEDFRESHESTCRL = "cadefinedfreshestcrl";
    protected static final String USEUTF8POLICYTEXT = "useutf8policytext";
    protected static final String USEPRINTABLESTRINGSUBJECTDN = "useprintablestringsubjectdn";
    protected static final String USELDAPDNORDER = "useldapdnorder";
    protected static final String USECRLDISTRIBUTIONPOINTONCRL = "usecrldistributionpointoncrl";
    protected static final String CRLDISTRIBUTIONPOINTONCRLCRITICAL = "crldistributionpointoncrlcritical";
    protected static final String CMPRAAUTHSECRET = "cmpraauthsecret";
    protected static final String NAMECONSTRAINTSPERMITTED = "nameconstraintspermitted";
    protected static final String NAMECONSTRAINTSEXCLUDED = "nameconstraintsexcluded";
    protected static final String EXTERNALCDP = "externalcdp";
    protected static final String NAMECHANGED = "namechanged";


    private static final CertificateTransparency ct = CertificateTransparencyFactory.getInstance();

    // Public Methods
    /** Creates a new instance of CA, this constructor should be used when a new CA is created */
    public X509CA(final X509CAInfo cainfo) {
        super(cainfo);
        //Verify integrity if caInfo, either one SubjectDN or SubjectAltName needs to be filled in
        if(StringUtils.isEmpty(DNFieldsUtil.removeAllEmpties(cainfo.getSubjectDN())) && StringUtils.isEmpty(cainfo.getSubjectAltName())) {
            throw new IllegalArgumentException("Subject DN and Alt Name can't both be blank for an X509 CA.");
        }
        data.put(POLICIES, cainfo.getPolicies());
        data.put(SUBJECTALTNAME, cainfo.getSubjectAltName());
        setUseAuthorityKeyIdentifier(cainfo.getUseAuthorityKeyIdentifier());
        setAuthorityKeyIdentifierCritical(cainfo.getAuthorityKeyIdentifierCritical());
        setUseCRLNumber(cainfo.getUseCRLNumber());
        setCRLNumberCritical(cainfo.getCRLNumberCritical());
        setDefaultCRLDistPoint(cainfo.getDefaultCRLDistPoint());
        setDefaultCRLIssuer(cainfo.getDefaultCRLIssuer());
        setCADefinedFreshestCRL(cainfo.getCADefinedFreshestCRL());
        setDefaultOCSPServiceLocator(cainfo.getDefaultOCSPServiceLocator());
        setUseUTF8PolicyText(cainfo.getUseUTF8PolicyText());
        setUsePrintableStringSubjectDN(cainfo.getUsePrintableStringSubjectDN());
        setUseLdapDNOrder(cainfo.getUseLdapDnOrder());
        setUseCrlDistributionPointOnCrl(cainfo.getUseCrlDistributionPointOnCrl());
        setCrlDistributionPointOnCrlCritical(cainfo.getCrlDistributionPointOnCrlCritical());
        setKeepExpiredCertsOnCRL(cainfo.getKeepExpiredCertsOnCRL());
        setCmpRaAuthSecret(cainfo.getCmpRaAuthSecret());
        // CA Issuer URI to put in CRLs (RFC5280 section 5.2.7, not the URI to put in certs
        setAuthorityInformationAccess(cainfo.getAuthorityInformationAccess());
        setCertificateAiaDefaultCaIssuerUri(cainfo.getCertificateAiaDefaultCaIssuerUri());
        setNameConstraintsPermitted(cainfo.getNameConstraintsPermitted());
        setNameConstraintsExcluded(cainfo.getNameConstraintsExcluded());
        data.put(CA.CATYPE, Integer.valueOf(CAInfo.CATYPE_X509));
        data.put(VERSION, new Float(LATEST_VERSION));
    }

    /**
     * Constructor used when retrieving existing X509CA from database.
     */
    @SuppressWarnings("deprecation")
    public X509CA(final HashMap<Object, Object> data, final int caId, final String subjectDn, final String name, final int status,
            final Date updateTime, final Date expireTime) {
        super(data);
        setExpireTime(expireTime); // Make sure the internal state is synched with the database column. Required for upgrades from EJBCA 3.5.6 or
                                   // EJBCA 3.6.1 and earlier.
        final List<ExtendedCAServiceInfo> externalcaserviceinfos = new ArrayList<>();
        for (final Integer type : getExternalCAServiceTypes()) {
            //Type was removed in 6.0.0. It is removed from the database in the upgrade method in this class, but it needs to be ignored
            //for instantiation.
            if (type != ExtendedCAServiceTypes.TYPE_OCSPEXTENDEDSERVICE) {
                ExtendedCAServiceInfo info = this.getExtendedCAServiceInfo(type.intValue());
                if (info != null) {
                    externalcaserviceinfos.add(info);
                }
            }
        }
        X509CAInfo info =  new X509CAInfo.X509CAInfoBuilder()
                .setSubjectDn(subjectDn)
                .setName(name)
                .setStatus(status)
                .setUpdateTime(updateTime)
                .setSubjectAltName(getSubjectAltName())
                .setCertificateProfileId(getCertificateProfileId())
                .setDefaultCertProfileId(getDefaultCertificateProfileId())
                .setUseNoConflictCertificateData(isUseNoConflictCertificateData())
                .setEncodedValidity(getEncodedValidity())
                .setExpireTime(getExpireTime())
                .setCaType(getCAType())
                .setSignedBy(getSignedBy())
                .setCertificateChain(getCertificateChain())
                .setCaToken(getCAToken())
                .setDescription(getDescription())
                .setRevocationReason(getRevocationReason())
                .setRevocationDate(getRevocationDate())
                .setPolicies(getPolicies())
                .setCrlPeriod(getCRLPeriod())
                .setCrlIssueInterval(getCRLIssueInterval())
                .setCrlOverlapTime(getCRLOverlapTime())
                .setDeltaCrlPeriod(getDeltaCRLPeriod())
                .setCrlPublishers(getCRLPublishers())
                .setValidators(getValidators())
                .setUseAuthorityKeyIdentifier(getUseAuthorityKeyIdentifier())
                .setAuthorityKeyIdentifierCritical(getAuthorityKeyIdentifierCritical())
                .setUseCrlNumber(getUseCRLNumber())
                .setCrlNumberCritical(getCRLNumberCritical())
                .setDefaultCrlDistPoint(getDefaultCRLDistPoint())
                .setDefaultCrlIssuer(getDefaultCRLIssuer())
                .setDefaultOcspCerviceLocator(getDefaultOCSPServiceLocator())
                .setAuthorityInformationAccess(getAuthorityInformationAccess())
                .setCertificateAiaDefaultCaIssuerUri(getCertificateAiaDefaultCaIssuerUri())
                .setNameConstraintsPermitted(getNameConstraintsPermitted())
                .setNameConstraintsExcluded(getNameConstraintsExcluded())
                .setCaDefinedFreshestCrl(getCADefinedFreshestCRL())
                .setFinishUser(getFinishUser())
                .setExtendedCaServiceInfos(externalcaserviceinfos)
                .setUseUtf8PolicyText(getUseUTF8PolicyText())
                .setApprovals(getApprovals())
                .setUsePrintableStringSubjectDN(getUsePrintableStringSubjectDN())
                .setUseLdapDnOrder(getUseLdapDNOrder())
                .setUseCrlDistributionPointOnCrl(getUseCrlDistributionPointOnCrl())
                .setCrlDistributionPointOnCrlCritical(getCrlDistributionPointOnCrlCritical())
                .setIncludeInHealthCheck(getIncludeInHealthCheck())
                .setDoEnforceUniquePublicKeys(isDoEnforceUniquePublicKeys())
                .setDoEnforceUniqueDistinguishedName(isDoEnforceUniqueDistinguishedName())
                .setDoEnforceUniqueSubjectDNSerialnumber(isDoEnforceUniqueSubjectDNSerialnumber())
                .setUseCertReqHistory(isUseCertReqHistory())
                .setUseUserStorage(isUseUserStorage())
                .setUseCertificateStorage(isUseCertificateStorage())
                .setAcceptRevocationNonExistingEntry(isAcceptRevocationNonExistingEntry())
                .setCmpRaAuthSecret(getCmpRaAuthSecret())
                .setKeepExpiredCertsOnCRL(getKeepExpiredCertsOnCRL())
                .build();
        info.setExternalCdp(getExternalCdp());
        info.setNameChanged(getNameChanged());
        //These to settings were deprecated in 6.8.0, but are still set for upgrade reasons
        info.setApprovalProfile(getApprovalProfile());
        info.setApprovalSettings(getApprovalSettings());
        super.setCAInfo(info);
        setCAId(caId);
    }

    private boolean isUseNoConflictCertificateData() {
        return getBoolean(USENOCONFLICTCERTIFICATEDATA, false);
    }

    // Public Methods.
    @SuppressWarnings("unchecked")
    public List<CertificatePolicy> getPolicies() {
        return (List<CertificatePolicy>) data.get(POLICIES);
    }

    public void setPolicies(List<CertificatePolicy> policies) {
        data.put(POLICIES, policies);
    }

    public String getSubjectAltName() {
        return (String) data.get(SUBJECTALTNAME);
    }

    public void setSubjectAltName(final String altName) {
        data.put(SUBJECTALTNAME, altName);
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

    /** CA Issuer URI to put in CRLs (RFC5280 section 5.2.7, not the URI to put in certs
     *
     * @return List of strings
     */
    @SuppressWarnings("unchecked")
    public List<String> getAuthorityInformationAccess() {
        return (List<String>) data.get(AUTHORITY_INFORMATION_ACCESS);
    }

    /** CA Issuer URI to put in CRLs (RFC5280 section 5.2.7, not the URI to put in certs
     *
     * @param authorityInformationAccess List of strings
     */
    public void setAuthorityInformationAccess(List<String> authorityInformationAccess) {
        data.put(AUTHORITY_INFORMATION_ACCESS, authorityInformationAccess);
    }

    @SuppressWarnings("unchecked")
    public List<String> getCertificateAiaDefaultCaIssuerUri() {
        return (List<String>) data.get(CERTIFICATE_AIA_DEFAULT_CA_ISSUER_URI);
    }

    public void setCertificateAiaDefaultCaIssuerUri(List<String> uris) {
        data.put(CERTIFICATE_AIA_DEFAULT_CA_ISSUER_URI, uris);
    }

    public boolean getUseCRLNumber() {
        return ((Boolean) data.get(USECRLNUMBER)).booleanValue();
    }

    public void setUseCRLNumber(boolean usecrlnumber) {
        data.put(USECRLNUMBER, Boolean.valueOf(usecrlnumber));
    }

    public boolean getCRLNumberCritical() {
        return ((Boolean) data.get(CRLNUMBERCRITICAL)).booleanValue();
    }

    public void setCRLNumberCritical(boolean crlnumbercritical) {
        data.put(CRLNUMBERCRITICAL, Boolean.valueOf(crlnumbercritical));
    }

    public String getDefaultCRLDistPoint() {
        return (String) data.get(DEFAULTCRLDISTPOINT);
    }

    public void setDefaultCRLDistPoint(String defaultcrldistpoint) {
        if (defaultcrldistpoint == null) {
            data.put(DEFAULTCRLDISTPOINT, "");
        } else {
            data.put(DEFAULTCRLDISTPOINT, defaultcrldistpoint);
        }
    }

    public String getDefaultCRLIssuer() {
        return (String) data.get(DEFAULTCRLISSUER);
    }

    public void setDefaultCRLIssuer(String defaultcrlissuer) {
        if (defaultcrlissuer == null) {
            data.put(DEFAULTCRLISSUER, "");
        } else {
            data.put(DEFAULTCRLISSUER, defaultcrlissuer);
        }
    }

    public String getCADefinedFreshestCRL() {
        return (String) data.get(CADEFINEDFRESHESTCRL);
    }

    public void setCADefinedFreshestCRL(String cadefinedfreshestcrl) {
        if (cadefinedfreshestcrl == null) {
            data.put(CADEFINEDFRESHESTCRL, "");
        } else {
            data.put(CADEFINEDFRESHESTCRL, cadefinedfreshestcrl);
        }
    }

    public String getDefaultOCSPServiceLocator() {
        return (String) data.get(DEFAULTOCSPSERVICELOCATOR);
    }

    public void setDefaultOCSPServiceLocator(String defaultocsplocator) {
        if (defaultocsplocator == null) {
            data.put(DEFAULTOCSPSERVICELOCATOR, "");
        } else {
            data.put(DEFAULTOCSPSERVICELOCATOR, defaultocsplocator);
        }
    }

    public boolean getUseUTF8PolicyText() {
        return ((Boolean) data.get(USEUTF8POLICYTEXT)).booleanValue();
    }

    public void setUseUTF8PolicyText(boolean useutf8) {
        data.put(USEUTF8POLICYTEXT, Boolean.valueOf(useutf8));
    }

    public boolean getUsePrintableStringSubjectDN() {
        return ((Boolean) data.get(USEPRINTABLESTRINGSUBJECTDN)).booleanValue();
    }

    public void setUsePrintableStringSubjectDN(boolean useprintablestring) {
        data.put(USEPRINTABLESTRINGSUBJECTDN, Boolean.valueOf(useprintablestring));
    }

    public boolean getUseLdapDNOrder() {
        return ((Boolean) data.get(USELDAPDNORDER)).booleanValue();
    }

    public void setUseLdapDNOrder(boolean useldapdnorder) {
        data.put(USELDAPDNORDER, Boolean.valueOf(useldapdnorder));
    }

    public boolean getUseCrlDistributionPointOnCrl() {
        return ((Boolean) data.get(USECRLDISTRIBUTIONPOINTONCRL)).booleanValue();
    }

    public void setUseCrlDistributionPointOnCrl(boolean useCrlDistributionPointOnCrl) {
        data.put(USECRLDISTRIBUTIONPOINTONCRL, Boolean.valueOf(useCrlDistributionPointOnCrl));
    }

    public boolean getCrlDistributionPointOnCrlCritical() {
        return ((Boolean) data.get(CRLDISTRIBUTIONPOINTONCRLCRITICAL)).booleanValue();
    }

    public void setCrlDistributionPointOnCrlCritical(boolean crlDistributionPointOnCrlCritical) {
        data.put(CRLDISTRIBUTIONPOINTONCRLCRITICAL, Boolean.valueOf(crlDistributionPointOnCrlCritical));
    }

    /** @return Encoded name constraints to permit */
    @SuppressWarnings("unchecked")
    public List<String> getNameConstraintsPermitted() {
        return (List<String>) data.get(NAMECONSTRAINTSPERMITTED);
    }

    public void setNameConstraintsPermitted(List<String> encodedNames) {
        data.put(NAMECONSTRAINTSPERMITTED, encodedNames);
    }

    /** @return Encoded name constraints to exclude */
    @SuppressWarnings("unchecked")
    public List<String> getNameConstraintsExcluded() {
        return (List<String>) data.get(NAMECONSTRAINTSEXCLUDED);
    }

    public void setNameConstraintsExcluded(List<String> encodedNames) {
        data.put(NAMECONSTRAINTSEXCLUDED, encodedNames);
    }


    public String getCmpRaAuthSecret() {
        // Default to empty value if it is not set. An empty value will be denied by CRMFMessageHandler
        return (String) getMapValueWithDefault(CMPRAAUTHSECRET, "");
    }

    public void setCmpRaAuthSecret(String cmpRaAuthSecret) {
        data.put(CMPRAAUTHSECRET, cmpRaAuthSecret);
    }

    /** @return what should be a String formatted URL pointing to an external CA's CDP. */
    public String getExternalCdp() {
        return (String) getMapValueWithDefault(EXTERNALCDP, "");
    }

    /** Set what should be a String formatted URL pointing to an external CA's CDP. */
    public void setExternalCdp(final String externalCdp) {
        data.put(EXTERNALCDP, externalCdp);
    }

    private Object getMapValueWithDefault(final String key, final Object defaultValue) {
        final Object o = data.get(key);
        if (o == null) {
            return defaultValue;
        }
        return o;
    }

    public void setNameChanged(boolean nameChanged) {
        if(getNameChanged() && !nameChanged){
            //This must not happen. Once CA "Name Changed" value is set to true it mustn't be set to false again
            log.warn("Not supported operation of setting CA Name Change value from TRUE to FALSE. Value not set!");
            return;
        }
        data.put(NAMECHANGED, Boolean.valueOf(nameChanged));
    }

    /** Retrieving NAMECHANGED flag that shows if this CA has gone through the Name Change any time in its history renewal. */
    public boolean getNameChanged() {
        Boolean v = ((Boolean) data.get(NAMECHANGED));
        return (v == null) ? false : v.booleanValue();
    }

    @Override
    public void updateCA(CryptoToken cryptoToken, CAInfo cainfo, final AvailableCustomCertificateExtensionsConfiguration cceConfig) throws InvalidAlgorithmException {
        super.updateCA(cryptoToken, cainfo, cceConfig);
        X509CAInfo info = (X509CAInfo) cainfo;
        setPolicies(info.getPolicies());
        setAuthorityInformationAccess(info.getAuthorityInformationAccess());
        setCertificateAiaDefaultCaIssuerUri(info.getCertificateAiaDefaultCaIssuerUri());
        setUseAuthorityKeyIdentifier(info.getUseAuthorityKeyIdentifier());
        setAuthorityKeyIdentifierCritical(info.getAuthorityKeyIdentifierCritical());
        setUseCRLNumber(info.getUseCRLNumber());
        setCRLNumberCritical(info.getCRLNumberCritical());
        setDefaultCRLDistPoint(info.getDefaultCRLDistPoint());
        setDefaultCRLIssuer(info.getDefaultCRLIssuer());
        setCADefinedFreshestCRL(info.getCADefinedFreshestCRL());
        setDefaultOCSPServiceLocator(info.getDefaultOCSPServiceLocator());
        setUseUTF8PolicyText(info.getUseUTF8PolicyText());
        setUsePrintableStringSubjectDN(info.getUsePrintableStringSubjectDN());
        setUseLdapDNOrder(info.getUseLdapDnOrder());
        setUseCrlDistributionPointOnCrl(info.getUseCrlDistributionPointOnCrl());
        setCrlDistributionPointOnCrlCritical(info.getCrlDistributionPointOnCrlCritical());
        setCmpRaAuthSecret(info.getCmpRaAuthSecret());
        setNameConstraintsPermitted(info.getNameConstraintsPermitted());
        setNameConstraintsExcluded(info.getNameConstraintsExcluded());
        setExternalCdp(info.getExternalCdp());
        setSubjectAltName(info.getSubjectAltName());
    }

    /**
     * Allows updating of fields that are otherwise not changeable in existing CAs.
     */
    @Override
    public void updateUninitializedCA(CAInfo cainfo) {
        super.updateUninitializedCA(cainfo);
        X509CAInfo info = (X509CAInfo) cainfo;
        data.put(SUBJECTALTNAME, info.getSubjectAltName());
        data.put(POLICIES, info.getPolicies());
    }

    @Override
    public byte[] createPKCS7(CryptoToken cryptoToken, X509Certificate cert, boolean includeChain) throws SignRequestSignatureException {
        // First verify that we signed this certificate
        final X509Certificate cacert = (X509Certificate) getCACertificate();
        if (cert!=null) {
            try {
                final PublicKey verifyKey;
                if (cacert != null) {
                    verifyKey = cacert.getPublicKey();
                } else {
                    verifyKey = cryptoToken.getPublicKey(getCAToken().getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
                }
                cert.verify(verifyKey);
            } catch (CryptoTokenOfflineException e) {
                throw new SignRequestSignatureException("The cryptotoken was not available, could not create a PKCS7", e);
            } catch (InvalidKeyException e) {
                throw new SignRequestSignatureException("The specified certificate contains the wrong public key.", e);
            } catch (CertificateException e) {
                throw new SignRequestSignatureException("An encoding error was encountered.", e);
            } catch (NoSuchAlgorithmException e) {
                throw new SignRequestSignatureException("The certificate provided was signed with an invalid algorithm.", e);
            } catch (NoSuchProviderException e) {
                throw new SignRequestSignatureException("The crypto provider was not found for verification of the certificate.", e);
            } catch (SignatureException e) {
                throw new SignRequestSignatureException("Cannot verify certificate in createPKCS7(), did I sign this?", e);
            }
        }
        final List<X509Certificate> x509Chain = new ArrayList<>();
        if (cert!=null) {
            x509Chain.add(cert);
        }
        if (includeChain) {
            x509Chain.addAll(CertTools.convertCertificateChainToX509Chain(getCertificateChain()));
        }
        List<JcaX509CertificateHolder> certList;
        try {
            certList = CertTools.convertToX509CertificateHolder(x509Chain);
        } catch (CertificateEncodingException e) {
            throw new SignRequestSignatureException("Could not encode certificate", e);
        }
        try {
            CMSTypedData msg = new CMSProcessableByteArray(new byte[0]);
            CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
            final PrivateKey privateKey = cryptoToken.getPrivateKey(getCAToken().getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
            if (privateKey == null) {
                String msg1 = "createPKCS7: Private key does not exist!";
                log.debug(msg1);
                throw new SignRequestSignatureException(msg1);
            }
            String signatureAlgorithmName = AlgorithmTools.getAlgorithmNameFromDigestAndKey(CMSSignedGenerator.DIGEST_SHA1, privateKey.getAlgorithm());
            try {
                ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithmName).setProvider(cryptoToken.getSignProviderName()).build(privateKey);
                JcaDigestCalculatorProviderBuilder calculatorProviderBuilder = new JcaDigestCalculatorProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME);
                JcaSignerInfoGeneratorBuilder builder = new JcaSignerInfoGeneratorBuilder(calculatorProviderBuilder.build());
                gen.addSignerInfoGenerator(builder.build(contentSigner, cacert));
            } catch (OperatorCreationException e) {
                throw new IllegalStateException("BouncyCastle failed in creating signature provider.", e);
            }
            gen.addCertificates(new CollectionStore<>(certList));
            CMSSignedData s = null;
            CAToken catoken = getCAToken();
            if (catoken != null && !(cryptoToken instanceof NullCryptoToken)) {
                log.debug("createPKCS7: Provider=" + cryptoToken.getSignProviderName() + " using algorithm "
                        + privateKey.getAlgorithm());
                s = gen.generate(msg, true);
            } else {
                String msg1 = "CA Token does not exist!";
                log.debug(msg1);
                throw new SignRequestSignatureException(msg1);
            }
            return s.getEncoded();
        } catch (CryptoTokenOfflineException e) {
            throw new IllegalStateException(e);
        } catch (Exception e) {
            //FIXME: This right here is just nasty
            throw new IllegalStateException(e);
        }
    }

    @Override
    public byte[] createPKCS7Rollover(CryptoToken cryptoToken) throws SignRequestSignatureException {
        List<Certificate> nextChain = getRolloverCertificateChain();
        if (nextChain == null) {
            log.debug("CA does not have a rollover chain, returning empty PKCS#7");
            nextChain = Collections.emptyList();
        } else if (nextChain.isEmpty()) {
            log.warn("next chain exists but is empty");
        }

        ArrayList<X509CertificateHolder> certList = new ArrayList<>();
        try {
            for (Certificate certificate : nextChain) {
                certList.add(new JcaX509CertificateHolder((X509Certificate) certificate));
            }
        } catch (CertificateEncodingException e) {
            throw new SignRequestSignatureException("Could not encode certificate", e);
        }
        if (log.isDebugEnabled()) {
            log.debug("createPKCS7Rollover: Creating a rollover chain with "+certList.size()+" certificates.");
        }
        try {
            CMSTypedData msg = new CMSProcessableByteArray(new byte[0]);
            CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
            // We always sign with the current key, even during rollover, so the new key can be linked to the old key. SCEP draft 23, "4.6.1.  Get Next CA Response Message Format"
            final PrivateKey privateKey = cryptoToken.getPrivateKey(getCAToken().getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
            if (privateKey == null) {
                final String msg1 = "createPKCS7Rollover: Private key does not exist!";
                log.debug(msg1);
                throw new SignRequestSignatureException(msg1);
            }
            String signatureAlgorithmName = AlgorithmTools.getAlgorithmNameFromDigestAndKey(CMSSignedGenerator.DIGEST_SHA1, privateKey.getAlgorithm());
            try {
                ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithmName).setProvider(cryptoToken.getSignProviderName()).build(privateKey);
                JcaDigestCalculatorProviderBuilder calculatorProviderBuilder = new JcaDigestCalculatorProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME);
                JcaSignerInfoGeneratorBuilder builder = new JcaSignerInfoGeneratorBuilder(calculatorProviderBuilder.build());
                gen.addSignerInfoGenerator(builder.build(contentSigner, (X509Certificate) getCACertificate()));
            } catch (OperatorCreationException e) {
                throw new IllegalStateException("BouncyCastle failed in creating signature provider.", e);
            } catch (CertificateEncodingException e) {
                throw new IllegalStateException(e);
            }
            gen.addCertificates(new CollectionStore<>(certList));
            CMSSignedData s = null;
            CAToken catoken = getCAToken();
            if (catoken != null && !(cryptoToken instanceof NullCryptoToken)) {
                log.debug("createPKCS7Rollover: Provider=" + cryptoToken.getSignProviderName() + " using algorithm "
                        + privateKey.getAlgorithm());
                // Don't encapsulate any content, i.e. the bytes in the message. This makes data section of the PKCS#7 message completely empty.
                // BER Sequence
                //   ObjectIdentifier(1.2.840.113549.1.7.1)
                // Instead of
                // BER Sequence
                //   ObjectIdentifier(1.2.840.113549.1.7.1)
                //   BER Tagged [0]
                //     BER Constructed Octet String[0]
                s = gen.generate(msg, false);
            } else {
                String msg1 = "CA Token does not exist!";
                log.debug(msg1);
                throw new SignRequestSignatureException(msg1);
            }
            return s.getEncoded();
        } catch (CryptoTokenOfflineException e) {
            throw new IllegalStateException(e);
        } catch (CMSException e) {
            throw new IllegalStateException(e);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to encode CMS data", e);
        }
    }

    /**
     * @see CA#createRequest(CryptoToken, Collection, String, Certificate, int, CertificateProfile, AvailableCustomCertificateExtensionsConfiguration)
     */
    @Override
    public byte[] createRequest(final CryptoToken cryptoToken, final Collection<ASN1Encodable> attributes, final String signAlg, final Certificate cacert,
            final int signatureKeyPurpose, final CertificateProfile certificateProfile, final AvailableCustomCertificateExtensionsConfiguration cceConfig)
                    throws CryptoTokenOfflineException, CertificateExtensionException {
        log.trace(">createRequest: " + signAlg + ", " + CertTools.getSubjectDN(cacert) + ", " + signatureKeyPurpose);
        ASN1Set attrset = new DERSet();
        if (attributes != null) {
            log.debug("Adding attributes in the request");
            ASN1EncodableVector vec = new ASN1EncodableVector();
            for (final ASN1Encodable o : attributes) {
                vec.add(o);
            }
            attrset = new DERSet(vec);
        }
        final X500NameStyle nameStyle;
        if (getUsePrintableStringSubjectDN()) {
            nameStyle = PrintableStringNameStyle.INSTANCE;
        } else {
            nameStyle = CeSecoreNameStyle.INSTANCE;
        }
        X500Name x509dn = CertTools.stringToBcX500Name(getSubjectDN(), nameStyle, getUseLdapDNOrder());
        PKCS10CertificationRequest req;
        try {
            final CAToken catoken = getCAToken();
            final String alias = catoken.getAliasFromPurpose(signatureKeyPurpose);
            final KeyPair keyPair = new KeyPair(cryptoToken.getPublicKey(alias), cryptoToken.getPrivateKey(alias));
            req = CertTools.genPKCS10CertificationRequest(signAlg, x509dn, keyPair.getPublic(), attrset, keyPair.getPrivate(), cryptoToken.getSignProviderName());
            log.trace("<createRequest");
            return req.getEncoded();
        } catch (CryptoTokenOfflineException e) { // NOPMD, since we catch wide below
            throw e;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /** This method is not supported for X509 CAs. */
    @Override
    public byte[] createAuthCertSignRequest(CryptoToken cryptoToken, final byte[] request) throws CryptoTokenOfflineException {
        throw new UnsupportedOperationException("Creation of authenticated CSRs is not supported for X509 CAs.");
    }

    /**
     * @param caNameChange if set to false, regular X509 link certificate will be created. Otherwise, created link certificates
     * will be modified as explained in the ICAO 9303 7th edition part 12. In addition to regular X509 link certificate format
     * this link certificate will have:
     *       SubjectDN as CA's SubjectDN/IssuerDN after CA Name Change
     *       IssuerDN as CA's SubjectDN/IssuerDN before CA Name Change
     *       the Name Change Extension
     * @param oldCaCert to get expire date info from the old CA certificate to put in the link certificate
     */
    private void createOrRemoveLinkCertificate(final CryptoToken cryptoToken, final boolean createLinkCertificate, final CertificateProfile certProfile,
            final AvailableCustomCertificateExtensionsConfiguration cceConfig, boolean caNameChange, final Certificate oldCaCert) throws CryptoTokenOfflineException {
        byte[] ret = null;
        if (createLinkCertificate) {
            try {
                final CAToken catoken = getCAToken();
                // Check if the input was a CA certificate, which is the same CA as this. If all is true we should create a NewWithOld link-certificate
                final X509Certificate currentCaCert = (X509Certificate) getCACertificate();
                if (log.isDebugEnabled()) {
                    log.debug("We will create a link certificate.");
                }
                final X509CAInfo info = (X509CAInfo) getCAInfo();
                final EndEntityInformation cadata = new EndEntityInformation("nobody", info.getSubjectDN(), info.getSubjectDN().hashCode(), info.getSubjectAltName(), null,
                        0, new EndEntityType(EndEntityTypes.INVALID), 0, info.getCertificateProfileId(), null, null, 0, 0, null);
                final PublicKey previousCaPublicKey = cryptoToken.getPublicKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN_PREVIOUS));
                final PrivateKey previousCaPrivateKey = cryptoToken.getPrivateKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN_PREVIOUS));
                final String provider = cryptoToken.getSignProviderName();
                // The sequence is ignored later, but we fetch the same previous for now to do this the same way as for CVC..
                final String ignoredKeySequence = catoken.getProperties().getProperty(CATokenConstants.PREVIOUS_SEQUENCE_PROPERTY);
                final Certificate retcert = generateCertificate(cadata, null, currentCaCert.getPublicKey(), -1, currentCaCert.getNotBefore(), ((X509Certificate) oldCaCert).getNotAfter(),
                        certProfile, null, ignoredKeySequence, previousCaPublicKey, previousCaPrivateKey, provider, null, cceConfig, /*createLinkCertificate=*/true, caNameChange);
                log.info(intres.getLocalizedMessage("cvc.info.createlinkcert", cadata.getDN(), ((X509Certificate)retcert).getIssuerDN().getName()));
                ret = retcert.getEncoded();
            } catch (CryptoTokenOfflineException e) {
                throw e;
            } catch (Exception e) {
                throw new IllegalStateException("Error withing creating or removing link certificate.", e);
            }
        }
        updateLatestLinkCertificate(ret);
    }


    public void createOrRemoveLinkCertificateDuringCANameChange(final CryptoToken cryptoToken, final boolean createLinkCertificate, final CertificateProfile certProfile,
            final AvailableCustomCertificateExtensionsConfiguration cceConfig, final Certificate oldCaCert) throws CryptoTokenOfflineException {
        createOrRemoveLinkCertificate(cryptoToken, createLinkCertificate, certProfile, cceConfig, /*caNameChange*/true, oldCaCert);
    }

    @Override
    public void createOrRemoveLinkCertificate(final CryptoToken cryptoToken, final boolean createLinkCertificate, final CertificateProfile certProfile,
            final AvailableCustomCertificateExtensionsConfiguration cceConfig, final Certificate oldCaCert) throws CryptoTokenOfflineException {
        createOrRemoveLinkCertificate(cryptoToken, createLinkCertificate, certProfile, cceConfig, /*caNameChange*/false, oldCaCert);
    }


    /**
     * @param request provided request message containing optional information, and will be set with the signing key and provider.
     * If the certificate profile allows subject DN override this value will be used instead of the value from subject.getDN. Its public key is going to be used if
     * publicKey == null && subject.extendedInformation.certificateRequest == null. Can be null.
     * @param publicKey provided public key which will have precedence over public key from the provided RequestMessage but not over subject.extendedInformation.certificateRequest
     * @param subject end entity information. If it contains certificateRequest under extendedInformation, it will be used instead of the provided RequestMessage and publicKey
     */
    @Override
    public Certificate generateCertificate(CryptoToken cryptoToken, final EndEntityInformation subject, final RequestMessage request,
            final PublicKey publicKey, final int keyusage, final Date notBefore, final Date notAfter, final CertificateProfile certProfile,
            final Extensions extensions, final String sequence, CertificateGenerationParams certGenParams, final AvailableCustomCertificateExtensionsConfiguration cceConfig)
            throws CryptoTokenOfflineException, CAOfflineException, InvalidAlgorithmException,
            IllegalValidityException, IllegalNameException, OperatorCreationException, CertificateCreateException, CertificateExtensionException, SignatureException, IllegalKeyException {
        // Before we start, check if the CA is off-line, we don't have to waste time
        // one the stuff below of we are off-line. The line below will throw CryptoTokenOfflineException of CA is offline
        final CAToken catoken = getCAToken();
        final int purpose = getUseNextCACert(request) ? CATokenConstants.CAKEYPURPOSE_CERTSIGN_NEXT : CATokenConstants.CAKEYPURPOSE_CERTSIGN;
        final PublicKey caPublicKey = cryptoToken.getPublicKey(catoken.getAliasFromPurpose(purpose));
        final PrivateKey caPrivateKey = cryptoToken.getPrivateKey(catoken.getAliasFromPurpose(purpose));
        final String provider = cryptoToken.getSignProviderName();
        return generateCertificate(subject, request, publicKey, keyusage, notBefore, notAfter, certProfile, extensions, sequence,
                caPublicKey, caPrivateKey, provider, certGenParams, cceConfig, /*linkCertificate=*/false, /*caNameChange=*/false);
    }

    /**
     * Sequence is ignored by X509CA. The ctParams argument will NOT be kept after the function call returns,
     * and is allowed to contain references to session beans.
     * @param providedRequestMessage provided request message containing optional information, and will be set with the signing key and provider.
     * If the certificate profile allows subject DN override this value will be used instead of the value from subject.getDN. Its public key is going to be used if
     * providedPublicKey == null && subject.extendedInformation.certificateRequest == null. Can be null.
     * @param providedPublicKey provided public key which will have precedence over public key from providedRequestMessage but not over subject.extendedInformation.certificateRequest
     * @param subject end entity information. If it contains certificateRequest under extendedInformation, it will be used instead of providedRequestMessage and providedPublicKey
     * Otherwise, providedRequestMessage will be used.
     *
     * @throws CAOfflineException if the CA wasn't active
     * @throws InvalidAlgorithmException if the signing algorithm in the certificate profile (or the CA Token if not found) was invalid.
     * @throws IllegalValidityException if validity was invalid
     * @throws IllegalNameException if the name specified in the certificate request was invalid
     * @throws CertificateExtensionException if any of the certificate extensions were invalid
     * @throws OperatorCreationException if CA's private key contained an unknown algorithm or provider
     * @throws CertificateCreateException if an error occurred when trying to create a certificate.
     * @throws SignatureException if the CA's certificate's and request's certificate's and signature algorithms differ
     * @throws IllegalKeyException if selected public key (check providedRequestMessage, providedPublicKey, subject) is not allowed with certProfile
     */
    private Certificate generateCertificate(final EndEntityInformation subject, final RequestMessage providedRequestMessage, final PublicKey providedPublicKey,
            final int keyusage, final Date notBefore, final Date notAfter, final CertificateProfile certProfile, final Extensions extensions,
            final String sequence, final PublicKey caPublicKey, final PrivateKey caPrivateKey, final String provider,
            CertificateGenerationParams certGenParams, AvailableCustomCertificateExtensionsConfiguration cceConfig, boolean linkCertificate, boolean caNameChange)
            throws CAOfflineException, InvalidAlgorithmException, IllegalValidityException, IllegalNameException, CertificateExtensionException,
             OperatorCreationException, CertificateCreateException, SignatureException, IllegalKeyException {

    	// We must only allow signing to take place if the CA itself is on line, even if the token is on-line.
        // We have to allow expired as well though, so we can renew expired CAs
        if ((getStatus() != CAConstants.CA_ACTIVE) && ((getStatus() != CAConstants.CA_EXPIRED))) {
            final String msg = intres.getLocalizedMessage("error.caoffline", getName(), getStatus());
            if (log.isDebugEnabled()) {
                log.debug(msg); // This is something we handle so no need to log with higher priority
            }
            throw new CAOfflineException(msg);
        }
        // Which public key and request shall we use?
        final ExtendedInformation ei = subject.getExtendedInformation();
        final RequestAndPublicKeySelector pkSelector = new RequestAndPublicKeySelector(providedRequestMessage, providedPublicKey, ei);
        final PublicKey publicKey = pkSelector.getPublicKey();
        final RequestMessage request = pkSelector.getRequestMessage();

        certProfile.verifyKey(publicKey);

        final String sigAlg;
        if (certProfile.getSignatureAlgorithm() == null) {
            sigAlg = getCAToken().getSignatureAlgorithm();
        } else {
            sigAlg = certProfile.getSignatureAlgorithm();
        }
        // Check that the signature algorithm is one of the allowed ones
        if (!StringTools.containsCaseInsensitive(AlgorithmConstants.AVAILABLE_SIGALGS, sigAlg)) {
            final String msg = intres.getLocalizedMessage("createcert.invalidsignaturealg", sigAlg, ArrayUtils.toString(AlgorithmConstants.AVAILABLE_SIGALGS));
            throw new InvalidAlgorithmException(msg);
        }
        // Check if this is a root CA we are creating
        final boolean isRootCA = certProfile.getType() == CertificateConstants.CERTTYPE_ROOTCA;

        final boolean useNextCACert = getUseNextCACert(request);
        final X509Certificate cacert = (X509Certificate) (useNextCACert ? getRolloverCertificateChain().get(0) : getCACertificate());
        final Date now = new Date();
        final Date checkDate = useNextCACert && cacert.getNotBefore().after(now) ? cacert.getNotBefore() : now;
        // Check CA certificate PrivateKeyUsagePeriod if it exists (throws CAOfflineException if it exists and is not within this time)
        CertificateValidity.checkPrivateKeyUsagePeriod(cacert, checkDate);
        // Get certificate validity time notBefore and notAfter
        final CertificateValidity val = new CertificateValidity(subject, certProfile, notBefore, notAfter, cacert, isRootCA, linkCertificate);

        // Serialnumber is either random bits, where random generator is initialized by the serno generator.
        // Or a custom serial number defined in the end entity object
        final BigInteger serno;
        {
            if (certProfile.getAllowCertSerialNumberOverride()) {
                if (ei != null && ei.certificateSerialNumber()!=null) {
                    serno = ei.certificateSerialNumber();
                } else {
                    serno = SernoGeneratorRandom.instance().getSerno();
                }
            } else {
                serno = SernoGeneratorRandom.instance().getSerno();
                if ((ei != null) && (ei.certificateSerialNumber() != null)) {
                    final String msg = intres.getLocalizedMessage("createcert.certprof_not_allowing_cert_sn_override_using_normal", ei.certificateSerialNumber().toString(16));
                    log.info(msg);
                }
            }
        }

        // Make DNs
        final X500NameStyle nameStyle;
        if (getUsePrintableStringSubjectDN()) {
            nameStyle = PrintableStringNameStyle.INSTANCE;
        } else {
            nameStyle = CeSecoreNameStyle.INSTANCE;
        }

        String dn = subject.getCertificateDN();
        if (certProfile.getUseSubjectDNSubSet()) {
            dn = certProfile.createSubjectDNSubSet(dn);
        }
        if (certProfile.getUseCNPostfix()) {
            dn = CertTools.insertCNPostfix(dn, certProfile.getCNPostfix(), nameStyle);
        }

        // Will we use LDAP DN order (CN first) or X500 DN order (CN last) for the subject DN
        final boolean ldapdnorder;
        if ((getUseLdapDNOrder() == false) || (certProfile.getUseLdapDnOrder() == false)) {
            ldapdnorder = false;
        } else {
            ldapdnorder = true;
        }
        // If we have a custom order defined in the certificate profile, take this. If this is null or empty it will be ignored
        String[] customDNOrder = null;
        if (certProfile.getUseCustomDnOrder()) {
            final ArrayList<String> order = certProfile.getCustomDnOrder();
            if (order != null && order.size() > 0) {
                if (log.isDebugEnabled()) {
                    log.debug("Using Custom DN order: "+order);
                }
                customDNOrder = order.toArray(new String[0]);
            }
        }
        final boolean applyLdapToCustomOrder = certProfile.getUseCustomDnOrderWithLdap();

        final X500Name subjectDNName;
        if (certProfile.getAllowDNOverride() && (request != null) && (request.getRequestX500Name() != null)) {
            subjectDNName = request.getRequestX500Name();
            if (log.isDebugEnabled()) {
                log.debug("Using X509Name from request instead of user's registered.");
            }
        } else {
            if (certProfile.getAllowDNOverrideByEndEntityInformation() && ei!=null && ei.getRawSubjectDn()!=null) {
                final String stripped = StringTools.strip(ei.getRawSubjectDn());
                final String escapedPluses = CertTools.handleUnescapedPlus(stripped);
                final String emptiesRemoved = DNFieldsUtil.removeAllEmpties(escapedPluses);
                final X500Name subjectDNNameFromEei = CertTools.stringToUnorderedX500Name(emptiesRemoved, CeSecoreNameStyle.INSTANCE);
                if (subjectDNNameFromEei.toString().length()>0) {
                    subjectDNName = subjectDNNameFromEei;
                    if (log.isDebugEnabled()) {
                        log.debug("Using X500Name from end entity information instead of user's registered subject DN fields.");
                        log.debug("ExtendedInformation.getRawSubjectDn(): " + ei.getRawSubjectDn() + " will use: " + CeSecoreNameStyle.INSTANCE.toString(subjectDNName));
                    }
                } else {
                    subjectDNName = CertTools.stringToBcX500Name(dn, nameStyle, ldapdnorder, customDNOrder, applyLdapToCustomOrder);
                }
            } else {
                subjectDNName = CertTools.stringToBcX500Name(dn, nameStyle, ldapdnorder, customDNOrder, applyLdapToCustomOrder);
            }
        }
        // Make sure the DN does not contain dangerous characters
        if (!StringTools.hasStripChars(subjectDNName.toString()).isEmpty()) {
            if (log.isTraceEnabled()) {
            	log.trace("DN with illegal name: "+subjectDNName);
            }
            final String msg = intres.getLocalizedMessage("createcert.illegalname");
        	throw new IllegalNameException(msg);
        }
        if (log.isDebugEnabled()) {
            log.debug("Using subjectDN: " + subjectDNName.toString());
        }

        // We must take the issuer DN directly from the CA-certificate otherwise we risk re-ordering the DN
        // which many applications do not like.
        X500Name issuerDNName;
        if (isRootCA) {
            // This will be an initial root CA, since no CA-certificate exists
            // Or it is a root CA, since the cert is self signed. If it is a root CA we want to use the same encoding for subject and issuer,
            // it might have changed over the years.
            if (log.isDebugEnabled()) {
                log.debug("Using subject DN also as issuer DN, because it is a root CA");
            }
            if(linkCertificate && caNameChange){
                List<Certificate> renewedCertificateChain = getRenewedCertificateChain();
                if(renewedCertificateChain == null || renewedCertificateChain.isEmpty()){
                    //"Should not happen" error
                    log.error("CA name change is in process but renewed (old) certificates chain is empty");
                    throw new CertificateCreateException("CA name change is in process but renewed (old) certificates chain is empty");
                }
                issuerDNName = X500Name.getInstance(((X509Certificate)renewedCertificateChain.get(renewedCertificateChain.size()-1)).getSubjectX500Principal().getEncoded());
            }else{
                issuerDNName = subjectDNName;
            }
        } else {
            issuerDNName = X500Name.getInstance(cacert.getSubjectX500Principal().getEncoded());
            if (log.isDebugEnabled()) {
                log.debug("Using issuer DN directly from the CA certificate: " + issuerDNName.toString());
            }
        }

        SubjectPublicKeyInfo pkinfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
        final X509v3CertificateBuilder certbuilder = new X509v3CertificateBuilder(issuerDNName, serno, val.getNotBefore(), val.getNotAfter(), subjectDNName, pkinfo);

        // Only created and used if Certificate Transparency is enabled
        final X509v3CertificateBuilder precertbuilder = certProfile.isUseCertificateTransparencyInCerts() ?
            new X509v3CertificateBuilder(issuerDNName, serno, val.getNotBefore(), val.getNotAfter(), subjectDNName, pkinfo) : null;


        // Check that the certificate fulfills name constraints
        if (cacert != null) {
            GeneralNames altNameGNs = null;
            String altName = subject.getSubjectAltName();
            if(certProfile.getUseSubjectAltNameSubSet()){
                altName = certProfile.createSubjectAltNameSubSet(altName);
            }
            if (altName != null && altName.length() > 0) {
                altNameGNs = CertTools.getGeneralNamesFromAltName(altName);
            }
            CertTools.checkNameConstraints(cacert, subjectDNName, altNameGNs);
        }

        // If the subject has Name Constraints, then name constraints must be enabled in the certificate profile!
        if (ei != null) {
            final List<String> permittedNC = ei.getNameConstraintsPermitted();
            final List<String> excludedNC = ei.getNameConstraintsExcluded();
            if ((permittedNC != null && !permittedNC.isEmpty()) ||
                (excludedNC != null && !excludedNC.isEmpty())) {
                if (!certProfile.getUseNameConstraints()) {
                    throw new CertificateCreateException("Tried to issue a certificate with Name Constraints without having enabled NC in the certificate profile.");
                }
            }
        }

        //
        // X509 Certificate Extensions
        //

        // Extensions we will add to the certificate, later when we have filled the structure with
        // everything we want.
        final ExtensionsGenerator extgen = new ExtensionsGenerator();

        // First we check if there is general extension override, and add all extensions from
        // the request in that case
        if (certProfile.getAllowExtensionOverride() && extensions != null) {
            Set<String> overridableExtensionOIDs = certProfile.getOverridableExtensionOIDs();
            Set<String> nonOverridableExtensionOIDs = certProfile.getNonOverridableExtensionOIDs();
            if (!overridableExtensionOIDs.isEmpty() && !nonOverridableExtensionOIDs.isEmpty()) {
                // If user have set both of these lists, user may not know what he/she has done as it doesn't make sense
                // hence the result may not be the desired. To get attention to this, log an error
                log.error("Both overridableExtensionOIDs and nonOverridableExtensionOIDs are set in certificate profile which "
                        + "does not make sense. NonOverridableExtensionOIDs will take precedence, is this the desired behavior?");
            }
            ASN1ObjectIdentifier[] oids = extensions.getExtensionOIDs();
            for(ASN1ObjectIdentifier oid : oids ) {
                // Start by excluding non overridable extensions
                // If there are no nonOverridableExtensionOIDs set, or if the set does not contain our oid, we allow it so move on
                // (nonOverridableExtensionOIDs can never by null)
                if (!nonOverridableExtensionOIDs.contains(oid.getId())) {
                    // Now check if we have specified which ones are allowed, if this is not set we allow everything
                    // (overridableExtensionOIDs can never by null)
                    if (overridableExtensionOIDs.size() == 0 || overridableExtensionOIDs.contains(oid.getId())) {
                        final Extension ext = extensions.getExtension(oid);
                        if (log.isDebugEnabled()) {
                            log.debug("Overriding extension with oid: " + oid.getId());
                        }
                        try {
                            extgen.addExtension(oid, ext.isCritical(), ext.getParsedValue());
                        } catch (IOException e) {
                            throw new IllegalStateException("Caught unexpected IOException.", e);
                        }
                    } else {
                        if (log.isDebugEnabled()) {
                            log.debug("Extension is not among overridable extensions, ignoring extension from request with oid "+oid.getId());
                        }
                    }
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("Extension is among non-overridable extensions, ignoring extension from request with oid "+oid.getId());
                    }
                }

            }
        }

        // Second we see if there is Key usage override
        Extensions overridenexts = extgen.generate();
        if (certProfile.getAllowKeyUsageOverride() && (keyusage >= 0)) {
            if (log.isDebugEnabled()) {
                log.debug("AllowKeyUsageOverride=true. Using KeyUsage from parameter: " + keyusage);
            }
            if ((certProfile.getUseKeyUsage() == true) && (keyusage >= 0)) {
                final KeyUsage ku = new KeyUsage(keyusage);
                // We don't want to try to add custom extensions with the same oid if we have already added them
                // from the request, if AllowExtensionOverride is enabled.
                // Two extensions with the same oid is not allowed in the standard.
                if (overridenexts.getExtension(Extension.keyUsage) == null) {
                    try {
                        extgen.addExtension(Extension.keyUsage, certProfile.getKeyUsageCritical(), ku);
                    } catch (IOException e) {
                        throw new IllegalStateException("Caught unexpected IOException.", e);
                    }
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("KeyUsage was already overridden by an extension, not using KeyUsage from parameter.");
                    }
                }
            }
        }

        // Third, check for standard Certificate Extensions that should be added.
        // Standard certificate extensions are defined in CertificateProfile and CertificateExtensionFactory
        // and implemented in package org.ejbca.core.model.certextensions.standard
        final CertificateExtensionFactory fact = CertificateExtensionFactory.getInstance();
        final List<String> usedStdCertExt = certProfile.getUsedStandardCertificateExtensions();
        final Iterator<String> certStdExtIter = usedStdCertExt.iterator();
        overridenexts = extgen.generate();
        while (certStdExtIter.hasNext()) {
            final String oid = certStdExtIter.next();
            // We don't want to try to add standard extensions with the same oid if we have already added them
            // from the request, if AllowExtensionOverride is enabled.
            // Two extensions with the same oid is not allowed in the standard.
            if (overridenexts.getExtension(new ASN1ObjectIdentifier(oid)) == null) {
                final CertificateExtension certExt = fact.getStandardCertificateExtension(oid, certProfile);
                if (certExt != null) {
                    final byte[] value = certExt.getValueEncoded(subject, this, certProfile, publicKey, caPublicKey, val);
                    if (value != null) {
                        extgen.addExtension(new ASN1ObjectIdentifier(certExt.getOID()), certExt.isCriticalFlag(), value);
                    }
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Extension with oid " + oid + " has been overridden, standard extension will not be added.");
                }
            }
        }

        // Fourth, ICAO standard extensions. Only Name Change extension is used and added only for link certificates
        if (caNameChange) {
            try {
                extgen.addExtension(ICAOObjectIdentifiers.id_icao_extensions_namechangekeyrollover, false, DERNull.INSTANCE);
            } catch (IOException e) {/*IOException with DERNull.INSTANCE will never happen*/}
        }

        //

        // Fifth, check for custom Certificate Extensions that should be added.
        // Custom certificate extensions is defined in AdminGUI -> SystemConfiguration -> Custom Certificate Extensions
        final List<Integer> usedCertExt = certProfile.getUsedCertificateExtensions();
        final Iterator<Integer> certExtIter = usedCertExt.iterator();
        while (certExtIter.hasNext()) {
            final int id = certExtIter.next();
            final CustomCertificateExtension certExt = cceConfig.getCustomCertificateExtension(id);
            if (certExt != null) {
                // We don't want to try to add custom extensions with the same oid if we have already added them
                // from the request, if AllowExtensionOverride is enabled.
                // Two extensions with the same oid is not allowed in the standard.
                if (overridenexts.getExtension(new ASN1ObjectIdentifier(certExt.getOID())) == null) {
                    final byte[] value = certExt.getValueEncoded(subject, this, certProfile, publicKey, caPublicKey, val);
                    if (value != null) {
                        extgen.addExtension(new ASN1ObjectIdentifier(certExt.getOID()), certExt.isCriticalFlag(), value);
                    } else if (certExt.isRequiredFlag()) {
                        throw new CertificateCreateException(ErrorCode.REQUIRED_CUSTOM_CERTIFICATE_EXTENSION_MISSING,
                                "Required custom certificate extension with oid " + certExt.getOID() + " is missing!");
                    }
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("Extension with oid " + certExt.getOID() + " has been overridden, custom extension will not be added.");
                    }
                }
            }
        }

        // Finally add extensions to certificate generator
        final Extensions exts = extgen.generate();
        ASN1ObjectIdentifier[] oids = exts.getExtensionOIDs();
        try {
            for (ASN1ObjectIdentifier oid : oids) {
                final Extension extension = exts.getExtension(oid);
                if(oid.equals(Extension.subjectAlternativeName)) { // subjectAlternativeName extension value needs special handling
                    ExtensionsGenerator sanExtGen = getSubjectAltNameExtensionForCert(extension, precertbuilder!=null);
                    Extensions sanExts = sanExtGen.generate();
                    Extension eext = sanExts.getExtension(oid);
                    certbuilder.addExtension(oid, eext.isCritical(), eext.getParsedValue()); // adding subjetAlternativeName extension to certbuilder
                    if(precertbuilder != null) { // if a pre-certificate is to be published to a CTLog
                        eext = getSubjectAltNameExtensionForCTCert(extension).generate().getExtension(oid);
                        precertbuilder.addExtension(oid, eext.isCritical(), eext.getParsedValue()); // adding subjectAlternativeName extension to precertbuilder

                        eext = sanExts.getExtension(new ASN1ObjectIdentifier(CertTools.id_ct_redacted_domains));
                        if(eext != null) {
                            certbuilder.addExtension(eext.getExtnId(), eext.isCritical(), eext.getParsedValue()); // adding nrOfRedactedLabels extension to certbuilder
                        }
                    }
                } else { // if not a subjectAlternativeName extension, just add it to both certbuilder and precertbuilder
                    final boolean isCritical = extension.isCritical();
                    // We must get the raw octets here in order to be able to create invalid extensions that is not constructed from proper ASN.1
                    final byte[] value = extension.getExtnValue().getOctets();
                    certbuilder.addExtension(extension.getExtnId(), isCritical, value);
                    if (precertbuilder != null) {
                        precertbuilder.addExtension(extension.getExtnId(), isCritical, value);
                    }
                }
            }

            // Add Certificate Transparency extension. It needs to access the certbuilder and
            // the CA key so it has to be processed here inside X509CA.
             if (ct != null && certProfile.isUseCertificateTransparencyInCerts() && certGenParams != null) {

                // Create pre-certificate
                // A critical extension is added to prevent this cert from being used
                ct.addPreCertPoison(precertbuilder);

                // Sign pre-certificate
                /*
                 *  TODO: Should be able to use a special CT signing certificate.
                 *  It should have CA=true and ExtKeyUsage=PRECERTIFICATE_SIGNING_OID,
                 *  and should not have any other key usages.
                 */
                final ContentSigner signer = new BufferingContentSigner(
                        new JcaContentSignerBuilder(sigAlg).setProvider(provider).build(caPrivateKey), 20480);
                final X509CertificateHolder certHolder = precertbuilder.build(signer);
                final X509Certificate cert = CertTools.getCertfromByteArray(certHolder.getEncoded(), X509Certificate.class);
                // ECA-6051 Re-Factor with Domain Service Layer.
                if (certGenParams.getAuthenticationToken() != null && certGenParams.getCertificateValidationDomainService() != null) {
                    try {
                        certGenParams.getCertificateValidationDomainService().validateCertificate(certGenParams.getAuthenticationToken(), IssuancePhase.PRE_CERTIFICATE_VALIDATION, this, subject, cert);
                    } catch (ValidationException e) {
                        throw new CertificateCreateException(ErrorCode.INVALID_CERTIFICATE, e);
                    }
                }

                if (certGenParams.getCTSubmissionConfigParams() == null) {
                    log.debug("Not logging to CT. CT submission configuration parameters was null.");
                } else if (MapUtils.isEmpty(certGenParams.getCTSubmissionConfigParams().getConfiguredCTLogs())) {
                    log.debug("Not logging to CT. There are no CT logs configured in System Configuration.");
                } else if (certGenParams.getCTAuditLogCallback() == null) {
                    log.debug("Not logging to CT. No CT audit logging callback was passed to X509CA.");
                } else {
                    // Get certificate chain
                    final List<Certificate> chain = new ArrayList<>();
                    chain.add(cert);
                    chain.addAll(getCertificateChain());

                    // Submit to logs and get signed timestamps
                    byte[] sctlist = null;
                    try {
                        sctlist = ct.fetchSCTList(chain, certProfile, certGenParams.getCTSubmissionConfigParams());
                    }  finally {
                        // Notify that pre-cert has been successfully or unsuccessfully submitted so it can be audit logged.
                        certGenParams.getCTAuditLogCallback().logPreCertSubmission(this, subject, cert, sctlist != null);
                    }
                    if (sctlist != null) { // can be null if the CTLog has been deleted from the configuration
                        ASN1ObjectIdentifier sctOid = new ASN1ObjectIdentifier(CertificateTransparency.SCTLIST_OID);
                        certbuilder.addExtension(sctOid, false, new DEROctetString(sctlist));
                    }
                }
            } else {
                if (log.isDebugEnabled()) {
                    String cause = "";
                    if (ct == null) {
                        cause += "CT is not available in this version of EJBCA.";
                    } else {
                        if (!certProfile.isUseCertificateTransparencyInCerts()) {
                            cause += "CT is not enabled in the certificate profile. ";
                        }
                        if (certGenParams == null) {
                            cause += "Certificate generation parameters was null.";
                        }
                    }
                    log.debug("Not logging to CT. "+cause);
                }
            }
        } catch (CertificateException e) {
            throw new CertificateCreateException("Could not process CA's private key when parsing Certificate Transparency extension.", e);
        } catch (IOException e) {
            throw new CertificateCreateException("IOException was caught when parsing Certificate Transparency extension.", e);
        } catch (CTLogException e) {
            throw new CertificateCreateException("An exception occurred because too many CT servers were down to satisfy the certificate profile.", e);
        }

        //
        // End of extensions
        //

        if (log.isTraceEnabled()) {
            log.trace(">certgen.generate");
        }
        final ContentSigner signer = new BufferingContentSigner(new JcaContentSignerBuilder(sigAlg).setProvider(provider).build(caPrivateKey), 20480);
        final X509CertificateHolder certHolder = certbuilder.build(signer);
        X509Certificate cert;
        try {
            cert = CertTools.getCertfromByteArray(certHolder.getEncoded(), X509Certificate.class);
        } catch (IOException e) {
            throw new IllegalStateException("Unexpected IOException caught when parsing certificate holder.", e);
        } catch (CertificateException e) {
            throw new CertificateCreateException("Could not create certificate from CA's private key,", e);
        }
        if (log.isTraceEnabled()) {
            log.trace("<certgen.generate");
        }

        // Verify using the CA certificate before returning
        // If we can not verify the issued certificate using the CA certificate we don't want to issue this cert
        // because something is wrong...
        final PublicKey verifyKey;
        // We must use the configured public key if this is a rootCA, because then we can renew our own certificate, after changing
        // the keys. In this case the _new_ key will not match the current CA certificate.
        if ((cacert != null) && (!isRootCA)) {
            verifyKey = cacert.getPublicKey();
        } else {
            verifyKey = caPublicKey;
        }
        try {
            cert.verify(verifyKey);
        } catch (InvalidKeyException e) {
            throw new CertificateCreateException("CA's public key was invalid,", e);
        } catch (NoSuchAlgorithmException e) {
           throw new CertificateCreateException(e);
        } catch (NoSuchProviderException e) {
            throw new IllegalStateException("Provider was unknown", e);
        } catch (CertificateException e) {
            throw new CertificateCreateException(e);
        }

        // Verify any Signed Certificate Timestamps (SCTs) in the certificate before returning. If one of the (embedded) SCTs does
        // not verify over the final certificate, it won't validate in the browser and we don't want to issue such certificates.
        if (ct != null) {
            Collection<CTLogInfo> ctLogs =
                    (certGenParams == null || certGenParams.getCTSubmissionConfigParams() == null || certGenParams.getCTSubmissionConfigParams().getConfiguredCTLogs() == null)
                    ? null
                    : certGenParams.getCTSubmissionConfigParams().getConfiguredCTLogs().values();
            ct.allSctsAreValidOrThrow(cert, getCertificateChain(), ctLogs);
        }

        //Sub CA certificates check: Check AKI against parent CA SKI and IssuerDN against parent CA SubjectDN
        if(!isRootCA && !linkCertificate){
            final byte[] aki = CertTools.getAuthorityKeyId(cert);
            final byte[] ski = CertTools.getSubjectKeyId(cacert);
            if ((aki != null) && (ski != null)) {
                final boolean eq = Arrays.equals(aki, ski);
                if (!eq) {
                    final String akistr = new String(Hex.encode(aki));
                    final String skistr = new String(Hex.encode(ski));
                    final String msg = intres.getLocalizedMessage("createcert.errorpathverifykeyid", akistr, skistr);
                    log.error(msg);
                    throw new CertificateCreateException(msg);
                }
            }
            final Principal issuerDN = cert.getIssuerX500Principal();
            final Principal caSubjectDN = cacert.getSubjectX500Principal();
            if ((issuerDN != null) && (caSubjectDN != null)) {
                final boolean eq = issuerDN.equals(caSubjectDN);
                if (!eq) {
                    final String msg = intres.getLocalizedMessage("createcert.errorpathverifydn", issuerDN.getName(), caSubjectDN.getName());
                    log.error(msg);
                    throw new CertificateCreateException(msg);
                }
            }
        }

        // Before returning from this method, we will set the private key and provider in the request message, in case the response  message needs to be signed
        if (request != null) {
            request.setResponseKeyInfo(caPrivateKey, provider);
        }
        if (log.isDebugEnabled()) {
            log.debug("X509CA: generated certificate, CA " + this.getCAId() + " for DN: " + subject.getCertificateDN());
        }
        return cert;
    }

    @Override
    public X509CRLHolder generateCRL(CryptoToken cryptoToken, Collection<RevokedCertInfo> certs, int crlnumber) throws CryptoTokenOfflineException, IllegalCryptoTokenException,
            IOException, SignatureException, NoSuchProviderException, InvalidKeyException, CRLException, NoSuchAlgorithmException {
        return generateCRL(cryptoToken, certs, getCRLPeriod(), crlnumber, false, 0);
    }

    @Override
    public X509CRLHolder generateDeltaCRL(CryptoToken cryptoToken, Collection<RevokedCertInfo> certs, int crlnumber, int basecrlnumber) throws CryptoTokenOfflineException,
            IllegalCryptoTokenException, IOException, SignatureException, NoSuchProviderException, InvalidKeyException, CRLException,
            NoSuchAlgorithmException {
        return generateCRL(cryptoToken, certs, getDeltaCRLPeriod(), crlnumber, true, basecrlnumber);
    }

    /**
     * Constructs the SubjectAlternativeName extension that will end up on the generated certificate.
     *
     * If the DNS values in the subjectAlternativeName extension contain parentheses to specify labels that should be redacted, the parentheses are removed and another extension
     * containing the number of redacted labels is added.
     *
     * @param subAltNameExt
     * @param publishToCT
     * @return An extension generator containing the SubjectAlternativeName extension and an extension holding the number of redacted labels if the certificate is to be published
     * to a CTLog
     * @throws IOException
     */
    protected ExtensionsGenerator getSubjectAltNameExtensionForCert(Extension subAltNameExt, boolean publishToCT) throws IOException {
        GeneralNames names = CertTools.getGeneralNamesFromExtension(subAltNameExt);
        GeneralName[] gns = names.getNames();
        boolean sanEdited = false;
        ASN1EncodableVector nrOfRecactedLables = new ASN1EncodableVector();
        for (int j = 0; j<gns.length; j++) {
            GeneralName generalName = gns[j];
            // Look for DNS name
            if (generalName.getTagNo() == 2) {
                final String str = CertTools.getGeneralNameString(2, generalName.getName());
                if(StringUtils.contains(str, "(") && StringUtils.contains(str, ")") ) { // if it contains parts that should be redacted
                    // Remove the parentheses from the SubjectAltName that will end up on the certificate
                    String certBuilderDNSValue = StringUtils.remove(str, "dNSName=");
                    certBuilderDNSValue = StringUtils.remove(certBuilderDNSValue, '(');
                    certBuilderDNSValue = StringUtils.remove(certBuilderDNSValue, ')');
                    // Replace the old value with the new
                    gns[j] = new GeneralName(2, new DERIA5String(certBuilderDNSValue));
                    sanEdited = true;
                    if (publishToCT) {
                        String redactedLable = StringUtils.substring(str, StringUtils.indexOf(str, "("), StringUtils.lastIndexOf(str, ")")+1); // tex. (top.secret).domain.se => redactedLable = (top.secret) aka. including the parentheses
                        nrOfRecactedLables.add(new ASN1Integer(StringUtils.countMatches(redactedLable, ".")+1));
                    }
                } else {
                    nrOfRecactedLables.add(new ASN1Integer(0));
                }
            }
            if(generalName.getTagNo() == 1) {
                final String str = CertTools.getGeneralNameString(1, generalName.getName());
                if(StringUtils.contains(str, "\\+") ) { // if it contains a '+' character that should be unescaped
                    // Remove '\' from the email that will end up on the certificate
                    String certBuilderEmailValue = StringUtils.remove(str, "rfc822name=");
                    certBuilderEmailValue = StringUtils.remove(certBuilderEmailValue, '\\');
                    // Replace the old value with the new
                    gns[j] = new GeneralName(1, new DERIA5String(certBuilderEmailValue));
                }
            }
        }
        ExtensionsGenerator gen = new ExtensionsGenerator();
        // Use the GeneralName from original altName in order to not re-encode anything
        gen.addExtension(Extension.subjectAlternativeName, subAltNameExt.isCritical(), new GeneralNames(gns));
        // If there actually are redacted parts, add the extension containing the number of redacted labels to the certificate
        if(publishToCT && sanEdited) {
            ASN1Encodable seq = new DERSequence(nrOfRecactedLables);
            gen.addExtension(new ASN1ObjectIdentifier(CertTools.id_ct_redacted_domains), false, seq);
        }

        return gen;
    }

    /**
     * Constructs the SubjectAlternativeName extension that will end up on the certificate published to a CTLog
     *
     * If the DNS values in the subjectAlternativeName extension contain parentheses to specify labels that should be redacted, these labels will be replaced by the string "PRIVATE"
     *
     * @param subAltNameExt
     * @returnAn extension generator containing the SubjectAlternativeName extension
     * @throws IOException
     */
    protected ExtensionsGenerator getSubjectAltNameExtensionForCTCert(Extension subAltNameExt) throws IOException {
        Pattern parenthesesRegex = Pattern.compile("\\(.*\\)"); // greedy match, so against "(a).(b).example.com" it will match "(a).(b)", like the old code did
        GeneralNames names = CertTools.getGeneralNamesFromExtension(subAltNameExt);
        GeneralName[] gns = names.getNames();
        for (int j = 0; j<gns.length; j++) {
            GeneralName generalName = gns[j];
            // Look for DNS name
            if (generalName.getTagNo() == 2) {
                final String value = DERIA5String.getInstance(generalName.getName()).getString();
                final Matcher matcher = parenthesesRegex.matcher(value);
                if (matcher.find()) {
                    final String newValue = matcher.replaceAll("(PRIVATE)");
                    gns[j] = new GeneralName(2, new DERIA5String(newValue));
                }
            }
            if(generalName.getTagNo() == 1) {
                final String str = CertTools.getGeneralNameString(1, generalName.getName());
                if(StringUtils.contains(str, "\\+") ) { // if it contains a '+' character that should be unescaped
                    // Remove '\' from the email that will end up on the certificate
                    String certBuilderEmailValue = StringUtils.remove(str, "rfc822name=");
                    certBuilderEmailValue = StringUtils.remove(certBuilderEmailValue, '\\');
                    // Replace the old value with the new
                    gns[j] = new GeneralName(1, new DERIA5String(certBuilderEmailValue));
                }
            }
        }

        ExtensionsGenerator gen = new ExtensionsGenerator();
        gen.addExtension(Extension.subjectAlternativeName, subAltNameExt.isCritical(), new GeneralNames(gns));
        return gen;
    }

    /**
     * Generate a CRL or a deltaCRL
     *
     * @param cryptoToken the cryptoToken with keys used to sign the CRL
     * @param certs list of revoked certificates
     * @param crlPeriod the validity period of the generated CRL, the CRLs nextUpdate will be set to (currentTimeMillis + crlPeriod)
     * @param crlnumber CRLNumber for this CRL
     * @param isDeltaCRL true if we should generate a DeltaCRL
     * @param basecrlnumber caseCRLNumber for a delta CRL, use 0 for full CRLs
     * @return X509CRLHolder with the generated CRL
     * @throws CryptoTokenOfflineException
     * @throws IllegalCryptoTokenException
     * @throws IOException
     * @throws SignatureException
     * @throws NoSuchProviderException
     * @throws InvalidKeyException
     * @throws CRLException
     * @throws NoSuchAlgorithmException
     */
    private X509CRLHolder generateCRL(CryptoToken cryptoToken, Collection<RevokedCertInfo> certs, long crlPeriod, int crlnumber, boolean isDeltaCRL, int basecrlnumber)
            throws CryptoTokenOfflineException, IllegalCryptoTokenException, IOException, SignatureException, NoSuchProviderException,
            InvalidKeyException, CRLException, NoSuchAlgorithmException {
        final String sigAlg = getCAInfo().getCAToken().getSignatureAlgorithm();

        if (log.isDebugEnabled()) {
            log.debug("generateCRL(" + certs.size() + ", " + crlPeriod + ", " + crlnumber + ", " + isDeltaCRL + ", " + basecrlnumber);
        }

        // Make DNs
        final X509Certificate cacert = (X509Certificate) getCACertificate();
        final X500Name issuer;
        if (cacert == null) {
            // This is an initial root CA, since no CA-certificate exists
            // (I don't think we can ever get here!!!)
            final X500NameStyle nameStyle;
            if (getUsePrintableStringSubjectDN()) {
                nameStyle = PrintableStringNameStyle.INSTANCE;
            } else {
                nameStyle = CeSecoreNameStyle.INSTANCE;
            }
            issuer = CertTools.stringToBcX500Name(getSubjectDN(), nameStyle, getUseLdapDNOrder());
        } else {
            issuer = X500Name.getInstance(cacert.getSubjectX500Principal().getEncoded());
        }
        final Date thisUpdate = new Date();
        final Date nextUpdate = new Date();
        nextUpdate.setTime(nextUpdate.getTime() + crlPeriod);
        final X509v2CRLBuilder crlgen = new X509v2CRLBuilder(issuer, thisUpdate);
        crlgen.setNextUpdate(nextUpdate);
        if (certs != null) {
            if (log.isDebugEnabled()) {
                log.debug("Adding "+certs.size()+" revoked certificates to CRL. Free memory="+Runtime.getRuntime().freeMemory());
            }
            for (final RevokedCertInfo certinfo : certs) {
                crlgen.addCRLEntry(certinfo.getUserCertificate(), certinfo.getRevocationDate(), certinfo.getReason());
            }
            if (log.isDebugEnabled()) {
                log.debug("Finished adding "+certs.size()+" revoked certificates to CRL. Free memory="+Runtime.getRuntime().freeMemory());
            }
        }


        // Authority key identifier
        if (getUseAuthorityKeyIdentifier() == true) {
            byte[] caSkid = (cacert != null ? CertTools.getSubjectKeyId(cacert) : null);
            if (caSkid != null) {
                // Use subject key id from CA certificate
                AuthorityKeyIdentifier aki = new AuthorityKeyIdentifier(caSkid);
                crlgen.addExtension(Extension.authorityKeyIdentifier, getAuthorityKeyIdentifierCritical(), aki);
            } else {
                JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils(SHA1DigestCalculator.buildSha1Instance());
                AuthorityKeyIdentifier aki = extensionUtils.createAuthorityKeyIdentifier(cryptoToken.getPublicKey(getCAToken().getAliasFromPurpose(
                        CATokenConstants.CAKEYPURPOSE_CRLSIGN)));
                crlgen.addExtension(Extension.authorityKeyIdentifier, getAuthorityKeyIdentifierCritical(), aki);
            }
        }

        // Authority Information Access
        final ASN1EncodableVector accessList = new ASN1EncodableVector();
        if (getAuthorityInformationAccess() != null) {
            for(String url :  getAuthorityInformationAccess()) {
                if(StringUtils.isNotEmpty(url)) {
                    GeneralName accessLocation = new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(url));
                    accessList.add(new AccessDescription(AccessDescription.id_ad_caIssuers, accessLocation));
                }
            }
        }
        if(accessList.size() > 0) {
            AuthorityInformationAccess authorityInformationAccess = AuthorityInformationAccess.getInstance(new DERSequence(accessList));
            // "This CRL extension MUST NOT be marked critical." according to rfc4325
            crlgen.addExtension(Extension.authorityInfoAccess, false, authorityInformationAccess);
        }

        // CRLNumber extension
        if (getUseCRLNumber() == true) {
            CRLNumber crlnum = new CRLNumber(BigInteger.valueOf(crlnumber));
            crlgen.addExtension(Extension.cRLNumber, this.getCRLNumberCritical(), crlnum);
        }

        // ExpiredCertsOnCRL extension (is always specified as not critical)
        // Date format to be used is: yyyyMMddHHmmss
        // https://www.itu.int/ITU-T/formal-language/itu-t/x/x509/2005/CertificateExtensions.html
        //
        // expiredCertsOnCRL EXTENSION ::= {
        //   SYNTAX         ExpiredCertsOnCRL
        //   IDENTIFIED BY  id-ce-expiredCertsOnCRL
        // }
        // ExpiredCertsOnCRL ::= GeneralizedTime
        // The ExpiredCertsOnCRL CRL extension is not specified by IETF-PKIX. It is defined by the ITU-T Recommendation X.509 and
        // indicates that a CRL containing this extension will include revocation status information for certificates that have
        // been already expired. When used, the ExpiredCertsOnCRL contains the date on which the CRL starts to keep revocation
        // status information for expired certificates (i.e. revocation entries are not removed from the CRL for any certificates
        // that expire at or after the date contained in the ExpiredCertsOnCRL extension).
        final ASN1ObjectIdentifier ExpiredCertsOnCRL = new ASN1ObjectIdentifier("2.5.29.60");
        boolean keepexpiredcertsoncrl = getKeepExpiredCertsOnCRL();
        if(keepexpiredcertsoncrl) {
            SimpleDateFormat sdf = new SimpleDateFormat();
            final String GMTdatePattern = "yyyyMMddHHmmss";
            sdf.setTimeZone(new SimpleTimeZone(0, "GMT"));
            sdf.applyPattern(GMTdatePattern);
            // For now force parameter with date equals NotBefore of CA certificate, or now
            final Date keepDate = cacert != null ? cacert.getNotBefore() : new Date();
            crlgen.addExtension(ExpiredCertsOnCRL, false, new DERGeneralizedTime(keepDate));
            if (log.isDebugEnabled()) {
                log.debug("ExpiredCertsOnCRL extension added to CRL. Keep date: "+keepDate);
            }
        }

        if (isDeltaCRL) {
            // DeltaCRLIndicator extension
            CRLNumber basecrlnum = new CRLNumber(BigInteger.valueOf(basecrlnumber));
            crlgen.addExtension(Extension.deltaCRLIndicator, true, basecrlnum);
        }
        // CRL Distribution point URI and Freshest CRL DP
        if (getUseCrlDistributionPointOnCrl()) {
            String crldistpoint = getDefaultCRLDistPoint();
            List<DistributionPoint> distpoints = generateDistributionPoints(crldistpoint);

            if (distpoints.size() > 0) {
                IssuingDistributionPoint idp = new IssuingDistributionPoint(distpoints.get(0).getDistributionPoint(), false, false, null, false,
                        false);

                // According to the RFC, IDP must be a critical extension.
                // Nonetheless, at the moment, Mozilla is not able to correctly
                // handle the IDP extension and discards the CRL if it is critical.
                crlgen.addExtension(Extension.issuingDistributionPoint, getCrlDistributionPointOnCrlCritical(), idp);
            }

            if (!isDeltaCRL) {
                String crlFreshestDP = getCADefinedFreshestCRL();
                List<DistributionPoint> freshestDistPoints = generateDistributionPoints(crlFreshestDP);
                if (freshestDistPoints.size() > 0) {
                    CRLDistPoint ext = new CRLDistPoint(freshestDistPoints.toArray(new DistributionPoint[freshestDistPoints.size()]));

                    // According to the RFC, the Freshest CRL extension on a
                    // CRL must not be marked as critical. Therefore it is
                    // hardcoded as not critical and is independent of
                    // getCrlDistributionPointOnCrlCritical().
                    crlgen.addExtension(Extension.freshestCRL, false, ext);
                }

            }
        }

        final X509CRLHolder crl;
        if (log.isDebugEnabled()) {
            log.debug("Signing CRL. Free memory="+Runtime.getRuntime().freeMemory());
        }
        final String alias = getCAToken().getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CRLSIGN);
        try {
            final ContentSigner signer = new BufferingContentSigner(new JcaContentSignerBuilder(sigAlg).setProvider(cryptoToken.getSignProviderName()).build(cryptoToken.getPrivateKey(alias)), 20480);
            crl = crlgen.build(signer);
        } catch (OperatorCreationException e) {
            // Very fatal error
            throw new RuntimeException("Can not create Jca content signer: ", e);
        }
        if (log.isDebugEnabled()) {
            log.debug("Finished signing CRL. Free memory="+Runtime.getRuntime().freeMemory());
        }

        // Verify using the CA certificate before returning
        // If we can not verify the issued CRL using the CA certificate we don't want to issue this CRL
        // because something is wrong...
        final PublicKey verifyKey;
        if (cacert != null) {
            verifyKey = cacert.getPublicKey();
            if (log.isTraceEnabled()) {
                log.trace("Got the verify key from the CA certificate.");
            }
        } else {
            verifyKey = cryptoToken.getPublicKey(alias);
            if (log.isTraceEnabled()) {
                log.trace("Got the verify key from the CA token.");
            }
        }
        try {
            final ContentVerifierProvider verifier = CertTools.genContentVerifierProvider(verifyKey);
            if (!crl.isSignatureValid(verifier)) {
                throw new SignatureException("Error verifying CRL to be returned.");
            }
        } catch (OperatorCreationException e) {
            // Very fatal error
            throw new RuntimeException("Can not create Jca content signer: ", e);
        } catch (CertException e) {
            throw new SignatureException(e.getMessage(), e);
        }
        if (log.isDebugEnabled()) {
            log.debug("Returning CRL. Free memory="+Runtime.getRuntime().freeMemory());
        }
        return crl;
    }

    /**
     * Generate a list of Distribution points.
     *
     * @param distPoints
     *            distribution points as String in semi column (';') separated format.
     * @return list of distribution points.
     */
    private List<DistributionPoint> generateDistributionPoints(String distPoints) {
        // Multiple CDPs are separated with the ';' sign
        ArrayList<DistributionPoint> result = new ArrayList<>();
        for (final String uri : StringTools.splitURIs(StringUtils.defaultString(distPoints))) {
            GeneralName gn = new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(uri));
            if (log.isDebugEnabled()) {
                log.debug("Added CRL distpoint: " + uri);
            }
            ASN1EncodableVector vec = new ASN1EncodableVector();
            vec.add(gn);
            GeneralNames gns = GeneralNames.getInstance(new DERSequence(vec));
            DistributionPointName dpn = new DistributionPointName(0, gns);
            result.add(new DistributionPoint(dpn, null, null));
        }
        return result;
    }

    /** Implementation of UpgradableDataHashMap function getLatestVersion */
    @Override
    public float getLatestVersion() {
        return LATEST_VERSION;
    }

    /**
     * Implementation of UpgradableDataHashMap function upgrade.
     */
    @Override
    @SuppressWarnings("deprecation")
    public void upgrade() {
        if (Float.compare(LATEST_VERSION, getVersion()) != 0) {
            // New version of the class, upgrade
            log.info("Upgrading X509CA with version " + getVersion());
            if (data.get(DEFAULTOCSPSERVICELOCATOR) == null) {
                setDefaultCRLDistPoint("");
                setDefaultOCSPServiceLocator("");
            }
            if (data.get(CRLISSUEINTERVAL) == null) {
                setCRLIssueInterval(0);
            }
            if (data.get(CRLOVERLAPTIME) == null) {
                // Default value 10 minutes
                // This used to be setting of 10, as an Integer, but was refactored to a long (ms) in v18->19, 
                // therefore we have to update this to reflect that as well. If's probably not hurting anyone here, it's too old, but right is right.
                setCRLOverlapTime(10 * SimpleTime.MILLISECONDS_PER_MINUTE);
            }
            boolean useprintablestring = true;
            if (data.get("alwaysuseutf8subjectdn") == null) {
                // Default value false
                if (data.get(USEUTF8POLICYTEXT) == null) {
                    setUseUTF8PolicyText(false);
                }
            } else {
                // Use the same value as we had before when we had alwaysuseutf8subjectdn
                boolean useutf8 = ((Boolean) data.get("alwaysuseutf8subjectdn")).booleanValue();
                if (data.get(USEUTF8POLICYTEXT) == null) {
                    setUseUTF8PolicyText(useutf8);
                }
                // If we had checked to use utf8 on an old CA, we do not want to use PrintableString after upgrading
                useprintablestring = !useutf8;
            }
            if (data.get(USEPRINTABLESTRINGSUBJECTDN) == null) {
                // Default value true (as before)
                setUsePrintableStringSubjectDN(useprintablestring);
            }
            if (data.get(DEFAULTCRLISSUER) == null) {
                setDefaultCRLIssuer(null);
            }
            if (data.get(USELDAPDNORDER) == null) {
                setUseLdapDNOrder(true); // Default value
            }
            if (data.get(DELTACRLPERIOD) == null) {
                setDeltaCRLPeriod(0); // v14
            }
            if (data.get(USECRLDISTRIBUTIONPOINTONCRL) == null) {
                setUseCrlDistributionPointOnCrl(false); // v15
            }
            if (data.get(CRLDISTRIBUTIONPOINTONCRLCRITICAL) == null) {
                setCrlDistributionPointOnCrlCritical(false); // v15
            }
            if (data.get(INCLUDEINHEALTHCHECK) == null) {
                setIncludeInHealthCheck(true); // v16
            }
            // v17->v18 is only an upgrade in order to upgrade CA token
            // v18->v19
            Object o = data.get(CRLPERIOD);
            if (o instanceof Integer) {
                setCRLPeriod(((Integer) o).longValue() * SimpleTime.MILLISECONDS_PER_HOUR); // h to ms
            }
            o = data.get(CRLISSUEINTERVAL);
            if (o instanceof Integer) {
                setCRLIssueInterval(((Integer) o).longValue() * SimpleTime.MILLISECONDS_PER_HOUR); // h to ms
            }
            o = data.get(CRLOVERLAPTIME);
            if (o instanceof Integer) {
                setCRLOverlapTime(((Integer) o).longValue() * SimpleTime.MILLISECONDS_PER_MINUTE); // min to ms
            }
            o = data.get(DELTACRLPERIOD);
            if (o instanceof Integer) {
                setDeltaCRLPeriod(((Integer) o).longValue() * SimpleTime.MILLISECONDS_PER_HOUR); // h to ms
            }
            // v20, remove XKMS CA service
            if (data.get(EXTENDEDCASERVICES) != null) {
                @SuppressWarnings("unchecked")
                Collection<Integer> types = (Collection<Integer>)data.get(EXTENDEDCASERVICES);
                // Remove type 2, which is XKMS
                types.remove(Integer.valueOf(2));
                data.put(EXTENDEDCASERVICES, types);
                // Remove any data if it exists
                data.remove(EXTENDEDCASERVICE+2);
            }
            if (data.get(NAMECHANGED) == null) {
                setNameChanged(false);
            }
            // v21, AIA: Copy CA issuer URI to separated AIA field.
            if (data.get(CERTIFICATE_AIA_DEFAULT_CA_ISSUER_URI) == null) {
            	if (null != getAuthorityInformationAccess()) {
            	    setCertificateAiaDefaultCaIssuerUri( getAuthorityInformationAccess());
            	} else {
            		setCertificateAiaDefaultCaIssuerUri( new ArrayList<String>());
            	}
            }
            // v22, 'encodedValidity' is derived by the former long value!
            if (null == data.get(ENCODED_VALIDITY)  && null != data.get(VALIDITY)) {
                setEncodedValidity(getEncodedValidity());
            }
            // v23 'keyValidators' new empty list.
            if (null == data.get(VALIDATORS)) {
                setValidators(new ArrayList<Integer>());
            }

            data.put(VERSION, new Float(LATEST_VERSION));
        }
    }

    /**
     * Method to upgrade new (or existing external caservices) This method needs to be called outside the regular upgrade since the CA isn't
     * instantiated in the regular upgrade.
     */
    @SuppressWarnings({ "rawtypes", "deprecation" })
    @Override
    public boolean upgradeExtendedCAServices() {
        boolean retval = false;
        // call upgrade, if needed, on installed CA services
        Collection<Integer> externalServiceTypes = getExternalCAServiceTypes();
        if (!CesecoreConfiguration.getCaKeepOcspExtendedService() && externalServiceTypes.contains(ExtendedCAServiceTypes.TYPE_OCSPEXTENDEDSERVICE)) {
            //This type has been removed, so remove it from any CAs it's been added to as well.
            externalServiceTypes.remove(ExtendedCAServiceTypes.TYPE_OCSPEXTENDEDSERVICE);
            data.put(EXTENDEDCASERVICES, externalServiceTypes);
            retval = true;
        }

        for (Integer type : externalServiceTypes) {
            ExtendedCAService service = getExtendedCAService(type);
            if (service != null) {
                if (Float.compare(service.getLatestVersion(), service.getVersion()) != 0) {
                    retval = true;
                    service.upgrade();
                    setExtendedCAServiceData(service.getExtendedCAServiceInfo().getType(), (HashMap) service.saveData());
                } else if (service.isUpgraded()) {
                    // Also return true if the service was automatically upgraded by a UpgradeableDataHashMap.load, which calls upgrade automagically.
                    retval = true;
                    setExtendedCAServiceData(service.getExtendedCAServiceInfo().getType(), (HashMap) service.saveData());
                }
            } else {
                log.error("Extended service is null, can not upgrade service of type: " + type);
            }
        }
        return retval;
    }

    /**
     * Encryption method used to encrypt a key pair using a CA
     *
     * @param cryptoToken the crypto token where the encryption key is
     * @param alias the alias of the key on the crypto token to use for encryption
     * @param keypair the data to encrypt
     * @return encrypted data
     * @throws CryptoTokenOfflineException If crypto token is off-line so encryption key can not be used.
     */
    public static byte[] encryptKeys(final CryptoToken cryptoToken, final String alias, final KeyPair keypair) throws CryptoTokenOfflineException {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutputStream os = new ObjectOutputStream(baos);
            os.writeObject(keypair);
            CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();
            CMSEnvelopedData ed;
            // Creating the KeyId may just throw an exception, we will log this but store the cert and ignore the error
            final PublicKey pk = cryptoToken.getPublicKey(alias);
            byte[] keyId = KeyTools.createSubjectKeyId(pk).getKeyIdentifier();
            edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(keyId, pk));
            JceCMSContentEncryptorBuilder jceCMSContentEncryptorBuilder = new JceCMSContentEncryptorBuilder(NISTObjectIdentifiers.id_aes256_CBC).setProvider(BouncyCastleProvider.PROVIDER_NAME);
            ed = edGen.generate(new CMSProcessableByteArray(baos.toByteArray()), jceCMSContentEncryptorBuilder.build());
            log.info("Encrypted keys using key alias '"+alias+"' from Crypto Token "+cryptoToken.getId());
            return ed.getEncoded();
        } catch (IOException | CMSException e) {
            throw new IllegalStateException("Failed to encrypt keys: " + e.getMessage(), e);
        }
    }

    /**
     * Decryption method used to decrypt a key pair using a CA
     *
     * @param cryptoToken the crypto token where the decryption key is
     * @param alias the alias of the key on the crypto token to use for decryption
     * @param data the data to decrypt
     * @return a KeyPair
     * @throws CryptoTokenOfflineException If crypto token is off-line so decryption key can not be used.
     * @throws IOException In case reading/writing data streams failed during decryption, or parsing decrypted data into KeyPair.
     */
    public static KeyPair decryptKeys(final CryptoToken cryptoToken, final String alias, final byte[] data) throws IOException, CryptoTokenOfflineException {
        try {
            CMSEnvelopedData ed = new CMSEnvelopedData(data);
            RecipientInformationStore recipients = ed.getRecipientInfos();
            RecipientInformation recipient = recipients.getRecipients().iterator().next();
            ObjectInputStream ois = null;
            JceKeyTransEnvelopedRecipient rec = new JceKeyTransEnvelopedRecipient(cryptoToken.getPrivateKey(alias));
            rec.setProvider(cryptoToken.getEncProviderName());
            rec.setContentProvider(BouncyCastleProvider.PROVIDER_NAME);
            // Option we must set to prevent Java PKCS#11 provider to try to make the symmetric decryption in the HSM,
            // even though we set content provider to BC. Symm decryption in HSM varies between different HSMs and at least for this case is known
            // to not work in SafeNet Luna (JDK behavior changed in JDK 7_75 where they introduced imho a buggy behavior)
            rec.setMustProduceEncodableUnwrappedKey(true);
            byte[] recdata = recipient.getContent(rec);
            ois = new ObjectInputStream(new ByteArrayInputStream(recdata));
            log.info("Decrypted keys using key alias '"+alias+"' from Crypto Token "+cryptoToken.getId());
            return (KeyPair) ois.readObject();
        } catch (ClassNotFoundException e) {
            throw new IOException("Could not deserialize key pair after decrypting it due to missing class: " + e.getMessage(), e);
        } catch (CMSException e) {
            throw new IOException("Could not parse encrypted data: " + e.getMessage(), e);
        }
    }

    @Override
    public byte[] decryptData(CryptoToken cryptoToken, byte[] data, int cAKeyPurpose) throws CMSException, CryptoTokenOfflineException {
        CMSEnvelopedData ed = new CMSEnvelopedData(data);
        RecipientInformationStore recipients = ed.getRecipientInfos();
        RecipientInformation recipient = recipients.getRecipients().iterator().next();
        final String keyAlias = getCAToken().getAliasFromPurpose(cAKeyPurpose);
        JceKeyTransEnvelopedRecipient rec = new JceKeyTransEnvelopedRecipient(cryptoToken.getPrivateKey(keyAlias));
        rec.setProvider(cryptoToken.getSignProviderName());
        rec.setContentProvider(BouncyCastleProvider.PROVIDER_NAME);
        // Option we must set to prevent Java PKCS#11 provider to try to make the symmetric decryption in the HSM,
        // even though we set content provider to BC. Symm decryption in HSM varies between different HSMs and at least for this case is known
        // to not work in SafeNet Luna (JDK behavior changed in JDK 7_75 where they introduced imho a buggy behavior)
        rec.setMustProduceEncodableUnwrappedKey(true);
        byte[] recdata = recipient.getContent(rec);
        log.info("Decrypted data using key alias '"+keyAlias+"' from Crypto Token "+cryptoToken.getId());
        return recdata;
    }

    @Override
    public byte[] encryptData(CryptoToken cryptoToken, byte[] data, int keyPurpose) throws IOException, CMSException, CryptoTokenOfflineException, NoSuchAlgorithmException, NoSuchProviderException {
        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();
        CMSEnvelopedData ed;
        final String keyAlias = getCAToken().getAliasFromPurpose(keyPurpose);
        final PublicKey pk = cryptoToken.getPublicKey(keyAlias);
        byte[] keyId = KeyTools.createSubjectKeyId(pk).getKeyIdentifier();
        edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(keyId, pk));
        JceCMSContentEncryptorBuilder jceCMSContentEncryptorBuilder = new JceCMSContentEncryptorBuilder(NISTObjectIdentifiers.id_aes256_CBC).setProvider(BouncyCastleProvider.PROVIDER_NAME);
        ed = edGen.generate(new CMSProcessableByteArray(data), jceCMSContentEncryptorBuilder.build());
        log.info("Encrypted data using key alias '"+keyAlias+"' from Crypto Token "+cryptoToken.getId());
        return ed.getEncoded();
    }
}
