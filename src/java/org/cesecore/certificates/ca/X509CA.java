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
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuingDistributionPoint;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509DefaultEntryConverter;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509ExtensionsGenerator;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.asn1.x509.X509NameEntryConverter;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.x509.X509V2CRLGenerator;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.ca.catoken.CATokenInfo;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAService;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
import org.cesecore.certificates.ca.internal.CertificateValidity;
import org.cesecore.certificates.ca.internal.SernoGeneratorRandom;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.certextensions.CertificateExtension;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionFactory;
import org.cesecore.certificates.certificateprofile.CertificatePolicy;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.dn.PrintableStringEntryConverter;
import org.cesecore.internal.InternalResources;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.IllegalCryptoTokenException;
import org.cesecore.keys.token.NullCryptoToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.SimpleTime;
import org.cesecore.util.StringTools;

/**
 * X509CA is a implementation of a CA and holds data specific for Certificate and CRL generation according to the X509 standard.
 * 
 * Based on EJBCA version: X509CA.java 11112 2011-01-09 16:17:33Z anatom
 * 
 * @version $Id$
 */
public class X509CA extends CA implements Serializable {

    private static final long serialVersionUID = -2882572653108530258L;

    private static final Logger log = Logger.getLogger(X509CA.class);

    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    /** Version of this class, if this is increased the upgrade() method will be called automatically */
    public static final float LATEST_VERSION = 19;

    /** key ID used for identifier of key used for key recovery encryption */
    private byte[] keyId = new byte[] { 1, 2, 3, 4, 5 };

    // protected fields for properties specific to this type of CA.
    protected static final String POLICIES = "policies";
    protected static final String SUBJECTALTNAME = "subjectaltname";
    protected static final String USEAUTHORITYKEYIDENTIFIER = "useauthoritykeyidentifier";
    protected static final String AUTHORITYKEYIDENTIFIERCRITICAL = "authoritykeyidentifiercritical";
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

    // Public Methods
    /** Creates a new instance of CA, this constructor should be used when a new CA is created */
    public X509CA(final X509CAInfo cainfo) {
        super(cainfo);

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
        setCmpRaAuthSecret(cainfo.getCmpRaAuthSecret());
        data.put(CA.CATYPE, Integer.valueOf(CAInfo.CATYPE_X509));
        data.put(VERSION, new Float(LATEST_VERSION));
    }

    /**
     * Constructor used when retrieving existing X509CA from database.
     * 
     * @throws IllegalCryptoTokenException
     */
    public X509CA(final HashMap<Object, Object> data, final int caId, final String subjectDN, final String name, final int status,
            final Date updateTime, final Date expireTime) throws IllegalCryptoTokenException {
        super(data);
        setExpireTime(expireTime); // Make sure the internal state is synched with the database column. Required for upgrades from EJBCA 3.5.6 or
                                   // EJBCA 3.6.1 and earlier.
        ArrayList<ExtendedCAServiceInfo> externalcaserviceinfos = new ArrayList<ExtendedCAServiceInfo>();
        Iterator<Integer> iter = getExternalCAServiceTypes().iterator();
        while (iter.hasNext()) {
            ExtendedCAServiceInfo info = this.getExtendedCAServiceInfo(iter.next().intValue());
            if (info != null) {
                externalcaserviceinfos.add(info);
            }
        }
        CAInfo info = new X509CAInfo(subjectDN, name, status, updateTime, getSubjectAltName(), getCertificateProfileId(), getValidity(),
                getExpireTime(), getCAType(), getSignedBy(), getCertificateChain(), getCAToken(caId).getTokenInfo(), getDescription(),
                getRevocationReason(), getRevocationDate(), getPolicies(), getCRLPeriod(), getCRLIssueInterval(), getCRLOverlapTime(),
                getDeltaCRLPeriod(), getCRLPublishers(), getUseAuthorityKeyIdentifier(), getAuthorityKeyIdentifierCritical(), getUseCRLNumber(),
                getCRLNumberCritical(), getDefaultCRLDistPoint(), getDefaultCRLIssuer(), getDefaultOCSPServiceLocator(), getCADefinedFreshestCRL(),
                getFinishUser(), externalcaserviceinfos, getUseUTF8PolicyText(), getApprovalSettings(), getNumOfRequiredApprovals(),
                getUsePrintableStringSubjectDN(), getUseLdapDNOrder(), getUseCrlDistributionPointOnCrl(), getCrlDistributionPointOnCrlCritical(),
                getIncludeInHealthCheck(), isDoEnforceUniquePublicKeys(), isDoEnforceUniqueDistinguishedName(),
                isDoEnforceUniqueSubjectDNSerialnumber(), isUseCertReqHistory(), isUseUserStorage(), isUseCertificateStorage(), getCmpRaAuthSecret());
        super.setCAInfo(info);
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

    public String getCmpRaAuthSecret() {
        Object o = data.get(CMPRAAUTHSECRET);
        if (o == null) {
            // Default to empty value if it is not set. An empty value will be denied by CRMFMessageHandler
            return "";
        }
        return (String) o;
    }

    public void setCmpRaAuthSecret(String cmpRaAuthSecret) {
        data.put(CMPRAAUTHSECRET, cmpRaAuthSecret);
    }

    public void updateCA(CAInfo cainfo) throws IllegalCryptoTokenException {
        super.updateCA(cainfo);
        X509CAInfo info = (X509CAInfo) cainfo;

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
    }

    public byte[] createPKCS7(Certificate cert, boolean includeChain) throws SignRequestSignatureException {
        // First verify that we signed this certificate
        try {
            if (cert != null) {
                cert.verify(getCAToken().getPublicKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
            }
        } catch (Exception e) {
            throw new SignRequestSignatureException("Cannot verify certificate in createPKCS7(), did I sign this?");
        }
        Collection<Certificate> chain = getCertificateChain();
        ArrayList<Certificate> certList = new ArrayList<Certificate>();
        if (cert != null) {
            certList.add(cert);
        }
        if (includeChain) {
            certList.addAll(chain);
        }
        try {
            CMSProcessable msg = new CMSProcessableByteArray("EJBCA".getBytes());
            CertStore certs = CertStore.getInstance("Collection", new CollectionCertStoreParameters(certList), "BC");
            CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
            if (getCAToken().getPrivateKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN) == null) {
                String msg1 = "createPKCS7: Private key does not exist!";
                log.debug(msg1);
                throw new SignRequestSignatureException(msg1);
            }
            gen.addSigner(getCAToken().getPrivateKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN), (X509Certificate) getCACertificate(),
                    CMSSignedGenerator.DIGEST_SHA1);
            gen.addCertificatesAndCRLs(certs);
            CMSSignedData s = null;
            CAToken catoken = getCAToken();
            CATokenInfo tokeninfo = getCAInfo().getCATokenInfo();
            if (catoken != null && !StringUtils.equals(NullCryptoToken.class.getName(), tokeninfo.getClass().getName())) {
                log.debug("createPKCS7: Provider=" + catoken.getCryptoToken().getSignProviderName() + " using algorithm "
                        + getCAToken().getPrivateKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN).getAlgorithm());
                s = gen.generate(msg, true, catoken.getCryptoToken().getSignProviderName());
            } else {
                String msg1 = "CA Token does not exist!";
                log.debug(msg);
                throw new SignRequestSignatureException(msg1);
            }
            return s.getEncoded();
        } catch (CryptoTokenOfflineException e) {
            throw new RuntimeException(e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * @see CA#createRequest(Collection, String, Certificate, int)
     */
    public byte[] createRequest(Collection<DEREncodable> attributes, String signAlg, Certificate cacert, int signatureKeyPurpose)
            throws CryptoTokenOfflineException {
        log.trace(">createRequest: " + signAlg + ", " + CertTools.getSubjectDN(cacert) + ", " + signatureKeyPurpose);
        ASN1Set attrset = new DERSet();
        if (attributes != null) {
            log.debug("Adding attributes in the request");
            Iterator<DEREncodable> iter = attributes.iterator();
            ASN1EncodableVector vec = new ASN1EncodableVector();
            while (iter.hasNext()) {
                DEREncodable o = (DEREncodable) iter.next();
                vec.add(o);
            }
            attrset = new DERSet(vec);
        }
        X509NameEntryConverter converter = null;
        if (getUsePrintableStringSubjectDN()) {
            converter = new PrintableStringEntryConverter();
        } else {
            converter = new X509DefaultEntryConverter();
        }
        X509Name x509dn = CertTools.stringToBcX509Name(getSubjectDN(), converter, getUseLdapDNOrder());
        PKCS10CertificationRequest req;
        try {
            CAToken catoken = getCAToken();
            KeyPair keyPair = new KeyPair(catoken.getPublicKey(signatureKeyPurpose), catoken.getPrivateKey(signatureKeyPurpose));
            req = new PKCS10CertificationRequest(signAlg, x509dn, keyPair.getPublic(), attrset, keyPair.getPrivate(), catoken.getCryptoToken().getSignProviderName());
            log.trace("<createRequest");
            return req.getEncoded();
        } catch (CryptoTokenOfflineException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * If request is an CA certificate, useprevious==true and createlinkcert==true it returns a new certificate signed with the CAs keys. This can be
     * used to create a NewWithOld certificate for CA key rollover. This method can only create a self-signed certificate and only uses the public key
     * from the passed in certificate. If the passed in certificate is not signed by the CAs signature key and does not have the same DN as the
     * current CA, null certificate is returned. This is because we do not want to create anything else than a NewWithOld certificate, because that
     * would be a security risk. Regular certificates must be issued using createCertificate.
     * 
     * Note: Creating the NewWithOld will only work correctly for Root CAs.
     * 
     * If request is a CSR (pkcs10) it returns null.
     * 
     * @param usepreviouskey
     *            must be trust otherwise null is returned, this is because this method on an X509CA should only be used to create a NewWithOld.
     * 
     * @see CA#signRequest(Collection, String)
     */
    public byte[] signRequest(byte[] request, boolean usepreviouskey, boolean createlinkcert) throws CryptoTokenOfflineException {
        byte[] ret = null;
        try {
            CAToken catoken = getCAToken();
            byte[] binbytes = request;
            X509Certificate cert = null;
            try {
                // We don't know if this is a PEM or binary certificate so we first try to
                // decode it as a PEM certificate, and if it's not we try it as a binary certificate
                Collection<Certificate> col = CertTools.getCertsFromPEM(new ByteArrayInputStream(request));
                cert = (X509Certificate) col.iterator().next();
                if (cert != null) {
                    binbytes = cert.getEncoded();
                }
            } catch (Exception e) {
                log.debug("This is not a PEM certificate?: " + e.getMessage());
            }
            cert = (X509Certificate) CertTools.getCertfromByteArray(binbytes);
            // Check if the input was a CA certificate, which is the same CA as this. If all is true we should create a NewWithOld link-certificate
            X509Certificate cacert = (X509Certificate) getCACertificate();
            if (CertTools.getSubjectDN(cert).equals(CertTools.getSubjectDN(cacert))) {
                PublicKey currentCaPublicKey = catoken.getPublicKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN);
                cert.verify(currentCaPublicKey); // Throws SignatureException if verify fails
                if (createlinkcert && usepreviouskey) {
                    log.debug("We will create a link certificate.");
                    X509CAInfo info = (X509CAInfo) getCAInfo();
                    EndEntityInformation cadata = new EndEntityInformation("nobody", info.getSubjectDN(), info.getSubjectDN().hashCode(), info.getSubjectAltName(), null,
                            0, 0, 0, info.getCertificateProfileId(), null, null, 0, 0, null);

                    CertificateProfile certProfile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA);
                    if ((info.getPolicies() != null) && (info.getPolicies().size() > 0)) {
                        certProfile.setUseCertificatePolicies(true);
                        certProfile.setCertificatePolicies(info.getPolicies());
                    }
                    PublicKey previousCaPublicKey = catoken.getPublicKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN_PREVIOUS);
                    PrivateKey previousCaPrivateKey = catoken.getPrivateKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN_PREVIOUS);
                    String provider = catoken.getCryptoToken().getSignProviderName();
                    String sequence = catoken.getKeySequence(); // get from CAtoken to make sure it is fresh
                    Certificate retcert = generateCertificate(cadata, null, cert.getPublicKey(), -1, cert.getNotBefore(), cert.getNotAfter(),
                            certProfile, null, sequence, previousCaPublicKey, previousCaPrivateKey, provider);
                    log.debug("Signed an X509Certificate: '" + cadata.getDN() + "'.");
                    String msg = intres.getLocalizedMessage("cvc.info.createlinkcert", cadata.getDN(), cadata.getDN());
                    log.info(msg);
                    ret = retcert.getEncoded();
                } else {
                    log.debug("Not signing any certificate, useprevious=" + usepreviouskey + ", createlinkcert=" + createlinkcert);
                }
            } else {
                log.debug("Not signing any certificate, certSubjectDN != cacertSubjectDN.");
            }

        } catch (IllegalCryptoTokenException e) {
            throw new javax.ejb.EJBException(e);
        } catch (SignatureException e) {
            log.debug("Not signing any certificate, input certificate did not verify with current CA signing key.");
            // Will return request as it was
        } catch (CertificateException e) {
            log.debug("Not signing any certificate, input was not a certificate.");
            // It was not a certificate, will return request as it was
        } catch (Exception e) {
            throw new javax.ejb.EJBException(e);
        }
        return ret;
    }

    @Override
    public Certificate generateCertificate(EndEntityInformation subject, X509Name requestX509Name, PublicKey publicKey, int keyusage, Date notBefore,
            Date notAfter, CertificateProfile certProfile, X509Extensions extensions, String sequence) throws Exception {
        // Before we start, check if the CA is off-line, we don't have to waste time
        // one the stuff below of we are off-line. The line below will throw CryptoTokenOfflineException of CA is offline
        CAToken catoken = getCAToken();
        PublicKey caPublicKey = catoken.getPublicKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN);
        PrivateKey caPrivateKey = catoken.getPrivateKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN);
        String provider = catoken.getCryptoToken().getSignProviderName();
        return generateCertificate(subject, requestX509Name, publicKey, keyusage, notBefore, notAfter, certProfile, extensions, sequence,
                caPublicKey, caPrivateKey, provider);
    }

    /**
     * sequence is ignored by X509CA
     */
    private Certificate generateCertificate(EndEntityInformation subject, X509Name requestX509Name, PublicKey publicKey, int keyusage, Date notBefore,
            Date notAfter, CertificateProfile certProfile, X509Extensions extensions, String sequence, PublicKey caPublicKey,
            PrivateKey caPrivateKey, String provider) throws Exception {

        // We must only allow signing to take place if the CA itself is on line, even if the token is on-line.
        // We have to allow expired as well though, so we can renew expired CAs
        if ((getStatus() != CAConstants.CA_ACTIVE) && ((getStatus() != CAConstants.CA_EXPIRED))) {
            final String msg = intres.getLocalizedMessage("error.caoffline", getName(), getStatus());
            if (log.isDebugEnabled()) {
                log.debug(msg); // This is something we handle so no need to log with higher priority
            }
            throw new CAOfflineException(msg);
        }

        final String sigAlg;
        if (certProfile.getSignatureAlgorithm() == null) {
            sigAlg = getCAInfo().getCATokenInfo().getSignatureAlgorithm();
        } else {
            sigAlg = certProfile.getSignatureAlgorithm();
        }
        // Check that the signature algorithm is one of the allowed ones
        if (!ArrayUtils.contains(AlgorithmConstants.AVAILABLE_SIGALGS, sigAlg)) {
            final String msg = intres.getLocalizedMessage("createcert.invalidsignaturealg", sigAlg);
            throw new InvalidAlgorithmException(msg);        	
        }
        final X509Certificate cacert = (X509Certificate) getCACertificate();
        String dn = subject.getCertificateDN();
        // Check if this is a root CA we are creating
        final boolean isRootCA = certProfile.getType() == CertificateConstants.CERTTYPE_ROOTCA;

        // Get certificate validity time notBefore and notAfter
        final CertificateValidity val = new CertificateValidity(subject, certProfile, notBefore, notAfter, cacert, isRootCA);

        final X509V3CertificateGenerator certgen = new X509V3CertificateGenerator();
        {
            // Serialnumber is either random bits, where random generator is initialized by the serno generator.
            // Or a custom serial number defined in the end entity object
            final ExtendedInformation ei = subject.getExtendedinformation();
            BigInteger customSN = ei != null ? ei.certificateSerialNumber() : null;
            if (customSN != null) {
                if (!certProfile.getAllowCertSerialNumberOverride()) {
                    final String msg = intres.getLocalizedMessage("createcert.certprof_not_allowing_cert_sn_override_using_normal",
                            customSN.toString(16));
                    log.info(msg);
                    customSN = null;
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("Using custom serial number: " + customSN.toString(16));
                    }
                }
            }
            final BigInteger serno = customSN != null ? customSN : SernoGeneratorRandom.instance().getSerno();
            certgen.setSerialNumber(serno);
        }
        certgen.setNotBefore(val.getNotBefore());
        certgen.setNotAfter(val.getNotAfter());
        certgen.setSignatureAlgorithm(sigAlg);

        // Make DNs
        if (certProfile.getUseSubjectDNSubSet()) {
            dn = certProfile.createSubjectDNSubSet(dn);
        }

        if (certProfile.getUseCNPostfix()) {
            dn = CertTools.insertCNPostfix(dn, certProfile.getCNPostfix());
        }

        X509NameEntryConverter converter = null;
        if (getUsePrintableStringSubjectDN()) {
            converter = new PrintableStringEntryConverter();
        } else {
            converter = new X509DefaultEntryConverter();
        }
        // Will we use LDAP DN order (CN first) or X500 DN order (CN last) for the subject DN
        boolean ldapdnorder = true;
        if ((getUseLdapDNOrder() == false) || (certProfile.getUseLdapDnOrder() == false)) {
            ldapdnorder = false;
        }
        X509Name subjectDNName = CertTools.stringToBcX509Name(dn, converter, ldapdnorder);
        if (certProfile.getAllowDNOverride() && (requestX509Name != null)) {
            subjectDNName = requestX509Name;
            if (log.isDebugEnabled()) {
                log.debug("Using X509Name from request instead of user's registered.");
            }
        }
        // Make sure the DN does not contain dangerous characters
        if (StringTools.hasStripChars(subjectDNName.toString())) {
            if (log.isTraceEnabled()) {
            	log.trace("DN with illegal name: "+subjectDNName);
            }
            final String msg = intres.getLocalizedMessage("createcert.illegalname");
        	throw new IllegalNameException(msg);
        }
        if (log.isDebugEnabled()) {
            log.debug("Using subjectDN: " + subjectDNName.toString());
        }
        certgen.setSubjectDN(subjectDNName);
        // We must take the issuer DN directly from the CA-certificate otherwise we risk re-ordering the DN
        // which many applications do not like.
        if (isRootCA) {
            // This will be an initial root CA, since no CA-certificate exists
            // Or it is a root CA, since the cert is self signed. If it is a root CA we want to use the same encoding for subject and issuer,
            // it might have changed over the years.
            if (log.isDebugEnabled()) {
                log.debug("Using subject DN also as issuer DN, because it is a root CA");
            }
            certgen.setIssuerDN(subjectDNName);
        } else {
            javax.security.auth.x500.X500Principal issuerPrincipal = cacert.getSubjectX500Principal();
            if (log.isDebugEnabled()) {
                log.debug("Using issuer DN directly from the CA certificate: " + issuerPrincipal.getName());
            }
            certgen.setIssuerDN(issuerPrincipal);
        }
        certgen.setPublicKey(publicKey);

        //
        // X509 Certificate Extensions
        //

        // Extensions we will add to the certificate, later when we have filled the structure with
        // everything we want.
        X509ExtensionsGenerator extgen = new X509ExtensionsGenerator();

        // First we check if there is general extension override, and add all extensions from
        // the request in that case
        if (certProfile.getAllowExtensionOverride() && extensions != null) {
            @SuppressWarnings("rawtypes")
            Enumeration en = extensions.oids();
            while (en != null && en.hasMoreElements()) {
                DERObjectIdentifier oid = (DERObjectIdentifier) en.nextElement();
                X509Extension ext = extensions.getExtension(oid);
                if (log.isDebugEnabled()) {
                    log.debug("Overriding extension with oid: " + oid);
                }
                extgen.addExtension(oid, ext.isCritical(), ext.getValue().getOctets());
            }
        }

        // Second we see if there is Key usage override
        X509Extensions overridenexts = extgen.generate();
        if (certProfile.getAllowKeyUsageOverride() && (keyusage >= 0)) {
            if (log.isDebugEnabled()) {
                log.debug("AllowKeyUsageOverride=true. Using KeyUsage from parameter: " + keyusage);
            }
            if ((certProfile.getUseKeyUsage() == true) && (keyusage >= 0)) {
                X509KeyUsage ku = new X509KeyUsage(keyusage);
                // We don't want to try to add custom extensions with the same oid if we have already added them
                // from the request, if AllowExtensionOverride is enabled.
                // Two extensions with the same oid is not allowed in the standard.
                if (overridenexts.getExtension(X509Extensions.KeyUsage) == null) {
                    extgen.addExtension(X509Extensions.KeyUsage, certProfile.getKeyUsageCritical(), ku);
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
        CertificateExtensionFactory fact = CertificateExtensionFactory.getInstance();
        List<String> usedStdCertExt = certProfile.getUsedStandardCertificateExtensions();
        Iterator<String> certStdExtIter = usedStdCertExt.iterator();
        overridenexts = extgen.generate();
        while (certStdExtIter.hasNext()) {
            String oid = certStdExtIter.next();
            // We don't want to try to add standard extensions with the same oid if we have already added them
            // from the request, if AllowExtensionOverride is enabled.
            // Two extensions with the same oid is not allowed in the standard.
            if (overridenexts.getExtension(new DERObjectIdentifier(oid)) == null) {
                CertificateExtension certExt = fact.getStandardCertificateExtension(oid, certProfile);
                if (certExt != null) {
                    byte[] value = certExt.getValueEncoded(subject, this, certProfile, publicKey, caPublicKey);
                    if (value != null) {
                        extgen.addExtension(new DERObjectIdentifier(certExt.getOID()), certExt.isCriticalFlag(), value);
                    }
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Extension with oid " + oid + " has been overridden, standard extension will not be added.");
                }
            }
        }

        // Fourth, check for custom Certificate Extensions that should be added.
        // Custom certificate extensions is defined in certextensions.properties
        fact = CertificateExtensionFactory.getInstance();
        List<Integer> usedCertExt = certProfile.getUsedCertificateExtensions();
        Iterator<Integer> certExtIter = usedCertExt.iterator();
        while (certExtIter.hasNext()) {
            Integer id = certExtIter.next();
            CertificateExtension certExt = fact.getCertificateExtensions(id);
            if (certExt != null) {
                // We don't want to try to add custom extensions with the same oid if we have already added them
                // from the request, if AllowExtensionOverride is enabled.
                // Two extensions with the same oid is not allowed in the standard.
                if (overridenexts.getExtension(new DERObjectIdentifier(certExt.getOID())) == null) {
                    byte[] value = certExt.getValueEncoded(subject, this, certProfile, publicKey, caPublicKey);
                    if (value != null) {
                        extgen.addExtension(new DERObjectIdentifier(certExt.getOID()), certExt.isCriticalFlag(), value);
                    }
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("Extension with oid " + certExt.getOID() + " has been overridden, custom extension will not be added.");
                    }
                }
            }
        }

        // Finally add extensions to certificate generator
        X509Extensions exts = extgen.generate();
        @SuppressWarnings("rawtypes")
        Enumeration en = exts.oids();
        while (en.hasMoreElements()) {
            DERObjectIdentifier oid = (DERObjectIdentifier) en.nextElement();
            X509Extension ext = exts.getExtension(oid);
            certgen.addExtension(oid, ext.isCritical(), ext.getValue().getOctets());
        }

        //
        // End of extensions
        //

        X509Certificate cert;
        if (log.isTraceEnabled()) {
            log.trace(">certgen.generate");
        }
        cert = certgen.generate(caPrivateKey, provider);
        if (log.isTraceEnabled()) {
            log.trace("<certgen.generate");
        }

        // Verify before returning
        cert.verify(caPublicKey);

        // If we have a CA-certificate, verify that we have all path verification stuff correct
        if (cacert != null) {
            final byte[] aki = CertTools.getAuthorityKeyId(cert);
            final byte[] ski = CertTools.getSubjectKeyId(isRootCA ? cert : cacert);
            if ((aki != null) && (ski != null)) {
                final boolean eq = Arrays.equals(aki, ski);
                if (!eq) {
                    final String akistr = new String(Hex.encode(aki));
                    final String skistr = new String(Hex.encode(ski));
                    final String msg = intres.getLocalizedMessage("signsession.errorpathverifykeyid", akistr, skistr);
                    log.error(msg);
                    throw new CertificateCreateException(msg);
                }
            }
            final Principal issuerDN = cert.getIssuerX500Principal();
            final Principal subjectDN = cacert.getSubjectX500Principal();
            if ((issuerDN != null) && (subjectDN != null)) {
                final boolean eq = issuerDN.equals(subjectDN);
                if (!eq) {
                	final String msg = intres.getLocalizedMessage("signsession.errorpathverifydn", issuerDN.getName(), subjectDN.getName());
                    log.error(msg);
                    throw new CertificateCreateException(msg);
                }
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("X509CA: generated certificate, CA " + this.getCAId() + " for DN: " + subject.getCertificateDN());
        }
        return cert;
    }

    public CRL generateCRL(Collection<RevokedCertInfo> certs, int crlnumber) throws CryptoTokenOfflineException, IllegalCryptoTokenException,
            IOException, SignatureException, NoSuchProviderException, InvalidKeyException, CRLException, NoSuchAlgorithmException {
        return generateCRL(certs, getCRLPeriod(), crlnumber, false, 0);
    }

    public CRL generateDeltaCRL(Collection<RevokedCertInfo> certs, int crlnumber, int basecrlnumber) throws CryptoTokenOfflineException,
            IllegalCryptoTokenException, IOException, SignatureException, NoSuchProviderException, InvalidKeyException, CRLException,
            NoSuchAlgorithmException {
        return generateCRL(certs, getDeltaCRLPeriod(), crlnumber, true, basecrlnumber);
    }

    /**
     * Generate a CRL or a deltaCRL
     * 
     * @param certs
     *            list of revoked certificates
     * @param crlnumber
     *            CRLNumber for this CRL
     * @param isDeltaCRL
     *            true if we should generate a DeltaCRL
     * @param basecrlnumber
     *            caseCRLNumber for a delta CRL, use 0 for full CRLs
     * @param certProfile
     *            certificate profile for CRL Distribution point in the CRL, or null
     * @return CRL
     * @throws CryptoTokenOfflineException
     * @throws IllegalCryptoTokenException
     * @throws IOException
     * @throws SignatureException
     * @throws NoSuchProviderException
     * @throws InvalidKeyException
     * @throws CRLException
     * @throws NoSuchAlgorithmException
     */
    private CRL generateCRL(Collection<RevokedCertInfo> certs, long crlPeriod, int crlnumber, boolean isDeltaCRL, int basecrlnumber)
            throws CryptoTokenOfflineException, IllegalCryptoTokenException, IOException, SignatureException, NoSuchProviderException,
            InvalidKeyException, CRLException, NoSuchAlgorithmException {
        final String sigAlg = getCAInfo().getCATokenInfo().getSignatureAlgorithm();

        if (log.isDebugEnabled()) {
            log.debug("generateCRL(" + certs.size() + ", " + crlPeriod + ", " + crlnumber + ", " + isDeltaCRL + ", " + basecrlnumber);
        }
        Date thisUpdate = new Date();
        Date nextUpdate = new Date();

        nextUpdate.setTime(nextUpdate.getTime() + crlPeriod);
        X509V2CRLGenerator crlgen = new X509V2CRLGenerator();
        crlgen.setThisUpdate(thisUpdate);
        crlgen.setNextUpdate(nextUpdate);
        crlgen.setSignatureAlgorithm(sigAlg);
        // Make DNs
        X509Certificate cacert = (X509Certificate) getCACertificate();
        if (cacert == null) {
            // This is an initial root CA, since no CA-certificate exists
            // (I don't think we can ever get here!!!)
            X509NameEntryConverter converter = null;
            if (getUsePrintableStringSubjectDN()) {
                converter = new PrintableStringEntryConverter();
            } else {
                converter = new X509DefaultEntryConverter();
            }

            X509Name caname = CertTools.stringToBcX509Name(getSubjectDN(), converter, getUseLdapDNOrder());
            crlgen.setIssuerDN(caname);
        } else {
            crlgen.setIssuerDN(cacert.getSubjectX500Principal());
        }
        if (certs != null) {
            Iterator<RevokedCertInfo> it = certs.iterator();
            while (it.hasNext()) {
                RevokedCertInfo certinfo = (RevokedCertInfo) it.next();
                crlgen.addCRLEntry(certinfo.getUserCertificate(), certinfo.getRevocationDate(), certinfo.getReason());
            }
        }

        // Authority key identifier
        if (getUseAuthorityKeyIdentifier() == true) {
            SubjectPublicKeyInfo apki = new SubjectPublicKeyInfo((ASN1Sequence) new ASN1InputStream(new ByteArrayInputStream(getCAToken()
                    .getPublicKey(CATokenConstants.CAKEYPURPOSE_CRLSIGN).getEncoded())).readObject());
            AuthorityKeyIdentifier aki = new AuthorityKeyIdentifier(apki);
            crlgen.addExtension(X509Extensions.AuthorityKeyIdentifier.getId(), getAuthorityKeyIdentifierCritical(), aki);
        }
        // CRLNumber extension
        if (getUseCRLNumber() == true) {
            CRLNumber crlnum = new CRLNumber(BigInteger.valueOf(crlnumber));
            crlgen.addExtension(X509Extensions.CRLNumber.getId(), this.getCRLNumberCritical(), crlnum);
        }

        if (isDeltaCRL) {
            // DeltaCRLIndicator extension
            CRLNumber basecrlnum = new CRLNumber(BigInteger.valueOf(basecrlnumber));
            crlgen.addExtension(X509Extensions.DeltaCRLIndicator.getId(), true, basecrlnum);
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
                crlgen.addExtension(X509Extensions.IssuingDistributionPoint.getId(), getCrlDistributionPointOnCrlCritical(), idp);
            }

            if (!isDeltaCRL) {
                String crlFreshestDP = getCADefinedFreshestCRL();
                List<DistributionPoint> freshestDistPoints = generateDistributionPoints(crlFreshestDP);
                if (freshestDistPoints.size() > 0) {
                    CRLDistPoint ext = new CRLDistPoint((DistributionPoint[]) freshestDistPoints.toArray(new DistributionPoint[freshestDistPoints
                            .size()]));

                    // According to the RFC, the Freshest CRL extension on a
                    // CRL must not be marked as critical. Therefore it is
                    // hardcoded as not critical and is independent of
                    // getCrlDistributionPointOnCrlCritical().
                    crlgen.addExtension(X509Extensions.FreshestCRL.getId(), false, ext);
                }

            }
        }

        X509CRL crl;
        crl = crlgen.generate(getCAToken().getPrivateKey(CATokenConstants.CAKEYPURPOSE_CRLSIGN), getCAToken().getCryptoToken().getSignProviderName());
        // Verify before sending back
        crl.verify(getCAToken().getPublicKey(CATokenConstants.CAKEYPURPOSE_CRLSIGN));

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
        if (distPoints == null) {
            distPoints = "";
        }
        // Multiple CDPs are separated with the ';' sign
        Iterator<String> it = StringTools.splitURIs(distPoints).iterator();
        ArrayList<DistributionPoint> result = new ArrayList<DistributionPoint>();
        while (it.hasNext()) {
            String uri = (String) it.next();
            GeneralName gn = new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(uri));
            if (log.isDebugEnabled()) {
                log.debug("Added CRL distpoint: " + uri);
            }
            ASN1EncodableVector vec = new ASN1EncodableVector();
            vec.add(gn);
            GeneralNames gns = new GeneralNames(new DERSequence(vec));
            DistributionPointName dpn = new DistributionPointName(0, gns);
            result.add(new DistributionPoint(dpn, null, null));
        }
        return result;
    }

    /** Implementation of UpgradableDataHashMap function getLatestVersion */
    public float getLatestVersion() {
        return LATEST_VERSION;
    }

    /**
     * Implementation of UpgradableDataHashMap function upgrade.
     */
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
                setCRLOverlapTime(10);
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
            data.put(VERSION, new Float(LATEST_VERSION));
        }
    }

    /**
     * Method to upgrade new (or existing external caservices) This method needs to be called outside the regular upgrade since the CA isn't
     * instantiated in the regular upgrade.
     */
    public boolean upgradeExtendedCAServices() {
        boolean retval = false;
        Collection<Integer> extendedServiceTypes = getExternalCAServiceTypes();

        // call upgrade, if needed, on installed CA services
        for (Iterator<Integer> iterator = extendedServiceTypes.iterator(); iterator.hasNext();) {
            Integer type = iterator.next();
            ExtendedCAService service = getExtendedCAService(type);
            if (service != null) {
                if (Float.compare(service.getLatestVersion(), service.getVersion()) != 0) {
                    retval = true;
                    service.upgrade();
                }            	
            } else {
            	log.error("Extended service is null, can not upgrade service of type: "+type);
            }
        }

        // TODO: in EJBCA we created external CA services (XKMS and CMS) if they did not exist here.
        // We don't want to do that here because we want the CA object toi be independent of the "user defined" Extended services.
        // So where will we do that in EJBCA? Is it needed, was that not only needed for an old upgrade when those services were introduced?
        // Since EJBCA from 4.0 can only be upgraded from 3.11.x where those services already exists, it is not needed right?

        return retval;
    }

    public byte[] encryptKeys(KeyPair keypair) throws IOException, CryptoTokenOfflineException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream os = new ObjectOutputStream(baos);
        os.writeObject(keypair);

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        CMSEnvelopedData ed;
        try {
            edGen.addKeyTransRecipient(this.getCAToken().getPublicKey(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT), this.keyId);
            ed = edGen.generate(new CMSProcessableByteArray(baos.toByteArray()), CMSEnvelopedDataGenerator.AES256_CBC, "BC");
        } catch (Exception e) {
            log.error("-encryptKeys: ", e);
            throw new IOException(e.getMessage());
        }

        return ed.getEncoded();
    }

    public KeyPair decryptKeys(byte[] data) throws Exception {
        CMSEnvelopedData ed = new CMSEnvelopedData(data);

        RecipientInformationStore recipients = ed.getRecipientInfos();
        @SuppressWarnings("unchecked")
        Iterator<RecipientInformation> it = recipients.getRecipients().iterator();
        RecipientInformation recipient =  it.next();
        ObjectInputStream ois = null;
        byte[] recdata = recipient
                .getContent(getCAToken().getPrivateKey(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT), getCAToken().getCryptoToken().getEncProviderName());
        ois = new ObjectInputStream(new ByteArrayInputStream(recdata));

        return (KeyPair) ois.readObject();
    }

    public byte[] decryptData(byte[] data, int cAKeyPurpose) throws Exception {
        CMSEnvelopedData ed = new CMSEnvelopedData(data);
        RecipientInformationStore recipients = ed.getRecipientInfos();
        RecipientInformation recipient = (RecipientInformation) recipients.getRecipients().iterator().next();
        byte[] recdata = recipient.getContent(getCAToken().getPrivateKey(cAKeyPurpose), getCAToken().getCryptoToken().getSignProviderName());
        return recdata;
    }

    public byte[] encryptData(byte[] data, int keyPurpose) throws Exception {
        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();
        CMSEnvelopedData ed;
        try {
            edGen.addKeyTransRecipient(this.getCAToken().getPublicKey(keyPurpose), this.keyId);
            ed = edGen.generate(new CMSProcessableByteArray(data), CMSEnvelopedDataGenerator.AES256_CBC, "BC");
        } catch (Exception e) {
            log.error("-encryptKeys: ", e);
            throw new IOException(e.getMessage());
        }

        return ed.getEncoded();
    }

}
