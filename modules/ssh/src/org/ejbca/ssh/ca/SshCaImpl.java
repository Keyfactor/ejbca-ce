/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ssh.ca;

import java.io.IOException;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
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
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.icao.ICAOObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.BufferingContentSigner;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.ErrorCode;
import org.cesecore.certificates.ca.CABase;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.CertificateGenerationParams;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.ca.IllegalValidityException;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.ca.internal.CertificateValidity;
import org.cesecore.certificates.ca.internal.RequestAndPublicKeySelector;
import org.cesecore.certificates.ca.internal.SernoGenerator;
import org.cesecore.certificates.ca.internal.SernoGeneratorRandom;
import org.cesecore.certificates.ca.ssh.SshCa;
import org.cesecore.certificates.ca.ssh.SshCaInfo;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificate.certextensions.AvailableCustomCertificateExtensionsConfiguration;
import org.cesecore.certificates.certificate.certextensions.CertificateExtension;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionFactory;
import org.cesecore.certificates.certificate.certextensions.CustomCertificateExtension;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificate.ssh.SshCertificateType;
import org.cesecore.certificates.certificate.ssh.SshPublicKey;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificatetransparency.CTLogException;
import org.cesecore.certificates.certificatetransparency.CTLogInfo;
import org.cesecore.certificates.certificatetransparency.CertificateTransparency;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.certificates.ocsp.SHA1DigestCalculator;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.certificates.util.dn.DNFieldsUtil;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.internal.InternalResources;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.validation.IssuancePhase;
import org.cesecore.keys.validation.ValidationException;
import org.cesecore.util.CeSecoreNameStyle;
import org.cesecore.util.CertTools;
import org.cesecore.util.EJBTools;
import org.cesecore.util.PrintableStringNameStyle;
import org.cesecore.util.StringTools;
import org.ejbca.core.protocol.ssh.SshRequestMessage;
import org.ejbca.ssh.certificate.SshCertificateBase;
import org.ejbca.ssh.certificate.SshEcCertificate;
import org.ejbca.ssh.certificate.SshRsaCertificate;
import org.ejbca.ssh.certificate.signature.ec.EcCertificateSigner;
import org.ejbca.ssh.certificate.signature.ec.EcSigningAlgorithm;
import org.ejbca.ssh.certificate.signature.rsa.RsaCertificateSigner;
import org.ejbca.ssh.certificate.signature.rsa.RsaSigningAlgorithms;
import org.ejbca.ssh.keys.ec.SshEcPublicKey;
import org.ejbca.ssh.keys.rsa.SshRsaPublicKey;

/**
 *
 * TODO SSH: Remove all references to CT in ECA-9182
 *
 * @version $Id$
 *
 */
public class SshCaImpl extends CABase implements Serializable, SshCa {
    private static final long serialVersionUID = 1L;

    private static final Logger log = Logger.getLogger(SshCaImpl.class);

    private static final InternalResources intres = InternalResources.getInstance();

    private static final String USEPRINTABLESTRINGSUBJECTDN = "useprintablestringsubjectdn";
    private static final String USELDAPDNORDER = "useldapdnorder";

    /** Buffer size used for BufferingContentSigner, this is the max buffer is collect before making a "sign" call.
     * This is important in order to not make several calls to a network attached HSM for example, as that slows signing down a lot
     * due to network round-trips. As long as the object to sign is smaller than this buffer a single round-trip is done.
     * Size is selected as certificates are almost never this big, and this is a reasonable size to do round-tripping on for CRLs.
     */
    private static final int SIGN_BUFFER_SIZE = 20480;

    // TODO SSH: Boilerplate, please remove in ECA-9182.
    private static final CertificateTransparency ct = null;

    public SshCaImpl() {
    }

    public SshCaImpl(SshCaInfo cainfo) {
        super(cainfo);
        data.put(CABase.CATYPE, CAInfo.CATYPE_SSH);
        data.put(VERSION, LATEST_VERSION);
        data.put(SUBJECTALTNAME, cainfo.getSubjectAltName());
        setUsePrintableStringSubjectDN(cainfo.getUsePrintableStringSubjectDN());
        setCaSerialNumberOctetSize(cainfo.getCaSerialNumberOctetSize());
        setUseLdapDNOrder(cainfo.getUseLdapDnOrder());
    }

    public SshCaImpl(final HashMap<Object, Object> data, final int caId, final String subjectDn, final String name, final int status,
            final Date updateTime, final Date expireTime) {
        super(data);

        SshCaInfo info = new SshCaInfo.SshCAInfoBuilder()
                .setSubjectDn(subjectDn)
                .setName(name)
                .setStatus(status)
                .setUpdateTime(updateTime)
                .setCaToken(getCAToken())
                .setSubjectAltName(getSubjectAltName())
                .setCertificateProfileId(getCertificateProfileId())
                .setDefaultCertProfileId(getDefaultCertificateProfileId())
                .setEncodedValidity(getEncodedValidity())
                .setExpireTime(getExpireTime())
                .setCaType(getCAType())
                .setSignedBy(getSignedBy())
                .setCertificateChain(getCertificateChain())
                .setCaToken(getCAToken())
                .setDescription(getDescription())
                .setCaSerialNumberOctetSize(getSerialNumberOctetSize())
                .setRevocationReason(getRevocationReason())
                .setRevocationDate(getRevocationDate())
                .setFinishUser(getFinishUser())
                .setUsePrintableStringSubjectDN(getUsePrintableStringSubjectDN())
                .setUseLdapDnOrder(getUseLdapDNOrder())
                .setIncludeInHealthCheck(getIncludeInHealthCheck())
                .setDoEnforceUniquePublicKeys(isDoEnforceUniquePublicKeys())
                .setDoEnforceKeyRenewal(isDoEnforceKeyRenewal())
                .setDoEnforceUniqueDistinguishedName(isDoEnforceUniqueDistinguishedName())
                .setDoEnforceUniqueSubjectDNSerialnumber(isDoEnforceUniqueSubjectDNSerialnumber())
                .setUseCertReqHistory(isUseCertReqHistory())
                .setUseUserStorage(isUseUserStorage())
                .setUseCertificateStorage(isUseCertificateStorage())
                .setAcceptRevocationNonExistingEntry(isAcceptRevocationNonExistingEntry())
                .build();
        super.setCAInfo(info);
        setCAId(caId);
    }

    @Override
    public Certificate generateCertificate(CryptoToken cryptoToken, EndEntityInformation subject, RequestMessage request, PublicKey publicKey,
            int keyusage, Date notBefore, Date notAfter, CertificateProfile certProfile, Extensions extensions, String sequence,
            CertificateGenerationParams certGenParams, AvailableCustomCertificateExtensionsConfiguration cceConfig)
            throws CryptoTokenOfflineException, CAOfflineException, InvalidAlgorithmException, IllegalValidityException, IllegalNameException,
            OperatorCreationException, CertificateCreateException, CertificateExtensionException, SignatureException, IllegalKeyException {
        /*
         * TODO SSH: This CA type needs to generate X509 Certs for its on certificates - break out common methods from X509CAImpl and make them into a common class.
         */

        // Before we start, check if the CA is off-line, we don't have to waste time
        // one the stuff below of we are off-line. The line below will throw CryptoTokenOfflineException of CA is offline
        final CAToken catoken = getCAToken();
        final int purpose = getUseNextCACert(request) ? CATokenConstants.CAKEYPURPOSE_CERTSIGN_NEXT : CATokenConstants.CAKEYPURPOSE_CERTSIGN;
        final PublicKey caPublicKey = cryptoToken.getPublicKey(catoken.getAliasFromPurpose(purpose));
        final PrivateKey caPrivateKey = cryptoToken.getPrivateKey(catoken.getAliasFromPurpose(purpose));
        final String provider = cryptoToken.getSignProviderName();

        //Depending on the certificate profile, either generate an X509 certificate (for CA use), or an SSH certificate
        switch (certProfile.getType()) {
        case CertificateConstants.CERTTYPE_ROOTCA:
        case CertificateConstants.CERTTYPE_SUBCA:
            return generateX509Certificate(subject, request, publicKey, keyusage, notBefore, notAfter, certProfile, extensions, caPublicKey,
                    caPrivateKey, provider, certGenParams, cceConfig, /*linkCertificate=*/false, /*caNameChange=*/false);
        case CertificateConstants.CERTTYPE_SSH:
            try {
                return generateSshCertificate(subject, (SshRequestMessage) request, publicKey, notBefore, notAfter, certProfile, caPublicKey,
                        caPrivateKey);
            } catch (InvalidKeyException | InvalidKeySpecException e) {
                throw new InvalidAlgorithmException("Unable to process either signature or public key.", e);
            } catch (CertificateEncodingException e) {
                throw new CertificateCreateException("Could not create certificate", e);
            }
        default:
            throw new CertificateCreateException("SSH CA can not generate certificates for other CA types than ROOT, SUBCA or SSH");
        }

    }

    /**
     * Produces an OpenSSH encoded SSH certificate
     *
     * @param endEntityInformation the end entity to create the certificate for
     * @param requestMessage a {@link SshRequestMessage} containing all pertinent information
     * @param publicKey the public key to sign for (also included in requestMessage)
     * @param notBefore the start date of the certificate
     * @param notAfter the end date of the certificate
     * @param certificateProfile the certificate profile for this certificate
     * @param caPublicKey the CA's public key, to be embedded in the certificate
     * @param caPrivateKey the CA's private key, used to sign the certificate
     *
     * @return a signed SSH certificate
     *
     * @throws InvalidKeySpecException if either the public key or signing keys were of incorrect type
     * @throws SignatureException if the signature couldn't be produced
     * @throws InvalidKeyException if the signing keys were invalid
     * @throws CertificateEncodingException if the certificates were encoded incorrectly
     * @throws CAOfflineException if the CA's private key has expired
     * @throws IllegalValidityException if the requested certificate validity was invalid
     */
    private SshCertificateBase generateSshCertificate(final EndEntityInformation endEntityInformation, final SshRequestMessage requestMessage,
            final PublicKey publicKey, final Date notBefore, final Date notAfter, final CertificateProfile certificateProfile,
            final PublicKey caPublicKey, final PrivateKey caPrivateKey) throws InvalidKeySpecException,
            SignatureException, InvalidKeyException, CertificateEncodingException, CAOfflineException, IllegalValidityException {

        //Generate a nine octet serial number - since the serial number generator always produces positive numbers, we'll simply squeeze it into an unsigned long.
        SernoGenerator sernoGenerator = SernoGeneratorRandom.instance(9);
        String serialNumber = Long.toUnsignedString(sernoGenerator.getSerno().longValue());
        //Create a 32 byte nonce
        byte[] nonceBytes = new byte[32];
        try {
            SecureRandom.getInstance("SHA1PRNG").nextBytes(nonceBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA1PRNG was unknown to provider", e);
        }
        final SshCertificateType certificateType = certificateProfile.getSshCertificateType();
        final String keyId = requestMessage.getKeyId();
        Set<String> principals = new HashSet<>(requestMessage.getPrincipals());
        Map<String, String> criticalOptions;
        //No critical options are defined for host certificates
        if (certificateType.equals(SshCertificateType.USER)) {
            criticalOptions = requestMessage.getCriticalOptions();
        } else {
            criticalOptions = new HashMap<>();
        }
        TreeMap<String, byte[]> extensions;
        //No extensions are defined for host certificates
        if (certificateType.equals(SshCertificateType.USER)) {
            extensions = new TreeMap<>(certificateProfile.getSshExtensionsMap());
            //Check if certificate profile allows adding additional extensions
            if (certificateProfile.getAllowExternalSshExtensions()) {
                //TODO SSH: Once defined in system configuration, also check (if required) that all additional extensions be known ECA-9183
                extensions.putAll(requestMessage.getAdditionalExtensions());
            }
        } else {
            extensions = new TreeMap<>();
        }
        SshPublicKey signatureKey;
        switch (AlgorithmTools.getKeyAlgorithm(caPublicKey)) {
        case AlgorithmConstants.KEYALGORITHM_RSA:
            signatureKey = new SshRsaPublicKey((RSAPublicKey) caPublicKey);
            break;
        case AlgorithmConstants.KEYALGORITHM_EC:
        case AlgorithmConstants.KEYALGORITHM_ECDSA:
            signatureKey = new SshEcPublicKey((ECPublicKey) caPublicKey);
            break;
        default:
            throw new InvalidKeySpecException("Key algorithm " + AlgorithmTools.getKeyAlgorithm(caPublicKey) + " is not supported for SSH.");
        }

        SshPublicKey sshKey;
        switch (AlgorithmTools.getKeyAlgorithm(publicKey)) {
        case AlgorithmConstants.KEYALGORITHM_RSA:
            sshKey = new SshRsaPublicKey((RSAPublicKey) publicKey);
            break;
        case AlgorithmConstants.KEYALGORITHM_EC:
        case AlgorithmConstants.KEYALGORITHM_ECDSA:
            sshKey = new SshEcPublicKey((ECPublicKey) publicKey);
            break;
        default:
            throw new InvalidKeySpecException("Key algorithm " + AlgorithmTools.getKeyAlgorithm(caPublicKey) + " is not supported for SSH.");
        }

        final X509Certificate cacert = (X509Certificate) getCACertificate();
        final Date checkDate = new Date();
        // Check CA certificate PrivateKeyUsagePeriod if it exists (throws CAOfflineException if it exists and is not within this time)
        CertificateValidity.checkPrivateKeyUsagePeriod(cacert, checkDate);
        // Get certificate validity time notBefore and notAfter
        final CertificateValidity validity = new CertificateValidity(endEntityInformation, certificateProfile, notBefore, notAfter, cacert, false, false);

        SshCertificateBase sshCertificate;
        if (publicKey instanceof ECPublicKey) {
            sshCertificate = new SshEcCertificate(sshKey, nonceBytes, serialNumber, certificateType, keyId, principals, validity.getNotBefore(), validity.getNotAfter(),
                    criticalOptions, extensions, signatureKey, requestMessage.getComment(), getSubjectDN());
            EcCertificateSigner ecCertificateSigner = new EcCertificateSigner(
                    EcSigningAlgorithm.getFromIdentifier(getCAInfo().getCAToken().getSignatureAlgorithm()));
            sshCertificate
                    .setSignature(ecCertificateSigner.signPayload(sshCertificate.encodeCertificateBody(), caPublicKey, caPrivateKey));
        } else if (publicKey instanceof RSAPublicKey) {
            sshCertificate = new SshRsaCertificate(sshKey, nonceBytes, serialNumber, certificateType, keyId, principals, notBefore, notAfter,
                    criticalOptions, extensions, signatureKey, requestMessage.getComment(), getSubjectDN());
            RsaCertificateSigner rsaCertificateSigner = new RsaCertificateSigner(RsaSigningAlgorithms.SHA1);
            sshCertificate
                    .setSignature(rsaCertificateSigner.signPayload(sshCertificate.getEncoded(), caPublicKey, caPrivateKey));
        } else {
            throw new InvalidKeySpecException("Public key was not of a type applicable for SSH certificates.");
        }
        return sshCertificate;
    }

    /**
     * TODO: Method is boilerplate, please move into a common class for SSH and X509 Certs ECA-9182
     */
    private X509Certificate generateX509Certificate(final EndEntityInformation subject, final RequestMessage providedRequestMessage,
            final PublicKey providedPublicKey, final int keyUsage, final Date notBefore, final Date notAfter, final CertificateProfile certProfile,
            final Extensions extensions, final PublicKey caPublicKey, final PrivateKey caPrivateKey, final String provider,
            CertificateGenerationParams certGenParams, AvailableCustomCertificateExtensionsConfiguration cceConfig, boolean linkCertificate,
            boolean caNameChange) throws CAOfflineException, InvalidAlgorithmException, IllegalValidityException, IllegalNameException,
            CertificateExtensionException, OperatorCreationException, CertificateCreateException, IllegalKeyException {

        // We must only allow signing to take place if the CA itself is on line, even if the token is on-line.
        // We have to allow expired as well though, so we can renew expired CAs
        if ((getStatus() != CAConstants.CA_ACTIVE) && (getStatus() != CAConstants.CA_EXPIRED)) {
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
            final String msg = intres.getLocalizedMessage("createcert.invalidsignaturealg", sigAlg,
                    ArrayUtils.toString(AlgorithmConstants.AVAILABLE_SIGALGS));
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
                if (ei != null && ei.certificateSerialNumber() != null) {
                    serno = ei.certificateSerialNumber();
                } else {
                    SernoGenerator instance = SernoGeneratorRandom.instance(getSerialNumberOctetSize());
                    serno = instance.getSerno();
                }
            } else {
                SernoGenerator instance = SernoGeneratorRandom.instance(getSerialNumberOctetSize());
                serno = instance.getSerno();
                if ((ei != null) && (ei.certificateSerialNumber() != null)) {
                    final String msg = intres.getLocalizedMessage("createcert.certprof_not_allowing_cert_sn_override_using_normal",
                            ei.certificateSerialNumber().toString(16));
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
        final boolean ldapdnorder = (getUseLdapDNOrder()) && (certProfile.getUseLdapDnOrder());
        // If we have a custom order defined in the certificate profile, take this. If this is null or empty it will be ignored
        String[] customDNOrder = null;
        if (certProfile.getUseCustomDnOrder()) {
            final ArrayList<String> order = certProfile.getCustomDnOrder();
            if (order != null && !order.isEmpty()) {
                if (log.isDebugEnabled()) {
                    log.debug("Using Custom DN order: " + order);
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
            if (certProfile.getAllowDNOverrideByEndEntityInformation() && ei != null && ei.getRawSubjectDn() != null) {
                final String stripped = StringTools.strip(ei.getRawSubjectDn());
                // Since support for multi-value RDNs in EJBCA 7.0.0, see ECA-3934, we don't automatically escape + signs anymore
                //final String escapedPluses = CertTools.handleUnescapedPlus(stripped);
                final String emptiesRemoved = DNFieldsUtil.removeAllEmpties(stripped);
                final X500Name subjectDNNameFromEei = CertTools.stringToUnorderedX500Name(emptiesRemoved, CeSecoreNameStyle.INSTANCE);
                if (subjectDNNameFromEei.toString().length() > 0) {
                    subjectDNName = subjectDNNameFromEei;
                    if (log.isDebugEnabled()) {
                        log.debug("Using X500Name from end entity information instead of user's registered subject DN fields.");
                        log.debug("ExtendedInformation.getRawSubjectDn(): " + ei.getRawSubjectDn() + " will use: "
                                + CeSecoreNameStyle.INSTANCE.toString(subjectDNName));
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
                log.trace("DN with illegal name: " + subjectDNName);
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
            if (linkCertificate && caNameChange) {
                List<Certificate> renewedCertificateChain = getRenewedCertificateChain();
                if (renewedCertificateChain == null || renewedCertificateChain.isEmpty()) {
                    //"Should not happen" error
                    log.error("CA name change is in process but renewed (old) certificates chain is empty");
                    throw new CertificateCreateException("CA name change is in process but renewed (old) certificates chain is empty");
                }
                issuerDNName = X500Name.getInstance(
                        ((X509Certificate) renewedCertificateChain.get(renewedCertificateChain.size() - 1)).getSubjectX500Principal().getEncoded());
            } else {
                issuerDNName = subjectDNName;
            }
        } else {
            issuerDNName = X500Name.getInstance(cacert.getSubjectX500Principal().getEncoded());
            if (log.isDebugEnabled()) {
                log.debug("Using issuer DN directly from the CA certificate: " + issuerDNName.toString());
            }
        }

        SubjectPublicKeyInfo pkinfo = verifyAndCorrectSubjectPublicKeyInfo(publicKey);
        final X509v3CertificateBuilder certbuilder = new X509v3CertificateBuilder(issuerDNName, serno, val.getNotBefore(), val.getNotAfter(),
                subjectDNName, pkinfo);

        // Only created and used if Certificate Transparency is enabled
        final X509v3CertificateBuilder precertbuilder = certProfile.isUseCertificateTransparencyInCerts()
                ? new X509v3CertificateBuilder(issuerDNName, serno, val.getNotBefore(), val.getNotAfter(), subjectDNName, pkinfo)
                : null;

        // Check that the certificate fulfills name constraints, as a service to the CA, so they don't issue certificates that
        // later fail verification in clients (browsers)
        if (cacert != null) {
            GeneralNames altNameGNs = null;
            String altName = subject.getSubjectAltName();
            if (certProfile.getUseSubjectAltNameSubSet()) {
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
            if ((permittedNC != null && !permittedNC.isEmpty()) || (excludedNC != null && !excludedNC.isEmpty())) {
                if (!certProfile.getUseNameConstraints()) {
                    throw new CertificateCreateException(
                            "Tried to issue a certificate with Name Constraints without having enabled NC in the certificate profile.");
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
            for (ASN1ObjectIdentifier oid : oids) {
                // Start by excluding non overridable extensions
                // If there are no nonOverridableExtensionOIDs set, or if the set does not contain our OID, we allow it so move on
                if (!nonOverridableExtensionOIDs.contains(oid.getId())) { // nonOverridableExtensionOIDs can never by null
                    // Now check if we have specified which ones are allowed, if this is not set we allow everything
                    if (overridableExtensionOIDs.isEmpty() || overridableExtensionOIDs.contains(oid.getId())) {
                        final Extension ext = extensions.getExtension(oid);
                        if (log.isDebugEnabled()) {
                            log.debug("Overriding extension with OID: " + oid.getId());
                        }
                        try {
                            extgen.addExtension(oid, ext.isCritical(), ext.getParsedValue());
                        } catch (IOException e) {
                            throw new IllegalStateException("IOException adding overridden extension with OID " + oid.getId() + ": ", e);
                        }
                    } else {
                        if (log.isDebugEnabled()) {
                            log.debug(
                                    "Extension is not among overridable extensions, not adding extension with OID " + oid.getId() + " from request.");
                        }
                    }
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("Extension is among non-overridable extensions, not adding extension with OID " + oid.getId() + " from request.");
                    }
                }
            }
        }

        // Second we see if there is Key usage override
        Extensions overridenexts = extgen.generate();
        if (certProfile.getAllowKeyUsageOverride() && (keyUsage >= 0)) {
            if (log.isDebugEnabled()) {
                log.debug("AllowKeyUsageOverride=true. Using KeyUsage from parameter: " + keyUsage);
            }
            if (certProfile.getUseKeyUsage()) {
                final KeyUsage ku = new KeyUsage(keyUsage);
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
            } catch (IOException e) {
                /*IOException with DERNull.INSTANCE will never happen*/}
        }

        // Fifth, check for custom Certificate Extensions that should be added.
        // Custom certificate extensions is defined in CA UI -> SystemConfiguration -> Custom Certificate Extensions
        final List<Integer> usedCertExt = certProfile.getUsedCertificateExtensions();
        final List<Integer> wildcardExt = new ArrayList<>();
        final Iterator<Integer> certExtIter = usedCertExt.iterator();
        Set<String> requestOids = new HashSet<>();
        if (subject.getExtendedInformation() != null) {
            requestOids = subject.getExtendedInformation().getExtensionDataOids();
        }
        while (certExtIter.hasNext()) {
            final int id = certExtIter.next();
            final CustomCertificateExtension certExt = cceConfig.getCustomCertificateExtension(id);
            if (certExt != null) {
                if (certExt.getOID().contains("*")) {
                    // Match wildcards later
                    wildcardExt.add(id);
                    continue;
                }
                // We don't want to try to add custom extensions with the same oid if we have already added them
                // from the request, if AllowExtensionOverride is enabled.
                // Two extensions with the same oid is not allowed in the standard.
                if (overridenexts.getExtension(new ASN1ObjectIdentifier(certExt.getOID())) == null) {
                    final byte[] value = certExt.getValueEncoded(subject, this, certProfile, publicKey, caPublicKey, val);
                    if (value != null) {
                        extgen.addExtension(new ASN1ObjectIdentifier(certExt.getOID()), certExt.isCriticalFlag(), value);
                        requestOids.remove(certExt.getOID());
                    }
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("Extension with oid " + certExt.getOID() + " has been overridden, custom extension will not be added.");
                    }
                }
            }
        }
        // Match remaining extensions (wild cards)
        for (int id : wildcardExt) {
            final int remainingOidsToMatch = requestOids.size();
            final CustomCertificateExtension certExt = cceConfig.getCustomCertificateExtension(id);
            if (certExt != null) {
                for (final String oid : requestOids) {
                    // Match requested OID with wildcard in CCE configuration
                    if (oid.matches(CertTools.getOidWildcardPattern(certExt.getOID()))) {
                        if (overridenexts.getExtension(new ASN1ObjectIdentifier(oid)) == null) {
                            final byte[] value = certExt.getValueEncoded(subject, this, certProfile, publicKey, caPublicKey, val, oid);
                            if (value != null) {
                                extgen.addExtension(new ASN1ObjectIdentifier(oid), certExt.isCriticalFlag(), value);
                                requestOids.remove(oid);
                                // Each wildcard CCE configuration may only be matched once.
                                break;
                            }
                        } else {
                            if (log.isDebugEnabled()) {
                                log.debug("Extension with oid " + oid + " has been overridden, custom extension will not be added.");
                            }
                        }
                    }
                }
                if ((remainingOidsToMatch == requestOids.size()) && certExt.isRequiredFlag()) {
                    // Required wildcard extension didn't match any OIDs in the request
                    throw new CertificateExtensionException(
                            intres.getLocalizedMessage("certext.basic.incorrectvalue", certExt.getId(), certExt.getOID())
                                    + "\nNo requested OID matched wildcard");
                }
            }
        }
        if (!requestOids.isEmpty()) {
            // All requested OIDs must match a CCE configuration
            throw new CertificateCreateException(ErrorCode.CUSTOM_CERTIFICATE_EXTENSION_ERROR,
                    "Request contained custom certificate extensions which couldn't match any configuration");
        }

        // Finally add extensions to certificate generator
        final Extensions exts = extgen.generate();
        ASN1ObjectIdentifier[] oids = exts.getExtensionOIDs();
        try {
            for (ASN1ObjectIdentifier oid : oids) {
                final Extension extension = exts.getExtension(oid);
                if (oid.equals(Extension.subjectAlternativeName)) { // subjectAlternativeName extension value needs special handling
                    ExtensionsGenerator sanExtGen = getSubjectAltNameExtensionForCert(extension, precertbuilder != null);
                    Extensions sanExts = sanExtGen.generate();
                    Extension eext = sanExts.getExtension(oid);
                    certbuilder.addExtension(oid, eext.isCritical(), eext.getParsedValue()); // adding subjetAlternativeName extension to certbuilder
                    if (precertbuilder != null) { // if a pre-certificate is to be published to a CTLog
                        eext = getSubjectAltNameExtensionForCTCert(extension).generate().getExtension(oid);
                        precertbuilder.addExtension(oid, eext.isCritical(), eext.getParsedValue()); // adding subjectAlternativeName extension to precertbuilder

                        eext = sanExts.getExtension(new ASN1ObjectIdentifier(CertTools.id_ct_redacted_domains));
                        if (eext != null) {
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

            // Sign the certificate with a dummy key for presign validation.
            // Do not call this if no validation will occur in the PRESIGN_CERTIFICATE_VALIDATION, because this code takes some time, signing a certificate
            if (certGenParams != null && certGenParams.getAuthenticationToken() != null
                    && certGenParams.getCertificateValidationDomainService() != null && certGenParams.getCertificateValidationDomainService()
                            .willValidateInPhase(IssuancePhase.PRESIGN_CERTIFICATE_VALIDATION, this)) {
                try {
                    PrivateKey presignKey = CAConstants.getPreSignPrivateKey(sigAlg);
                    if (presignKey == null) {
                        throw new CertificateCreateException("No pre-sign key exist usable with algorithm " + sigAlg
                                + ", PRESIGN_CERTIFICATE_VALIDATION is not possible with this CA.");
                    }
                    ContentSigner presignSigner = new BufferingContentSigner(
                            new JcaContentSignerBuilder(sigAlg).setProvider(BouncyCastleProvider.PROVIDER_NAME).build(presignKey), SIGN_BUFFER_SIZE);
                    // Since this certificate may be written to file through the validator we want to ensure it's not a real certificate
                    // We do that by signing with a hard coded fake key, and set authorityKeyIdentifier accordingly, so the cert can
                    // not be verified even accidentally by someone
                    // Confirmed in CT mailing list that this approach is ok.
                    // https://groups.google.com/forum/#!topic/certificate-transparency/sDRcVBAgjCY
                    // - "Anyone can create a certificate with a given issuer and sign it with a key they create. So it cannot be misissuance just because a name was used."

                    // Get the old, real, authorityKeyIdentifier
                    Extension ext = exts.getExtension(Extension.authorityKeyIdentifier);
                    if (ext != null) {
                        // Create a new authorityKeyIdentifier for the fake key
                        // SHA1 used here, but it's not security relevant here as this is the RFC5280 Key Identifier
                        JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils(SHA1DigestCalculator.buildSha1Instance());
                        AuthorityKeyIdentifier aki = extensionUtils.createAuthorityKeyIdentifier(CAConstants.getPreSignPublicKey(sigAlg));
                        certbuilder.replaceExtension(Extension.authorityKeyIdentifier, ext.isCritical(), aki.getEncoded());
                    }
                    X509CertificateHolder presignCertHolder = certbuilder.build(presignSigner);
                    X509Certificate presignCert = CertTools.getCertfromByteArray(presignCertHolder.getEncoded(), X509Certificate.class);
                    certGenParams.getCertificateValidationDomainService().validateCertificate(certGenParams.getAuthenticationToken(),
                            IssuancePhase.PRESIGN_CERTIFICATE_VALIDATION, this, subject, presignCert);
                    // Restore the original, real, authorityKeyIdentifier
                    if (ext != null) {
                        certbuilder.replaceExtension(Extension.authorityKeyIdentifier, ext.isCritical(), ext.getExtnValue().getOctets());
                    }
                } catch (IOException e) {
                    throw new CertificateCreateException("Cannot create presign certificate: ", e);
                } catch (ValidationException e) {
                    throw new CertificateCreateException(ErrorCode.INVALID_CERTIFICATE, e);
                }
            } else {
                if (log.isDebugEnabled()) {
                    if (certGenParams == null) {
                        log.debug("No PRESIGN_CERTIFICATE_VALIDATION: certGenParams is null");
                    } else {
                        log.debug("No PRESIGN_CERTIFICATE_VALIDATION: "
                                + (certGenParams.getAuthenticationToken() != null ? "" : "certGenParams.authenticationToken is null") + ":"
                                + (certGenParams.getCertificateValidationDomainService() != null ? ""
                                        : "certGenParams.getCertificateValidationDomainService is null"));
                    }
                }
            }

            // Add Certificate Transparency extension. It needs to access the certbuilder and
            // the CA key so it has to be processed here inside X509CA.
            if (ct != null && certProfile.isUseCertificateTransparencyInCerts() && certGenParams != null) {

                // Create CT pre-certificate
                // A critical extension is added to prevent this cert from being used
                ct.addPreCertPoison(precertbuilder);

                // Sign CT pre-certificate
                /*
                 *  TODO: It would be nice to be able to do the SCT fetching on a separate proxy node (ECA-4732).
                 *  The proxy node would then use a special CT pre-certificate signing certificate.
                 *  It should have CA=true and ExtKeyUsage=PRECERTIFICATE_SIGNING_OID
                 *  and should not have any other key usages (see RFC 6962, section 3.1)
                 */
                final ContentSigner signer = new BufferingContentSigner(new JcaContentSignerBuilder(sigAlg).setProvider(provider).build(caPrivateKey),
                        SIGN_BUFFER_SIZE);
                // TODO: with the new BC methods remove- and replaceExtension we can get rid of the precertbuilder and only use one builder to save some time and space
                final X509CertificateHolder certHolder = precertbuilder.build(signer);
                final X509Certificate cert = CertTools.getCertfromByteArray(certHolder.getEncoded(), X509Certificate.class);
                // ECA-6051 Re-Factored with Domain Service Layer.
                if (certGenParams.getAuthenticationToken() != null && certGenParams.getCertificateValidationDomainService() != null) {
                    try {
                        certGenParams.getCertificateValidationDomainService().validateCertificate(certGenParams.getAuthenticationToken(),
                                IssuancePhase.PRE_CERTIFICATE_VALIDATION, this, subject, cert);
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
                } else if (certGenParams.getSctDataCallback() == null) {
                    log.debug("Not logging to CT. No sctData persistance callback was passed.");
                } else {
                    // Get certificate chain
                    final List<Certificate> chain = new ArrayList<>();
                    chain.add(cert);
                    chain.addAll(getCertificateChain());
                    // Submit to logs and get signed timestamps
                    byte[] sctlist;
                    try {
                        sctlist = ct.fetchSCTList(chain, certProfile, certGenParams.getCTSubmissionConfigParams(),
                                certGenParams.getSctDataCallback());
                    } catch (CTLogException e) {
                        e.setPreCertificate(EJBTools.wrap(cert));
                        throw e;
                    } finally {
                        // Notify that pre-cert has been successfully or unsuccessfully submitted so it can be audit logged.
                        // TODO: BOILERPLATE
                        //certGenParams.getCTAuditLogCallback().logPreCertSubmission(this, subject, cert, sctlist != null);
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
                    log.debug("Not logging to CT. " + cause);
                }
            }
        } catch (CertificateException e) {
            throw new CertificateCreateException("Could not process CA's private key when parsing Certificate Transparency extension.", e);
        } catch (IOException e) {
            throw new CertificateCreateException("IOException was caught when parsing Certificate Transparency extension.", e);
        } catch (CTLogException e) {
            throw new CertificateCreateException("An exception occurred because too many CT servers were down to satisfy the certificate profile.",
                    e);
        }

        //
        // End of extensions
        //

        if (log.isTraceEnabled()) {
            log.trace(">certgen.generate");
        }
        final ContentSigner signer = new BufferingContentSigner(new JcaContentSignerBuilder(sigAlg).setProvider(provider).build(caPrivateKey),
                SIGN_BUFFER_SIZE);
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
        } catch (SignatureException e) {
            final String msg = "Public key in the CA certificate does not match the configured certSignKey, is the CA in renewal process? : "
                    + e.getMessage();
            log.warn(msg);
            throw new CertificateCreateException(msg, e);
        } catch (InvalidKeyException e) {
            throw new CertificateCreateException("CA's public key was invalid,", e);
        } catch (NoSuchAlgorithmException | CertificateException e) {
            throw new CertificateCreateException(e);
        } catch (NoSuchProviderException e) {
            throw new IllegalStateException("Provider was unknown", e);
        }

        // Verify any Signed Certificate Timestamps (SCTs) in the certificate before returning. If one of the (embedded) SCTs does
        // not verify over the final certificate, it won't validate in the browser and we don't want to issue such certificates.
        if (ct != null) {
            Collection<CTLogInfo> ctLogs = (certGenParams == null || certGenParams.getCTSubmissionConfigParams() == null
                    || certGenParams.getCTSubmissionConfigParams().getConfiguredCTLogs() == null) ? null
                            : certGenParams.getCTSubmissionConfigParams().getConfiguredCTLogs().values();
            ct.allSctsAreValidOrThrow(cert, getCertificateChain(), ctLogs);
        }

        //Sub CA certificates check: Check AKI against parent CA SKI and IssuerDN against parent CA SubjectDN
        if (!isRootCA && !linkCertificate) {
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

    /**
     * TODO: Boilerplate ECA-9182
     */
    private ExtensionsGenerator getSubjectAltNameExtensionForCTCert(Extension subAltNameExt) throws IOException {
        Pattern parenthesesRegex = Pattern.compile("\\(.*\\)"); // greedy match, so against "(a).(b).example.com" it will match "(a).(b)", like the old code did
        GeneralNames names = CertTools.getGeneralNamesFromExtension(subAltNameExt);
        GeneralName[] gns = names != null ? names.getNames() : new GeneralName[0];
        for (int j = 0; j < gns.length; j++) {
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
            if (generalName.getTagNo() == 1) {
                final String str = CertTools.getGeneralNameString(1, generalName.getName());
                if (StringUtils.contains(str, "\\+")) { // if it contains a '+' character that should be unescaped
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

    /*
     * TODO: Boilerplate ECA-9182
     */
    private ExtensionsGenerator getSubjectAltNameExtensionForCert(Extension subAltNameExt, boolean publishToCT) throws IOException {
        GeneralNames names = CertTools.getGeneralNamesFromExtension(subAltNameExt);
        GeneralName[] gns = names != null ? names.getNames() : new GeneralName[0];
        boolean sanEdited = false;
        ASN1EncodableVector nrOfRecactedLables = new ASN1EncodableVector();
        for (int j = 0; j < gns.length; j++) {
            GeneralName generalName = gns[j];
            // Look for DNS name
            if (generalName.getTagNo() == 2) {
                final String str = CertTools.getGeneralNameString(2, generalName.getName());
                if (StringUtils.contains(str, "(") && StringUtils.contains(str, ")")) { // if it contains parts that should be redacted
                    // Remove the parentheses from the SubjectAltName that will end up on the certificate
                    String certBuilderDNSValue = StringUtils.remove(str, "dNSName=");
                    certBuilderDNSValue = StringUtils.remove(certBuilderDNSValue, '(');
                    certBuilderDNSValue = StringUtils.remove(certBuilderDNSValue, ')');
                    // Replace the old value with the new
                    gns[j] = new GeneralName(2, new DERIA5String(certBuilderDNSValue));
                    sanEdited = true;
                    if (publishToCT) {
                        String redactedLable = StringUtils.substring(str, StringUtils.indexOf(str, "("), StringUtils.lastIndexOf(str, ")") + 1); // tex. (top.secret).domain.se => redactedLable = (top.secret) aka. including the parentheses
                        nrOfRecactedLables.add(new ASN1Integer(StringUtils.countMatches(redactedLable, ".") + 1));
                    }
                } else {
                    nrOfRecactedLables.add(new ASN1Integer(0));
                }
            }
            // Look for rfc822Name
            if (generalName.getTagNo() == 1) {
                final String str = CertTools.getGeneralNameString(1, generalName.getName());
                if (StringUtils.contains(str, "\\+")) { // if it contains a '+' character that should be unescaped
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
        if (publishToCT && sanEdited) {
            ASN1Encodable seq = new DERSequence(nrOfRecactedLables);
            gen.addExtension(new ASN1ObjectIdentifier(CertTools.id_ct_redacted_domains), false, seq);
        }

        return gen;
    }

    @Override
    public X509CRLHolder generateCRL(CryptoToken cryptoToken, int crlPartitionIndex, Collection<RevokedCertInfo> certs, int crlnumber) {
        String msg = intres.getLocalizedMessage("createcrl.nocrlcreate", "SSH");
        log.info(msg);
        return null;
    }

    @Override
    public X509CRLHolder generateDeltaCRL(CryptoToken cryptoToken, int crlPartitionIndex, Collection<RevokedCertInfo> certs, int crlNumber,
            int baseCrlNumber) {
        String msg = intres.getLocalizedMessage("createcrl.nocrlcreate", "SSH");
        log.info(msg);
        return null;
    }

    public byte[] createPKCS7(CryptoToken cryptoToken, X509Certificate cert, boolean includeChain) {
        return null;
    }

    public byte[] createPKCS7Rollover(CryptoToken cryptoToken) {
        return null;
    }

    public byte[] createRequest(CryptoToken cryptoToken, Collection<ASN1Encodable> attributes, String signAlg, Certificate cacert,
            int signatureKeyPurpose, CertificateProfile certificateProfile, AvailableCustomCertificateExtensionsConfiguration cceConfig) {
        return null;
    }

    public byte[] createAuthCertSignRequest(CryptoToken cryptoToken, byte[] request) {
        return null;
    }

    public String getCaImplType() {
        return "SSHCA";
    }

    public void createOrRemoveLinkCertificate(CryptoToken cryptoToken, boolean createLinkCertificate, CertificateProfile certProfile,
            AvailableCustomCertificateExtensionsConfiguration cceConfig, Certificate oldCaCert) {
    }

    public float getLatestVersion() {
        return 0.0F;
    }

    /**
     * TODO: Move into common baseclass ECA-9182
     */
    private SubjectPublicKeyInfo verifyAndCorrectSubjectPublicKeyInfo(final PublicKey publicKey) throws IllegalKeyException {
        SubjectPublicKeyInfo pkinfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
        final AlgorithmIdentifier keyAlgId = pkinfo.getAlgorithm();
        if (keyAlgId == null) {
            throw new IllegalKeyException("Public key must have an AlgorithmIdentifier, but it is missing. The public key is invalid.");
        } else if (keyAlgId.getAlgorithm() == null) {
            throw new IllegalKeyException("Public key must have an AlgorithmIdentifier.algorithm OID, but it is missing. The public key is invalid.");
        }
        if (keyAlgId.getAlgorithm().equals(PKCSObjectIdentifiers.rsaEncryption)
                && (keyAlgId.getParameters() == null || !DERNull.INSTANCE.equals(keyAlgId.getParameters()))) {
            // parameters can not be null, and MUST be DERNull
            if (log.isDebugEnabled()) {
                log.debug(
                        "Public key is an RSA key, but algorithmID parameters are null or not DERNull, where it should be DERNull according to RFC3279, modifying parameters to DERNull");
                if (keyAlgId.getParameters() != null) {
                    final String dump = ASN1Dump.dumpAsString(keyAlgId.getParameters());
                    log.debug("Invalid parameters (not null): " + dump);
                }
            }
            final AlgorithmIdentifier newAlgId = new AlgorithmIdentifier(keyAlgId.getAlgorithm(), DERNull.INSTANCE);
            try {
                pkinfo = new SubjectPublicKeyInfo(newAlgId, pkinfo.parsePublicKey());
            } catch (IOException e) {
                throw new IllegalKeyException("RSA public key with invalid AlgorithmIdentifier parameters detected, and we are unable to modify it: ",
                        e);
            }
        } else if (keyAlgId.getAlgorithm().equals(X9ObjectIdentifiers.id_ecPublicKey) && (keyAlgId.getParameters() == null)) {
            throw new IllegalKeyException("EC public key without AlgorithmIdentifier parameters, invalid public key.");
        }
        return pkinfo;
    }

    /* (non-Javadoc)
     * @see org.cesecore.certificates.ca.X509CA#getSerialNumberOctetSize()
     */
    @Override
    public Integer getSerialNumberOctetSize() {
        return (Integer) getMapValueWithDefault(SERIALNUMBEROCTETSIZE, CesecoreConfiguration.getSerialNumberOctetSizeForNewCa());
    }

    /* (non-Javadoc)
     * @see org.cesecore.certificates.ca.X509CA#setCaSerialNumberOctetSize(int)
     */
    @Override
    public void setCaSerialNumberOctetSize(int serialNumberOctetSize) {
        data.put(SERIALNUMBEROCTETSIZE, serialNumberOctetSize);
    }

    @Override
    public boolean getUsePrintableStringSubjectDN() {
        return (Boolean) data.get(USEPRINTABLESTRINGSUBJECTDN);
    }

    @Override
    public void setUsePrintableStringSubjectDN(boolean useprintablestring) {
        data.put(USEPRINTABLESTRINGSUBJECTDN, useprintablestring);
    }

    /* (non-Javadoc)
     * @see org.cesecore.certificates.ca.X509CA#getUseLdapDNOrder()
     */
    @Override
    public boolean getUseLdapDNOrder() {
        return (Boolean) data.get(USELDAPDNORDER);
    }

    /* (non-Javadoc)
     * @see org.cesecore.certificates.ca.X509CA#setUseLdapDNOrder(boolean)
     */
    @Override
    public void setUseLdapDNOrder(boolean useldapdnorder) {
        data.put(USELDAPDNORDER, useldapdnorder);
    }
}
