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
package org.cesecore;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Properties;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.operator.OperatorCreationException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CAExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CVCCAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.CvcCA;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenManagementProxySessionRemote;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.CryptoTokenNameInUseException;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.keys.token.SoftCryptoToken;
import org.cesecore.keys.token.p11.exception.NoSuchSlotException;
import org.cesecore.util.CertTools;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.StringTools;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.KeyRecoveryCAServiceInfo;
import org.ejbca.cvc.AccessRightEnum;
import org.ejbca.cvc.AuthorizationRoleEnum;
import org.ejbca.cvc.CAReferenceField;
import org.ejbca.cvc.CVCertificate;
import org.ejbca.cvc.CardVerifiableCertificate;
import org.ejbca.cvc.CertificateGenerator;
import org.ejbca.cvc.HolderReferenceField;
import org.ejbca.cvc.exception.ConstructionException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

/**
 * Common class for test classes which need to create a CA.
 *
 * @version $Id$
 *
 */
public abstract class CaTestUtils {
    
    private static final Logger log = Logger.getLogger(CaTestUtils.class);

    /**
     * Creates and stores a simple X509 Root CA
     *
     * @param authenticationToken Authentication token (usually an always allow token)
     * @param cryptoTokenName Name of new Crypto Token
     * @param caName Name of new CA
     * @param cadn Subject DN of new CA
     */
    public static X509CA createX509Ca(final AuthenticationToken authenticationToken, final String cryptoTokenName, final String caName, final String cadn)
            throws CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException, CryptoTokenNameInUseException,
            AuthorizationDeniedException, InvalidKeyException, InvalidAlgorithmParameterException, CertificateException, InvalidAlgorithmException,
            IllegalStateException, OperatorCreationException, CAExistsException {
        final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
        final CryptoTokenManagementProxySessionRemote cryptoTokenManagementProxySession = EjbRemoteHelper.INSTANCE
                .getRemoteSession(CryptoTokenManagementProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
        final int cryptoTokenId = initCryptoTokenId(cryptoTokenManagementProxySession, authenticationToken, cryptoTokenName);
        final CryptoToken cryptoToken = cryptoTokenManagementProxySession.getCryptoToken(cryptoTokenId);
        final X509CA x509Ca = createX509Ca(cryptoToken, caName, cadn);
        caSession.addCA(authenticationToken, x509Ca);
        // Now our CA should be operational
        return x509Ca;
    }

    private static X509CA createX509Ca(final CryptoToken cryptoToken, String caName, String cadn) throws CertificateException,
            CryptoTokenOfflineException, InvalidAlgorithmException, IllegalStateException, OperatorCreationException {
        CAToken catoken = createCaToken(cryptoToken.getId(), AlgorithmConstants.SIGALG_SHA256_WITH_RSA, AlgorithmConstants.SIGALG_SHA256_WITH_RSA);
        // No extended services
        X509CAInfo cainfo = new X509CAInfo(cadn, caName, CAConstants.CA_ACTIVE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, "3650d", CAInfo.SELFSIGNED, null, catoken);
        cainfo.setDescription("JUnit RSA CA");
        X509CA x509ca = new X509CA(cainfo);
        x509ca.setCAToken(catoken);
        // A CA certificate
        X509Certificate cacert = CertTools.genSelfCert(cadn, 10L, "1.1.1.1",
                cryptoToken.getPrivateKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN)),
                cryptoToken.getPublicKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN)),
                "SHA256WithRSA", true);
        assertNotNull(cacert);
        List<Certificate> cachain = new ArrayList<>();
        cachain.add(cacert);
        x509ca.setCertificateChain(cachain);
        return x509ca;
    }

    /** Removes a CA, and it's associated certificate and Crypto Token. */
    public static void removeCa(AuthenticationToken authenticationToken, String cryptoTokenName, String caName) throws AuthorizationDeniedException {
        CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
        CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CryptoTokenManagementSessionRemote.class);
        InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
        CAInfo caInfo = caSession.getCAInfo(authenticationToken, caName);
        if (caInfo != null) {
            caSession.removeCA(authenticationToken, caInfo.getCAId());
            internalCertificateStoreSession.removeCertificatesBySubject(caInfo.getSubjectDN());
        }

        Integer cryptoTokenId = cryptoTokenManagementSession.getIdFromName(cryptoTokenName);
        if (cryptoTokenId != null) {
            cryptoTokenManagementSession.deleteCryptoToken(authenticationToken, cryptoTokenId);
        }
    }

    /**
     * Removes a CA, and it's associated certificate and Crypto Token.
     * See {@link #removeCa(AuthenticationToken, String, String)}, which is more robust, in case the test got aborted for some reason.
     */
    public static void removeCa(AuthenticationToken authenticationToken, CAInfo caInfo) throws AuthorizationDeniedException {
        CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
        CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE
                .getRemoteSession(CryptoTokenManagementSessionRemote.class);
        InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
        caSession.removeCA(authenticationToken, caInfo.getCAId());
        cryptoTokenManagementSession.deleteCryptoToken(authenticationToken, caInfo.getCAToken().getCryptoTokenId());
        internalCertificateStoreSession.removeCertificatesBySubject(caInfo.getSubjectDN());
    }

    /** Creates a CA object, but does not actually add the CA to EJBCA. */
    public static X509CA createTestX509CAOptionalGenKeys(String cadn, char[] tokenpin, boolean genKeys, boolean pkcs11)
            throws CertificateParsingException, CryptoTokenOfflineException, OperatorCreationException {
        return CaTestUtils.createTestX509CAOptionalGenKeys(cadn, tokenpin, genKeys, pkcs11, "1024", -1);
    }

    /** Creates a CA object, but does not actually add the CA to EJBCA. */
    public static X509CA createTestX509CAOptionalGenKeys(String cadn, char[] tokenpin, boolean genKeys, boolean pkcs11, final String keyspec,
            int keyusage) throws CryptoTokenOfflineException, CertificateParsingException, OperatorCreationException {
        return createTestX509CAOptionalGenKeys(cadn, tokenpin, genKeys, pkcs11, CAInfo.SELFSIGNED, keyspec, keyusage);
    }

    /** Creates a CA object, but does not actually add the CA to EJBCA. */
    public static X509CA createTestX509CAOptionalGenKeys(String cadn, char[] tokenpin, boolean genKeys, boolean pkcs11, int signedBy, final String keyspec,
            int keyusage) throws CryptoTokenOfflineException, CertificateParsingException, OperatorCreationException {
        // Create catoken
        CryptoTokenManagementProxySessionRemote cryptoTokenManagementProxySession = EjbRemoteHelper.INSTANCE.getRemoteSession(
                CryptoTokenManagementProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
        int cryptoTokenId = CryptoTokenTestUtils.createCryptoTokenForCA(null, tokenpin, genKeys, pkcs11, cadn, keyspec);
        final CAToken catoken = createCaToken(cryptoTokenId, AlgorithmConstants.SIGALG_SHA256_WITH_RSA, AlgorithmConstants.SIGALG_SHA256_WITH_RSA);
        final List<ExtendedCAServiceInfo> extendedCaServices = new ArrayList<>(2);
        extendedCaServices.add(new KeyRecoveryCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE));
        String caname = CertTools.getPartFromDN(cadn, "CN");
        boolean ldapOrder = !CertTools.isDNReversed(cadn);
        X509CAInfo cainfo = new X509CAInfo(cadn, caname, CAConstants.CA_ACTIVE, CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, "3650d",
                signedBy, null, catoken);
        cainfo.setDescription("JUnit RSA CA");
        cainfo.setExtendedCAServiceInfos(extendedCaServices);
        cainfo.setUseLdapDnOrder(ldapOrder);
        cainfo.setCmpRaAuthSecret("foo123");
        X509CA x509ca = new X509CA(cainfo);
        try {
            x509ca.setCAToken(catoken);
        } catch (InvalidAlgorithmException e) {
            throw new IllegalStateException(e);
        }
        // A CA certificate
        List<Certificate> cachain = new ArrayList<>();
        if (genKeys) {
            final PublicKey publicKey = cryptoTokenManagementProxySession.getPublicKey(cryptoTokenId,
                    catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN)).getPublicKey();
            final PrivateKey privateKey = cryptoTokenManagementProxySession.getPrivateKey(cryptoTokenId,
                    catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
            final String keyalg = AlgorithmTools.getKeyAlgorithm(publicKey);
            String sigalg = AlgorithmConstants.SIGALG_SHA256_WITH_RSA;
            if (keyalg.equals(AlgorithmConstants.KEYALGORITHM_DSA)) {
                sigalg = AlgorithmConstants.SIGALG_SHA1_WITH_DSA;
            } else if (keyalg.equals(AlgorithmConstants.KEYALGORITHM_ECDSA)) {
                sigalg = AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA;
            }
            X509Certificate cacert;
            if (keyusage == -1) {
                cacert = CertTools.genSelfCert(cadn, 10L, "1.1.1.1", privateKey, publicKey, sigalg, true,
                        cryptoTokenManagementProxySession.getSignProviderName(cryptoTokenId), ldapOrder);
            } else {
                cacert = CertTools.genSelfCertForPurpose(cadn, 10L, "1.1.1.1", privateKey, publicKey, sigalg, true, keyusage, ldapOrder);
            }
            assertNotNull(cacert);
            cachain.add(cacert);
        }
        x509ca.setCertificateChain(cachain);
        // Now our CA should be operational, if we generated keys, otherwise we will have to generate it, and a CA certificate later.
        return x509ca;
    }

    /** Creates and adds a Sub CA to EJBCA. */
    public static CAInfo createTestX509SubCAGenKeys(AuthenticationToken admin, String cadn, char[] tokenpin, int signedBy, final String keyspec) throws CryptoTokenOfflineException, CAExistsException, InvalidAlgorithmException, AuthorizationDeniedException {
        // Create catoken
        int cryptoTokenId = CryptoTokenTestUtils.createCryptoTokenForCA(null, tokenpin, true, false, cadn, keyspec);
        final CAToken catoken = createCaToken(cryptoTokenId, AlgorithmConstants.SIGALG_SHA256_WITH_RSA, AlgorithmConstants.SIGALG_SHA256_WITH_RSA);
        final List<ExtendedCAServiceInfo> extendedCaServices = new ArrayList<>(2);
        extendedCaServices.add(new KeyRecoveryCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE));
        String caname = CertTools.getPartFromDN(cadn, "CN");
        X509CAInfo cainfo = new X509CAInfo(cadn, caname, CAConstants.CA_ACTIVE, CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA, "3650d",
                signedBy, null, catoken);
        cainfo.setDescription("JUnit RSA CA");
        cainfo.setExtendedCAServiceInfos(extendedCaServices);
        boolean ldapOrder = !CertTools.isDNReversed(cadn);
        cainfo.setUseLdapDnOrder(ldapOrder);
        cainfo.setCmpRaAuthSecret("foo123");
        X509CA x509ca = new X509CA(cainfo);
        try {
            x509ca.setCAToken(catoken);
        } catch (InvalidAlgorithmException e) {
            throw new IllegalStateException(e);
        }
        // Create the SubCA, signed by Root designated by "signedby"
        CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
        CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
        caAdminSession.createCA(admin, cainfo);
        CAInfo newinfo = caSession.getCAInfo(admin, caname);
        Collection<Certificate> newcerts = newinfo.getCertificateChain();
        assertNotNull(newcerts);
        assertEquals("A subCA should have two certificates in the certificate chain", 2, newcerts.size());
        // Now our CA should be operational
        return newinfo;
    }

    /** @return a CAToken for referencing the specified CryptoToken. */
    public static CAToken createCaToken(final int cryptoTokenId, String sigAlg, String encAlg) {
        // Create CAToken (what key in the CryptoToken should be used for what)
        final Properties caTokenProperties = new Properties();
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, CAToken.SOFTPRIVATEDECKEYALIAS);
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING_NEXT , CAToken.SOFTPRIVATEDECKEYALIAS);
        final CAToken catoken = new CAToken(cryptoTokenId, caTokenProperties);
        catoken.setSignatureAlgorithm(sigAlg);
        catoken.setEncryptionAlgorithm(encAlg);
        catoken.setKeySequence(CAToken.DEFAULT_KEYSEQUENCE);
        catoken.setKeySequenceFormat(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);
        return catoken;
    }


    public static CvcCA createTestCVCCA(String cadn, char[] tokenpin, boolean pkcs11) throws Exception {
        CryptoTokenManagementProxySessionRemote cryptoTokenManagementProxySession = EjbRemoteHelper.INSTANCE.getRemoteSession(CryptoTokenManagementProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
        // Create catoken
        final int cryptoTokenId = CryptoTokenTestUtils.createCryptoTokenForCA(null, tokenpin, true, pkcs11, cadn, "1024");
        final CAToken catoken = createCaToken(cryptoTokenId, AlgorithmConstants.SIGALG_SHA256_WITH_RSA, AlgorithmConstants.SIGALG_SHA256_WITH_RSA);
        // No extended services
        final List<ExtendedCAServiceInfo> extendedcaservices = new ArrayList<>(0);
        CVCCAInfo cainfo = new CVCCAInfo(cadn, "TESTCVC", CAConstants.CA_ACTIVE,
            CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, "3650d", CAInfo.SELFSIGNED, null, catoken);
        cainfo.setDescription("JUnit RSA CVC CA");
        cainfo.setExtendedCAServiceInfos(extendedcaservices);
        CvcCA cvcca = CvcCA.getInstance(cainfo);
        cvcca.setCAToken(catoken);
        // A CA certificate
        CAReferenceField caRef = new CAReferenceField("SE", "CAREF001", "00000");
        HolderReferenceField holderRef = new HolderReferenceField("SE", "CAREF001", "00000");
        final PublicKey publicKey = cryptoTokenManagementProxySession.getPublicKey(cryptoTokenId, catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN)).getPublicKey();
        final PrivateKey privateKey = cryptoTokenManagementProxySession.getPrivateKey(cryptoTokenId, catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
        CVCertificate cv = CaTestUtils.createTestCvcCertificate(publicKey, privateKey, caRef, holderRef, "SHA256WithRSA", AuthorizationRoleEnum.CVCA,
                cryptoTokenManagementProxySession.getSignProviderName(cryptoTokenId));
        Certificate cacert = new CardVerifiableCertificate(cv);
        assertNotNull(cacert);
        List<Certificate> cachain = new ArrayList<>();
        cachain.add(cacert);
        cvcca.setCertificateChain(cachain);
        // Now our CA should be operational
        return cvcca;
    }


    public static CVCertificate createTestCvcCertificate(PublicKey publicKey, PrivateKey privateKey, CAReferenceField caRef,
            HolderReferenceField holderRef, String algorithm, AuthorizationRoleEnum role, String provider) throws IOException,
            NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException, ConstructionException {
        // Skapa default-datum
        Calendar cal1 = Calendar.getInstance();
        Date validFrom = cal1.getTime();

        Calendar cal2 = Calendar.getInstance();
        cal2.add(Calendar.MONTH, 3);
        Date validTo = cal2.getTime();
        return CertificateGenerator.createCertificate(publicKey, privateKey, algorithm, caRef, holderRef, role,
                AccessRightEnum.READ_ACCESS_DG3_AND_DG4, validFrom, validTo, provider);
    }

    /** Creates a CA object, but does not actually add the CA to EJBCA. */
    public static X509CA createTestX509CA(String cadn, char[] tokenpin, boolean pkcs11) throws CertificateParsingException,
            CryptoTokenOfflineException, OperatorCreationException {
        return createTestX509CAOptionalGenKeys(cadn, tokenpin, true, pkcs11);
    }

    /** Creates a CA object, but does not actually add the CA to EJBCA. */
    public static X509CA createTestX509CA(String cadn, char[] tokenpin, boolean pkcs11, int keyusage) throws CertificateParsingException,
            CryptoTokenOfflineException, OperatorCreationException {
        return createTestX509CAOptionalGenKeys(cadn, tokenpin, true, pkcs11, "1024", keyusage);
    }

    /** Creates a CA object, but does not actually add the CA to EJBCA. */
    public static X509CA createTestX509CA(String cadn, char[] tokenpin, boolean pkcs11, int signedBy, int keyusage) throws CertificateParsingException,
            CryptoTokenOfflineException, OperatorCreationException {
        return createTestX509CAOptionalGenKeys(cadn, tokenpin, true, pkcs11, signedBy, "1024", keyusage);
    }

    /** Creates a CA object, but does not actually add the CA to EJBCA. */
    public static X509CA createTestX509CA(String cadn, int signedBy, char[] tokenpin, boolean pkcs11, int keyusage) throws CertificateParsingException,
            CryptoTokenOfflineException, OperatorCreationException {
        return createTestX509CAOptionalGenKeys(cadn, tokenpin, true, pkcs11, "1024", keyusage);
    }

    /** Creates a CA object, but does not actually add the CA to EJBCA. */
    public static X509CA createTestX509CA(String cadn, char[] tokenpin, boolean pkcs11, final String keyspec) throws CertificateParsingException,
            CryptoTokenOfflineException, OperatorCreationException {
        return createTestX509CAOptionalGenKeys(cadn, tokenpin, true, pkcs11, keyspec, -1);
    }

    /**
     * Creates and stores a simple X509 Root Throw-away CA
     *
     * @param authenticationToken Authentication token (usually an always allow token)
     * @param cryptoTokenName Name of new Crypto Token
     * @param caName Name of new CA
     * @param cadn Subject DN of new CA
     * @param defaultCertificateProfileId Default CA profile id
     */
    public static CA createX509ThrowAwayCa(final AuthenticationToken authenticationToken, final String cryptoTokenName, final String caName, final String cadn, final int defaultCertificateProfileId) throws Exception {
        final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
        final CryptoTokenManagementProxySessionRemote cryptoTokenManagementProxySession = EjbRemoteHelper.INSTANCE.getRemoteSession(CryptoTokenManagementProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
        final int cryptoTokenId = initCryptoTokenId(cryptoTokenManagementProxySession, authenticationToken, cryptoTokenName);
        final CryptoToken cryptoToken = cryptoTokenManagementProxySession.getCryptoToken(cryptoTokenId);
        final CA x509Ca = createX509ThrowAwayCa(cryptoToken, caName, cadn, defaultCertificateProfileId);
        caSession.addCA(authenticationToken, x509Ca);
        // Now our CA should be operational
        return x509Ca;
    }

    private static CA createX509ThrowAwayCa(final CryptoToken cryptoToken, final String caName, final String caDn, final int defaultCertificateProfileId) throws Exception {
        CAToken caToken = createCaToken(cryptoToken.getId(), AlgorithmConstants.SIGALG_SHA256_WITH_RSA, AlgorithmConstants.SIGALG_SHA256_WITH_RSA);
        // Set useNoConflictCertificateData, defaultCertprofileId, _useUserStorage and _useCertificateStorage to false
        X509CAInfo cainfo =  new X509CAInfo.X509CAInfoBuilder()
                .setSubjectDn(caDn)
                .setName(caName)
                .setStatus(CAConstants.CA_ACTIVE)
                .setCertificateProfileId(CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA)
                .setDefaultCertProfileId(defaultCertificateProfileId)
                .setUseNoConflictCertificateData(true)
                .setEncodedValidity("3650d")
                .setSignedBy(CAInfo.SELFSIGNED)
                .setCertificateChain(null)
                .setCaToken(caToken)
                .setCrlIssueInterval(0L)
                .setUseUserStorage(false)
                .setUseCertificateStorage(false)
                .setAcceptRevocationNonExistingEntry(true)
                .setCaSerialNumberOctetSize(20)
                .build();
        cainfo.setDescription("JUnit RSA CA");
        X509CA x509ca = new X509CA(cainfo);
        x509ca.setCAToken(caToken);
        // A CA certificate
        X509Certificate cacert = CertTools.genSelfCert(caDn, 10L, "1.1.1.1",
                cryptoToken.getPrivateKey(caToken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN)),
                cryptoToken.getPublicKey(caToken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN)),
                "SHA256WithRSA", true);
        assertNotNull(cacert);
        List<Certificate> cachain = new ArrayList<>();
        cachain.add(cacert);
        x509ca.setCertificateChain(cachain);
        return x509ca;
    }

    private static int initCryptoTokenId(final CryptoTokenManagementProxySessionRemote cryptoTokenManagementProxySession, final AuthenticationToken authenticationToken, final String cryptoTokenName) throws AuthorizationDeniedException, CryptoTokenAuthenticationFailedException, CryptoTokenOfflineException, CryptoTokenNameInUseException, InvalidAlgorithmParameterException, InvalidKeyException {
        CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CryptoTokenManagementSessionRemote.class);
        final Properties cryptoTokenProperties = new Properties();
        cryptoTokenProperties.setProperty(CryptoToken.AUTOACTIVATE_PIN_PROPERTY, "foo123");
        cryptoTokenProperties.setProperty(CryptoToken.ALLOW_EXTRACTABLE_PRIVATE_KEY, Boolean.TRUE.toString());
        int cryptoTokenId;
        if (!cryptoTokenManagementProxySession.isCryptoTokenNameUsed(cryptoTokenName)) {
            try {
                cryptoTokenId = cryptoTokenManagementSession.createCryptoToken(
                        authenticationToken,
                        cryptoTokenName,
                        SoftCryptoToken.class.getName(),
                        cryptoTokenProperties,
                        null,
                        null);
            } catch (NoSuchSlotException e) {
                throw new RuntimeException("Attempted to find a slot for a soft crypto token. This should not happen.");
            }
        } else {
            cryptoTokenId = cryptoTokenManagementSession.getIdFromName(cryptoTokenName);
        }
        if (!cryptoTokenManagementSession.isAliasUsedInCryptoToken(cryptoTokenId, CAToken.SOFTPRIVATESIGNKEYALIAS)) {
            cryptoTokenManagementSession.createKeyPair(authenticationToken, cryptoTokenId, CAToken.SOFTPRIVATESIGNKEYALIAS, "1024");
        }
        if (!cryptoTokenManagementSession.isAliasUsedInCryptoToken(cryptoTokenId, CAToken.SOFTPRIVATEDECKEYALIAS)) {
            cryptoTokenManagementSession.createKeyPair(authenticationToken, cryptoTokenId, CAToken.SOFTPRIVATEDECKEYALIAS, "1024");
        }
        return cryptoTokenId;
    }

    /**
     * Returns the CA that was used to issue the server TLS certificate.
     * By default, this method looks for "ManagementCA" and "AdminCA1", but this may
     * be overridden in systemtests.properties using 'target.servercert.ca'.
     * <p>
     * This CA can be an external CA, so don't assume you can issue certificates from it!
     */
    public static CAInfo getServerCertCaInfo(final AuthenticationToken authenticationToken) {
        return getCaInfo(authenticationToken, SystemTestsConfiguration.getServerCertificateCaNames());
    }

    /**
     * Returns a CA that is trusted by the application server.
     * By default, this method looks for "ManagementCA" and "AdminCA1", but this may
     * be overridden in systemtests.properties using 'target.clientcert.ca'.
     * <p>
     * This CA should be an active CA, that we can issue certificates from.
     */
    public static CAInfo getClientCertCaInfo(final AuthenticationToken authenticationToken) {
        final CAInfo caInfo = getCaInfo(authenticationToken, SystemTestsConfiguration.getClientCertificateCaNames());
        if (caInfo.getStatus() != CAConstants.CA_ACTIVE) {
            log.warn("CA for issuing client certificates is not active. Please check the following CAs or change '" + SystemTestsConfiguration.TARGET_CLIENTCERT_CA +
                    "': '" + StringUtils.join(SystemTestsConfiguration.getClientCertificateCaNames(), "', '") + "'");
        }
        return caInfo;
    }

    /**
     * Returns the first available CA in the list.
     * @throws IllegalStateException if none exist or if access was denied.
     */
    private static CAInfo getCaInfo(final AuthenticationToken authenticationToken, final String[] cas) {
        final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
        for (final String ca : cas) {
            try {
                final CAInfo caInfo = caSession.getCAInfo(authenticationToken, ca);
                if (caInfo != null) {
                    return caInfo;
                }
            } catch (AuthorizationDeniedException e) {
                throw new IllegalStateException("Unable to access CA '" + ca + "': "+ e.getMessage(), e);
            }
        }
        throw new IllegalStateException("Cannot find the required CA. Looked for: '" + StringUtils.join(cas, "', '") +
                "'. Use '" + SystemTestsConfiguration.TARGET_SERVERCERT_CA + "' and '" + SystemTestsConfiguration.TARGET_CLIENTCERT_CA +
                "' in systemtests.properties to override.");
    }

}
