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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Properties;

import org.bouncycastle.operator.OperatorCreationException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CADoesntExistsException;
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
import org.cesecore.certificates.certificate.CertificateCreateSessionRemote;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.request.SimpleRequestMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenManagementProxySessionRemote;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.CryptoTokenManagementSessionTest;
import org.cesecore.keys.token.CryptoTokenNameInUseException;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.IllegalCryptoTokenException;
import org.cesecore.keys.token.SoftCryptoToken;
import org.cesecore.keys.token.p11.exception.NoSuchSlotException;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.StringTools;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.KeyRecoveryCAServiceInfo;
import org.ejbca.cvc.AccessRightEnum;
import org.ejbca.cvc.AuthorizationRoleEnum;
import org.ejbca.cvc.CAReferenceField;
import org.ejbca.cvc.CVCertificate;
import org.ejbca.cvc.CardVerifiableCertificate;
import org.ejbca.cvc.CertificateGenerator;
import org.ejbca.cvc.HolderReferenceField;
import org.ejbca.cvc.exception.ConstructionException;

/**
 * Common class for test classes which need to create a CA.   
 * 
 * @version $Id$
 *
 */
public abstract class CaTestUtils {

    
    /**
     * Creates and stores a simple X509 CA 
     * 
     * @param authenticationToken
     * @param cryptoTokenName
     * @param cadn
     */
    public static CA createX509Ca(AuthenticationToken authenticationToken, String cryptoTokenName, String caName, String cadn)
            throws CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException, CryptoTokenNameInUseException,
            AuthorizationDeniedException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException,
            SignatureException, KeyStoreException, CertificateException, InvalidAlgorithmException, IllegalStateException, OperatorCreationException,
            IOException, CAExistsException, IllegalCryptoTokenException {
        CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
        CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE
                .getRemoteSession(CryptoTokenManagementSessionRemote.class);
        CryptoTokenManagementProxySessionRemote cryptoTokenManagementProxySession = EjbRemoteHelper.INSTANCE
                .getRemoteSession(CryptoTokenManagementProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);

        final Properties cryptoTokenProperties = new Properties();
        cryptoTokenProperties.setProperty(CryptoToken.AUTOACTIVATE_PIN_PROPERTY, "foo123");
        int cryptoTokenId;
        if (!cryptoTokenManagementProxySession.isCryptoTokenNameUsed(cryptoTokenName)) {
            try {
                cryptoTokenId = cryptoTokenManagementSession.createCryptoToken(authenticationToken, cryptoTokenName, SoftCryptoToken.class.getName(),
                        cryptoTokenProperties, null, null);
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

        final CryptoToken cryptoToken = cryptoTokenManagementProxySession.getCryptoToken(cryptoTokenId);
        final CA x509Ca = createX509Ca(cryptoToken, caName, cadn);
        caSession.addCA(authenticationToken, x509Ca);
        return x509Ca;
    }

    
    private static CA createX509Ca(final CryptoToken cryptoToken, String caName, String cadn) throws InvalidKeyException, NoSuchAlgorithmException,
            NoSuchProviderException, InvalidAlgorithmParameterException, SignatureException, KeyStoreException, CertificateException,
            CryptoTokenOfflineException, IOException, InvalidAlgorithmException, IllegalStateException, OperatorCreationException {
        Properties caTokenProperties = new Properties();
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, CAToken.SOFTPRIVATEDECKEYALIAS);
        CAToken catoken = new CAToken(cryptoToken.getId(), caTokenProperties);
        // Set key sequence so that next sequence will be 00001 (this is the default though so not really needed here)
        catoken.setKeySequence(CAToken.DEFAULT_KEYSEQUENCE);
        catoken.setKeySequenceFormat(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);
        catoken.setSignatureAlgorithm(AlgorithmConstants.SIGALG_SHA256_WITH_RSA);
        catoken.setEncryptionAlgorithm(AlgorithmConstants.SIGALG_SHA256_WITH_RSA);
        // No extended services
        X509CAInfo cainfo = new X509CAInfo(cadn, caName, CAConstants.CA_ACTIVE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, 3650, CAInfo.SELFSIGNED, null, catoken);
        cainfo.setDescription("JUnit RSA CA");
        X509CA x509ca = new X509CA(cainfo);
        x509ca.setCAToken(catoken);
        // A CA certificate
        X509Certificate cacert = CertTools.genSelfCert(cadn, 10L, "1.1.1.1",
                cryptoToken.getPrivateKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN)),
                cryptoToken.getPublicKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN)),
                "SHA256WithRSA", true);
        assertNotNull(cacert);
        Collection<Certificate> cachain = new ArrayList<Certificate>();
        cachain.add(cacert);
        x509ca.setCertificateChain(cachain);
        // Now our CA should be operational
        return x509ca;
    }
    
    public static void removeCA(AuthenticationToken authenticationToken, String cryptoTokenName, String caName) throws AuthorizationDeniedException, CADoesntExistsException {
        CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
        CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE
                .getRemoteSession(CryptoTokenManagementSessionRemote.class);
        int caid = caSession.getCAInfo(authenticationToken, caName).getCAId();
        caSession.removeCA(authenticationToken, caid);
        int cryptoTokenId = cryptoTokenManagementSession.getIdFromName(cryptoTokenName);
        cryptoTokenManagementSession.deleteCryptoToken(authenticationToken, cryptoTokenId);
    }


    public static X509CA createTestX509CAOptionalGenKeys(String cadn, char[] tokenpin, boolean genKeys, boolean pkcs11) throws Exception {
        return CaTestUtils.createTestX509CAOptionalGenKeys(cadn, tokenpin, genKeys, pkcs11, "1024", -1);
    }


    public static X509CA createTestX509CAOptionalGenKeys(String cadn, char[] tokenpin, boolean genKeys, boolean pkcs11, final String keyspec,
            int keyusage) throws Exception {
        // Create catoken
        CryptoTokenManagementProxySessionRemote cryptoTokenManagementProxySession = EjbRemoteHelper.INSTANCE.getRemoteSession(
                CryptoTokenManagementProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
        int cryptoTokenId = CryptoTokenManagementSessionTest.createCryptoTokenForCA(null, tokenpin, genKeys, pkcs11, cadn, keyspec);
        final CAToken catoken = createCaToken(cryptoTokenId, AlgorithmConstants.SIGALG_SHA256_WITH_RSA, AlgorithmConstants.SIGALG_SHA256_WITH_RSA);
        final List<ExtendedCAServiceInfo> extendedCaServices = new ArrayList<ExtendedCAServiceInfo>(2);
        extendedCaServices.add(new KeyRecoveryCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE));
        String caname = CertTools.getPartFromDN(cadn, "CN");
        boolean ldapOrder = !CertTools.isDNReversed(cadn);
        X509CAInfo cainfo = new X509CAInfo(cadn, caname, CAConstants.CA_ACTIVE, CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, 3650,
                CAInfo.SELFSIGNED, null, catoken);
        cainfo.setDescription("JUnit RSA CA");
        cainfo.setExtendedCAServiceInfos(extendedCaServices);
        cainfo.setUseLdapDnOrder(ldapOrder);
        cainfo.setCmpRaAuthSecret("foo123");
        X509CA x509ca = new X509CA(cainfo);
        x509ca.setCAToken(catoken);
        // A CA certificate
        Collection<Certificate> cachain = new ArrayList<Certificate>();
        if (genKeys) {
            final PublicKey publicKey = cryptoTokenManagementProxySession.getPublicKey(cryptoTokenId,
                    catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
            final PrivateKey privateKey = cryptoTokenManagementProxySession.getPrivateKey(cryptoTokenId,
                    catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
            final String keyalg = AlgorithmTools.getKeyAlgorithm(publicKey);
            String sigalg = AlgorithmConstants.SIGALG_SHA256_WITH_RSA;
            if (keyalg.equals(AlgorithmConstants.KEYALGORITHM_DSA)) {
                sigalg = AlgorithmConstants.SIGALG_SHA1_WITH_DSA;
            } else if (keyalg.equals(AlgorithmConstants.KEYALGORITHM_ECDSA)) {
                sigalg = AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA;
            }
            X509Certificate cacert = null;
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
        // Now our CA should be operational, if we generated keys, otherwise we will have to generate is, and a CA certificate later.
        return x509ca;
    }


    /** @return a CAToken for referencing the specified CryptoToken. */
    public static CAToken createCaToken(final int cryptoTokenId, String sigAlg, String encAlg) {
        // Create CAToken (what key in the CryptoToken should be used for what)
        final Properties caTokenProperties = new Properties();
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, CAToken.SOFTPRIVATEDECKEYALIAS);
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
        final int cryptoTokenId = CryptoTokenManagementSessionTest.createCryptoTokenForCA(null, tokenpin, true, pkcs11, cadn, "1024");
        final CAToken catoken = createCaToken(cryptoTokenId, AlgorithmConstants.SIGALG_SHA256_WITH_RSA, AlgorithmConstants.SIGALG_SHA256_WITH_RSA);
        // No extended services
        final List<ExtendedCAServiceInfo> extendedcaservices = new ArrayList<ExtendedCAServiceInfo>(0);
        CVCCAInfo cainfo = new CVCCAInfo(cadn, "TESTCVC", CAConstants.CA_ACTIVE,
            CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, 3650, CAInfo.SELFSIGNED, null, catoken);
        cainfo.setDescription("JUnit RSA CVC CA");
        cainfo.setExtendedCAServiceInfos(extendedcaservices);
        CvcCA cvcca = CvcCA.getInstance(cainfo);
        cvcca.setCAToken(catoken);
        // A CA certificate
        CAReferenceField caRef = new CAReferenceField("SE", "CAREF001", "00000");
        HolderReferenceField holderRef = new HolderReferenceField("SE", "CAREF001", "00000");
        final PublicKey publicKey = cryptoTokenManagementProxySession.getPublicKey(cryptoTokenId, catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
        final PrivateKey privateKey = cryptoTokenManagementProxySession.getPrivateKey(cryptoTokenId, catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
        CVCertificate cv = CaTestUtils.createTestCvcCertificate(publicKey, privateKey, caRef, holderRef, "SHA256WithRSA", AuthorizationRoleEnum.CVCA,
                cryptoTokenManagementProxySession.getSignProviderName(cryptoTokenId));
        CardVerifiableCertificate cvccacert = new CardVerifiableCertificate(cv);
        Certificate cacert = cvccacert;
        assertNotNull(cacert);
        Collection<Certificate> cachain = new ArrayList<Certificate>();
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


    public static X509CA createTestX509CA(String cadn, char[] tokenpin, boolean pkcs11) throws Exception {
        return createTestX509CAOptionalGenKeys(cadn, tokenpin, true, pkcs11);
    }


    public static X509CA createTestX509CA(String cadn, char[] tokenpin, boolean pkcs11, int keyusage) throws Exception {
        return createTestX509CAOptionalGenKeys(cadn, tokenpin, true, pkcs11, "1024", keyusage);
    }


    public static X509CA createTestX509CA(String cadn, char[] tokenpin, boolean pkcs11, final String keyspec) throws Exception {
        return createTestX509CAOptionalGenKeys(cadn, tokenpin, true, pkcs11, keyspec, -1);
    }
    
    public static void addCAUseSessionBeanToGenerateKeys2(CA ca, String cadn, String tokenpwd) throws Exception {
        CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
        CertificateCreateSessionRemote certificateCreateSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateCreateSessionRemote.class);
        CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE
                .getRemoteSession(CryptoTokenManagementSessionRemote.class);
        InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(
                InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
        SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);

        AuthenticationToken authenticationToken = new TestAlwaysAllowLocalAuthenticationToken("addCAUseSessionBeanToGenerateKeys2");
        // Generate CA keys
        Certificate cert = null;
        try {
            CAToken caToken = ca.getCAToken();
            caToken.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, "signKeyAlias");
            caToken.setProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, "signKeyAlias");
            ca.setCAToken(caToken);
            caSession.addCA(authenticationToken, ca);
            final int cryptoTokenId = caToken.getCryptoTokenId();
            cryptoTokenManagementSession.createKeyPair(authenticationToken, cryptoTokenId, "signKeyAlias", "1024");
            PublicKey pubK = cryptoTokenManagementSession.getPublicKey(authenticationToken, cryptoTokenId, "signKeyAlias");
            assertNotNull(pubK);
            // Now create a CA certificate
            CAInfo info = caSession.getCAInfo(authenticationToken, ca.getCAId());
            Collection<Certificate> certs = info.getCertificateChain();
            assertEquals(0, certs.size());

            EndEntityInformation user = new EndEntityInformation("casessiontestca", ca.getSubjectDN(), ca.getCAId(), null, null, new EndEntityType(
                    EndEntityTypes.ENDUSER), 0, CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, EndEntityConstants.TOKEN_USERGEN, 0, null);
            user.setStatus(EndEntityConstants.STATUS_NEW);
            user.setPassword("foo123");
            SimpleRequestMessage req = new SimpleRequestMessage(pubK, user.getUsername(), user.getPassword());
            X509ResponseMessage resp = (X509ResponseMessage) certificateCreateSession.createCertificate(authenticationToken, user, req,
                    org.cesecore.certificates.certificate.request.X509ResponseMessage.class, signSession.fetchCertGenParams());
            cert = (X509Certificate) resp.getCertificate();
            assertNotNull("Failed to create certificate", cert);
            // Verifies with CA token?
            cert.verify(pubK);
            // Add the new CA cert
            certs.add(cert);
            info.setCertificateChain(certs);
            caSession.editCA(authenticationToken, info);

            // Get it again
            CAInfo info1 = caSession.getCAInfo(authenticationToken, ca.getCAId());
            Collection<Certificate> certs1 = info1.getCertificateChain();
            assertEquals(1, certs1.size());
            Certificate cert1 = certs1.iterator().next();
            cert1.verify(pubK);
        } finally {
            // Since this could be a P11 slot, we need to clean up the actual keys in the slot, not just delete the token
            int cryptoTokenId = ca.getCAToken().getCryptoTokenId();
            final String signKeyAlias = ca.getCAToken().getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN);
            cryptoTokenManagementSession.removeKeyPair(authenticationToken, cryptoTokenId, signKeyAlias);
            CryptoTokenManagementSessionTest.removeCryptoToken(null, cryptoTokenId);
            caSession.removeCA(authenticationToken, ca.getCAId());
            internalCertificateStoreSession.removeCertificate(cert);
        }
    }
}
