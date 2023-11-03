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
package org.cesecore.certificates.certificate;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectAltPublicKeyInfo;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.ca.IllegalValidityException;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.SignRequestSignatureException;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificate.exception.CustomCertificateSerialNumberException;
import org.cesecore.certificates.certificate.request.PKCS10RequestMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.KeyPairInfo;
import org.cesecore.keys.token.SoftCryptoToken;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.ra.CouldNotRemoveEndEntityException;
import org.ejbca.core.ejb.ra.EndEntityExistsException;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ra.CustomFieldException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestName;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;

import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.StringTools;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.keys.token.CryptoToken;
import com.keyfactor.util.keys.token.CryptoTokenOfflineException;
import com.keyfactor.util.keys.token.KeyGenParams;

/**
 * System tests focusing on the creation of Hybrid X509 Certificates
 */
public class HybridCertificateTest {

    @Rule
    public final TestWatcher traceLogMethodsRule = new TestWatcher() {
        @Override
        protected void starting(final Description description) {
            log.trace(">" + description.getMethodName());
            super.starting(description);
        };

        @Override
        protected void finished(final Description description) {
            log.trace("<" + description.getMethodName());
            super.finished(description);
        }
    };

    @Rule
    public TestName testName = new TestName();

    private static final AuthenticationToken alwaysAllowToken = new TestAlwaysAllowLocalAuthenticationToken(
            new UsernamePrincipal("HybridCertificateTest"));
    private static final Logger log = Logger.getLogger(HybridCertificateTest.class);

    private final CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
    private final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private final CertificateCreateSessionRemote certificateCreateSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CertificateCreateSessionRemote.class);
    private final CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CryptoTokenManagementSessionRemote.class);
    private final EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(EndEntityManagementSessionRemote.class);
    private final InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);

    private int cryptoTokenId;
    private X509CAInfo hybridRoot;

    private final String username = testName.getMethodName() + "_EE";
    private final String subjectDn = "CN=" + username;

    @BeforeClass
    public static void setUpCryptoProvider() {
        CryptoProviderTools.installBCProvider();
    }

    @Before
    public void setUp() throws Exception {
        final String cryptoTokenPin = "foo123";
        final String cryptoTokenName = testName.getMethodName() + "CryptoToken";
        final Properties cryptoTokenProperties = new Properties();
        cryptoTokenProperties.setProperty(SoftCryptoToken.NODEFAULTPWD, "true");
        cryptoTokenProperties.setProperty(CryptoToken.AUTOACTIVATE_PIN_PROPERTY, cryptoTokenPin);
        cryptoTokenId = cryptoTokenManagementSession.createCryptoToken(alwaysAllowToken, cryptoTokenName, SoftCryptoToken.class.getName(),
                cryptoTokenProperties, null, cryptoTokenPin.toCharArray());
        cryptoTokenManagementSession.createKeyPair(alwaysAllowToken, cryptoTokenId, CAToken.SOFTPRIVATESIGNKEYALIAS,
                KeyGenParams.builder("secp256r1").build());
        cryptoTokenManagementSession.createKeyPair(alwaysAllowToken, cryptoTokenId, CAToken.ALTERNATE_SOFT_PRIVATE_SIGNKEY_ALIAS,
                KeyGenParams.builder(AlgorithmConstants.KEYALGORITHM_DILITHIUM2).build());

        final String caDn = "CN=" + testName.getMethodName() + "_CA";

        // Create CAToken
        Properties caTokenProperties = constructCaTokenProperties();
        CAToken caToken = new CAToken(cryptoTokenId, caTokenProperties);
        // Set key sequence so that next sequence will be 00001 (this is the default though so not really needed here)
        caToken.setKeySequence(CAToken.DEFAULT_KEYSEQUENCE);
        caToken.setKeySequenceFormat(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);
        caToken.setSignatureAlgorithm(AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA);
        caToken.setEncryptionAlgorithm(AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA);
        caToken.setAlternativeSignatureAlgorithm(AlgorithmConstants.SIGALG_DILITHIUM2);

        hybridRoot = X509CAInfo.getDefaultX509CAInfo(caDn, "testHybridRootCa", CAConstants.CA_ACTIVE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, "3650d", CAInfo.SELFSIGNED, null, caToken);

        caAdminSession.createCA(alwaysAllowToken, hybridRoot);
    }

    @After
    public void tearDown() throws Exception {
        //Delete the end entity 
        if (endEntityManagementSession.existsUser(username)) {
            endEntityManagementSession.deleteUser(alwaysAllowToken, username);
        }
        internalCertificateStoreSession.removeCertificatesByUsername(username);

        //Delete the CA
        if (cryptoTokenManagementSession.isCryptoTokenPresent(alwaysAllowToken, cryptoTokenId)) {
            try {
                for (KeyPairInfo keyPairInfo : cryptoTokenManagementSession.getKeyPairInfos(alwaysAllowToken, cryptoTokenId)) {
                    cryptoTokenManagementSession.removeKeyPair(alwaysAllowToken, cryptoTokenId, keyPairInfo.getAlias());
                }
            } catch (InvalidKeyException | CryptoTokenOfflineException e) {
                throw new IllegalStateException(e);
            }
            cryptoTokenManagementSession.deleteCryptoToken(alwaysAllowToken, cryptoTokenId);
        }

        if (hybridRoot != null) {
            CAInfo caInfo = caSession.getCAInfo(alwaysAllowToken, hybridRoot.getCAId());
            if (caInfo != null) {
                internalCertificateStoreSession.removeCertificate(caInfo.getCertificateChain().get(0));
            }
            caSession.removeCA(alwaysAllowToken, hybridRoot.getCAId());
        }
    }

    /**
     * Try enrolling a hybrid X509 certificate 
     *
     */
    @Test
    public void testEnrollHybridEndEntityCertificate()
            throws EndEntityExistsException, CADoesntExistsException, IllegalNameException, CustomFieldException, ApprovalException,
            CertificateSerialNumberException, AuthorizationDeniedException, EndEntityProfileValidationException, WaitingForApprovalException,
            CouldNotRemoveEndEntityException, CustomCertificateSerialNumberException, IllegalKeyException, CertificateCreateException,
            CryptoTokenOfflineException, SignRequestSignatureException, CertificateRevokeException, IllegalValidityException, CAOfflineException,
            InvalidAlgorithmException, CertificateExtensionException, NoSuchAlgorithmException, NoSuchProviderException,
            InvalidAlgorithmParameterException, OperatorCreationException, IOException, PKCSException, CertificateEncodingException, CertException {

        EndEntityInformation endEntityInformation = new EndEntityInformation(username, subjectDn, hybridRoot.getCAId(), null, null,
                EndEntityTypes.ENDUSER.toEndEntityType(), EndEntityConstants.EMPTY_END_ENTITY_PROFILE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_PEM, null);
        endEntityInformation.setPassword("foo123");
        endEntityManagementSession.addUser(alwaysAllowToken, endEntityInformation, false);
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(AlgorithmConstants.KEYALGORITHM_EC, BouncyCastleProvider.PROVIDER_NAME);
            keyPairGenerator.initialize(new ECGenParameterSpec("P-256"));
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            KeyPairGenerator alternativeKeyPairGenerator = KeyPairGenerator.getInstance(AlgorithmConstants.KEYALGORITHM_DILITHIUM,
                    BouncyCastleProvider.PROVIDER_NAME);
            alternativeKeyPairGenerator.initialize(DilithiumParameterSpec.dilithium2);
            KeyPair alternativeKeyPair = alternativeKeyPairGenerator.generateKeyPair();

            JcaPKCS10CertificationRequestBuilder jcaPKCS10CertificationRequestBuilder = new JcaPKCS10CertificationRequestBuilder(
                    new X500Name(subjectDn), keyPair.getPublic());

            ContentSigner altSigner = new JcaContentSignerBuilder(AlgorithmConstants.SIGALG_DILITHIUM2)
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(alternativeKeyPair.getPrivate());

            PKCS10CertificationRequest pkcs10CertificationRequest = jcaPKCS10CertificationRequestBuilder
                    .build(new JcaContentSignerBuilder(AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA).setProvider(BouncyCastleProvider.PROVIDER_NAME)
                            .build(keyPair.getPrivate()), alternativeKeyPair.getPublic(), altSigner);

            //Verify the validity of the PKCS#10
            assertTrue("Basic signature of hybrid request was not valid.", pkcs10CertificationRequest.isSignatureValid(
                    new JcaContentVerifierProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build(keyPair.getPublic())));
            assertTrue("Alternative public key of hybrid request was not present as an extension.", pkcs10CertificationRequest.hasAltPublicKey());
            assertTrue("Alternative signature of hybrid request was not valid.", pkcs10CertificationRequest.isAltSignatureValid(
                    new JcaContentVerifierProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build(alternativeKeyPair.getPublic())));

            PKCS10RequestMessage request = new PKCS10RequestMessage(pkcs10CertificationRequest.toASN1Structure().getEncoded());
            X509ResponseMessage response = (X509ResponseMessage) certificateCreateSession.createCertificate(alwaysAllowToken, endEntityInformation,
                    request, X509ResponseMessage.class, signSession.fetchCertGenParams());

            X509Certificate responseCertificate = (X509Certificate) response.getCertificate();
            X509CertificateHolder certHolder = new JcaX509CertificateHolder(responseCertificate);

            assertEquals("Incorrect alternative public key", ASN1Primitive.fromByteArray(alternativeKeyPair.getPublic().getEncoded()),
                    SubjectAltPublicKeyInfo.fromExtensions(certHolder.getExtensions()));

            PublicKey caAlternativePublicKey = cryptoTokenManagementSession.getPublicKey(alwaysAllowToken, cryptoTokenId, CAToken.ALTERNATE_SOFT_PRIVATE_SIGNKEY_ALIAS).getPublicKey();
            assertTrue("Alternative signature does not verify", certHolder.isAlternativeSignatureValid(
                    new JcaContentVerifierProviderBuilder().setProvider(BouncyCastlePQCProvider.PROVIDER_NAME).build(caAlternativePublicKey)));
        } finally {
            try {
                endEntityManagementSession.deleteUser(alwaysAllowToken, username);
            } catch (NoSuchEndEntityException e) {
                // Ignore
            }

            internalCertificateStoreSession.removeCertificatesByIssuer(hybridRoot.getSubjectDN());
        }
    }

    private Properties constructCaTokenProperties() {
        Properties caTokenProperties = new Properties();
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING_NEXT, CAToken.SOFTPRIVATESIGNKEYALIAS);
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING_PREVIOUS, CAToken.SOFTPRIVATESIGNKEYALIAS);
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_ALTERNATIVE_CERTSIGN_STRING, CAToken.ALTERNATE_SOFT_PRIVATE_SIGNKEY_ALIAS);
        return caTokenProperties;
    }
}
