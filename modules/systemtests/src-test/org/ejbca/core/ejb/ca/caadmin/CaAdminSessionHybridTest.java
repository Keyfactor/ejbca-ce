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
package org.ejbca.core.ejb.ca.caadmin;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Properties;

import javax.ejb.EJBException;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.SubjectAltPublicKeyInfo;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.CryptoTokenNameInUseException;
import org.cesecore.keys.token.KeyPairInfo;
import org.cesecore.keys.token.SoftCryptoToken;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
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
import com.keyfactor.util.keys.token.CryptoTokenAuthenticationFailedException;
import com.keyfactor.util.keys.token.CryptoTokenOfflineException;
import com.keyfactor.util.keys.token.KeyGenParams;
import com.keyfactor.util.keys.token.pkcs11.NoSuchSlotException;

/**
 * Tests CAAdminSessionBean with a focus on hybrid certificates. 
 */
public class CaAdminSessionHybridTest {

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
            new UsernamePrincipal("CaAdminSessionHybridTest"));
    private static final Logger log = Logger.getLogger(CaAdminSessionHybridTest.class);

    private final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private final CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
    private final CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CryptoTokenManagementSessionRemote.class);
    private final InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);

    @BeforeClass
    public static void setUpCryptoProvider() {
        CryptoProviderTools.installBCProvider();
    }

    @Test
    public void testCreateRootCertificate()
            throws CAExistsException, CryptoTokenOfflineException, InvalidAlgorithmException, AuthorizationDeniedException, InvalidKeyException,
            InvalidAlgorithmParameterException, CryptoTokenAuthenticationFailedException, CryptoTokenNameInUseException, NoSuchSlotException,
            CADoesntExistsException, CertificateEncodingException, IOException, OperatorCreationException, CertException {

        final String cryptoTokenPin = "foo123";
        final String cryptoTokenName = testName.getMethodName() + "CryptoToken";
        final String caName = testName.getMethodName() + "RootCa";

        Integer cryptoTokenId = null;
        X509CAInfo hybridRoot = null;
        try {
            cryptoTokenId = createCryptoTokenAndKeypairs(cryptoTokenName, cryptoTokenPin);
            hybridRoot = constructCa(cryptoTokenId, caName, CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, CAInfo.SELFSIGNED, true);

            X509Certificate rootCertificate = (X509Certificate) caSession.getCaChain(alwaysAllowToken, caName).get(0).getCertificate();

            X509CertificateHolder certHolder = new JcaX509CertificateHolder(rootCertificate);

            PublicKey alternativePublicKey = cryptoTokenManagementSession
                    .getPublicKey(alwaysAllowToken, cryptoTokenId, CAToken.ALTERNATE_SOFT_PRIVATE_SIGNKEY_ALIAS).getPublicKey();

            assertEquals("Incorrect alternative public key", ASN1Primitive.fromByteArray(alternativePublicKey.getEncoded()),
                    SubjectAltPublicKeyInfo.fromExtensions(certHolder.getExtensions()));

            PublicKey caAlternativePublicKey = cryptoTokenManagementSession
                    .getPublicKey(alwaysAllowToken, cryptoTokenId, CAToken.ALTERNATE_SOFT_PRIVATE_SIGNKEY_ALIAS).getPublicKey();
            assertTrue("Alternative signature does not verify", certHolder.isAlternativeSignatureValid(
                    new JcaContentVerifierProviderBuilder().setProvider(BouncyCastlePQCProvider.PROVIDER_NAME).build(caAlternativePublicKey)));
        } finally {
            //Delete the CA
            deleteCryptoTokenAndKeys(cryptoTokenId);

            if (hybridRoot != null) {
                CAInfo caInfo = caSession.getCAInfo(alwaysAllowToken, hybridRoot.getCAId());
                if (caInfo != null) {
                    internalCertificateStoreSession.removeCertificate(caInfo.getCertificateChain().get(0));
                }
                caSession.removeCA(alwaysAllowToken, hybridRoot.getCAId());
            }
        }
    }

    @Test
    public void testCreateSubCaCertificate()
            throws AuthorizationDeniedException, InvalidKeyException, CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException,
            CryptoTokenNameInUseException, InvalidAlgorithmParameterException, NoSuchSlotException, CAExistsException, InvalidAlgorithmException,
            CADoesntExistsException, IOException, CertificateEncodingException, OperatorCreationException, CertException {
        Integer rootCryptoTokenId = null;
        Integer subCryptoTokenId = null;
        final String rootCryptoTokenName = testName.getMethodName() + "CryptoTokenRoot";
        final String subCryptoTokenName = testName.getMethodName() + "CryptoTokenSub";
        X509CAInfo hybridRoot = null;
        X509CAInfo hybridSub = null;
        final String rootCaName = testName.getMethodName() + "RootCa";
        final String subCaName = testName.getMethodName() + "SubCa";
        try {
            rootCryptoTokenId = createCryptoTokenAndKeypairs(rootCryptoTokenName, "foo123");
            
            subCryptoTokenId = createCryptoTokenAndKeypairs(subCryptoTokenName, "foo123");
      
            hybridRoot = constructCa(rootCryptoTokenId, rootCaName, CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, CAInfo.SELFSIGNED, true);

            hybridSub = constructCa(subCryptoTokenId, subCaName, CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA, hybridRoot.getCAId(), true);

            X509Certificate subCaCertificate = (X509Certificate) caSession.getCaChain(alwaysAllowToken, subCaName).get(0).getCertificate();

            X509CertificateHolder certHolder = new JcaX509CertificateHolder(subCaCertificate);

            PublicKey alternativePublicKey = cryptoTokenManagementSession
                    .getPublicKey(alwaysAllowToken, subCryptoTokenId, CAToken.ALTERNATE_SOFT_PRIVATE_SIGNKEY_ALIAS).getPublicKey();

            assertEquals("Incorrect alternative public key", ASN1Primitive.fromByteArray(alternativePublicKey.getEncoded()),
                    SubjectAltPublicKeyInfo.fromExtensions(certHolder.getExtensions()).toASN1Primitive());

            PublicKey caAlternativePublicKey = cryptoTokenManagementSession
                    .getPublicKey(alwaysAllowToken, rootCryptoTokenId, CAToken.ALTERNATE_SOFT_PRIVATE_SIGNKEY_ALIAS).getPublicKey();
            assertTrue("Alternative signature does not verify", certHolder.isAlternativeSignatureValid(
                    new JcaContentVerifierProviderBuilder().setProvider(BouncyCastlePQCProvider.PROVIDER_NAME).build(caAlternativePublicKey)));

        } finally {
            deleteCryptoTokenAndKeys(rootCryptoTokenId);
            deleteCryptoTokenAndKeys(subCryptoTokenId);

            if (hybridRoot != null) {
                CAInfo caInfo = caSession.getCAInfo(alwaysAllowToken, hybridRoot.getCAId());
                if (caInfo != null) {
                    internalCertificateStoreSession.removeCertificate(caInfo.getCertificateChain().get(0));
                }
                caSession.removeCA(alwaysAllowToken, hybridRoot.getCAId());
            }

            if (hybridSub != null) {
                CAInfo caInfo = caSession.getCAInfo(alwaysAllowToken, hybridSub.getCAId());
                if (caInfo != null) {
                    internalCertificateStoreSession.removeCertificate(caInfo.getCertificateChain().get(0));
                }
                caSession.removeCA(alwaysAllowToken, hybridSub.getCAId());
            }
        }
    }
    
    @Test
    public void testCreateProhibitedSubCaCertificateUnderHybridRootShouldFail()
            throws AuthorizationDeniedException, InvalidKeyException, CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException,
            CryptoTokenNameInUseException, InvalidAlgorithmParameterException, NoSuchSlotException, CAExistsException, InvalidAlgorithmException,
            CADoesntExistsException, IOException, CertificateEncodingException, OperatorCreationException, CertException {
        Integer rootCryptoTokenId = null;
        Integer subCryptoTokenId = null;
        final String rootCryptoTokenName = testName.getMethodName() + "CryptoTokenRoot";
        final String subCryptoTokenName = testName.getMethodName() + "CryptoTokenSub";
        X509CAInfo hybridRoot = null;
        X509CAInfo hybridSub = null;
        final String rootCaName = testName.getMethodName() + "RootCa";
        final String subCaName = testName.getMethodName() + "SubCa";
        try {
            // given
            rootCryptoTokenId = createCryptoTokenAndKeypairs(rootCryptoTokenName, "foo123");
            subCryptoTokenId = createCryptoTokenAndKeypairsForNonHybridCA(subCryptoTokenName, "foo123");
            try {
                // when
                hybridRoot = constructCa(rootCryptoTokenId, rootCaName, CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, CAInfo.SELFSIGNED, true);
                hybridSub = constructCa(subCryptoTokenId, subCaName, CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA, hybridRoot.getCAId(), false);
                fail("Should throw EJBException when Root CA is a Hybrid CA but Sub CA is not a Hybrid CA");
            } catch (EJBException e) {
                String msg = "InvalidConfigurationException: Sub CA '" + subCaName+ "' should be hybrid CA iff Root CA is hybrid CA.";
                // then
                assertTrue(e.getMessage().endsWith(msg));
            }
        } finally {
            deleteCryptoTokenAndKeys(rootCryptoTokenId);
            deleteCryptoTokenAndKeys(subCryptoTokenId);

            if (hybridRoot != null) {
                CAInfo caInfo = caSession.getCAInfo(alwaysAllowToken, hybridRoot.getCAId());
                if (caInfo != null) {
                    internalCertificateStoreSession.removeCertificate(caInfo.getCertificateChain().get(0));
                }
                caSession.removeCA(alwaysAllowToken, hybridRoot.getCAId());
            }

            if (hybridSub != null) {
                CAInfo caInfo = caSession.getCAInfo(alwaysAllowToken, hybridSub.getCAId());
                if (caInfo != null) {
                    internalCertificateStoreSession.removeCertificate(caInfo.getCertificateChain().get(0));
                }
                caSession.removeCA(alwaysAllowToken, hybridSub.getCAId());
            }
        }
    }

    @Test
    public void testCreateProhibitedSubCaCertificateUnderNonHybridRootShouldFail()
            throws AuthorizationDeniedException, InvalidKeyException, CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException,
            CryptoTokenNameInUseException, InvalidAlgorithmParameterException, NoSuchSlotException, CAExistsException, InvalidAlgorithmException,
            CADoesntExistsException, IOException, CertificateEncodingException, OperatorCreationException, CertException {
        Integer rootCryptoTokenId = null;
        Integer subCryptoTokenId = null;
        final String rootCryptoTokenName = testName.getMethodName() + "CryptoTokenRoot";
        final String subCryptoTokenName = testName.getMethodName() + "CryptoTokenSub";
        X509CAInfo hybridRoot = null;
        X509CAInfo hybridSub = null;
        final String rootCaName = testName.getMethodName() + "RootCa";
        final String subCaName = testName.getMethodName() + "SubCa";
        try {
            // given
            rootCryptoTokenId = createCryptoTokenAndKeypairsForNonHybridCA(rootCryptoTokenName, "foo123");
            subCryptoTokenId = createCryptoTokenAndKeypairs(subCryptoTokenName, "foo123");
            try {
                // when
                hybridRoot = constructCa(rootCryptoTokenId, rootCaName, CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, CAInfo.SELFSIGNED, false);
                hybridSub = constructCa(subCryptoTokenId, subCaName, CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA, hybridRoot.getCAId(), true);
                fail("Should throw EJBException when Root CA is not a Hybrid CA but Sub CA is a Hybrid CA");
            } catch (EJBException e) {
                String msg = "InvalidConfigurationException: Sub CA '" + subCaName+ "' should be hybrid CA iff Root CA is hybrid CA.";
                // then
                assertTrue(e.getMessage().endsWith(msg));
            }
        } finally {
            deleteCryptoTokenAndKeys(rootCryptoTokenId);
            deleteCryptoTokenAndKeys(subCryptoTokenId);

            if (hybridRoot != null) {
                CAInfo caInfo = caSession.getCAInfo(alwaysAllowToken, hybridRoot.getCAId());
                if (caInfo != null) {
                    internalCertificateStoreSession.removeCertificate(caInfo.getCertificateChain().get(0));
                }
                caSession.removeCA(alwaysAllowToken, hybridRoot.getCAId());
            }

            if (hybridSub != null) {
                CAInfo caInfo = caSession.getCAInfo(alwaysAllowToken, hybridSub.getCAId());
                if (caInfo != null) {
                    internalCertificateStoreSession.removeCertificate(caInfo.getCertificateChain().get(0));
                }
                caSession.removeCA(alwaysAllowToken, hybridSub.getCAId());
            }
        }
    }
    
    private X509CAInfo constructCa(final int cryptoTokenId, final String caName, final int certificateProfileId, final int signedBy, boolean hybrid)
            throws CAExistsException, CryptoTokenOfflineException, InvalidAlgorithmException, AuthorizationDeniedException, EJBException {
        // Create CAToken
        Properties caTokenProperties;
        if (!hybrid) {
            caTokenProperties = constructCaTokenPropertiesForNonHybrid();
        } else {
            caTokenProperties = constructCaTokenProperties();
        }
        CAToken caToken = createCaToken(cryptoTokenId, caTokenProperties /*TEST*/,hybrid);
        final String caDn = "CN=" + caName;
        X509CAInfo x509caInfo = X509CAInfo.getDefaultX509CAInfo(caDn, caName, CAConstants.CA_ACTIVE, certificateProfileId, "3650d", signedBy, null,
                caToken);
        caAdminSession.createCA(alwaysAllowToken, x509caInfo);
        return x509caInfo;
    }

    private CAToken createCaToken(int cryptoTokenId, Properties caTokenProperties, boolean hybrid) {
        CAToken caToken = new CAToken(cryptoTokenId, caTokenProperties);
        // Set key sequence so that next sequence will be 00001 (this is the default though so not really needed here)
        caToken.setKeySequence(CAToken.DEFAULT_KEYSEQUENCE);
        caToken.setKeySequenceFormat(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);
        caToken.setSignatureAlgorithm(AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA);
        caToken.setEncryptionAlgorithm(AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA);
        if (hybrid) {
            caToken.setAlternativeSignatureAlgorithm(AlgorithmConstants.SIGALG_DILITHIUM2);
        }
        return caToken;
    }

    private void deleteCryptoTokenAndKeys(int cryptoTokenId) throws AuthorizationDeniedException {
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
    }

    private int createCryptoTokenAndKeypairs(final String cryptoTokenName, final String cryptoTokenPin)
            throws CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException, CryptoTokenNameInUseException, AuthorizationDeniedException,
            NoSuchSlotException, InvalidKeyException, InvalidAlgorithmParameterException {
        final Properties cryptoTokenProperties = new Properties();
        cryptoTokenProperties.setProperty(SoftCryptoToken.NODEFAULTPWD, "true");
        cryptoTokenProperties.setProperty(CryptoToken.AUTOACTIVATE_PIN_PROPERTY, cryptoTokenPin);
        int cryptoTokenId = cryptoTokenManagementSession.createCryptoToken(alwaysAllowToken, cryptoTokenName, SoftCryptoToken.class.getName(),
                cryptoTokenProperties, null, cryptoTokenPin.toCharArray());
        cryptoTokenManagementSession.createKeyPair(alwaysAllowToken, cryptoTokenId, CAToken.SOFTPRIVATESIGNKEYALIAS,
                KeyGenParams.builder("secp256r1").build());
        cryptoTokenManagementSession.createKeyPair(alwaysAllowToken, cryptoTokenId, CAToken.ALTERNATE_SOFT_PRIVATE_SIGNKEY_ALIAS,
                KeyGenParams.builder(AlgorithmConstants.KEYALGORITHM_DILITHIUM2).build());
        return cryptoTokenId;
    }
    
    private int createCryptoTokenAndKeypairsForNonHybridCA(final String cryptoTokenName, final String cryptoTokenPin)
            throws CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException, CryptoTokenNameInUseException, AuthorizationDeniedException,
            NoSuchSlotException, InvalidKeyException, InvalidAlgorithmParameterException {
        final Properties cryptoTokenProperties = new Properties();
        cryptoTokenProperties.setProperty(SoftCryptoToken.NODEFAULTPWD, "true");
        cryptoTokenProperties.setProperty(CryptoToken.AUTOACTIVATE_PIN_PROPERTY, cryptoTokenPin);
        int cryptoTokenId = cryptoTokenManagementSession.createCryptoToken(alwaysAllowToken, cryptoTokenName, SoftCryptoToken.class.getName(),
                cryptoTokenProperties, null, cryptoTokenPin.toCharArray());
        cryptoTokenManagementSession.createKeyPair(alwaysAllowToken, cryptoTokenId, CAToken.SOFTPRIVATESIGNKEYALIAS,
                KeyGenParams.builder("secp256r1").build());
        return cryptoTokenId;
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
    private Properties constructCaTokenPropertiesForNonHybrid() {
        Properties caTokenProperties = new Properties();
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING_NEXT, CAToken.SOFTPRIVATESIGNKEYALIAS);
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING_PREVIOUS, CAToken.SOFTPRIVATESIGNKEYALIAS);
        return caTokenProperties;
    }
}
