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
package org.ejbca.ui.web.rest.api.resource;

import static org.ejbca.ui.web.rest.api.Assert.EjbcaAssert.assertJsonContentType;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Properties;

import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

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
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.KeyPairInfo;
import org.cesecore.keys.token.SoftCryptoToken;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityExistsException;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ra.CustomFieldException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;
import org.ejbca.core.protocol.rest.EnrollPkcs10CertificateRequest;
import org.ejbca.ui.web.rest.api.config.ObjectMapperContextResolver;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestName;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.keyfactor.util.Base64;
import com.keyfactor.util.CertTools;
import com.keyfactor.util.StringTools;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.keys.token.CryptoToken;
import com.keyfactor.util.keys.token.CryptoTokenOfflineException;
import com.keyfactor.util.keys.token.KeyGenParams;

/**
 * Test class with system tests verifying that hybrid certificates can be enrolled via REST. 
 */
public class CertificateRestResourceHybridTest extends RestResourceSystemTestBase {

    private static final Logger log = Logger.getLogger(CertificateRestResourceHybridTest.class);

    private static final AuthenticationToken alwaysAllowToken = new TestAlwaysAllowLocalAuthenticationToken(
            new UsernamePrincipal("CertificateRestResourceHybridTest"));

    private final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private final CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
    private final CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CryptoTokenManagementSessionRemote.class);
    private final EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(EndEntityManagementSessionRemote.class);
    private final InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);

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

    private int cryptoTokenId;
    private X509CAInfo hybridRoot;

    private final String username = testName.getMethodName() + "_EE";
    private final String subjectDn = "CN=" + username;

    @BeforeClass
    public static void beforeClass() throws Exception {
        RestResourceSystemTestBase.beforeClass();
    }

    @AfterClass
    public static void afterClass() throws Exception {
        RestResourceSystemTestBase.afterClass();
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

    @Test
    public void testCertificateRequest() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException,
            OperatorCreationException, EndEntityExistsException, CADoesntExistsException, IllegalNameException, CustomFieldException,
            ApprovalException, CertificateSerialNumberException, AuthorizationDeniedException, EndEntityProfileValidationException,
            WaitingForApprovalException, UnrecoverableKeyException, KeyManagementException, KeyStoreException, CertificateParsingException,
            ParseException, CertificateEncodingException, CryptoTokenOfflineException, IOException, CertException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(AlgorithmConstants.KEYALGORITHM_EC, BouncyCastleProvider.PROVIDER_NAME);
        keyPairGenerator.initialize(new ECGenParameterSpec("P-256"));
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        KeyPairGenerator alternativeKeyPairGenerator = KeyPairGenerator.getInstance(AlgorithmConstants.KEYALGORITHM_DILITHIUM,
                BouncyCastleProvider.PROVIDER_NAME);
        alternativeKeyPairGenerator.initialize(DilithiumParameterSpec.dilithium2);
        KeyPair alternativeKeyPair = alternativeKeyPairGenerator.generateKeyPair();

        JcaPKCS10CertificationRequestBuilder jcaPKCS10CertificationRequestBuilder = new JcaPKCS10CertificationRequestBuilder(new X500Name(subjectDn),
                keyPair.getPublic());

        ContentSigner altSigner = new JcaContentSignerBuilder(AlgorithmConstants.SIGALG_DILITHIUM2).setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(alternativeKeyPair.getPrivate());

        PKCS10CertificationRequest pkcs10CertificationRequest = jcaPKCS10CertificationRequestBuilder
                .build(new JcaContentSignerBuilder(AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA).setProvider(BouncyCastleProvider.PROVIDER_NAME)
                        .build(keyPair.getPrivate()), alternativeKeyPair.getPublic(), altSigner);

        String certificateRequest = CertTools.buildCsr(pkcs10CertificationRequest);

        //User is cleaned up in tearDown()
        EndEntityInformation endEntityInformation = new EndEntityInformation(username, subjectDn, hybridRoot.getCAId(), null, null,
                new EndEntityType(EndEntityTypes.ENDUSER), EndEntityConstants.EMPTY_END_ENTITY_PROFILE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_BROWSERGEN, new ExtendedInformation());
        endEntityInformation.setPassword("foo123");
        endEntityInformation.setStatus(EndEntityConstants.STATUS_NEW);
        endEntityInformation.getExtendedInformation().setKeyStoreAlgorithmType(AlgorithmConstants.KEYALGORITHM_RSA);
        endEntityInformation.getExtendedInformation().setKeyStoreAlgorithmSubType("1024");
        endEntityManagementSession.addUser(alwaysAllowToken, endEntityInformation, false);

        EnrollPkcs10CertificateRequest enrollPkcs10CertificateRequest = new EnrollPkcs10CertificateRequest.Builder()
                .certificateAuthorityName(hybridRoot.getName()).certificateProfileName("ENDUSER").endEntityProfileName("EMPTY").username(username)
                .password("foo123").email(username + "@foo.com").certificateRequest(certificateRequest).build();

        final ObjectMapperContextResolver objectMapperContextResolver = new ObjectMapperContextResolver();

        // Construct POST  request
        final ObjectMapper objectMapper = objectMapperContextResolver.getContext(null);
        final String requestBody = objectMapper.writeValueAsString(enrollPkcs10CertificateRequest);
        final Entity<String> requestEntity = Entity.entity(requestBody, MediaType.APPLICATION_JSON);

        // Send request
        final Response actualResponse = newRequest("/v1/certificate/certificaterequest").request().post(requestEntity);
        final String actualJsonString = actualResponse.readEntity(String.class);
        // Verify response
        assertJsonContentType(actualResponse);

        JSONParser jsonParser = new JSONParser();

        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        final String base64cert = (String) actualJsonObject.get("certificate");
        assertNotNull(base64cert);
        byte[] certBytes = Base64.decode(base64cert.getBytes());
        X509Certificate responseCertificate = CertTools.getCertfromByteArray(certBytes, X509Certificate.class);
        // Assert End Entity DN is used. CSR subject should be ignored.
        assertEquals("Returned certificate contained unexpected subject DN", subjectDn, responseCertificate.getSubjectDN().getName());

        X509CertificateHolder certHolder = new JcaX509CertificateHolder(responseCertificate);

        assertEquals("Incorrect alternative public key", ASN1Primitive.fromByteArray(alternativeKeyPair.getPublic().getEncoded()),
                SubjectAltPublicKeyInfo.fromExtensions(certHolder.getExtensions()));

        PublicKey caAlternativePublicKey = cryptoTokenManagementSession
                .getPublicKey(alwaysAllowToken, cryptoTokenId, CAToken.ALTERNATE_SOFT_PRIVATE_SIGNKEY_ALIAS).getPublicKey();
        assertTrue("Alternative signature does not verify", certHolder.isAlternativeSignatureValid(
                new JcaContentVerifierProviderBuilder().setProvider(BouncyCastlePQCProvider.PROVIDER_NAME).build(caAlternativePublicKey)));
    }
    
    @Test
    public void testPkcs10Request() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException,
            OperatorCreationException, EndEntityExistsException, CADoesntExistsException, IllegalNameException, CustomFieldException,
            ApprovalException, CertificateSerialNumberException, AuthorizationDeniedException, EndEntityProfileValidationException,
            WaitingForApprovalException, UnrecoverableKeyException, KeyManagementException, KeyStoreException, CertificateParsingException,
            ParseException, CertificateEncodingException, CryptoTokenOfflineException, IOException, CertException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(AlgorithmConstants.KEYALGORITHM_EC, BouncyCastleProvider.PROVIDER_NAME);
        keyPairGenerator.initialize(new ECGenParameterSpec("P-256"));
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        KeyPairGenerator alternativeKeyPairGenerator = KeyPairGenerator.getInstance(AlgorithmConstants.KEYALGORITHM_DILITHIUM,
                BouncyCastleProvider.PROVIDER_NAME);
        alternativeKeyPairGenerator.initialize(DilithiumParameterSpec.dilithium2);
        KeyPair alternativeKeyPair = alternativeKeyPairGenerator.generateKeyPair();

        JcaPKCS10CertificationRequestBuilder jcaPKCS10CertificationRequestBuilder = new JcaPKCS10CertificationRequestBuilder(new X500Name(subjectDn),
                keyPair.getPublic());

        ContentSigner altSigner = new JcaContentSignerBuilder(AlgorithmConstants.SIGALG_DILITHIUM2).setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(alternativeKeyPair.getPrivate());

        PKCS10CertificationRequest pkcs10CertificationRequest = jcaPKCS10CertificationRequestBuilder
                .build(new JcaContentSignerBuilder(AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA).setProvider(BouncyCastleProvider.PROVIDER_NAME)
                        .build(keyPair.getPrivate()), alternativeKeyPair.getPublic(), altSigner);

        String certificateRequest = CertTools.buildCsr(pkcs10CertificationRequest);

        EnrollPkcs10CertificateRequest enrollPkcs10CertificateRequest = new EnrollPkcs10CertificateRequest.Builder().
                certificateAuthorityName(hybridRoot.getName()).
                certificateProfileName("ENDUSER").
                endEntityProfileName("EMPTY").
                username(username).
                password("foo123").
                certificateRequest(certificateRequest).build();
        
        // Construct POST  request
        final ObjectMapper objectMapper = objectMapperContextResolver.getContext(null);
        final String requestBody = objectMapper.writeValueAsString(enrollPkcs10CertificateRequest);
        final Entity<String> requestEntity = Entity.entity(requestBody, MediaType.APPLICATION_JSON);

        // Send request
        final Response actualResponse = newRequest("/v1/certificate/pkcs10enroll").request().post(requestEntity);
        final String actualJsonString = actualResponse.readEntity(String.class);
        // Verify response
        assertJsonContentType(actualResponse);
        
        JSONParser jsonParser = new JSONParser();
        
        final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(actualJsonString);
        final String base64cert = (String) actualJsonObject.get("certificate");
        assertNotNull(base64cert);
        byte[] certBytes = Base64.decode(base64cert.getBytes());
        X509Certificate responseCertificate = CertTools.getCertfromByteArray(certBytes, X509Certificate.class);

        X509CertificateHolder certHolder = new JcaX509CertificateHolder(responseCertificate);

        assertEquals("Incorrect alternative public key", ASN1Primitive.fromByteArray(alternativeKeyPair.getPublic().getEncoded()),
                SubjectAltPublicKeyInfo.fromExtensions(certHolder.getExtensions()));

        PublicKey caAlternativePublicKey = cryptoTokenManagementSession
                .getPublicKey(alwaysAllowToken, cryptoTokenId, CAToken.ALTERNATE_SOFT_PRIVATE_SIGNKEY_ALIAS).getPublicKey();
        assertTrue("Alternative signature does not verify", certHolder.isAlternativeSignatureValid(
                new JcaContentVerifierProviderBuilder().setProvider(BouncyCastlePQCProvider.PROVIDER_NAME).build(caAlternativePublicKey)));
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
