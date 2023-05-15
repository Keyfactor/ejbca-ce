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
package org.cesecore.certificates.ocsp.integrated;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.NoSuchProviderException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Properties;
import java.util.Random;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.BufferingContentSigner;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAExistsException;
import org.cesecore.certificates.ca.CAFactory;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateCreateSessionRemote;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.request.SimpleRequestMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.ocsp.OcspResponseGeneratorTestSessionRemote;
import org.cesecore.certificates.ocsp.exception.MalformedRequestException;
import org.cesecore.certificates.ocsp.logging.AuditLogger;
import org.cesecore.certificates.ocsp.logging.GuidHolder;
import org.cesecore.certificates.ocsp.logging.TransactionCounter;
import org.cesecore.certificates.ocsp.logging.TransactionLogger;
import org.cesecore.config.GlobalOcspConfiguration;
import org.cesecore.config.OcspConfiguration;
import org.cesecore.configuration.CesecoreConfigurationProxySessionRemote;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.junit.util.CryptoTokenRunner;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.IllegalCryptoTokenException;
import org.cesecore.keys.token.NullCryptoToken;
import org.cesecore.keys.token.SoftCryptoToken;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.oscp.OcspResponseData;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.TraceLogMethodsRule;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.ocsp.OcspDataSessionRemote;
import org.ejbca.core.ejb.ocsp.OcspResponseGeneratorSessionRemote;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestName;
import org.junit.rules.TestRule;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.EJBTools;
import com.keyfactor.util.SHA1DigestCalculator;
import com.keyfactor.util.StringTools;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.keys.KeyTools;
import com.keyfactor.util.keys.token.CryptoToken;
import com.keyfactor.util.keys.token.KeyGenParams;

/**
 */
@RunWith(Parameterized.class)
public class IntegratedOcspResponseTest {

    @Parameters(name = "{0}")
    public static Collection<CryptoTokenRunner> runners() {
       return CryptoTokenRunner.defaultRunners;
    }
    
    private static final String PKIX_OCSP_NONCE = "123456789";
    private CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private CertificateCreateSessionRemote certificateCreateSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateCreateSessionRemote.class);
    private CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);
    private CesecoreConfigurationProxySessionRemote cesecoreConfigurationProxySession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CesecoreConfigurationProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CryptoTokenManagementSessionRemote.class);
    private InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private GlobalConfigurationSessionRemote globalConfigurationSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(GlobalConfigurationSessionRemote.class);
    private OcspResponseGeneratorSessionRemote ocspResponseGeneratorSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(OcspResponseGeneratorSessionRemote.class);
    private OcspDataSessionRemote ocspDataSession = EjbRemoteHelper.INSTANCE.getRemoteSession(OcspDataSessionRemote.class);
    private OcspResponseGeneratorTestSessionRemote ocspResponseGeneratorTestSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(OcspResponseGeneratorTestSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);

    private X509Certificate caCertificate;
    private X509Certificate ocspCertificate;
    private X509CAInfo testx509ca;
    private String originalDefaultResponder;

    private final AuthenticationToken internalAdmin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("Internal Admin"));

    @Rule
    public TestRule traceLogMethodsRule = new TraceLogMethodsRule();
    
    @Rule
    public TestName testName = new TestName();

    private CryptoTokenRunner cryptoTokenRunner;

    public IntegratedOcspResponseTest(CryptoTokenRunner cryptoTokenRunner) throws Exception {
        this.cryptoTokenRunner = cryptoTokenRunner;
       
    }
    
    @Before
    public void setUp() throws Exception {
        assumeTrue("Test with runner " + cryptoTokenRunner.getSimpleName() + " cannot run on this platform.", cryptoTokenRunner.canRun());
        testx509ca = cryptoTokenRunner.createX509Ca("CN="+testName.getMethodName(), testName.getMethodName()); 
        caCertificate = (X509Certificate) testx509ca.getCertificateChain().get(0);
        EndEntityInformation user = new EndEntityInformation("username", "CN=User", testx509ca.getCAId(), "rfc822Name=user@user.com", "user@user.com",
                EndEntityTypes.ENDUSER.toEndEntityType(), 0, 0, EndEntityConstants.TOKEN_USERGEN, null);
        user.setPassword("foo123");
        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        SimpleRequestMessage req = new SimpleRequestMessage(keys.getPublic(), user.getUsername(), user.getPassword());
        ocspCertificate = (X509Certificate) (((X509ResponseMessage) certificateCreateSession.createCertificate(internalAdmin, user, req,
                X509ResponseMessage.class, signSession.fetchCertGenParams())).getCertificate());
        // Modify the default value
        originalDefaultResponder = setOcspDefaultResponderReference(CertTools.getSubjectDN(caCertificate));
        cesecoreConfigurationProxySession.setConfigurationValue("ocsp.nonexistingisgood", "false");
    }

    @After
    public void tearDown() throws AuthorizationDeniedException {
        cryptoTokenRunner.cleanUp();
        if (ocspCertificate != null) {
            internalCertificateStoreSession.removeCertificate(ocspCertificate.getSerialNumber());
        }
        // Restore the default value
        setOcspDefaultResponderReference(originalDefaultResponder);
    }

    @Test
    public void testOcspPreProducedResponseDoNotStoreStatusUnknown() throws Exception {
        final BigInteger unknownSerialNumber = BigInteger.valueOf(1111111111111L);
        // Enable OCSP pre production, store responses on demand and make sure the response has nextUpdate set.
        final String originalNextUpdateTime = setOcspDefaultNextUpdateTime("3600");
        testx509ca.setDoPreProduceOcspResponses(true);
        testx509ca.setDoStoreOcspResponsesOnDemand(true);
        try {
            caSession.editCA(internalAdmin, testx509ca);
            ocspResponseGeneratorTestSession.reloadOcspSigningCache();
            // Prepare OCSP request
            final int localTransactionId = TransactionCounter.INSTANCE.getTransactionNumber();
            final GlobalOcspConfiguration configuration = (GlobalOcspConfiguration) globalConfigurationSession
                    .getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
            final TransactionLogger transactionLogger = new TransactionLogger(localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "",
                    configuration);
            final AuditLogger auditLogger = new AuditLogger("", localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "", configuration);
            final OCSPReqBuilder gen = new OCSPReqBuilder();
            gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), caCertificate, unknownSerialNumber));
            OCSPReq ocspRequest = gen.build();
            // Send OCSP Request for unknown serialNr
            byte[] responseBytes = ocspResponseGeneratorSession
                    .getOcspResponse(ocspRequest.getEncoded(), null, "", null, null, auditLogger, transactionLogger, false, false, false).getOcspResponse();
            // Verify return status was 'Unknown'
            final OCSPResp ocspResponse = new OCSPResp(responseBytes);
            final BasicOCSPResp basicOcspResponse = (BasicOCSPResp) ocspResponse.getResponseObject();
            final SingleResp[] singleResponses = basicOcspResponse.getResponses();
            assertTrue(singleResponses[0].getCertStatus() instanceof UnknownStatus);
            // Make sure the response wasn't stored
            OcspResponseData ocspResponseData = ocspDataSession.findOcspDataByCaIdSerialNumber(testx509ca.getCAId(), unknownSerialNumber.toString());
            assertNull("Response with status 'Unknown' was (wrongly) stored", ocspResponseData);
        } finally {
            setOcspDefaultNextUpdateTime(originalNextUpdateTime);
        }
    }

    @Test
    public void testOcspPreProducedResponseOnDemandUseCannedResponse() throws Exception {
        // Enable OCSP pre production, store responses on demand and make sure the response has nextUpdate set.
        final String originalNextUpdateTime = setOcspDefaultNextUpdateTime("3600");
        testx509ca.setDoPreProduceOcspResponses(true);
        testx509ca.setDoStoreOcspResponsesOnDemand(true);
        try {
            caSession.editCA(internalAdmin, testx509ca);
            ocspResponseGeneratorTestSession.reloadOcspSigningCache();

            // Prepare OCSP request
            final int localTransactionId = TransactionCounter.INSTANCE.getTransactionNumber();
            final GlobalOcspConfiguration configuration = (GlobalOcspConfiguration) globalConfigurationSession
                    .getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
            TransactionLogger transactionLogger = new TransactionLogger(localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "", configuration);
            AuditLogger auditLogger = new AuditLogger("", localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "", configuration);
            final OCSPReqBuilder gen = new OCSPReqBuilder();
            gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), caCertificate, caCertificate.getSerialNumber()));
            OCSPReq ocspRequest = gen.build();

            // Send two OCSP requests for the same CertId
            byte[] firstOcspResponseBytes = ocspResponseGeneratorSession
                    .getOcspResponse(ocspRequest.getEncoded(), null, "", null, null, auditLogger, transactionLogger, false, false, false).getOcspResponse();
            OCSPResp firstOcspResponse = new OCSPResp(firstOcspResponseBytes);
            // Required sleep here since producedAt is the only thing which could distingiushing the two responses.
            Thread.sleep(1000);
            byte[] secondResponseBytes = ocspResponseGeneratorSession
                    .getOcspResponse(ocspRequest.getEncoded(), null, "", null, null, auditLogger, transactionLogger, false, false, false).getOcspResponse();
            OCSPResp secondOcspResponse = new OCSPResp(secondResponseBytes);

            // Verify response objects. First response should have been stored and used as reply to the second request.
            assertNotNull("OCSP responder replied null", firstOcspResponseBytes);
            assertNotNull("OCSP responder replied null", secondResponseBytes);
            long firstResponseProducedAt = ((BasicOCSPResp) firstOcspResponse.getResponseObject()).getProducedAt().getTime();
            long secondResponseProducedAt = ((BasicOCSPResp) secondOcspResponse.getResponseObject()).getProducedAt().getTime();
            assertEquals("Stored response was not used for the second request", firstResponseProducedAt, secondResponseProducedAt);
        } finally {
            setOcspDefaultNextUpdateTime(originalNextUpdateTime);
        }
    }

    @Test
    public void testOcspPreProducedResponseInvalidated() throws Exception {
        // Enable OCSP pre production and make sure the response expires after 1 second.
        final String originalNextUpdateTime = setOcspDefaultNextUpdateTime("1");
        testx509ca.setDoPreProduceOcspResponses(true);
        testx509ca.setDoStoreOcspResponsesOnDemand(true);
        try {
            caSession.editCA(internalAdmin, testx509ca);
            ocspResponseGeneratorTestSession.reloadOcspSigningCache();

            // Prepare OCSP request
            final int localTransactionId = TransactionCounter.INSTANCE.getTransactionNumber();
            final GlobalOcspConfiguration configuration = (GlobalOcspConfiguration) globalConfigurationSession
                    .getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
            TransactionLogger transactionLogger = new TransactionLogger(localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "", configuration);
            AuditLogger auditLogger = new AuditLogger("", localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "", configuration);
            final OCSPReqBuilder gen = new OCSPReqBuilder();
            gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), caCertificate, caCertificate.getSerialNumber()));
            OCSPReq ocspRequest = gen.build();

            // Send two OCSP requests for the same CertId
            byte[] firstOcspResponseBytes = ocspResponseGeneratorSession
                    .getOcspResponse(ocspRequest.getEncoded(), null, "", null, null, auditLogger, transactionLogger, false, false, false).getOcspResponse();
            OCSPResp firstOcspResponse = new OCSPResp(firstOcspResponseBytes);
            // Make sure the first response expire (by nextUpdate)
            Thread.sleep(1500);
            byte[] secondResponseBytes = ocspResponseGeneratorSession
                    .getOcspResponse(ocspRequest.getEncoded(), null, "", null, null, auditLogger, transactionLogger, false, false, false).getOcspResponse();
            OCSPResp secondOcspResponse = new OCSPResp(secondResponseBytes);

            // Verify response objects. First response should have been stored but expired by the time the second request
            // occurs, hence a new response should be generated for the second request rather than using the stored one.
            assertNotNull("OCSP responder replied null", firstOcspResponseBytes);
            assertNotNull("OCSP responder replied null", secondResponseBytes);
            long firstResponseProducedAt = ((BasicOCSPResp) firstOcspResponse.getResponseObject()).getProducedAt().getTime();
            long secondResponseProducedAt = ((BasicOCSPResp) secondOcspResponse.getResponseObject()).getProducedAt().getTime();
            assertNotEquals("Expired OCSP response was returned", firstResponseProducedAt, secondResponseProducedAt);
        } finally {
            cesecoreConfigurationProxySession.setConfigurationValue(OcspConfiguration.UNTIL_NEXT_UPDATE, originalNextUpdateTime);
        }
    }

    /** After renewing a CA with a new key pair, the new CA certificate should be used to sign requests */
    @Test
    public void testOcspSignerIssuerRenewal() throws Exception {
        final X509Certificate caCertificateRenew = (X509Certificate) testx509ca.getCertificateChain().get(0);
        final EndEntityInformation user = new EndEntityInformation("testOcspSignerIssuerRenewal", "CN=testOcspSignerIssuerRenewal",
                testx509ca.getCAId(), null, null, EndEntityTypes.ENDUSER.toEndEntityType(), 0, 0, EndEntityConstants.TOKEN_USERGEN, null);
        user.setPassword("foo123");
        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        SimpleRequestMessage req = new SimpleRequestMessage(keys.getPublic(), user.getUsername(), user.getPassword());
        X509Certificate eeCertificate = (X509Certificate) (((X509ResponseMessage) certificateCreateSession.createCertificate(internalAdmin, user, req,
                X509ResponseMessage.class, signSession.fetchCertGenParams())).getCertificate());
        setOcspDefaultResponderReference(null);
        try {
            ocspResponseGeneratorTestSession.reloadOcspSigningCache();
            testOcspSignerIssuerRenewalInternal(eeCertificate, caCertificateRenew, OCSPResp.SUCCESSFUL);
            // Try the same thing after CA has been renewed
            caAdminSession.renewCA(internalAdmin, testx509ca.getCAId(), true, null, false);
            final X509Certificate caCertificateRenewed = (X509Certificate) caSession.getCAInfo(internalAdmin, testx509ca.getCAId())
                    .getCertificateChain().iterator().next();
            ocspResponseGeneratorTestSession.reloadOcspSigningCache();
            assertEquals("Status is not null (good)", null,
                    testOcspSignerIssuerRenewalInternal(eeCertificate, caCertificateRenewed, OCSPResp.SUCCESSFUL));
            /*
             * If we query for EE certificate with the previous issuer cert, the responder will think it is from an unknown CA,
             * since we do the lookup of the issuer from the combination of issuerName and keyHash.
             * 
             * The expected outcome is "unauthorized", since the default responder is disabled during this test.
             */
            testOcspSignerIssuerRenewalInternal(eeCertificate, caCertificateRenew, OCSPResp.UNAUTHORIZED);
        } finally {
            internalCertificateStoreSession.removeCertificate(eeCertificate.getSerialNumber());
        }
    }

    private String setOcspDefaultResponderReference(final String dn) throws AuthorizationDeniedException {
        final GlobalOcspConfiguration configuration = (GlobalOcspConfiguration) globalConfigurationSession
                .getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
        final String originalDefaultResponder = configuration.getOcspDefaultResponderReference();
        configuration.setOcspDefaultResponderReference(dn);
        globalConfigurationSession.saveConfiguration(internalAdmin, configuration);
        return originalDefaultResponder;
    }

    private String setOcspDefaultNextUpdateTime(final String nextUpdateInSeconds) {
        final String originalConfigurationValue = cesecoreConfigurationProxySession.getConfigurationValue(OcspConfiguration.UNTIL_NEXT_UPDATE);
        cesecoreConfigurationProxySession.setConfigurationValue(OcspConfiguration.UNTIL_NEXT_UPDATE, nextUpdateInSeconds);
        return originalConfigurationValue;
    }

    private CertificateStatus testOcspSignerIssuerRenewalInternal(X509Certificate eeCertificate, X509Certificate caCertificate, int expectedStatus)
            throws Exception {
        OCSPReq ocspReq = new OCSPReqBuilder()
                .addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), caCertificate, eeCertificate.getSerialNumber())).build();
        final int localTransactionId = TransactionCounter.INSTANCE.getTransactionNumber();
        final GlobalOcspConfiguration configuration = (GlobalOcspConfiguration) globalConfigurationSession
                .getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
        TransactionLogger transactionLogger = new TransactionLogger(localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "", configuration);
        AuditLogger auditLogger = new AuditLogger("", localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "", configuration);
        byte[] responseBytes = ocspResponseGeneratorSession
                .getOcspResponse(ocspReq.getEncoded(), null, "", null, null, auditLogger, transactionLogger, false, false, false).getOcspResponse();
        assertNotNull("OCSP responder replied null", responseBytes);
        OCSPResp response = new OCSPResp(responseBytes);
        if (expectedStatus == OCSPResp.UNAUTHORIZED) {
            assertEquals("Response status not zero.", OCSPResp.UNAUTHORIZED, response.getStatus());
            return null;
        }
        assertEquals("Response status not zero.", OCSPResp.SUCCESSFUL, response.getStatus());
        BasicOCSPResp basicOcspResponse = (BasicOCSPResp) response.getResponseObject();
        assertTrue("OCSP response was not signed correctly.", basicOcspResponse.isSignatureValid(
                new JcaContentVerifierProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build(caCertificate.getPublicKey())));
        SingleResp[] singleResponses = basicOcspResponse.getResponses();
        assertEquals("Delivered some thing else than one and exactly one response.", 1, singleResponses.length);
        assertEquals("Response cert did not match up with request cert", eeCertificate.getSerialNumber(),
                singleResponses[0].getCertID().getSerialNumber());
        return singleResponses[0].getCertStatus();
    }

    /**
     * Tests creating an OCSP response using the root CA cert.
     * Tests using both SHA1, SHA256 and SHA224 CertID. SHA1 and SHA256 should work, while SHA224 should give an error.
     * Tests that OCSP Nonce with more than 32 bytes are not allowed.
     */
    @Test
    public void testGetOcspResponseSanity() throws Exception {
        ocspResponseGeneratorTestSession.reloadOcspSigningCache();

        final int localTransactionId = TransactionCounter.INSTANCE.getTransactionNumber();
        // Create the transaction logger for this transaction.
        final GlobalOcspConfiguration configuration = (GlobalOcspConfiguration) globalConfigurationSession
                .getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
        TransactionLogger transactionLogger = new TransactionLogger(localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "", configuration);
        // Create the audit logger for this transaction.
        AuditLogger auditLogger = new AuditLogger("", localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "", configuration);

        // An OCSP request
        OCSPReqBuilder gen = new OCSPReqBuilder();
        gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), caCertificate, caCertificate.getSerialNumber()));
        Extension[] extensions = new Extension[1];

        // Use a nonce with more than 32 bytes to see if we reject it. We should not allow too long nonces due to the possibility of using 
        // this as a chosen-prefix attack on hash collisions.
        // https://groups.google.com/forum/#!topic/mozilla.dev.security.policy/x3TOIJL7MGw
        // https://www.rfc-editor.org/rfc/rfc8954.txt
        extensions[0] = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString(new byte[33]).getEncoded());
        gen.setRequestExtensions(new Extensions(extensions));
        OCSPReq reqnonce = gen.build();

        byte[] errResponseBytes = ocspResponseGeneratorSession
                .getOcspResponse(reqnonce.getEncoded(), null, "", null, null, auditLogger, transactionLogger, false, false, false).getOcspResponse();
        assertNotNull("OCSP responder replied null", errResponseBytes);
        OCSPResp errResponse = new OCSPResp(errResponseBytes);
        assertEquals("Response status not 1 (malformed request see RFC8954) when sending 33 bytes nonce.", OCSPRespBuilder.MALFORMED_REQUEST,
                errResponse.getStatus());

        // Go on now with a nonce that is too short (0 bytes)
        extensions[0] = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString("".getBytes()).getEncoded());
        gen.setRequestExtensions(new Extensions(extensions));
        reqnonce = gen.build();

        errResponseBytes = ocspResponseGeneratorSession
                .getOcspResponse(reqnonce.getEncoded(), null, "", null, null, auditLogger, transactionLogger, false, false, false).getOcspResponse();
        assertNotNull("OCSP responder replied null", errResponseBytes);
        errResponse = new OCSPResp(errResponseBytes);
        assertEquals("Response status not 1 (malformed request see RFC8954) when sending 0 byte nonce.", OCSPRespBuilder.MALFORMED_REQUEST,
                errResponse.getStatus());

        // Go on now with a nonce that is not too long, exactly 1 byte
        extensions[0] = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString(new byte[1]).getEncoded());
        gen.setRequestExtensions(new Extensions(extensions));
        OCSPReq req = gen.build();
        byte[] responseBytes = ocspResponseGeneratorSession
                .getOcspResponse(req.getEncoded(), null, "", null, null, auditLogger, transactionLogger, false, false, false).getOcspResponse();
        assertNotNull("OCSP responder replied null", responseBytes);

        // Go on now with a nonce that is not too long, exactly 32 bytes
        extensions[0] = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString(new byte[32]).getEncoded());
        gen.setRequestExtensions(new Extensions(extensions));
        req = gen.build();
        responseBytes = ocspResponseGeneratorSession
                .getOcspResponse(req.getEncoded(), null, "", null, null, auditLogger, transactionLogger, false, false, false).getOcspResponse();
        assertNotNull("OCSP responder replied null", responseBytes);

        OCSPResp response = new OCSPResp(responseBytes);
        assertEquals("Response status not zero (ok).", OCSPRespBuilder.SUCCESSFUL, response.getStatus());
        BasicOCSPResp basicOcspResponse = (BasicOCSPResp) response.getResponseObject();
        assertTrue("OCSP response was not signed correctly.", basicOcspResponse.isSignatureValid(
                new JcaContentVerifierProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build(caCertificate.getPublicKey())));
        SingleResp[] singleResponses = basicOcspResponse.getResponses();
        assertEquals("Delivered some thing else than one and exactly one response.", 1, singleResponses.length);
        assertEquals("Response cert did not match up with request cert", caCertificate.getSerialNumber(),
                singleResponses[0].getCertID().getSerialNumber());
        assertEquals("Status is not null (good)", null, singleResponses[0].getCertStatus());

        // Do the same test but using SHA256 as hash algorithm for CertID
        gen = new OCSPReqBuilder();
        gen.addRequest(new JcaCertificateID(new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256)),
                caCertificate, caCertificate.getSerialNumber()));
        extensions = new Extension[1];
        extensions[0] = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString(PKIX_OCSP_NONCE.getBytes()).getEncoded());
        gen.setRequestExtensions(new Extensions(extensions));
        req = gen.build();
        responseBytes = ocspResponseGeneratorSession
                .getOcspResponse(req.getEncoded(), null, "", null, null, auditLogger, transactionLogger, false, false, false).getOcspResponse();
        assertNotNull("OCSP responder replied null", responseBytes);
        response = new OCSPResp(responseBytes);
        assertEquals("Response status not zero.", 0, response.getStatus());
        basicOcspResponse = (BasicOCSPResp) response.getResponseObject();
        assertTrue("OCSP response was not signed correctly.", basicOcspResponse.isSignatureValid(
                new JcaContentVerifierProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build(caCertificate.getPublicKey())));
        singleResponses = basicOcspResponse.getResponses();
        assertEquals("Delivered some thing else than one and exactly one response.", 1, singleResponses.length);
        assertEquals("Response cert did not match up with request cert", caCertificate.getSerialNumber(),
                singleResponses[0].getCertID().getSerialNumber());
        assertEquals("Status is not null (good)", null, singleResponses[0].getCertStatus());

        // Do the same test but using SHA384 as hash algorithm for CertID, that should work
        gen = new OCSPReqBuilder();
        gen.addRequest(new JcaCertificateID(new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha384)),
                caCertificate, caCertificate.getSerialNumber()));
        extensions = new Extension[1];
        extensions[0] = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString(PKIX_OCSP_NONCE.getBytes()).getEncoded());
        gen.setRequestExtensions(new Extensions(extensions));
        req = gen.build();
        responseBytes = ocspResponseGeneratorSession
                .getOcspResponse(req.getEncoded(), null, "", null, null, auditLogger, transactionLogger, false, false, false).getOcspResponse();
        assertNotNull("OCSP responder replied null", responseBytes);
        response = new OCSPResp(responseBytes);
        assertEquals("Response status not zero.", 0, response.getStatus());
        basicOcspResponse = (BasicOCSPResp) response.getResponseObject();
        assertTrue("OCSP response was not signed correctly.", basicOcspResponse.isSignatureValid(
                new JcaContentVerifierProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build(caCertificate.getPublicKey())));
        singleResponses = basicOcspResponse.getResponses();
        assertEquals("Delivered some thing else than one and exactly one response.", 1, singleResponses.length);
        assertEquals("Response cert did not match up with request cert", caCertificate.getSerialNumber(),
                singleResponses[0].getCertID().getSerialNumber());
        assertEquals("Status is not null (good)", null, singleResponses[0].getCertStatus());

        // Do the same test but using SHA512 as hash algorithm for CertID, that should work
        gen = new OCSPReqBuilder();
        gen.addRequest(new JcaCertificateID(new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha512)),
                caCertificate, caCertificate.getSerialNumber()));
        extensions = new Extension[1];
        extensions[0] = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString(PKIX_OCSP_NONCE.getBytes()).getEncoded());
        gen.setRequestExtensions(new Extensions(extensions));
        req = gen.build();
        responseBytes = ocspResponseGeneratorSession
                .getOcspResponse(req.getEncoded(), null, "", null, null, auditLogger, transactionLogger, false, false, false).getOcspResponse();
        assertNotNull("OCSP responder replied null", responseBytes);
        response = new OCSPResp(responseBytes);
        assertEquals("Response status not zero.", 0, response.getStatus());
        basicOcspResponse = (BasicOCSPResp) response.getResponseObject();
        assertTrue("OCSP response was not signed correctly.", basicOcspResponse.isSignatureValid(
                new JcaContentVerifierProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build(caCertificate.getPublicKey())));
        singleResponses = basicOcspResponse.getResponses();
        assertEquals("Delivered some thing else than one and exactly one response.", 1, singleResponses.length);
        assertEquals("Response cert did not match up with request cert", caCertificate.getSerialNumber(),
                singleResponses[0].getCertID().getSerialNumber());
        assertEquals("Status is not null (good)", null, singleResponses[0].getCertStatus());

        // Do the same test but using SHA224 as hash algorithm for CertID to see that we get an error back
        gen = new OCSPReqBuilder();
        gen.addRequest(new JcaCertificateID(new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha224)),
                caCertificate, caCertificate.getSerialNumber()));
        extensions = new Extension[1];
        extensions[0] = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString(PKIX_OCSP_NONCE.getBytes()).getEncoded());
        gen.setRequestExtensions(new Extensions(extensions));
        req = gen.build();
        responseBytes = ocspResponseGeneratorSession
                .getOcspResponse(req.getEncoded(), null, "", null, null, auditLogger, transactionLogger, false, false, false).getOcspResponse();
        assertNotNull("OCSP responder replied null", responseBytes);
        response = new OCSPResp(responseBytes);
        // Response status 1 means malformed request
        assertEquals("Response status not one, it should be a malformed_request.", 1, response.getStatus());
        basicOcspResponse = (BasicOCSPResp) response.getResponseObject();
        assertNull("No response object for this unsigned error response.", basicOcspResponse);
    }

    /**
     * Tests with nonexistingisrevoked
     */
    @Test
    public void testNonExistingIsRevoked() throws Exception {
        String originalValue = cesecoreConfigurationProxySession.getConfigurationValue(OcspConfiguration.NON_EXISTING_IS_REVOKED);
        cesecoreConfigurationProxySession.setConfigurationValue(OcspConfiguration.NON_EXISTING_IS_REVOKED, "true");
        try {
            ocspResponseGeneratorTestSession.reloadOcspSigningCache();
            BigInteger randomSerialNumber = BigInteger.valueOf(9);
            // An OCSP request
            OCSPReqBuilder gen = new OCSPReqBuilder();
            gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), caCertificate, randomSerialNumber));
            Extension[] extensions = new Extension[1];
            extensions[0] = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString(PKIX_OCSP_NONCE.getBytes()).getEncoded());
            gen.setRequestExtensions(new Extensions(extensions));

            OCSPReq req = gen.build();

            final int localTransactionId = TransactionCounter.INSTANCE.getTransactionNumber();
            final GlobalOcspConfiguration configuration = (GlobalOcspConfiguration) globalConfigurationSession
                    .getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);

            // Create the transaction logger for this transaction.
            TransactionLogger transactionLogger = new TransactionLogger(localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "", configuration);
            // Create the audit logger for this transaction.
            AuditLogger auditLogger = new AuditLogger("", localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "", configuration);
            byte[] responseBytes = ocspResponseGeneratorSession.getOcspResponse(req.getEncoded(), null, "", null, new StringBuffer("http://foo.com"),
                    auditLogger, transactionLogger, false, false, false).getOcspResponse();
            assertNotNull("OCSP responder replied null", responseBytes);

            OCSPResp response = new OCSPResp(responseBytes);
            assertEquals("Response status not zero.", response.getStatus(), 0);
            BasicOCSPResp basicOcspResponse = (BasicOCSPResp) response.getResponseObject();
            assertTrue("OCSP response was not signed correctly.", basicOcspResponse.isSignatureValid(
                    new JcaContentVerifierProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build(caCertificate.getPublicKey())));
            SingleResp[] singleResponses = basicOcspResponse.getResponses();

            assertEquals("Delivered some thing else than one and exactly one response.", 1, singleResponses.length);
            assertEquals("Response cert did not match up with request cert", randomSerialNumber, singleResponses[0].getCertID().getSerialNumber());

            responseBytes = ocspResponseGeneratorSession.getOcspResponse(req.getEncoded(), null, "", null, new StringBuffer("http://foo.com"),
                    auditLogger, transactionLogger, false, false, false).getOcspResponse();
            assertNotNull("OCSP responder replied null", responseBytes);

            response = new OCSPResp(responseBytes);
            assertEquals("Response status not zero.", response.getStatus(), 0);
            basicOcspResponse = (BasicOCSPResp) response.getResponseObject();
            assertTrue("OCSP response was not signed correctly.", basicOcspResponse.isSignatureValid(
                    new JcaContentVerifierProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build(caCertificate.getPublicKey())));
            singleResponses = basicOcspResponse.getResponses();

            assertEquals("Delivered some thing else than one and exactly one response.", 1, singleResponses.length);
            assertEquals("Response cert did not match up with request cert", randomSerialNumber, singleResponses[0].getCertID().getSerialNumber());

            // Assert that status is revoked
            CertificateStatus status = singleResponses[0].getCertStatus();
            assertTrue("Status is not RevokedStatus", status instanceof RevokedStatus);

            // Set ocsp.nonexistingisgood=true, veryify that answer comes out okay.
            String originalNoneExistingIsGood = cesecoreConfigurationProxySession.getConfigurationValue(OcspConfiguration.NON_EXISTING_IS_GOOD);
            cesecoreConfigurationProxySession.setConfigurationValue(OcspConfiguration.NON_EXISTING_IS_GOOD, "true");
            try {
                responseBytes = ocspResponseGeneratorSession.getOcspResponse(req.getEncoded(), null, "", null, new StringBuffer("http://foo.com"),
                        auditLogger, transactionLogger, false, false, false).getOcspResponse();
                assertNotNull("OCSP responder replied null", responseBytes);

                response = new OCSPResp(responseBytes);
                assertEquals("Response status not zero.", response.getStatus(), 0);
                basicOcspResponse = (BasicOCSPResp) response.getResponseObject();
                assertTrue("OCSP response was not signed correctly.", basicOcspResponse.isSignatureValid(
                        new JcaContentVerifierProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build(caCertificate.getPublicKey())));
                singleResponses = basicOcspResponse.getResponses();

                assertEquals("Delivered some thing else than one and exactly one response.", 1, singleResponses.length);
                assertEquals("Response cert did not match up with request cert", randomSerialNumber,
                        singleResponses[0].getCertID().getSerialNumber());
                assertEquals("Status is not null (good)", null, singleResponses[0].getCertStatus());
            } finally {
                cesecoreConfigurationProxySession.setConfigurationValue(OcspConfiguration.NON_EXISTING_IS_GOOD, originalNoneExistingIsGood);
            }
        } finally {
            cesecoreConfigurationProxySession.setConfigurationValue(OcspConfiguration.NON_EXISTING_IS_REVOKED, originalValue);
        }

    }

    /**
     * Tests with non-existing as unauthorized, using the default configuration value.
     */
    @Test
    public void testNonExistingIsUnauthorizedConfiguration() throws Exception {
        String originalValue = cesecoreConfigurationProxySession.getConfigurationValue(OcspConfiguration.NON_EXISTING_IS_UNAUTHORIZED);
        cesecoreConfigurationProxySession.setConfigurationValue(OcspConfiguration.NON_EXISTING_IS_UNAUTHORIZED, "true");
        try {
            ocspResponseGeneratorTestSession.reloadOcspSigningCache();
            // An OCSP request
            OCSPReqBuilder gen = new OCSPReqBuilder();
            //Add a "random" serial number
            gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), caCertificate, BigInteger.valueOf(9)));
            Extension[] extensions = new Extension[1];
            extensions[0] = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString(PKIX_OCSP_NONCE.getBytes()).getEncoded());
            gen.setRequestExtensions(new Extensions(extensions));
            OCSPReq req = gen.build();
            final int localTransactionId = TransactionCounter.INSTANCE.getTransactionNumber();
            final GlobalOcspConfiguration configuration = (GlobalOcspConfiguration) globalConfigurationSession
                    .getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
            TransactionLogger transactionLogger = new TransactionLogger(localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "", configuration);
            AuditLogger auditLogger = new AuditLogger("", localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "", configuration);
            byte[] responseBytes = ocspResponseGeneratorSession.getOcspResponse(req.getEncoded(), null, "", null, new StringBuffer("http://foo.com"),
                    auditLogger, transactionLogger, false, false, false).getOcspResponse();
            assertNotNull("OCSP responder replied null", responseBytes);
            OCSPResp response = new OCSPResp(responseBytes);
            assertEquals("Response status not OCSPRespBuilder.UNAUTHORIZED.", response.getStatus(), OCSPRespBuilder.UNAUTHORIZED);
            assertNull("Response should not have contained a response object.", response.getResponseObject());
        } finally {
            cesecoreConfigurationProxySession.setConfigurationValue(OcspConfiguration.NON_EXISTING_IS_UNAUTHORIZED, originalValue);
        }
    }

    @Test
    public void testGetOcspResponseWithOcspCertificate() throws Exception {
        ocspResponseGeneratorTestSession.reloadOcspSigningCache();

        // An OCSP request
        OCSPReqBuilder gen = new OCSPReqBuilder();
        gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), caCertificate, ocspCertificate.getSerialNumber()));
        Extension[] extensions = new Extension[1];
        extensions[0] = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString(PKIX_OCSP_NONCE.getBytes()).getEncoded());
        gen.setRequestExtensions(new Extensions(extensions));

        OCSPReq req = gen.build();
        final int localTransactionId = TransactionCounter.INSTANCE.getTransactionNumber();
        final GlobalOcspConfiguration configuration = (GlobalOcspConfiguration) globalConfigurationSession
                .getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
        TransactionLogger transactionLogger = new TransactionLogger(localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "", configuration);
        AuditLogger auditLogger = new AuditLogger("", localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "", configuration);
        byte[] responseBytes = ocspResponseGeneratorSession
                .getOcspResponse(req.getEncoded(), null, "", null, null, auditLogger, transactionLogger, false, false, false).getOcspResponse();
        assertNotNull("OCSP responder replied null", responseBytes);

        OCSPResp response = new OCSPResp(responseBytes);
        assertEquals("Response status not zero.", response.getStatus(), 0);
        BasicOCSPResp basicOcspResponse = (BasicOCSPResp) response.getResponseObject();
        assertTrue("OCSP response was not signed correctly.", basicOcspResponse.isSignatureValid(
                new JcaContentVerifierProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build(caCertificate.getPublicKey())));
        SingleResp[] singleResponses = basicOcspResponse.getResponses();
        assertEquals("Delivered some thing else than one and exactly one response.", 1, singleResponses.length);
        assertEquals("Response cert did not match up with request cert", ocspCertificate.getSerialNumber(),
                singleResponses[0].getCertID().getSerialNumber());
        assertEquals("Status is not null (good)", null, singleResponses[0].getCertStatus());
    }

    /**
     * Tests creating an OCSP response using the ocspCertificate, revoking it.
     * Tests using both SHA1 and SHA256 CertID.
     */
    @Test
    public void testGetOcspResponseWithRevokedCertificate() throws Exception {
        doTestWithRevokedCertificate(true, RevokedCertInfo.REVOCATION_REASON_SUPERSEDED);
    }

    /**
     * Like testGetOcspResponseWithRevokedCertificate, but tests with the "Unspecified" revocation reason.
     * Per CA/B Forum Baseline Requirements, the reason code must be omitted when the revocation reason is "Unspecified".
     */
    @Test
    public void testGetOcspResponseWithUnspecifiedRevocationReason() throws Exception {
        doTestWithRevokedCertificate(false, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);
    }

    private void doTestWithRevokedCertificate(final boolean shouldHaveRevocationReason, final int expectedRevocationReason) throws Exception {
        ocspResponseGeneratorTestSession.reloadOcspSigningCache();

        // An OCSP request
        OCSPReqBuilder gen = new OCSPReqBuilder();
        gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), caCertificate, ocspCertificate.getSerialNumber()));
        Extension[] extensions = new Extension[1];
        extensions[0] = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString(PKIX_OCSP_NONCE.getBytes()).getEncoded());
        gen.setRequestExtensions(new Extensions(extensions));

        OCSPReq req = gen.build();

        // Now revoke the ocspCertificate
        internalCertificateStoreSession.setRevokeStatus(internalAdmin, ocspCertificate, new Date(), null, expectedRevocationReason);
        final int localTransactionId = TransactionCounter.INSTANCE.getTransactionNumber();
        final GlobalOcspConfiguration configuration = (GlobalOcspConfiguration) globalConfigurationSession
                .getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
        TransactionLogger transactionLogger = new TransactionLogger(localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "", configuration);

        AuditLogger auditLogger = new AuditLogger("", localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "", configuration);
        byte[] responseBytes = ocspResponseGeneratorSession
                .getOcspResponse(req.getEncoded(), null, "", null, null, auditLogger, transactionLogger, false, false, false).getOcspResponse();
        assertRevokedOcspResponse(shouldHaveRevocationReason, expectedRevocationReason, responseBytes);

        // Do the same test but using SHA256 as hash algorithm for CertID
        gen = new OCSPReqBuilder();
        gen.addRequest(new JcaCertificateID(new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256)),
                caCertificate, ocspCertificate.getSerialNumber()));
        extensions = new Extension[1];
        extensions[0] = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString(PKIX_OCSP_NONCE.getBytes()).getEncoded());
        gen.setRequestExtensions(new Extensions(extensions));
        req = gen.build();
        responseBytes = ocspResponseGeneratorSession
                .getOcspResponse(req.getEncoded(), null, "", null, null, auditLogger, transactionLogger, false, false, false).getOcspResponse();
        assertRevokedOcspResponse(shouldHaveRevocationReason, expectedRevocationReason, responseBytes);
    }

    private void assertRevokedOcspResponse(final boolean shouldHaveRevocationReason, final int expectedRevocationReason, byte[] responseBytes)
            throws IOException, OCSPException, OperatorCreationException {
        assertNotNull("OCSP responder replied null", responseBytes);

        final OCSPResp response = new OCSPResp(responseBytes);
        assertEquals("Response status not zero.", response.getStatus(), 0);
        final BasicOCSPResp basicOcspResponse = (BasicOCSPResp) response.getResponseObject();
        assertTrue("OCSP response was not signed correctly.", basicOcspResponse.isSignatureValid(
                new JcaContentVerifierProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build(caCertificate.getPublicKey())));
        final SingleResp[] singleResponses = basicOcspResponse.getResponses();
        assertEquals("Delivered some thing else than one and exactly one response.", 1, singleResponses.length);
        assertEquals("Response cert did not match up with request cert", ocspCertificate.getSerialNumber(),
                singleResponses[0].getCertID().getSerialNumber());
        final Object status = singleResponses[0].getCertStatus();
        assertTrue("Status is not RevokedStatus", status instanceof RevokedStatus);
        final RevokedStatus rev = (RevokedStatus) status;
        assertEquals("Wrong revocation reason", rev.getRevocationReason(), expectedRevocationReason);
    }

    @Test
    public void testGetOcspResponseWithUnavailableCertificate() throws Exception {
        ocspResponseGeneratorTestSession.reloadOcspSigningCache();

        // An OCSP request
        OCSPReqBuilder gen = new OCSPReqBuilder();
        gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), caCertificate, ocspCertificate.getSerialNumber()));
        Extension[] extensions = new Extension[1];
        extensions[0] = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString(PKIX_OCSP_NONCE.getBytes()).getEncoded());
        gen.setRequestExtensions(new Extensions(extensions));

        OCSPReq req = gen.build();

        // Now remove the certificate
        internalCertificateStoreSession.removeCertificate(ocspCertificate.getSerialNumber());
        ocspResponseGeneratorTestSession.reloadOcspSigningCache();
        final int localTransactionId = TransactionCounter.INSTANCE.getTransactionNumber();
        final GlobalOcspConfiguration configuration = (GlobalOcspConfiguration) globalConfigurationSession
                .getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
        TransactionLogger transactionLogger = new TransactionLogger(localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "", configuration);
        AuditLogger auditLogger = new AuditLogger("", localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "", configuration);
        byte[] responseBytes = ocspResponseGeneratorSession
                .getOcspResponse(req.getEncoded(), null, "", null, new StringBuffer("http://foo.com"), auditLogger, transactionLogger, false, false, false)
                .getOcspResponse();
        assertNotNull("OCSP responder replied null", responseBytes);

        OCSPResp response = new OCSPResp(responseBytes);
        assertEquals("Response status not zero.", response.getStatus(), 0);
        BasicOCSPResp basicOcspResponse = (BasicOCSPResp) response.getResponseObject();
        assertTrue("OCSP response was not signed correctly.", basicOcspResponse.isSignatureValid(
                new JcaContentVerifierProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build(caCertificate.getPublicKey())));
        SingleResp[] singleResponses = basicOcspResponse.getResponses();

        assertEquals("Delivered some thing else than one and exactly one response.", 1, singleResponses.length);
        assertEquals("Response cert did not match up with request cert", ocspCertificate.getSerialNumber(),
                singleResponses[0].getCertID().getSerialNumber());

        // Set that an unknown CA is "good", and redo the test (cache is reloaded automatically)
        cesecoreConfigurationProxySession.setConfigurationValue("ocsp.nonexistingisgood", "true");

        responseBytes = ocspResponseGeneratorSession
                .getOcspResponse(req.getEncoded(), null, "", null, new StringBuffer("http://foo.com"), auditLogger, transactionLogger, false, false, false)
                .getOcspResponse();
        assertNotNull("OCSP responder replied null", responseBytes);

        response = new OCSPResp(responseBytes);
        assertEquals("Response status not zero.", response.getStatus(), 0);
        basicOcspResponse = (BasicOCSPResp) response.getResponseObject();
        assertTrue("OCSP response was not signed correctly.", basicOcspResponse.isSignatureValid(
                new JcaContentVerifierProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build(caCertificate.getPublicKey())));
        singleResponses = basicOcspResponse.getResponses();

        assertEquals("Delivered some thing else than one and exactly one response.", 1, singleResponses.length);
        assertEquals("Response cert did not match up with request cert", ocspCertificate.getSerialNumber(),
                singleResponses[0].getCertID().getSerialNumber());

        // Assert that status is null, i.e. "good"
        assertNull(singleResponses[0].getCertStatus());

        cesecoreConfigurationProxySession.setConfigurationValue("ocsp.nonexistingisgood", "false");
    }

    /**
     * Note that this test is time dependent. Debugging it will create strange behavior.
     * 
     * @throws OCSPException
     * @throws AuthorizationDeniedException
     * @throws MalformedRequestException
     * @throws IOException
     * @throws InterruptedException
     * @throws IllegalCryptoTokenException
     * @throws CADoesntExistsException
     * @throws CertificateEncodingException 
     */
    @Test
    public void testCacheUpdates() throws OCSPException, AuthorizationDeniedException, MalformedRequestException, IOException, InterruptedException,
            CADoesntExistsException, IllegalCryptoTokenException, CertificateEncodingException {
        final Integer timeToWait = 2;
        // Set the validity time to a single second for testing purposes.
        cesecoreConfigurationProxySession.setConfigurationValue(OcspConfiguration.SIGNING_CERTD_VALID_TIME, timeToWait.toString());
        ocspResponseGeneratorTestSession.reloadOcspSigningCache();
        try {
            // An OCSP request
            OCSPReqBuilder gen = new OCSPReqBuilder();
            gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), caCertificate, ocspCertificate.getSerialNumber()));
            Extension[] extensions = new Extension[1];
            extensions[0] = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString(PKIX_OCSP_NONCE.getBytes()).getEncoded());
            gen.setRequestExtensions(new Extensions(extensions));
            OCSPReq req = gen.build();
            byte[] responseBytes;
            ocspResponseGeneratorTestSession.reloadOcspSigningCache();
            final int localTransactionId = TransactionCounter.INSTANCE.getTransactionNumber();
            final GlobalOcspConfiguration configuration = (GlobalOcspConfiguration) globalConfigurationSession
                    .getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
            TransactionLogger transactionLogger = new TransactionLogger(localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "", configuration);
            AuditLogger auditLogger = new AuditLogger("", localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "", configuration);
            responseBytes = ocspResponseGeneratorSession
                    .getOcspResponse(req.getEncoded(), null, "", null, null, auditLogger, transactionLogger, false, false, false).getOcspResponse();
            assertNotNull("OCSP responder replied null", responseBytes);
            // Initial assert that status is null, i.e. "good"
            assertNull("Test could not run because initial ocsp response failed.",
                    ((BasicOCSPResp) (new OCSPResp(responseBytes)).getResponseObject()).getResponses()[0].getCertStatus());
            // Erase the cert. It should still exist in the cache.
            caSession.removeCA(internalAdmin, testx509ca.getCAId());
            responseBytes = ocspResponseGeneratorSession
                    .getOcspResponse(req.getEncoded(), null, "", null, null, auditLogger, transactionLogger, false, false, false).getOcspResponse();
            // Initial assert that status is null, i.e. "good"
            assertNull("Test could not run because cache changed before the entire test could run.",
                    ((BasicOCSPResp) (new OCSPResp(responseBytes)).getResponseObject()).getResponses()[0].getCertStatus());
            // Now sleep and try again, Glassfish has a default "minimum-delivery-interval-in-millis" of 7 seconds, so we have
            // to wait that long, make it 8 seconds. We have set the timer to 2 seconds above.
            Thread.sleep(8 * 1000);
            // Since the CA is gone, expect an unauthorized response
            responseBytes = ocspResponseGeneratorSession
                    .getOcspResponse(req.getEncoded(), null, "", null, null, auditLogger, transactionLogger, false, false, false).getOcspResponse();
            assertNotNull("OCSP responder replied null", responseBytes);
            OCSPResp response = new OCSPResp(responseBytes);
            assertEquals("Response status not OCSPRespBuilder.UNAUTHORIZED.", OCSPRespBuilder.UNAUTHORIZED, response.getStatus());
            assertNull("Response should not have contained a response object.", response.getResponseObject());
        } finally {
            // Reset sign trust valid time.
            cesecoreConfigurationProxySession.setConfigurationValue(OcspConfiguration.SIGNING_CERTD_VALID_TIME,
                    Integer.toString(OcspConfiguration.getSigningCertsValidTimeInMilliseconds()));

        }
    }

    /**
     * This test should use the default OCSP responder to sign the response as unknown.
     * 
     * @throws OCSPException
     * @throws AuthorizationDeniedException
     * @throws IOException
     * @throws MalformedRequestException
     * @throws CADoesntExistsException
     * @throws IllegalCryptoTokenException
     * @throws NoSuchProviderException
     * @throws CertificateEncodingException 
     * @throws OperatorCreationException 
     */
    @Test
    public void testGetOcspResponseWithCertificateFromUnknownCa()
            throws OCSPException, AuthorizationDeniedException, IOException, MalformedRequestException, CADoesntExistsException,
            IllegalCryptoTokenException, NoSuchProviderException, CertificateEncodingException, OperatorCreationException {
        ocspResponseGeneratorTestSession.reloadOcspSigningCache();
        // An OCSP request
        OCSPReqBuilder gen = new OCSPReqBuilder();
        gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), ocspCertificate, ocspCertificate.getSerialNumber()));
        Extension[] extensions = new Extension[1];
        extensions[0] = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString(PKIX_OCSP_NONCE.getBytes()).getEncoded());
        gen.setRequestExtensions(new Extensions(extensions));
        OCSPReq req = gen.build();
        final int localTransactionId = TransactionCounter.INSTANCE.getTransactionNumber();
        final GlobalOcspConfiguration configuration = (GlobalOcspConfiguration) globalConfigurationSession
                .getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
        TransactionLogger transactionLogger = new TransactionLogger(localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "", configuration);
        AuditLogger auditLogger = new AuditLogger("", localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "", configuration);
        byte[] responseBytes = ocspResponseGeneratorSession
                .getOcspResponse(req.getEncoded(), null, "", null, null, auditLogger, transactionLogger, false, false, false).getOcspResponse();
        assertNotNull("OCSP responder replied null", responseBytes);
        OCSPResp response = new OCSPResp(responseBytes);
        assertEquals("Response status not SUCCESSFUL.", OCSPRespBuilder.SUCCESSFUL, response.getStatus());
        BasicOCSPResp basicOcspResponse = (BasicOCSPResp) response.getResponseObject();
        assertTrue("OCSP response was not signed correctly.", basicOcspResponse.isSignatureValid(
                new JcaContentVerifierProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build(caCertificate.getPublicKey())));
        SingleResp[] singleResponses = basicOcspResponse.getResponses();
        assertEquals("Delivered some thing else than one and exactly one response.", 1, singleResponses.length);
        assertEquals("Response cert did not match up with request cert", ocspCertificate.getSerialNumber(),
                singleResponses[0].getCertID().getSerialNumber());
        assertTrue(singleResponses[0].getCertStatus() instanceof UnknownStatus);

    }

    @Test
    public void testGetOcspResponseWithIncorrectDefaultResponder()
            throws OCSPException, AuthorizationDeniedException, IOException, MalformedRequestException, CertificateEncodingException {
        // Set a fake value
        GlobalOcspConfiguration configuration = (GlobalOcspConfiguration) globalConfigurationSession
                .getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
        configuration.setOcspDefaultResponderReference("CN=FancyPants");
        globalConfigurationSession.saveConfiguration(internalAdmin, configuration);

        ocspResponseGeneratorTestSession.reloadOcspSigningCache();

        // An OCSP request
        OCSPReqBuilder gen = new OCSPReqBuilder();
        gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), ocspCertificate, ocspCertificate.getSerialNumber()));
        Extension[] extensions = new Extension[1];
        extensions[0] = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString(PKIX_OCSP_NONCE.getBytes()).getEncoded());
        gen.setRequestExtensions(new Extensions(extensions));

        OCSPReq req = gen.build();

        final int localTransactionId = TransactionCounter.INSTANCE.getTransactionNumber();
        TransactionLogger transactionLogger = new TransactionLogger(localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "", configuration);
        AuditLogger auditLogger = new AuditLogger("", localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "", configuration);
        byte[] responseBytes = ocspResponseGeneratorSession
                .getOcspResponse(req.getEncoded(), null, "", null, null, auditLogger, transactionLogger, false, false, false).getOcspResponse();
        //We're expecting back an unsigned reply saying unauthorized, as per RFC2690 Section 2.3
        assertNotNull("OCSP responder replied null", responseBytes);
        OCSPResp response = new OCSPResp(responseBytes);
        assertEquals("Response status not OCSPRespBuilder.UNAUTHORIZED.", response.getStatus(), OCSPRespBuilder.UNAUTHORIZED);
    }

    /**
     * Makes sure that the OcspSigningCache doesn't add Unsigned CAs
     * @throws AuthorizationDeniedException 
     * @throws IllegalCryptoTokenException 
     * @throws CAExistsException 
     * @throws CADoesntExistsException 
     * @throws InvalidAlgorithmException 
     */
    @Test
    public void testOcspSigningCacheDoesntAddUnsignedCa()
            throws CAExistsException, IllegalCryptoTokenException, AuthorizationDeniedException, CADoesntExistsException, InvalidAlgorithmException {
        final Properties cryptoTokenProperties = new Properties();
        cryptoTokenProperties.setProperty(CryptoToken.AUTOACTIVATE_PIN_PROPERTY, "foo1234");
        int cryptoTokenId = 0;
        try {
            try {
                cryptoTokenId = cryptoTokenManagementSession.createCryptoToken(internalAdmin, "testOcspSigningCacheDoesntAddUnsignedCa",
                        SoftCryptoToken.class.getName(), cryptoTokenProperties, null, null);
                cryptoTokenManagementSession.createKeyPair(internalAdmin, cryptoTokenId, CAToken.SOFTPRIVATESIGNKEYALIAS,
                        KeyGenParams.builder("RSA1024").build());
                cryptoTokenManagementSession.createKeyPair(internalAdmin, cryptoTokenId, CAToken.SOFTPRIVATEDECKEYALIAS,
                        KeyGenParams.builder("RSA1024").build());
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
            // Create CAToken (what key in the CryptoToken should be used for what)
            final Properties caTokenProperties = new Properties();
            caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
            caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
            caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, CAToken.SOFTPRIVATEDECKEYALIAS);
            final CAToken catoken = new CAToken(cryptoTokenId, caTokenProperties);
            catoken.setSignatureAlgorithm(AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
            catoken.setEncryptionAlgorithm(AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
            catoken.setKeySequence(CAToken.DEFAULT_KEYSEQUENCE);
            catoken.setKeySequenceFormat(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);

            // Create an inactive OSCP CA Service.

            X509CAInfo cainfo = X509CAInfo.getDefaultX509CAInfo("CN=TESTSIGNEDBYEXTERNAL", "TESTSIGNEDBYEXTERNAL",
                    CAConstants.CA_WAITING_CERTIFICATE_RESPONSE, CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA, "1000d",
                    CAInfo.SIGNEDBYEXTERNALCA, // Signed by the first TEST CA we created
                    null, catoken);
            cainfo.setDescription("TESTSIGNEDBYEXTERNAL");
            try {
                CA ca = (CA) CAFactory.INSTANCE.getX509CAImpl(cainfo);
                ca.setCAToken(catoken);
                ocspResponseGeneratorTestSession.reloadOcspSigningCache();
                int originalCacheSize = ocspResponseGeneratorTestSession.getCacheOcspCertificates().size();
                caSession.addCA(internalAdmin, ca);
                ocspResponseGeneratorTestSession.reloadOcspSigningCache();
                int laterCacheSize = ocspResponseGeneratorTestSession.getCacheOcspCertificates().size();
                assertEquals("An unsigned CA has been added to cache.", originalCacheSize, laterCacheSize);
            } finally {
                CaTestUtils.removeCa(internalAdmin, cainfo);
            }
        } finally {
            if (cryptoTokenId != 0) {
                cryptoTokenManagementSession.deleteCryptoToken(internalAdmin, cryptoTokenId);
            }
        }
    }

    /** Tests using the default responder for external CAs for a good certificate. */
    @Test
    public void testResponseWithDefaultResponderForExternal() throws Exception {
        // Make sure that a default responder is set
        GlobalOcspConfiguration ocspConfiguration = (GlobalOcspConfiguration) globalConfigurationSession
                .getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
        final String originalDefaultResponder = ocspConfiguration.getOcspDefaultResponderReference();
        ocspConfiguration.setOcspDefaultResponderReference(testx509ca.getSubjectDN());
        globalConfigurationSession.saveConfiguration(internalAdmin, ocspConfiguration);
        try {
            // Now, construct an external CA. 
            final String externalCaName = "testStandAloneOcspResponseExternalCa";
            final String externalCaSubjectDn = "CN=" + externalCaName;
            final long validity = 3650L;
            final String encodedValidity = "3650d";
            KeyPair externalCaKeys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
            Certificate externalCaCertificate = CertTools.genSelfCert(externalCaSubjectDn, validity, null, externalCaKeys.getPrivate(),
                    externalCaKeys.getPublic(), AlgorithmConstants.SIGALG_SHA1_WITH_RSA, true);
            X509CAInfo externalCaInfo = X509CAInfo.getDefaultX509CAInfo(externalCaSubjectDn, externalCaName, CAConstants.CA_EXTERNAL,
                    CertificateProfileConstants.CERTPROFILE_NO_PROFILE, encodedValidity, CAInfo.SELFSIGNED, null, null);
            CAToken token = new CAToken(externalCaInfo.getCAId(), new NullCryptoToken().getProperties());
            X509CA externalCa = (X509CA) CAFactory.INSTANCE.getX509CAImpl(externalCaInfo);
            externalCa.setCAToken(token);
            externalCa.setCertificateChain(Arrays.asList(externalCaCertificate));
            caSession.addCA(internalAdmin, externalCa);
            certificateStoreSession.storeCertificateRemote(internalAdmin, EJBTools.wrap(externalCaCertificate), externalCaName, "1234",
                    CertificateConstants.CERT_ACTIVE, CertificateConstants.CERTTYPE_ROOTCA, CertificateProfileConstants.CERTPROFILE_NO_PROFILE,
                    EndEntityConstants.NO_END_ENTITY_PROFILE, CertificateConstants.NO_CRL_PARTITION, null, new Date().getTime(), null);
            ocspResponseGeneratorSession.reloadOcspSigningCache();
            try {
                final String externalUsername = "testStandAloneOcspResponseExternalUser";
                final String externalSubjectDn = "CN=" + externalUsername;
                // Create a certificate signed by the external CA and stuff it in the database (we can pretend it was imported)
                Date firstDate = new Date();
                firstDate.setTime(firstDate.getTime() - (10 * 60 * 1000));
                Date lastDate = new Date();
                lastDate.setTime(lastDate.getTime() + (24 * 60 * 60 * 1000));
                byte[] serno = new byte[8];
                // This is a test, so randomness does not have to be secure (CSPRNG)
                Random random = new Random();
                random.nextBytes(serno);
                KeyPair certificateKeyPair = KeyTools.genKeys("1024", "RSA");
                final SubjectPublicKeyInfo pkinfo = SubjectPublicKeyInfo.getInstance(certificateKeyPair.getPublic().getEncoded());
                X509v3CertificateBuilder certbuilder = new X509v3CertificateBuilder(CertTools.stringToBcX500Name(externalCaSubjectDn, false),
                        new BigInteger(serno).abs(), firstDate, lastDate, CertTools.stringToBcX500Name(externalSubjectDn, false), pkinfo);
                final ContentSigner signer = new BufferingContentSigner(new JcaContentSignerBuilder("SHA256WithRSA")
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(externalCaKeys.getPrivate()), 20480);
                final X509CertificateHolder certHolder = certbuilder.build(signer);
                X509Certificate importedCertificate = CertTools.getCertfromByteArray(certHolder.getEncoded(), X509Certificate.class);
                certificateStoreSession.storeCertificateRemote(internalAdmin, EJBTools.wrap(importedCertificate), externalUsername, "1234",
                        CertificateConstants.CERT_ACTIVE, CertificateConstants.CERTTYPE_ENDENTITY,
                        CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, EndEntityConstants.NO_END_ENTITY_PROFILE,
                        CertificateConstants.NO_CRL_PARTITION, null, new Date().getTime(), null);
                try {
                    //Now everything is in place. Perform a request, make sure that the default responder signed it. 
                    OCSPReqBuilder gen = new OCSPReqBuilder();
                    gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), (X509Certificate) externalCaCertificate,
                            importedCertificate.getSerialNumber()));
                    Extension[] extensions = new Extension[1];
                    extensions[0] = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString(PKIX_OCSP_NONCE.getBytes()).getEncoded());
                    gen.setRequestExtensions(new Extensions(extensions));
                    OCSPReq ocspRequest = gen.build();
                    final int localTransactionId = TransactionCounter.INSTANCE.getTransactionNumber();
                    final GlobalOcspConfiguration configuration = (GlobalOcspConfiguration) globalConfigurationSession
                            .getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
                    TransactionLogger transactionLogger = new TransactionLogger(localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "",
                            configuration);
                    AuditLogger auditLogger = new AuditLogger("", localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "", configuration);
                    byte[] responseBytes = ocspResponseGeneratorSession
                            .getOcspResponse(ocspRequest.getEncoded(), null, "", null, null, auditLogger, transactionLogger, false, false, false)
                            .getOcspResponse();
                    assertNotNull("OCSP responder replied null", responseBytes);

                    OCSPResp response = new OCSPResp(responseBytes);
                    assertEquals("Response status not zero.", OCSPResp.SUCCESSFUL, response.getStatus());
                    final BasicOCSPResp basicOcspResponse = (BasicOCSPResp) response.getResponseObject();
                    assertNotNull("Signed request generated null-response.", basicOcspResponse);
                    assertTrue("OCSP response was not signed correctly.", basicOcspResponse.isSignatureValid(new JcaContentVerifierProviderBuilder()
                            .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(testx509ca.getCertificateChain().get(0).getPublicKey())));
                    final SingleResp[] singleResponses = basicOcspResponse.getResponses();
                    assertEquals("Delivered some thing else than one and exactly one response.", 1, singleResponses.length);
                    assertEquals("Response cert did not match up with request cert", importedCertificate.getSerialNumber(),
                            singleResponses[0].getCertID().getSerialNumber());
                    assertEquals("Status is not null (good)", null, singleResponses[0].getCertStatus());
                } finally {
                    internalCertificateStoreSession.removeCertificate(importedCertificate);
                }
            } finally {
                CaTestUtils.removeCa(internalAdmin, externalCa.getCAInfo());
                internalCertificateStoreSession.removeCertificate(externalCaCertificate);
            }
        } finally {
            GlobalOcspConfiguration restoredOcspConfiguration = (GlobalOcspConfiguration) globalConfigurationSession
                    .getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
            ocspConfiguration.setOcspDefaultResponderReference(originalDefaultResponder);
            globalConfigurationSession.saveConfiguration(internalAdmin, restoredOcspConfiguration);
        }
    }

    /**
     * Tests enabling and disabling nonces when expecting a reply from a CA
     */
    @Test
    public void testDisableNonceGlobally() throws Exception {
        GlobalOcspConfiguration globalOcspConfiguration = (GlobalOcspConfiguration) globalConfigurationSession
                .getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
        boolean originalNonceEnabledValue = globalOcspConfiguration.getNonceEnabled();
        //First test with NONCE enabled
        globalOcspConfiguration.setNonceEnabled(true);
        globalConfigurationSession.saveConfiguration(internalAdmin, globalOcspConfiguration);

        try {
            ocspResponseGeneratorTestSession.reloadOcspSigningCache();
            final int localTransactionId = TransactionCounter.INSTANCE.getTransactionNumber();
            final GlobalOcspConfiguration configuration = (GlobalOcspConfiguration) globalConfigurationSession
                    .getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
            TransactionLogger transactionLogger = new TransactionLogger(localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "", configuration);
            AuditLogger auditLogger = new AuditLogger("", localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "", configuration);
            // An OCSP request
            OCSPReqBuilder gen = new OCSPReqBuilder();
            gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), caCertificate, caCertificate.getSerialNumber()));
            Extension[] extensions = new Extension[1];
            ASN1OctetString nonce = new DEROctetString(PKIX_OCSP_NONCE.getBytes());
            extensions[0] = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, nonce.getEncoded());
            gen.setRequestExtensions(new Extensions(extensions));
            OCSPReq req = gen.build();
            byte[] responseBytes = ocspResponseGeneratorSession
                    .getOcspResponse(req.getEncoded(), null, "", null, null, auditLogger, transactionLogger, false, false, false).getOcspResponse();
            assertNotNull("OCSP responder replied null", responseBytes);
            OCSPResp response = new OCSPResp(responseBytes);
            assertEquals("Response status not zero (ok).", OCSPRespBuilder.SUCCESSFUL, response.getStatus());
            BasicOCSPResp basicOcspResponse = (BasicOCSPResp) response.getResponseObject();
            Extension retrievedNonce = basicOcspResponse.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
            assertNotNull("No nonce was received in spite of being globally enabled and in the request", retrievedNonce);
            assertEquals("Correct nonce was not retrieved", nonce, retrievedNonce.getParsedValue());
            //First test with NONCE disabled
            globalOcspConfiguration.setNonceEnabled(false);
            globalConfigurationSession.saveConfiguration(internalAdmin, globalOcspConfiguration);
            ocspResponseGeneratorTestSession.reloadOcspSigningCache();
            responseBytes = ocspResponseGeneratorSession
                    .getOcspResponse(req.getEncoded(), null, "", null, null, auditLogger, transactionLogger, false, false, false).getOcspResponse();
            assertNotNull("OCSP responder replied null", responseBytes);
            response = new OCSPResp(responseBytes);
            assertEquals("Response status not zero (ok).", OCSPRespBuilder.SUCCESSFUL, response.getStatus());
            basicOcspResponse = (BasicOCSPResp) response.getResponseObject();
            retrievedNonce = basicOcspResponse.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
            assertNull("Nonce was received in spite of being globally disabled.", retrievedNonce);
        } finally {
            globalOcspConfiguration.setNonceEnabled(originalNonceEnabledValue);
            globalConfigurationSession.saveConfiguration(internalAdmin, globalOcspConfiguration);
        }
    }
}
