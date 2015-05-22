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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
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
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAExistsException;
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
import org.cesecore.certificates.ocsp.OcspResponseGeneratorSessionRemote;
import org.cesecore.certificates.ocsp.OcspResponseGeneratorTestSessionRemote;
import org.cesecore.certificates.ocsp.SHA1DigestCalculator;
import org.cesecore.certificates.ocsp.exception.MalformedRequestException;
import org.cesecore.certificates.ocsp.logging.AuditLogger;
import org.cesecore.certificates.ocsp.logging.GuidHolder;
import org.cesecore.certificates.ocsp.logging.TransactionCounter;
import org.cesecore.certificates.ocsp.logging.TransactionLogger;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.config.GlobalOcspConfiguration;
import org.cesecore.config.OcspConfiguration;
import org.cesecore.configuration.CesecoreConfigurationProxySessionRemote;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.junit.util.CryptoTokenRule;
import org.cesecore.junit.util.CryptoTokenTestRunner;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.IllegalCryptoTokenException;
import org.cesecore.keys.token.NullCryptoToken;
import org.cesecore.keys.token.SoftCryptoToken;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.roles.RoleNotFoundException;
import org.cesecore.util.CertTools;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.StringTools;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.junit.After;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

/**
 * 
 * @version $Id$
 * 
 */
@RunWith(CryptoTokenTestRunner.class)
public class IntegratedOcspResponseTest {

    private final static Logger log = Logger.getLogger(IntegratedOcspResponseTest.class);

    private CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private CertificateCreateSessionRemote certificateCreateSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateCreateSessionRemote.class);
    private CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);
    private CesecoreConfigurationProxySessionRemote cesecoreConfigurationProxySession = EjbRemoteHelper.INSTANCE.getRemoteSession(
            CesecoreConfigurationProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CryptoTokenManagementSessionRemote.class);
    private InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(
            InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private GlobalConfigurationSessionRemote globalConfigurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);
    private OcspResponseGeneratorSessionRemote ocspResponseGeneratorSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(OcspResponseGeneratorSessionRemote.class);
    private OcspResponseGeneratorTestSessionRemote ocspResponseGeneratorTestSession = EjbRemoteHelper.INSTANCE.getRemoteSession(
            OcspResponseGeneratorTestSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);

    private X509Certificate caCertificate;
    private X509Certificate ocspCertificate;
    private CA testx509ca;
    private String originalDefaultResponder;

    private final AuthenticationToken internalAdmin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("Internal Admin"));

    @ClassRule
    public static CryptoTokenRule cryptoTokenRule = new CryptoTokenRule();

    @Before
    public void setUp() throws Exception {
        testx509ca = cryptoTokenRule.createX509Ca(); 
        caCertificate = (X509Certificate) testx509ca.getCACertificate();
        EndEntityInformation user = new EndEntityInformation("username", "CN=User", testx509ca.getCAId(), "rfc822Name=user@user.com", "user@user.com",
                EndEntityTypes.ENDUSER.toEndEntityType(), 0, 0, EndEntityConstants.TOKEN_USERGEN, 0, null);
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
    public void tearDown() throws AuthorizationDeniedException, RoleNotFoundException {
        cryptoTokenRule.cleanUp();
        internalCertificateStoreSession.removeCertificate(ocspCertificate.getSerialNumber());
        // Restore the default value
        setOcspDefaultResponderReference(originalDefaultResponder);
    }

    /** After renewing a CA with a new key pair, the new CA certificate should be used to sign requests */
    @Test
    public void testOcspSignerIssuerRenewal() throws Exception {
        log.trace(">testOcspSignerIssuerRenewal");
        final X509CA testx509caRenew = cryptoTokenRule.createX509Ca(); 
        final X509Certificate caCertificateRenew = (X509Certificate) testx509caRenew.getCACertificate();
        final EndEntityInformation user = new EndEntityInformation("testOcspSignerIssuerRenewal", "CN=testOcspSignerIssuerRenewal", testx509ca.getCAId(), null, null,
                EndEntityTypes.ENDUSER.toEndEntityType(), 0, 0, EndEntityConstants.TOKEN_USERGEN, 0, null);
        user.setPassword("foo123");
        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        SimpleRequestMessage req = new SimpleRequestMessage(keys.getPublic(), user.getUsername(), user.getPassword());
        X509Certificate eeCertificate = (X509Certificate) (((X509ResponseMessage) certificateCreateSession.createCertificate(internalAdmin, user, req,
                X509ResponseMessage.class, signSession.fetchCertGenParams())).getCertificate());
        final String ocspDefaultResponderReference = setOcspDefaultResponderReference(null);
        try {
            ocspResponseGeneratorTestSession.reloadOcspSigningCache();
            testOcspSignerIssuerRenewalInternal(eeCertificate, caCertificateRenew, OCSPResp.SUCCESSFUL);
            // Try the same thing after CA has been renewed
            caAdminSession.renewCA(internalAdmin, testx509caRenew.getCAId(), true, null, false);
            final X509Certificate caCertificateRenewed = (X509Certificate) caSession.getCAInfo(internalAdmin, testx509caRenew.getCAId()).getCertificateChain().iterator().next();
            ocspResponseGeneratorTestSession.reloadOcspSigningCache();
            assertEquals("Status is not null (good)", null, testOcspSignerIssuerRenewalInternal(eeCertificate, caCertificateRenewed, OCSPResp.SUCCESSFUL));
            /*
             * If we query for EE certificate with the previous issuer cert, the responder will think it is from an unknown CA,
             * since we do the lookup of the issuer from the combination of issuerName and keyHash.
             * 
             * The expected outcome is "unauthorized", since the default responder is disabled during this test.
             */
            testOcspSignerIssuerRenewalInternal(eeCertificate, caCertificateRenew, OCSPResp.UNAUTHORIZED);
        } finally {
            setOcspDefaultResponderReference(ocspDefaultResponderReference);
            internalCertificateStoreSession.removeCertificate(eeCertificate.getSerialNumber());
        }
        log.trace("<testOcspSignerIssuerRenewal");
    }
    
    private String setOcspDefaultResponderReference(final String dn) throws AuthorizationDeniedException {
        final GlobalOcspConfiguration configuration = (GlobalOcspConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
        final String originalDefaultResponder = configuration.getOcspDefaultResponderReference();
        configuration.setOcspDefaultResponderReference(dn);
        globalConfigurationSession.saveConfiguration(internalAdmin, configuration);
        return originalDefaultResponder;
    }
    
    private CertificateStatus testOcspSignerIssuerRenewalInternal(X509Certificate eeCertificate, X509Certificate caCertificate, int expectedStatus) throws Exception {
        OCSPReq ocspReq = new OCSPReqBuilder().addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), caCertificate, eeCertificate.getSerialNumber())).build();
        final int localTransactionId = TransactionCounter.INSTANCE.getTransactionNumber();
        TransactionLogger transactionLogger = new TransactionLogger(localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "");
        AuditLogger auditLogger = new AuditLogger("", localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "");
        byte[] responseBytes = ocspResponseGeneratorSession.getOcspResponse(ocspReq.getEncoded(), null, "", null, auditLogger, transactionLogger).getOcspResponse();
        assertNotNull("OCSP responder replied null", responseBytes);
        OCSPResp response = new OCSPResp(responseBytes);
        if (expectedStatus == OCSPResp.UNAUTHORIZED) {
            assertEquals("Response status not zero.", OCSPResp.UNAUTHORIZED, response.getStatus());
            return null;
        } else {
            assertEquals("Response status not zero.", OCSPResp.SUCCESSFUL, response.getStatus());
            BasicOCSPResp basicOcspResponse = (BasicOCSPResp) response.getResponseObject();
            assertTrue("OCSP response was not signed correctly.", basicOcspResponse.isSignatureValid(new JcaContentVerifierProviderBuilder().build(caCertificate.getPublicKey())));
            SingleResp[] singleResponses = basicOcspResponse.getResponses();
            assertEquals("Delivered some thing else than one and exactly one response.", 1, singleResponses.length);
            assertEquals("Response cert did not match up with request cert", eeCertificate.getSerialNumber(), singleResponses[0].getCertID().getSerialNumber());
            return singleResponses[0].getCertStatus();
        }
    }
    
    /**
     * Tests creating an OCSP response using the root CA cert.
     * Tests using both SHA1, SHA256 and SHA224 CertID. SHA1 and SHA256 should work, while SHA224 should give an error.
     */
    @Test
    public void testGetOcspResponseSanity() throws Exception {
        ocspResponseGeneratorTestSession.reloadOcspSigningCache();
        // An OCSP request
        OCSPReqBuilder gen = new OCSPReqBuilder();
        gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), caCertificate, caCertificate.getSerialNumber()));
        Extension[] extensions = new Extension[1];
        extensions[0] = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString("123456789".getBytes()));
        gen.setRequestExtensions(new Extensions(extensions));
        OCSPReq req = gen.build();

        final int localTransactionId = TransactionCounter.INSTANCE.getTransactionNumber();
        // Create the transaction logger for this transaction.
        TransactionLogger transactionLogger = new TransactionLogger(localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "");
        // Create the audit logger for this transaction.
        AuditLogger auditLogger = new AuditLogger("", localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "");
        byte[] responseBytes = ocspResponseGeneratorSession.getOcspResponse(req.getEncoded(), null, "", null, auditLogger, transactionLogger)
                .getOcspResponse();
        assertNotNull("OCSP responder replied null", responseBytes);

        OCSPResp response = new OCSPResp(responseBytes);
        assertEquals("Response status not zero.", 0, response.getStatus());
        BasicOCSPResp basicOcspResponse = (BasicOCSPResp) response.getResponseObject();
        assertTrue("OCSP response was not signed correctly.",
                basicOcspResponse.isSignatureValid(new JcaContentVerifierProviderBuilder().build(caCertificate.getPublicKey())));
        SingleResp[] singleResponses = basicOcspResponse.getResponses();
        assertEquals("Delivered some thing else than one and exactly one response.", 1, singleResponses.length);
        assertEquals("Response cert did not match up with request cert", caCertificate.getSerialNumber(), singleResponses[0].getCertID()
                .getSerialNumber());
        assertEquals("Status is not null (good)", null, singleResponses[0].getCertStatus());
        
        // Do the same test but using SHA256 as hash algorithm for CertID
        gen = new OCSPReqBuilder();
        gen.addRequest(new JcaCertificateID(new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256)), caCertificate, caCertificate.getSerialNumber()));
        extensions = new Extension[1];
        extensions[0] = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString("123456789".getBytes()));
        gen.setRequestExtensions(new Extensions(extensions));
        req = gen.build();
        responseBytes = ocspResponseGeneratorSession.getOcspResponse(req.getEncoded(), null, "", null, auditLogger, transactionLogger)
                .getOcspResponse();
        assertNotNull("OCSP responder replied null", responseBytes);
        response = new OCSPResp(responseBytes);
        assertEquals("Response status not zero.", 0, response.getStatus());
        basicOcspResponse = (BasicOCSPResp) response.getResponseObject();
        assertTrue("OCSP response was not signed correctly.",
                basicOcspResponse.isSignatureValid(new JcaContentVerifierProviderBuilder().build(caCertificate.getPublicKey())));
        singleResponses = basicOcspResponse.getResponses();
        assertEquals("Delivered some thing else than one and exactly one response.", 1, singleResponses.length);
        assertEquals("Response cert did not match up with request cert", caCertificate.getSerialNumber(), singleResponses[0].getCertID()
                .getSerialNumber());
        assertEquals("Status is not null (good)", null, singleResponses[0].getCertStatus());

        // Do the same test but using SHA224 as hash algorithm for CertID to see that we get an error back
        gen = new OCSPReqBuilder();
        gen.addRequest(new JcaCertificateID(new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha224)), caCertificate, caCertificate.getSerialNumber()));
        extensions = new Extension[1];
        extensions[0] = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString("123456789".getBytes()));
        gen.setRequestExtensions(new Extensions(extensions));
        req = gen.build();
        responseBytes = ocspResponseGeneratorSession.getOcspResponse(req.getEncoded(), null, "", null, auditLogger, transactionLogger)
                .getOcspResponse();
        assertNotNull("OCSP responder replied null", responseBytes);
        response = new OCSPResp(responseBytes);
        // Response status 1 means malformed request
        assertEquals("Response status not zero.", 1, response.getStatus());
        basicOcspResponse = (BasicOCSPResp) response.getResponseObject();
        assertNull("No response object for this unsigned error response.", basicOcspResponse);

    }
    
    /**
     * Tests with nonexistingisrevoked
     */
    @Test
    public void testNonExistingIsRevoked() throws Exception {
        String originalValue = cesecoreConfigurationProxySession.getConfigurationValue(OcspConfiguration.NONE_EXISTING_IS_REVOKED);
        cesecoreConfigurationProxySession.setConfigurationValue(OcspConfiguration.NONE_EXISTING_IS_REVOKED, "true");
        try {
        ocspResponseGeneratorTestSession.reloadOcspSigningCache();

        // An OCSP request
        OCSPReqBuilder gen = new OCSPReqBuilder();
        gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), caCertificate, ocspCertificate.getSerialNumber()));
        Extension[] extensions = new Extension[1];
        extensions[0] = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString("123456789".getBytes()));
        gen.setRequestExtensions(new Extensions(extensions));

        OCSPReq req = gen.build();

        // Now remove the certificate
        internalCertificateStoreSession.removeCertificate(ocspCertificate.getSerialNumber());
        ocspResponseGeneratorTestSession.reloadOcspSigningCache();
        final int localTransactionId = TransactionCounter.INSTANCE.getTransactionNumber();
        // Create the transaction logger for this transaction.
        TransactionLogger transactionLogger = new TransactionLogger(localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "");
        // Create the audit logger for this transaction.
            AuditLogger auditLogger = new AuditLogger("", localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "");
            byte[] responseBytes = ocspResponseGeneratorSession.getOcspResponse(req.getEncoded(), null, "", new StringBuffer("http://foo.com"),
                    auditLogger, transactionLogger).getOcspResponse();
            assertNotNull("OCSP responder replied null", responseBytes);

            OCSPResp response = new OCSPResp(responseBytes);
            assertEquals("Response status not zero.", response.getStatus(), 0);
            BasicOCSPResp basicOcspResponse = (BasicOCSPResp) response.getResponseObject();
            assertTrue("OCSP response was not signed correctly.",
                    basicOcspResponse.isSignatureValid(new JcaContentVerifierProviderBuilder().build(caCertificate.getPublicKey())));
            SingleResp[] singleResponses = basicOcspResponse.getResponses();

            assertEquals("Delivered some thing else than one and exactly one response.", 1, singleResponses.length);
            assertEquals("Response cert did not match up with request cert", ocspCertificate.getSerialNumber(), singleResponses[0].getCertID()
                    .getSerialNumber());

            responseBytes = ocspResponseGeneratorSession.getOcspResponse(req.getEncoded(), null, "", new StringBuffer("http://foo.com"),
                    auditLogger, transactionLogger).getOcspResponse();
            assertNotNull("OCSP responder replied null", responseBytes);

            response = new OCSPResp(responseBytes);
            assertEquals("Response status not zero.", response.getStatus(), 0);
            basicOcspResponse = (BasicOCSPResp) response.getResponseObject();
            assertTrue("OCSP response was not signed correctly.",
                    basicOcspResponse.isSignatureValid(new JcaContentVerifierProviderBuilder().build(caCertificate.getPublicKey())));
            singleResponses = basicOcspResponse.getResponses();

            assertEquals("Delivered some thing else than one and exactly one response.", 1, singleResponses.length);
            assertEquals("Response cert did not match up with request cert", ocspCertificate.getSerialNumber(), singleResponses[0].getCertID()
                    .getSerialNumber());

            // Assert that status is revoked
            CertificateStatus status = singleResponses[0].getCertStatus();
            assertTrue("Status is not RevokedStatus", status instanceof RevokedStatus);
            
            // Set ocsp.nonexistingisgood=true, veryify that answer comes out okay.
            String originalNoneExistingIsGood = cesecoreConfigurationProxySession.getConfigurationValue(OcspConfiguration.NONE_EXISTING_IS_GOOD);
            cesecoreConfigurationProxySession.setConfigurationValue(OcspConfiguration.NONE_EXISTING_IS_GOOD, "true");
            try {
                responseBytes = ocspResponseGeneratorSession.getOcspResponse(req.getEncoded(), null, "", new StringBuffer("http://foo.com"),
                        auditLogger, transactionLogger).getOcspResponse();
                assertNotNull("OCSP responder replied null", responseBytes);

                response = new OCSPResp(responseBytes);
                assertEquals("Response status not zero.", response.getStatus(), 0);
                basicOcspResponse = (BasicOCSPResp) response.getResponseObject();
                assertTrue("OCSP response was not signed correctly.",
                        basicOcspResponse.isSignatureValid(new JcaContentVerifierProviderBuilder().build(caCertificate.getPublicKey())));
                singleResponses = basicOcspResponse.getResponses();

                assertEquals("Delivered some thing else than one and exactly one response.", 1, singleResponses.length);
                assertEquals("Response cert did not match up with request cert", ocspCertificate.getSerialNumber(), singleResponses[0].getCertID()
                        .getSerialNumber());
                assertEquals("Status is not null (good)", null, singleResponses[0].getCertStatus());
            } finally {
                cesecoreConfigurationProxySession.setConfigurationValue(OcspConfiguration.NONE_EXISTING_IS_GOOD, originalNoneExistingIsGood);
            }
        } finally {
            cesecoreConfigurationProxySession.setConfigurationValue(OcspConfiguration.NONE_EXISTING_IS_REVOKED, originalValue);
        }

    }


    @Test
    public void testGetOcspResponseWithOcspCertificate() throws Exception {
        ocspResponseGeneratorTestSession.reloadOcspSigningCache();

        // An OCSP request
        OCSPReqBuilder gen = new OCSPReqBuilder();
        gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), caCertificate, ocspCertificate.getSerialNumber()));
        Extension[] extensions = new Extension[1];
        extensions[0] = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString("123456789".getBytes()));
        gen.setRequestExtensions(new Extensions(extensions));

        OCSPReq req = gen.build();
        final int localTransactionId = TransactionCounter.INSTANCE.getTransactionNumber();
        // Create the transaction logger for this transaction.
        TransactionLogger transactionLogger = new TransactionLogger(localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "");
        // Create the audit logger for this transaction.
        AuditLogger auditLogger = new AuditLogger("", localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "");
        byte[] responseBytes = ocspResponseGeneratorSession.getOcspResponse(req.getEncoded(), null, "", null, auditLogger, transactionLogger)
                .getOcspResponse();
        assertNotNull("OCSP responder replied null", responseBytes);

        OCSPResp response = new OCSPResp(responseBytes);
        assertEquals("Response status not zero.", response.getStatus(), 0);
        BasicOCSPResp basicOcspResponse = (BasicOCSPResp) response.getResponseObject();
        assertTrue("OCSP response was not signed correctly.",
                basicOcspResponse.isSignatureValid(new JcaContentVerifierProviderBuilder().build(caCertificate.getPublicKey())));
        SingleResp[] singleResponses = basicOcspResponse.getResponses();
        assertEquals("Delivered some thing else than one and exactly one response.", 1, singleResponses.length);
        assertEquals("Response cert did not match up with request cert", ocspCertificate.getSerialNumber(), singleResponses[0].getCertID()
                .getSerialNumber());
        assertEquals("Status is not null (good)", null, singleResponses[0].getCertStatus());
    }

    /**
     * Tests creating an OCSP response using the ocspCertificate, revoking it.
     * Tests using both SHA1 and SHA256 CertID.
     */
    @Test
    public void testGetOcspResponseWithRevokedCertificate() throws Exception {
        ocspResponseGeneratorTestSession.reloadOcspSigningCache();

        // An OCSP request
        OCSPReqBuilder gen = new OCSPReqBuilder();
        gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), caCertificate, ocspCertificate.getSerialNumber()));
        Extension[] extensions = new Extension[1];
        extensions[0] = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString("123456789".getBytes()));
        gen.setRequestExtensions(new Extensions(extensions));

        OCSPReq req = gen.build();

        // Now revoke the ocspCertificate
        certificateStoreSession.setRevokeStatus(internalAdmin, ocspCertificate, new Date(), RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);
        final int localTransactionId = TransactionCounter.INSTANCE.getTransactionNumber();
        // Create the transaction logger for this transaction.
        TransactionLogger transactionLogger = new TransactionLogger(localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "");
        // Create the audit logger for this transaction.
        AuditLogger auditLogger = new AuditLogger("", localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "");
        byte[] responseBytes = ocspResponseGeneratorSession.getOcspResponse(req.getEncoded(), null, "", null, auditLogger, transactionLogger)
                .getOcspResponse();
        assertNotNull("OCSP responder replied null", responseBytes);

        OCSPResp response = new OCSPResp(responseBytes);
        assertEquals("Response status not zero.", response.getStatus(), 0);
        BasicOCSPResp basicOcspResponse = (BasicOCSPResp) response.getResponseObject();
        assertTrue("OCSP response was not signed correctly.",
                basicOcspResponse.isSignatureValid(new JcaContentVerifierProviderBuilder().build(caCertificate.getPublicKey())));
        SingleResp[] singleResponses = basicOcspResponse.getResponses();
        assertEquals("Delivered some thing else than one and exactly one response.", 1, singleResponses.length);
        assertEquals("Response cert did not match up with request cert", ocspCertificate.getSerialNumber(), singleResponses[0].getCertID()
                .getSerialNumber());
        Object status = singleResponses[0].getCertStatus();
        assertTrue("Status is not RevokedStatus", status instanceof RevokedStatus);
        RevokedStatus rev = (RevokedStatus) status;
        assertTrue("Status does not have reason", rev.hasRevocationReason());
        int reason = rev.getRevocationReason();
        assertEquals("Wrong revocation reason", reason, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);
        
        // Do the same test but using SHA256 as hash algorithm for CertID
        gen = new OCSPReqBuilder();
        gen.addRequest(new JcaCertificateID(new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256)), caCertificate, ocspCertificate.getSerialNumber()));
        extensions = new Extension[1];
        extensions[0] = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString("123456789".getBytes()));
        gen.setRequestExtensions(new Extensions(extensions));
        req = gen.build();
        responseBytes = ocspResponseGeneratorSession.getOcspResponse(req.getEncoded(), null, "", null, auditLogger, transactionLogger)
                .getOcspResponse();
        response = new OCSPResp(responseBytes);
        assertEquals("Response status not zero.", response.getStatus(), 0);
        basicOcspResponse = (BasicOCSPResp) response.getResponseObject();
        assertTrue("OCSP response was not signed correctly.",
                basicOcspResponse.isSignatureValid(new JcaContentVerifierProviderBuilder().build(caCertificate.getPublicKey())));
        singleResponses = basicOcspResponse.getResponses();
        assertEquals("Delivered some thing else than one and exactly one response.", 1, singleResponses.length);
        assertEquals("Response cert did not match up with request cert", ocspCertificate.getSerialNumber(), singleResponses[0].getCertID()
                .getSerialNumber());
        status = singleResponses[0].getCertStatus();
        assertTrue("Status is not RevokedStatus", status instanceof RevokedStatus);
        rev = (RevokedStatus) status;
        assertTrue("Status does not have reason", rev.hasRevocationReason());
        reason = rev.getRevocationReason();
        assertEquals("Wrong revocation reason", reason, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);

    }

    @Test
    public void testGetOcspResponseWithUnavailableCertificate() throws Exception {
        ocspResponseGeneratorTestSession.reloadOcspSigningCache();

        // An OCSP request
        OCSPReqBuilder gen = new OCSPReqBuilder();
        gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), caCertificate, ocspCertificate.getSerialNumber()));
        Extension[] extensions = new Extension[1];
        extensions[0] = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString("123456789".getBytes()));
        gen.setRequestExtensions(new Extensions(extensions));

        OCSPReq req = gen.build();

        // Now remove the certificate
        internalCertificateStoreSession.removeCertificate(ocspCertificate.getSerialNumber());
        ocspResponseGeneratorTestSession.reloadOcspSigningCache();
        final int localTransactionId = TransactionCounter.INSTANCE.getTransactionNumber();
        // Create the transaction logger for this transaction.
        TransactionLogger transactionLogger = new TransactionLogger(localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "");
        // Create the audit logger for this transaction.
        AuditLogger auditLogger = new AuditLogger("", localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "");
        byte[] responseBytes = ocspResponseGeneratorSession.getOcspResponse(req.getEncoded(), null, "", new StringBuffer("http://foo.com"),
                auditLogger, transactionLogger).getOcspResponse();
        assertNotNull("OCSP responder replied null", responseBytes);

        OCSPResp response = new OCSPResp(responseBytes);
        assertEquals("Response status not zero.", response.getStatus(), 0);
        BasicOCSPResp basicOcspResponse = (BasicOCSPResp) response.getResponseObject();
        assertTrue("OCSP response was not signed correctly.",
                basicOcspResponse.isSignatureValid(new JcaContentVerifierProviderBuilder().build(caCertificate.getPublicKey())));
        SingleResp[] singleResponses = basicOcspResponse.getResponses();

        assertEquals("Delivered some thing else than one and exactly one response.", 1, singleResponses.length);
        assertEquals("Response cert did not match up with request cert", ocspCertificate.getSerialNumber(), singleResponses[0].getCertID()
                .getSerialNumber());

        // Set that an unknown CA is "good", and redo the test (cache is reloaded automatically)
        cesecoreConfigurationProxySession.setConfigurationValue("ocsp.nonexistingisgood", "true");

        responseBytes = ocspResponseGeneratorSession.getOcspResponse(req.getEncoded(), null, "", new StringBuffer("http://foo.com"), auditLogger,
                transactionLogger).getOcspResponse();
        assertNotNull("OCSP responder replied null", responseBytes);

        response = new OCSPResp(responseBytes);
        assertEquals("Response status not zero.", response.getStatus(), 0);
        basicOcspResponse = (BasicOCSPResp) response.getResponseObject();
        assertTrue("OCSP response was not signed correctly.",
                basicOcspResponse.isSignatureValid(new JcaContentVerifierProviderBuilder().build(caCertificate.getPublicKey())));
        singleResponses = basicOcspResponse.getResponses();

        assertEquals("Delivered some thing else than one and exactly one response.", 1, singleResponses.length);
        assertEquals("Response cert did not match up with request cert", ocspCertificate.getSerialNumber(), singleResponses[0].getCertID()
                .getSerialNumber());

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
            extensions[0] = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString("123456789".getBytes()));
            gen.setRequestExtensions(new Extensions(extensions));
            OCSPReq req = gen.build();
            byte[] responseBytes;
            ocspResponseGeneratorTestSession.reloadOcspSigningCache();
            final int localTransactionId = TransactionCounter.INSTANCE.getTransactionNumber();
            // Create the transaction logger for this transaction.
            TransactionLogger transactionLogger = new TransactionLogger(localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "");
            // Create the audit logger for this transaction.
            AuditLogger auditLogger = new AuditLogger("", localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "");
            responseBytes = ocspResponseGeneratorSession.getOcspResponse(req.getEncoded(), null, "", null, auditLogger, transactionLogger)
                    .getOcspResponse();
            assertNotNull("OCSP responder replied null", responseBytes);
            // Initial assert that status is null, i.e. "good"
            assertNull("Test could not run because initial ocsp response failed.",
                    ((BasicOCSPResp) (new OCSPResp(responseBytes)).getResponseObject()).getResponses()[0].getCertStatus());
            // Erase the cert. It should still exist in the cache.
            caSession.removeCA(internalAdmin, testx509ca.getCAId());
            responseBytes = ocspResponseGeneratorSession.getOcspResponse(req.getEncoded(), null, "", null, auditLogger, transactionLogger)
                    .getOcspResponse();
            // Initial assert that status is null, i.e. "good"
            assertNull("Test could not run because cache changed before the entire test could run.",
                    ((BasicOCSPResp) (new OCSPResp(responseBytes)).getResponseObject()).getResponses()[0].getCertStatus());
            // Now sleep and try again, Glassfish has a default "minimum-delivery-interval-in-millis" of 7 seconds, so we have
            // to wait that long, make it 8 seconds. We have set the timer to 2 seconds above.
            Thread.sleep(8 * 1000);
            // Since the CA is gone, expect an unauthorized response
            responseBytes = ocspResponseGeneratorSession.getOcspResponse(req.getEncoded(), null, "", null, auditLogger, transactionLogger)
                    .getOcspResponse();
            assertNotNull("OCSP responder replied null", responseBytes);
            OCSPResp response = new OCSPResp(responseBytes);
            assertEquals("Response status not OCSPRespBuilder.UNAUTHORIZED.", response.getStatus(), OCSPRespBuilder.UNAUTHORIZED);
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
    public void testGetOcspResponseWithCertificateFromUnknownCa() throws OCSPException, AuthorizationDeniedException, IOException,
            MalformedRequestException, CADoesntExistsException, IllegalCryptoTokenException, NoSuchProviderException, CertificateEncodingException,
            OperatorCreationException {
        ocspResponseGeneratorTestSession.reloadOcspSigningCache();
        // An OCSP request
        OCSPReqBuilder gen = new OCSPReqBuilder();
        gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), ocspCertificate, ocspCertificate.getSerialNumber()));
        Extension[] extensions = new Extension[1];
        extensions[0] = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString("123456789".getBytes()));
        gen.setRequestExtensions(new Extensions(extensions));
        OCSPReq req = gen.build();
        final int localTransactionId = TransactionCounter.INSTANCE.getTransactionNumber();
        // Create the transaction logger for this transaction.
        TransactionLogger transactionLogger = new TransactionLogger(localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "");
        // Create the audit logger for this transaction.
        AuditLogger auditLogger = new AuditLogger("", localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "");
        byte[] responseBytes = ocspResponseGeneratorSession.getOcspResponse(req.getEncoded(), null, "", null, auditLogger, transactionLogger)
                .getOcspResponse();
        assertNotNull("OCSP responder replied null", responseBytes);
        OCSPResp response = new OCSPResp(responseBytes);
        assertEquals("Response status not SUCCESSFUL.", OCSPRespBuilder.SUCCESSFUL, response.getStatus());
        BasicOCSPResp basicOcspResponse = (BasicOCSPResp) response.getResponseObject();
        assertTrue("OCSP response was not signed correctly.",
                basicOcspResponse.isSignatureValid(new JcaContentVerifierProviderBuilder().build(caCertificate.getPublicKey())));
        SingleResp[] singleResponses = basicOcspResponse.getResponses();
        assertEquals("Delivered some thing else than one and exactly one response.", 1, singleResponses.length);
        assertEquals("Response cert did not match up with request cert", ocspCertificate.getSerialNumber(), singleResponses[0].getCertID()
                .getSerialNumber());
        assertTrue(singleResponses[0].getCertStatus() instanceof UnknownStatus);

    }

    @Test
    public void testGetOcspResponseWithIncorrectDefaultResponder() throws OCSPException, AuthorizationDeniedException, IOException,
            MalformedRequestException, CADoesntExistsException, IllegalCryptoTokenException, CertificateEncodingException {
        // Set a fake value
        GlobalOcspConfiguration configuration = (GlobalOcspConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
        configuration.setOcspDefaultResponderReference("CN=FancyPants");
        globalConfigurationSession.saveConfiguration(internalAdmin, configuration);
        
        ocspResponseGeneratorTestSession.reloadOcspSigningCache();

        // An OCSP request
        OCSPReqBuilder gen = new OCSPReqBuilder();
        gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), ocspCertificate, ocspCertificate.getSerialNumber()));
        Extension[] extensions = new Extension[1];
        extensions[0] = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString("123456789".getBytes()));
        gen.setRequestExtensions(new Extensions(extensions));

        OCSPReq req = gen.build();

        final int localTransactionId = TransactionCounter.INSTANCE.getTransactionNumber();
        // Create the transaction logger for this transaction.
        TransactionLogger transactionLogger = new TransactionLogger(localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "");
        // Create the audit logger for this transaction.
        AuditLogger auditLogger = new AuditLogger("", localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "");
        byte[] responseBytes = ocspResponseGeneratorSession.getOcspResponse(req.getEncoded(), null, "", null, auditLogger, transactionLogger)
                .getOcspResponse();
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
    public void testOcspSigningCacheDoesntAddUnsignedCa() throws CAExistsException, IllegalCryptoTokenException, AuthorizationDeniedException,
            CADoesntExistsException, InvalidAlgorithmException {
        final Properties cryptoTokenProperties = new Properties();
        cryptoTokenProperties.setProperty(CryptoToken.AUTOACTIVATE_PIN_PROPERTY, "foo1234");
        int cryptoTokenId = 0;
        try {
            try {
                cryptoTokenId = cryptoTokenManagementSession.createCryptoToken(internalAdmin, "testOcspSigningCacheDoesntAddUnsignedCa",
                        SoftCryptoToken.class.getName(), cryptoTokenProperties, null, null);
                cryptoTokenManagementSession.createKeyPair(internalAdmin, cryptoTokenId, CAToken.SOFTPRIVATESIGNKEYALIAS, "1024");
                cryptoTokenManagementSession.createKeyPair(internalAdmin, cryptoTokenId, CAToken.SOFTPRIVATEDECKEYALIAS, "1024");
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

            X509CAInfo cainfo = new X509CAInfo("CN=TESTSIGNEDBYEXTERNAL", "TESTSIGNEDBYEXTERNAL", CAConstants.CA_WAITING_CERTIFICATE_RESPONSE,
                    CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA, 1000, CAInfo.SIGNEDBYEXTERNALCA, // Signed by the first TEST CA we created
                    null, catoken);
            cainfo.setDescription("TESTSIGNEDBYEXTERNAL");
            try {
                CA ca = new X509CA(cainfo);
                ca.setCAToken(catoken);
                ocspResponseGeneratorTestSession.reloadOcspSigningCache();
                int originalCacheSize = ocspResponseGeneratorTestSession.getCacheOcspCertificates().size();
                caSession.addCA(internalAdmin, ca);
                ocspResponseGeneratorTestSession.reloadOcspSigningCache();
                int laterCacheSize = ocspResponseGeneratorTestSession.getCacheOcspCertificates().size();
                assertEquals("An unsigned CA has been added to cache.", originalCacheSize, laterCacheSize);
            } finally {
                caSession.removeCA(internalAdmin, cainfo.getCAId());
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
            long validity = 3650L;
            KeyPair externalCaKeys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
            Certificate externalCaCertificate = CertTools.genSelfCert(externalCaSubjectDn, validity, null, externalCaKeys.getPrivate(),
                    externalCaKeys.getPublic(), AlgorithmConstants.SIGALG_SHA1_WITH_RSA, true);
            X509CAInfo externalCaInfo = new X509CAInfo(externalCaSubjectDn, externalCaName, CAConstants.CA_EXTERNAL,
                    CertificateProfileConstants.CERTPROFILE_NO_PROFILE, validity, CAInfo.SELFSIGNED, null, null);
            CAToken token = new CAToken(externalCaInfo.getCAId(), new NullCryptoToken().getProperties());
            X509CA externalCa = new X509CA(externalCaInfo);
            externalCa.setCAToken(token);
            externalCa.setCertificateChain(Arrays.asList(externalCaCertificate));
            caSession.addCA(internalAdmin, externalCa);
            certificateStoreSession.storeCertificateRemote(internalAdmin, externalCaCertificate, externalCaName, "1234", CertificateConstants.CERT_ACTIVE,
                    CertificateConstants.CERTTYPE_ROOTCA, CertificateProfileConstants.CERTPROFILE_NO_PROFILE, null, new Date().getTime());
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
                SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
                random.setSeed(new Date().getTime());
                random.nextBytes(serno);
                KeyPair certificateKeyPair = KeyTools.genKeys("1024", "RSA");
                final SubjectPublicKeyInfo pkinfo = new SubjectPublicKeyInfo((ASN1Sequence) ASN1Primitive.fromByteArray(certificateKeyPair
                        .getPublic().getEncoded()));
                X509v3CertificateBuilder certbuilder = new X509v3CertificateBuilder(CertTools.stringToBcX500Name(externalCaSubjectDn, false),
                        new BigInteger(serno).abs(), firstDate, lastDate, CertTools.stringToBcX500Name(externalSubjectDn, false), pkinfo);
                final ContentSigner signer = new BufferingContentSigner(new JcaContentSignerBuilder("SHA256WithRSA").setProvider(
                        BouncyCastleProvider.PROVIDER_NAME).build(externalCaKeys.getPrivate()), 20480);
                final X509CertificateHolder certHolder = certbuilder.build(signer);
                X509Certificate importedCertificate = (X509Certificate) CertTools.getCertfromByteArray(certHolder.getEncoded());
                certificateStoreSession.storeCertificateRemote(internalAdmin, importedCertificate, externalUsername, "1234",
                        CertificateConstants.CERT_ACTIVE, CertificateConstants.CERTTYPE_ENDENTITY,
                        CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, null, new Date().getTime());
                try {
                    //Now everything is in place. Perform a request, make sure that the default responder signed it. 
                    OCSPReqBuilder gen = new OCSPReqBuilder();
                    gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), (X509Certificate) externalCaCertificate,
                            importedCertificate.getSerialNumber()));
                    Extension[] extensions = new Extension[1];
                    extensions[0] = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString("123456789".getBytes()));
                    gen.setRequestExtensions(new Extensions(extensions));
                    OCSPReq ocspRequest = gen.build();
                    final int localTransactionId = TransactionCounter.INSTANCE.getTransactionNumber();
                    // Create the transaction logger for this transaction.
                    TransactionLogger transactionLogger = new TransactionLogger(localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "");
                    // Create the audit logger for this transaction.
                    AuditLogger auditLogger = new AuditLogger("", localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "");
                    byte[] responseBytes = ocspResponseGeneratorSession.getOcspResponse(ocspRequest.getEncoded(), null, "", null, auditLogger,
                            transactionLogger).getOcspResponse();
                    assertNotNull("OCSP responder replied null", responseBytes);

                    OCSPResp response = new OCSPResp(responseBytes);
                    assertEquals("Response status not zero.", OCSPResp.SUCCESSFUL, response.getStatus());
                    final BasicOCSPResp basicOcspResponse = (BasicOCSPResp) response.getResponseObject();
                    assertNotNull("Signed request generated null-response.", basicOcspResponse);
                    assertTrue("OCSP response was not signed correctly.", basicOcspResponse.isSignatureValid(new JcaContentVerifierProviderBuilder()
                            .build(testx509ca.getCACertificate().getPublicKey())));
                    final SingleResp[] singleResponses = basicOcspResponse.getResponses();
                    assertEquals("Delivered some thing else than one and exactly one response.", 1, singleResponses.length);
                    assertEquals("Response cert did not match up with request cert", importedCertificate.getSerialNumber(), singleResponses[0]
                            .getCertID().getSerialNumber());
                    assertEquals("Status is not null (good)", null, singleResponses[0].getCertStatus());
                } finally {
                    internalCertificateStoreSession.removeCertificate(importedCertificate);
                }
            } finally {
                caSession.removeCA(internalAdmin, externalCa.getCAId());
                internalCertificateStoreSession.removeCertificate(externalCaCertificate);
            }
        } finally {
            GlobalOcspConfiguration restoredOcspConfiguration = (GlobalOcspConfiguration) globalConfigurationSession
                    .getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
            ocspConfiguration.setOcspDefaultResponderReference(originalDefaultResponder);
            globalConfigurationSession.saveConfiguration(internalAdmin, restoredOcspConfiguration);
        }
    }
    
}
