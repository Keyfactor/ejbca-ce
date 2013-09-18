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
package org.cesecore.certificates.ocsp.standalone;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Random;

import javax.ejb.CreateException;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID;
import org.bouncycastle.operator.BufferingContentSigner;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateCreateSessionRemote;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.request.SimpleRequestMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.ocsp.OcspResponseGeneratorSessionRemote;
import org.cesecore.certificates.ocsp.OcspResponseInformation;
import org.cesecore.certificates.ocsp.SHA1DigestCalculator;
import org.cesecore.certificates.ocsp.exception.MalformedRequestException;
import org.cesecore.certificates.ocsp.logging.AuditLogger;
import org.cesecore.certificates.ocsp.logging.GuidHolder;
import org.cesecore.certificates.ocsp.logging.TransactionCounter;
import org.cesecore.certificates.ocsp.logging.TransactionLogger;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.config.OcspConfiguration;
import org.cesecore.configuration.CesecoreConfigurationProxySessionRemote;
import org.cesecore.keybind.InternalKeyBinding;
import org.cesecore.keybind.InternalKeyBindingMgmtSessionRemote;
import org.cesecore.keybind.InternalKeyBindingStatus;
import org.cesecore.keybind.InternalKeyBindingTrustEntry;
import org.cesecore.keybind.impl.OcspKeyBinding;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.protocol.ocsp.OcspTestUtils;
import org.ejbca.util.TraceLogMethodsRule;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;

/**
 * Functional tests for StandaloneOcspResponseGeneratorSessionBean
 * 
 * @version $Id$
 * 
 */
public class StandaloneOcspResponseGeneratorSessionTest {

    private static final String PASSWORD = "foo123";
    private static final String CA_DN = "CN=OcspDefaultTestCA";
    
    private static final String TESTCLASSNAME = StandaloneOcspResponseGeneratorSessionTest.class.getSimpleName();
    private static final Logger log = Logger.getLogger(StandaloneOcspResponseGeneratorSessionTest.class);
 
    private String originalSigningTruststoreValidTime;

    private final CesecoreConfigurationProxySessionRemote cesecoreConfigurationProxySession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CesecoreConfigurationProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST); 
    private final CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CertificateStoreSessionRemote.class);
    private final CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CryptoTokenManagementSessionRemote.class);
    private final InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private final InternalKeyBindingMgmtSessionRemote internalKeyBindingMgmtSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(InternalKeyBindingMgmtSessionRemote.class);
    private final OcspResponseGeneratorSessionRemote ocspResponseGeneratorSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(OcspResponseGeneratorSessionRemote.class);
    private CertificateCreateSessionRemote certificateCreateSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateCreateSessionRemote.class);


    private final AuthenticationToken authenticationToken = new TestAlwaysAllowLocalAuthenticationToken(TESTCLASSNAME);
    
    private X509CA x509ca;
    private int cryptoTokenId;
    private int internalKeyBindingId;
    private X509Certificate ocspSigningCertificate;
    private X509Certificate caCertificate;

    @Rule
    public TestRule traceLogMethodsRule = new TraceLogMethodsRule();

    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }

    @AfterClass
    public static void afterClass() throws Exception {
    }

    @Before
    public void setUp() throws Exception {
        x509ca = CryptoTokenTestUtils.createTestCA(authenticationToken, CA_DN);
        cryptoTokenId = CryptoTokenTestUtils.createCryptoToken(authenticationToken, TESTCLASSNAME);
        originalSigningTruststoreValidTime = cesecoreConfigurationProxySession.getConfigurationValue(OcspConfiguration.SIGNING_TRUSTSTORE_VALID_TIME);
        //Make sure timers don't run while we debug
        cesecoreConfigurationProxySession.setConfigurationValue(OcspConfiguration.SIGNING_TRUSTSTORE_VALID_TIME, Integer.toString(Integer.MAX_VALUE/1000));
        internalKeyBindingId = OcspTestUtils.createInternalKeyBinding(authenticationToken, cryptoTokenId, OcspKeyBinding.IMPLEMENTATION_ALIAS,
                TESTCLASSNAME, "RSA2048", AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        String signerDN = "CN=ocspTestSigner";
        ocspSigningCertificate = OcspTestUtils.createOcspSigningCertificate(authenticationToken, OcspTestUtils.OCSP_END_USER_NAME, signerDN, internalKeyBindingId, x509ca.getCAId());
        caCertificate = createCaCertificate();
    }

    @After
    public void tearDown() throws Exception {
        try {
            internalCertificateStoreSession.removeCertificate(ocspSigningCertificate);
        } catch (Exception e) {
            //Ignore any failures.
        }
        try {
            internalCertificateStoreSession.removeCertificate(caCertificate);
        } catch (Exception e) {
            //Ignore any failures.
        }
        internalKeyBindingMgmtSession.deleteInternalKeyBinding(authenticationToken, internalKeyBindingId);
        cryptoTokenManagementSession.deleteCryptoToken(authenticationToken, cryptoTokenId);
        OcspTestUtils.deleteCa(authenticationToken, x509ca);
        cesecoreConfigurationProxySession.setConfigurationValue(OcspConfiguration.SIGNING_TRUSTSTORE_VALID_TIME, originalSigningTruststoreValidTime);
    }

    /** Tests the basic case of a standalone OCSP installation, i.e where this is a classic VA */
    @Test
    public void testStandAloneOcspResponseSanity() throws Exception {
        //Now delete the original CA, making this test completely standalone.
        OcspTestUtils.deleteCa(authenticationToken, x509ca);
        activateKeyBinding(internalKeyBindingId);
        ocspResponseGeneratorSession.reloadTokenAndChainCache(PASSWORD);
        // Do the OCSP request
        final OCSPReq ocspRequest = buildOcspRequest(null, null, caCertificate, ocspSigningCertificate.getSerialNumber());
        final OCSPResp response = sendRequest(ocspRequest);
        assertEquals("Response status not zero.", OCSPResp.SUCCESSFUL, response.getStatus());
        validateSuccessfulResponse((BasicOCSPResp) response.getResponseObject(), ocspSigningCertificate.getPublicKey());
    }
    
    /** Tests the case where there exists both a CA and a key binding for that CA on the same machine. The Key Binding should have priority. */
    @Test
    public void testStandAloneOcspResponseWithBothCaAndInternalKeyBinding() throws Exception {
        //Note: The CA never gets deleted in this test, so there exists both a CA and a key binding at the same time. 
        activateKeyBinding(internalKeyBindingId);
        ocspResponseGeneratorSession.reloadTokenAndChainCache(PASSWORD);
        // Do the OCSP request
        final OCSPReq ocspRequest = buildOcspRequest(null, null, caCertificate, ocspSigningCertificate.getSerialNumber());
        final OCSPResp response = sendRequest(ocspRequest);
        assertEquals("Response status not zero.", OCSPResp.SUCCESSFUL, response.getStatus());
        validateSuccessfulResponse((BasicOCSPResp) response.getResponseObject(), ocspSigningCertificate.getPublicKey());
    }

    
    /** Test that trust settings are properly persisted */
    @Test
    public void testTrustPersistance() throws Exception {
        // Configure the OcspKeyBinding to require a signature (by any certificate)
        final OcspKeyBinding ocspKeyBinding = (OcspKeyBinding) internalKeyBindingMgmtSession.getInternalKeyBinding(authenticationToken, internalKeyBindingId);
        ocspKeyBinding.setRequireTrustedSignature(true);
        addTrustEntry(ocspKeyBinding, -1, new BigInteger("3"));
        addTrustEntry(ocspKeyBinding, -2, null);
        addTrustEntry(ocspKeyBinding, x509ca.getCAId(), new BigInteger("0"));
        internalKeyBindingMgmtSession.persistInternalKeyBinding(authenticationToken, ocspKeyBinding);

        final int responseCode = ((HttpURLConnection) new URL("http://localhost:8080/ejbca/clearcache/?command=clearcaches").openConnection()).getResponseCode();
        assertEquals("Failed to invoked clear cache servlet.", HttpURLConnection.HTTP_OK, responseCode);
        final OcspKeyBinding ocspKeyBindingLoaded = (OcspKeyBinding) internalKeyBindingMgmtSession.getInternalKeyBinding(authenticationToken, internalKeyBindingId);
        assertTrue("RequireTrustedSignature setting was not persisted.", ocspKeyBindingLoaded.getRequireTrustedSignature());
        final List<InternalKeyBindingTrustEntry> trustEntries = ocspKeyBindingLoaded.getTrustedCertificateReferences();
        assertEquals("Not the same number of entries in list of trusted requestors", 3, trustEntries.size());
        boolean found = false;
        for (final InternalKeyBindingTrustEntry trustEntry : trustEntries) {
            log.debug("Comparing " + trustEntry.getCaId() + " " + trustEntry.getCertificateSerialNumber());
            if (trustEntry.getCaId() == x509ca.getCAId() && trustEntry.getCertificateSerialNumber() != null && trustEntry.getCertificateSerialNumber().equals(new BigInteger("0"))) {
                found = true;
            }
        }
        assertTrue("Configured trust entry was no longer present after cache flush", found);
        ocspResponseGeneratorSession.reloadTokenAndChainCache(PASSWORD);
    }

    /**
     * Request signature requirement: ANY known certificate.
     * Request signature:             None.
     * Expected outcome:              5 (OCSPResp.SIG_REQUIRED)
     */
    @Test
    public void testAnySignatureRequiredNoSignature() throws Exception {
        //Now delete the original CA, making this test completely standalone.
        OcspTestUtils.deleteCa(authenticationToken, x509ca);
        activateKeyBinding(internalKeyBindingId);
        // Configure the OcspKeyBinding to require a signature (by any certificate)
        final OcspKeyBinding ocspKeyBinding = (OcspKeyBinding) internalKeyBindingMgmtSession.getInternalKeyBinding(authenticationToken, internalKeyBindingId);
        ocspKeyBinding.setRequireTrustedSignature(true);
        internalKeyBindingMgmtSession.persistInternalKeyBinding(authenticationToken, ocspKeyBinding);
        ocspResponseGeneratorSession.reloadTokenAndChainCache(PASSWORD);
        // Try to send an unsigned OCSP requests
        final OCSPReq ocspRequestUnsigned = buildOcspRequest(null, null, caCertificate, ocspSigningCertificate.getSerialNumber());
        final OCSPResp ocspResponseUnsigned = sendRequest(ocspRequestUnsigned);
        assertEquals("We expected a 'Signature Required' status code: ", OCSPResp.SIG_REQUIRED, ocspResponseUnsigned.getStatus());
        assertNull("We expected the response object to be null when 'Signature Required' is recieved.", ocspResponseUnsigned.getResponseObject());
    }

    /**
     * Request signature requirement: None.
     * Request signature:             Present.
     * Expected outcome:              0 (OCSPResp.SUCCESSFUL)
     */
    @Test
    public void testNoSignatureRequiredButSignaturePresent() throws Exception {
        final String TESTNAME = Thread.currentThread().getStackTrace()[1].getMethodName();
        // Issue a request authentication certificate while we still have the CA
        final String ocspAuthenticationUsername = TESTNAME+new Random().nextLong();
        final KeyPair ocspAuthenticationKeyPair = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        final X509Certificate ocspAuthenticationCertificate = issueOcspAuthenticationCertificate(ocspAuthenticationUsername, ocspAuthenticationKeyPair.getPublic());
        //Now delete the original CA, making this test completely standalone.
        OcspTestUtils.deleteCa(authenticationToken, x509ca);
        activateKeyBinding(internalKeyBindingId);
        // Configure the OcspKeyBinding to require a signature (by any certificate)
        final OcspKeyBinding ocspKeyBinding = (OcspKeyBinding) internalKeyBindingMgmtSession.getInternalKeyBinding(authenticationToken, internalKeyBindingId);
        ocspKeyBinding.setRequireTrustedSignature(false);
        internalKeyBindingMgmtSession.persistInternalKeyBinding(authenticationToken, ocspKeyBinding);
        ocspResponseGeneratorSession.reloadTokenAndChainCache(PASSWORD);
        // Try to send a signed OCSP requests
        final OCSPReq ocspRequestSigned = buildOcspRequest(ocspAuthenticationCertificate, ocspAuthenticationKeyPair.getPrivate(),
                caCertificate, ocspSigningCertificate.getSerialNumber());
        final OCSPResp ocspResponseSigned = sendRequest(ocspRequestSigned);
        assertEquals("We expected a 'Successful' status code: ", OCSPResp.SUCCESSFUL, ocspResponseSigned.getStatus());
        validateSuccessfulResponse((BasicOCSPResp)ocspResponseSigned.getResponseObject(), ocspSigningCertificate.getPublicKey());
    }

    /**
     * Request signature requirement: ANY known certificate.
     * Request signature:             By a known certificate.
     * Expected outcome:              0 (OCSPResp.SUCCESSFUL)
     */
    @Test
    public void testAnySignatureRequiredSignature() throws Exception {
        final String TESTNAME = Thread.currentThread().getStackTrace()[1].getMethodName();
        // Issue a request authentication certificate while we still have the CA
        final String ocspAuthenticationUsername = TESTNAME+new Random().nextLong();
        final KeyPair ocspAuthenticationKeyPair = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        final X509Certificate ocspAuthenticationCertificate = issueOcspAuthenticationCertificate(ocspAuthenticationUsername, ocspAuthenticationKeyPair.getPublic());
        //Now delete the original CA, making this test completely standalone.
        OcspTestUtils.deleteCa(authenticationToken, x509ca);
        activateKeyBinding(internalKeyBindingId);
        // Configure the OcspKeyBinding to require a signature (by any certificate)
        final OcspKeyBinding ocspKeyBinding = (OcspKeyBinding) internalKeyBindingMgmtSession.getInternalKeyBinding(authenticationToken, internalKeyBindingId);
        ocspKeyBinding.setRequireTrustedSignature(true);
        internalKeyBindingMgmtSession.persistInternalKeyBinding(authenticationToken, ocspKeyBinding);
        ocspResponseGeneratorSession.reloadTokenAndChainCache(PASSWORD);
        // Try to send a signed OCSP requests
        final OCSPReq ocspRequestSigned = buildOcspRequest(ocspAuthenticationCertificate, ocspAuthenticationKeyPair.getPrivate(),
                caCertificate, ocspSigningCertificate.getSerialNumber());
        final OCSPResp ocspResponseSigned = sendRequest(ocspRequestSigned);
        assertEquals("We expected a 'Successful' status code: ", OCSPResp.SUCCESSFUL, ocspResponseSigned.getStatus());
        validateSuccessfulResponse((BasicOCSPResp)ocspResponseSigned.getResponseObject(), ocspSigningCertificate.getPublicKey());
    }
    
    /**
     * Request signature requirement: ANY certificate issued by a CA with caId=-1.
     * Request signature:             By a known certificate issued by a CA with caId!=-1.
     * Expected outcome:              6 (OCSPResp.UNAUTHORIZED)
     */
    @Test
    public void testSpecificIssuerSignatureRequiredWrongSignatureIssuer() throws Exception {
        final String TESTNAME = Thread.currentThread().getStackTrace()[1].getMethodName();
        // Issue a request authentication certificate while we still have the CA
        final String ocspAuthenticationUsername = TESTNAME+new Random().nextLong();
        final KeyPair ocspAuthenticationKeyPair = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        final X509Certificate ocspAuthenticationCertificate = issueOcspAuthenticationCertificate(ocspAuthenticationUsername, ocspAuthenticationKeyPair.getPublic());
        //Now delete the original CA, making this test completely standalone.
        OcspTestUtils.deleteCa(authenticationToken, x509ca);
        activateKeyBinding(internalKeyBindingId);
        // Configure the OcspKeyBinding to require a signature (by any certificate)
        final OcspKeyBinding ocspKeyBinding = (OcspKeyBinding) internalKeyBindingMgmtSession.getInternalKeyBinding(authenticationToken, internalKeyBindingId);
        ocspKeyBinding.setRequireTrustedSignature(true);
        // Trust signatures from CA with id -1 (should not exist)
        addTrustEntry(ocspKeyBinding, -1, null);
        internalKeyBindingMgmtSession.persistInternalKeyBinding(authenticationToken, ocspKeyBinding);
        ocspResponseGeneratorSession.reloadTokenAndChainCache(PASSWORD);
        // Try to send a signed OCSP requests
        final OCSPReq ocspRequestSigned = buildOcspRequest(ocspAuthenticationCertificate, ocspAuthenticationKeyPair.getPrivate(),
                caCertificate, ocspSigningCertificate.getSerialNumber());
        final OCSPResp ocspResponseSigned = sendRequest(ocspRequestSigned);
        assertEquals("We expected a 'Unauthorized' status code: ", OCSPResp.UNAUTHORIZED, ocspResponseSigned.getStatus());
        assertNull("Unauthorized signed request did not generate null-response.", ocspResponseSigned.getResponseObject());
    }
    
    /**
     * Request signature requirement: ANY certificate issued by a our test CA.
     * Request signature:             By a known certificate issued by our test CA.
     * Expected outcome:              0 (OCSPResp.SUCCESSFUL)
     */
    @Test
    public void testSpecificIssuerSignatureRequiredRightSignatureIssuer() throws Exception {
        final String TESTNAME = Thread.currentThread().getStackTrace()[1].getMethodName();
        // Issue a request authentication certificate while we still have the CA
        final String ocspAuthenticationUsername = TESTNAME+new Random().nextLong();
        final KeyPair ocspAuthenticationKeyPair = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        final X509Certificate ocspAuthenticationCertificate = issueOcspAuthenticationCertificate(ocspAuthenticationUsername, ocspAuthenticationKeyPair.getPublic());
        //Now delete the original CA, making this test completely standalone.
        OcspTestUtils.deleteCa(authenticationToken, x509ca);
        activateKeyBinding(internalKeyBindingId);
        // Configure the OcspKeyBinding to require a signature
        final OcspKeyBinding ocspKeyBinding = (OcspKeyBinding) internalKeyBindingMgmtSession.getInternalKeyBinding(authenticationToken, internalKeyBindingId);
        ocspKeyBinding.setRequireTrustedSignature(true);
        // Trust signatures from our test CA
        addTrustEntry(ocspKeyBinding, x509ca.getCAId(), null);
        internalKeyBindingMgmtSession.persistInternalKeyBinding(authenticationToken, ocspKeyBinding);
        ocspResponseGeneratorSession.reloadTokenAndChainCache(PASSWORD);
        // Try to send a signed OCSP requests
        final OCSPReq ocspRequestSigned = buildOcspRequest(ocspAuthenticationCertificate, ocspAuthenticationKeyPair.getPrivate(),
                caCertificate, ocspSigningCertificate.getSerialNumber());
        final OCSPResp ocspResponseSigned = sendRequest(ocspRequestSigned);
        assertEquals("We expected a 'Successful' status code: ", OCSPResp.SUCCESSFUL, ocspResponseSigned.getStatus());
        validateSuccessfulResponse((BasicOCSPResp)ocspResponseSigned.getResponseObject(), ocspSigningCertificate.getPublicKey());
    }
    
    /**
     * Request signature requirement: A certificate issued by a our test CA with certificate serialnumer=0.
     * Request signature:             By a known certificate issued by our test CA with certificate serialnumer!=0.
     * Expected outcome:              6 (OCSPResp.UNAUTHORIZED)
     */
    @Test
    public void testSpecificSignerSignatureRequiredWrongSignatureCert() throws Exception {
        final String TESTNAME = Thread.currentThread().getStackTrace()[1].getMethodName();
        // Issue a request authentication certificate while we still have the CA
        final String ocspAuthenticationUsername = TESTNAME+new Random().nextLong();
        final KeyPair ocspAuthenticationKeyPair = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        final X509Certificate ocspAuthenticationCertificate = issueOcspAuthenticationCertificate(ocspAuthenticationUsername, ocspAuthenticationKeyPair.getPublic());
        //Now delete the original CA, making this test completely standalone.
        OcspTestUtils.deleteCa(authenticationToken, x509ca);
        activateKeyBinding(internalKeyBindingId);
        // Configure the OcspKeyBinding to require a signature (by any certificate)
        final OcspKeyBinding ocspKeyBinding = (OcspKeyBinding) internalKeyBindingMgmtSession.getInternalKeyBinding(authenticationToken, internalKeyBindingId);
        ocspKeyBinding.setRequireTrustedSignature(true);
        // Trust signatures from our test CA and certificate serial number "0" (that should be the one we are using)
        addTrustEntry(ocspKeyBinding, x509ca.getCAId(), new BigInteger("0"));
        internalKeyBindingMgmtSession.persistInternalKeyBinding(authenticationToken, ocspKeyBinding);
        ocspResponseGeneratorSession.reloadTokenAndChainCache(PASSWORD);
        // Try to send a signed OCSP requests
        final OCSPReq ocspRequestSigned = buildOcspRequest(ocspAuthenticationCertificate, ocspAuthenticationKeyPair.getPrivate(),
                caCertificate, ocspSigningCertificate.getSerialNumber());
        final OCSPResp ocspResponseSigned = sendRequest(ocspRequestSigned);
        assertEquals("We expected a 'Unauthorized' status code: ", OCSPResp.UNAUTHORIZED, ocspResponseSigned.getStatus());
        assertNull("Unauthorized signed request did not generate null-response.", ocspResponseSigned.getResponseObject());
    }
    
    /**
     * Request signature requirement: A certificate issued by a our test CA with the certificate's serialnumber.
     * Request signature:             By the required certificate.
     * Expected outcome:              0 (OCSPResp.SUCCESSFUL)
     */
    @Test
    public void testSpecificSignerSignatureRequiredRightSignatureCert() throws Exception {
        final String TESTNAME = Thread.currentThread().getStackTrace()[1].getMethodName();
        // Issue a request authentication certificate while we still have the CA
        final String ocspAuthenticationUsername = TESTNAME+new Random().nextLong();
        final KeyPair ocspAuthenticationKeyPair = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        final X509Certificate ocspAuthenticationCertificate = issueOcspAuthenticationCertificate(ocspAuthenticationUsername, ocspAuthenticationKeyPair.getPublic());
        //Now delete the original CA, making this test completely standalone.
        OcspTestUtils.deleteCa(authenticationToken, x509ca);
        activateKeyBinding(internalKeyBindingId);
        // Configure the OcspKeyBinding to require a signature
        final OcspKeyBinding ocspKeyBinding = (OcspKeyBinding) internalKeyBindingMgmtSession.getInternalKeyBinding(authenticationToken, internalKeyBindingId);
        ocspKeyBinding.setRequireTrustedSignature(true);
        // Trust signatures from our test CA and the certificate serial number from our auth cert
        addTrustEntry(ocspKeyBinding, x509ca.getCAId(), ocspAuthenticationCertificate.getSerialNumber());
        internalKeyBindingMgmtSession.persistInternalKeyBinding(authenticationToken, ocspKeyBinding);
        ocspResponseGeneratorSession.reloadTokenAndChainCache(PASSWORD);
        // Try to send a signed OCSP requests
        final OCSPReq ocspRequestSigned = buildOcspRequest(ocspAuthenticationCertificate, ocspAuthenticationKeyPair.getPrivate(),
                caCertificate, ocspSigningCertificate.getSerialNumber());
        final OCSPResp ocspResponseSigned = sendRequest(ocspRequestSigned);
        assertEquals("We expected a 'Successful' status code: ", OCSPResp.SUCCESSFUL, ocspResponseSigned.getStatus());
        validateSuccessfulResponse((BasicOCSPResp)ocspResponseSigned.getResponseObject(), ocspSigningCertificate.getPublicKey());
    }
    
    /**
     * Request signature requirement: Multiple options.
     * Request signature:             By a known certificate issued by our test CA, not matching any of the configured trust entries.
     * Expected outcome:              6 (OCSPResp.UNAUTHORIZED)
     */
    @Test
    public void testOneOfManySignatureRequiredWrongSignatureCert() throws Exception {
        final String TESTNAME = Thread.currentThread().getStackTrace()[1].getMethodName();
        // Issue a request authentication certificate while we still have the CA
        final String ocspAuthenticationUsername = TESTNAME+new Random().nextLong();
        final KeyPair ocspAuthenticationKeyPair = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        final X509Certificate ocspAuthenticationCertificate = issueOcspAuthenticationCertificate(ocspAuthenticationUsername, ocspAuthenticationKeyPair.getPublic());
        //Now delete the original CA, making this test completely standalone.
        OcspTestUtils.deleteCa(authenticationToken, x509ca);
        activateKeyBinding(internalKeyBindingId);
        // Configure the OcspKeyBinding to require a signature
        final OcspKeyBinding ocspKeyBinding = (OcspKeyBinding) internalKeyBindingMgmtSession.getInternalKeyBinding(authenticationToken, internalKeyBindingId);
        ocspKeyBinding.setRequireTrustedSignature(true);
        // Trust signatures from our test CA and the certificate serial number from our auth cert
        addTrustEntry(ocspKeyBinding, -1, ocspAuthenticationCertificate.getSerialNumber());
        addTrustEntry(ocspKeyBinding, -2, null);
        addTrustEntry(ocspKeyBinding, x509ca.getCAId(), new BigInteger("0"));
        internalKeyBindingMgmtSession.persistInternalKeyBinding(authenticationToken, ocspKeyBinding);
        ocspResponseGeneratorSession.reloadTokenAndChainCache(PASSWORD);
        // Try to send a signed OCSP requests
        final OCSPReq ocspRequestSigned = buildOcspRequest(ocspAuthenticationCertificate, ocspAuthenticationKeyPair.getPrivate(),
                caCertificate, ocspSigningCertificate.getSerialNumber());
        final OCSPResp ocspResponseSigned = sendRequest(ocspRequestSigned);
        assertEquals("We expected a 'Unauthorized' status code: ", OCSPResp.UNAUTHORIZED, ocspResponseSigned.getStatus());
        assertNull("Unauthorized signed request did not generate null-response.", ocspResponseSigned.getResponseObject());
    }
    
    /**
     * Request signature requirement: Multiple options where one is the CA and serialnumber of the issued authentication certificate.
     * Request signature:             By a known certificate issued by our test CA.
     * Expected outcome:              0 (OCSPResp.SUCCESSFUL)
     */
    @Test
    public void testOneOfManySignatureRequiredRightSignatureCert() throws Exception {
        final String TESTNAME = Thread.currentThread().getStackTrace()[1].getMethodName();
        // Issue a request authentication certificate while we still have the CA
        final String ocspAuthenticationUsername = TESTNAME+new Random().nextLong();
        final KeyPair ocspAuthenticationKeyPair = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        final X509Certificate ocspAuthenticationCertificate = issueOcspAuthenticationCertificate(ocspAuthenticationUsername, ocspAuthenticationKeyPair.getPublic());
        //Now delete the original CA, making this test completely standalone.
        OcspTestUtils.deleteCa(authenticationToken, x509ca);
        activateKeyBinding(internalKeyBindingId);
        // Configure the OcspKeyBinding to require a signature
        final OcspKeyBinding ocspKeyBinding = (OcspKeyBinding) internalKeyBindingMgmtSession.getInternalKeyBinding(authenticationToken, internalKeyBindingId);
        ocspKeyBinding.setRequireTrustedSignature(true);
        // Trust signatures from our test CA and the certificate serial number from our auth cert
        addTrustEntry(ocspKeyBinding, -1, ocspAuthenticationCertificate.getSerialNumber());
        addTrustEntry(ocspKeyBinding, -2, null);
        addTrustEntry(ocspKeyBinding, x509ca.getCAId(), ocspAuthenticationCertificate.getSerialNumber());
        internalKeyBindingMgmtSession.persistInternalKeyBinding(authenticationToken, ocspKeyBinding);
        ocspResponseGeneratorSession.reloadTokenAndChainCache(PASSWORD);
        // Try to send a signed OCSP requests
        final OCSPReq ocspRequestSigned = buildOcspRequest(ocspAuthenticationCertificate, ocspAuthenticationKeyPair.getPrivate(),
                caCertificate, ocspSigningCertificate.getSerialNumber());
        final OCSPResp ocspResponseSigned = sendRequest(ocspRequestSigned);
        assertEquals("We expected a 'Successful' status code: ", OCSPResp.SUCCESSFUL, ocspResponseSigned.getStatus());
        validateSuccessfulResponse((BasicOCSPResp)ocspResponseSigned.getResponseObject(), ocspSigningCertificate.getPublicKey());
    }
    
    // Trusting a certificateSerialNumber of null means any certificate from the CA
    private void addTrustEntry(InternalKeyBinding internalKeyBinding, int caId, BigInteger certificateSerialNumber) {
        final List<InternalKeyBindingTrustEntry> trustList = new ArrayList<InternalKeyBindingTrustEntry>(internalKeyBinding.getTrustedCertificateReferences());
        trustList.add(new InternalKeyBindingTrustEntry(caId, certificateSerialNumber));
        internalKeyBinding.setTrustedCertificateReferences(trustList);
    }
    
    /** Ask the OcspKeyBinding to search the database for the latest certificate matching its public key and set the status to ACTIVE */
    private void activateKeyBinding(int internalKeyBindingId) throws Exception {
        // Ask the key binding to search the database for a new certificate matching its public key
        final String ocspSigningCertificateFingerprint = internalKeyBindingMgmtSession.updateCertificateForInternalKeyBinding(authenticationToken,
                internalKeyBindingId);
        if (!CertTools.getFingerprintAsString(ocspSigningCertificate).equals(ocspSigningCertificateFingerprint)) {
            throw new Error("Wrong certificate was found for InternalKeyBinding");
        }
        OcspTestUtils.setInternalKeyBindingStatus(authenticationToken, internalKeyBindingId, InternalKeyBindingStatus.ACTIVE);
    }
    
    /** Build an OCSP request, that will optionally be signed if authentication parameters are specified */
    private OCSPReq buildOcspRequest(final X509Certificate ocspAuthenticationCertificate, final PrivateKey ocspAuthenticationPrivateKey,
            final X509Certificate caCertificate, final BigInteger certificateSerialnumber) throws Exception {
        final OCSPReqBuilder ocspReqBuilder = new OCSPReqBuilder();
        if (ocspAuthenticationCertificate != null) {
            // Signed requests are required to have an OCSPRequest.TBSRequest.requestorName
            ocspReqBuilder.setRequestorName(new X500Name(ocspAuthenticationCertificate.getSubjectDN().getName()));
        }
        ocspReqBuilder.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), caCertificate, certificateSerialnumber));
        ocspReqBuilder.setRequestExtensions(new Extensions(new Extension[] {new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString("123456789".getBytes()))}));
        if (ocspAuthenticationCertificate != null && ocspAuthenticationPrivateKey != null) {
            // Create a signed request
            final ContentSigner signer = new BufferingContentSigner(new JcaContentSignerBuilder(AlgorithmConstants.SIGALG_SHA1_WITH_RSA).build(ocspAuthenticationPrivateKey), 20480);
            return ocspReqBuilder.build(signer, new X509CertificateHolder[] {new X509CertificateHolder(ocspAuthenticationCertificate.getEncoded())});
        } else {
            // Create an unsigned request
            return ocspReqBuilder.build();
        }
    }

    /** Issue a plain end user certificate from the test CA for the provided public key */
    private X509Certificate issueOcspAuthenticationCertificate(final String username, final PublicKey publicKey) throws Exception {
        final EndEntityInformation user = new EndEntityInformation(username, "CN="+username, x509ca.getCAId(), null, null,
                new EndEntityType(EndEntityTypes.ENDUSER), 0, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, EndEntityConstants.TOKEN_USERGEN, 0, null);
        user.setStatus(EndEntityConstants.STATUS_NEW);
        user.setPassword("foo123");
        final SimpleRequestMessage req = new SimpleRequestMessage(publicKey, user.getUsername(), user.getPassword());
        final X509ResponseMessage resp = (X509ResponseMessage)certificateCreateSession.createCertificate(authenticationToken, user, req,
                org.cesecore.certificates.certificate.request.X509ResponseMessage.class);
        final X509Certificate cert = (X509Certificate)resp.getCertificate();
        assertNotNull("Failed to create certificate", cert);
        assertTrue("Issued certificate was not for the requested public key.", cert.getPublicKey().equals(publicKey));
        return cert;
    }
    
    /** Perform OCSP requests over remote EJB interface and assert the the response is not null. */
    private OCSPResp sendRequest(final OCSPReq ocspRequest) throws MalformedRequestException, IOException, OCSPException {
        final int localTransactionId = TransactionCounter.INSTANCE.getTransactionNumber();
        // Create the transaction and audit logger for this transaction.
        final TransactionLogger transactionLogger = new TransactionLogger(localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "");
        final AuditLogger auditLogger = new AuditLogger("", localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "");
        final OcspResponseInformation responseInformation = ocspResponseGeneratorSession.getOcspResponse(ocspRequest.getEncoded(), null, "", "", null,
                auditLogger, transactionLogger);
        byte[] responseBytes = responseInformation.getOcspResponse();
        assertNotNull("OCSP resonder replied null", responseBytes);
        return new OCSPResp(responseBytes);
    }
    
    private void validateSuccessfulResponse(final BasicOCSPResp basicOcspResponse, final PublicKey publicKey) throws Exception {
        assertNotNull("Signed request generated null-response.", basicOcspResponse);
        assertTrue("OCSP response was not signed correctly.", basicOcspResponse.isSignatureValid(new JcaContentVerifierProviderBuilder().build(publicKey)));
        final SingleResp[] singleResponses = basicOcspResponse.getResponses();
        assertEquals("Delivered some thing else than one and exactly one response.", 1, singleResponses.length);
        assertEquals("Response cert did not match up with request cert", ocspSigningCertificate.getSerialNumber(), singleResponses[0].getCertID().getSerialNumber());
        assertEquals("Status is not null (good)", null, singleResponses[0].getCertStatus());
    }
    
    private X509Certificate createCaCertificate() throws CreateException, AuthorizationDeniedException {
        X509Certificate caCertificate = (X509Certificate) x509ca.getCACertificate();
        //Store the CA Certificate.
        certificateStoreSession.storeCertificate(authenticationToken, caCertificate, "foo", "1234", CertificateConstants.CERT_ACTIVE,
                CertificateConstants.CERTTYPE_ROOTCA, CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, "footag", new Date().getTime());
        return caCertificate;
    }
}
