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
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.ejb.CreateException;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.cesecore.CesecoreException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.CustomCertSerialNumberException;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.ocsp.OcspResponseGeneratorSessionRemote;
import org.cesecore.certificates.ocsp.OcspResponseInformation;
import org.cesecore.certificates.ocsp.SHA1DigestCalculator;
import org.cesecore.certificates.ocsp.exception.MalformedRequestException;
import org.cesecore.certificates.ocsp.logging.AuditLogger;
import org.cesecore.certificates.ocsp.logging.GuidHolder;
import org.cesecore.certificates.ocsp.logging.TransactionCounter;
import org.cesecore.certificates.ocsp.logging.TransactionLogger;
import org.cesecore.config.OcspConfiguration;
import org.cesecore.configuration.CesecoreConfigurationProxySessionRemote;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.keybind.CertificateImportException;
import org.ejbca.core.ejb.keybind.InternalKeyBindingMgmtSessionRemote;
import org.ejbca.core.ejb.keybind.InternalKeyBindingNameInUseException;
import org.ejbca.core.ejb.keybind.InternalKeyBindingStatus;
import org.ejbca.core.ejb.keybind.impl.OcspKeyBinding;
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
                TESTCLASSNAME);
        ocspSigningCertificate = OcspTestUtils.createOcspSigningCertificate(authenticationToken, internalKeyBindingId, x509ca.getCAId());
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

    /**
     * Tests the basic case of a standalone OCSP installation, i.e where this is a classic VA
     */
    @Test
    public void testStandAloneOcspResponseSanity() throws OCSPException, AuthorizationDeniedException, MalformedRequestException, IOException,
            NoSuchProviderException, CertificateEncodingException, OperatorCreationException, CustomCertSerialNumberException, IllegalKeyException,
            CADoesntExistsException, CertificateCreateException, CesecoreException, CertificateImportException, InternalKeyBindingNameInUseException,
            InvalidKeyException, InvalidAlgorithmParameterException, CreateException {
  
        //Now delete the original CA, making this test completely standalone.
        OcspTestUtils.deleteCa(authenticationToken, x509ca);

        // Ask the key binding to search the database for a new certificate matching its public key
        String ocspSigningCertificateFingerprint = internalKeyBindingMgmtSession.updateCertificateForInternalKeyBinding(authenticationToken,
                internalKeyBindingId);
        if (!CertTools.getFingerprintAsString(ocspSigningCertificate).equals(ocspSigningCertificateFingerprint)) {
            throw new Error("Wrong certificate was found for InternalKeyBinding");
        }
        OcspTestUtils.setInternalKeyBindingStatus(authenticationToken, internalKeyBindingId, InternalKeyBindingStatus.ACTIVE);
        ocspResponseGeneratorSession.reloadTokenAndChainCache(PASSWORD);
        // An OCSP request
        OCSPReqBuilder gen = new OCSPReqBuilder();

        gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), caCertificate, ocspSigningCertificate.getSerialNumber()));
        Extension[] extensions = new Extension[1];
        extensions[0] = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString("123456789".getBytes()));
        gen.setRequestExtensions(new Extensions(extensions));

        OCSPReq ocspRequest = gen.build();
        final int localTransactionId = TransactionCounter.INSTANCE.getTransactionNumber();
        // Create the transaction logger for this transaction.
        TransactionLogger transactionLogger = new TransactionLogger(localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "");
        // Create the audit logger for this transaction.
        AuditLogger auditLogger = new AuditLogger("", localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "");
        OcspResponseInformation responseInformation = ocspResponseGeneratorSession.getOcspResponse(ocspRequest.getEncoded(), null, "", "", null,
                auditLogger, transactionLogger);
        byte[] responseBytes = responseInformation.getOcspResponse();
        assertNotNull("OCSP resonder replied null", responseBytes);

        OCSPResp response = new OCSPResp(responseBytes);
        assertEquals("Response status not zero.", response.getStatus(), 0);
        BasicOCSPResp basicOcspResponse = (BasicOCSPResp) response.getResponseObject();
        assertTrue("OCSP response was not signed correctly.",
                basicOcspResponse.isSignatureValid(new JcaContentVerifierProviderBuilder().build(ocspSigningCertificate.getPublicKey())));
        SingleResp[] singleResponses = basicOcspResponse.getResponses();
        assertEquals("Delivered some thing else than one and exactly one response.", 1, singleResponses.length);
        assertEquals("Response cert did not match up with request cert", ocspSigningCertificate.getSerialNumber(), singleResponses[0].getCertID()
                .getSerialNumber());
        assertEquals("Status is not null (good)", null, singleResponses[0].getCertStatus());
    }
    
    /**
     * Tests the case where there exists both a CA and a key binding for that CA on the same machine. The Key Binding should have priority. 
     */
    @Test
    public void testStandAloneOcspResponseWithBothCaAndInternalKeyBinding() throws OCSPException, AuthorizationDeniedException,
            MalformedRequestException, IOException, NoSuchProviderException, CertificateEncodingException, OperatorCreationException,
            CustomCertSerialNumberException, IllegalKeyException, CADoesntExistsException, CertificateCreateException, CesecoreException,
            CertificateImportException, InternalKeyBindingNameInUseException, InvalidKeyException, InvalidAlgorithmParameterException,
            CreateException {
        //Note: The CA never gets deleted in this test, so there exists both a CA and a key binding at the same time. 

        // Ask the key binding to search the database for a new certificate matching its public key
        String ocspSigningCertificateFingerprint = internalKeyBindingMgmtSession.updateCertificateForInternalKeyBinding(authenticationToken,
                internalKeyBindingId);
        if (!CertTools.getFingerprintAsString(ocspSigningCertificate).equals(ocspSigningCertificateFingerprint)) {
            throw new Error("Wrong certificate was found for InternalKeyBinding");
        }
        OcspTestUtils.setInternalKeyBindingStatus(authenticationToken, internalKeyBindingId, InternalKeyBindingStatus.ACTIVE);
        ocspResponseGeneratorSession.reloadTokenAndChainCache(PASSWORD);
        // An OCSP request
        OCSPReqBuilder gen = new OCSPReqBuilder();

        gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), caCertificate, ocspSigningCertificate.getSerialNumber()));
        Extension[] extensions = new Extension[1];
        extensions[0] = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString("123456789".getBytes()));
        gen.setRequestExtensions(new Extensions(extensions));

        OCSPReq ocspRequest = gen.build();
        final int localTransactionId = TransactionCounter.INSTANCE.getTransactionNumber();
        // Create the transaction logger for this transaction.
        TransactionLogger transactionLogger = new TransactionLogger(localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "");
        // Create the audit logger for this transaction.
        AuditLogger auditLogger = new AuditLogger("", localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "");
        OcspResponseInformation responseInformation = ocspResponseGeneratorSession.getOcspResponse(ocspRequest.getEncoded(), null, "", "", null,
                auditLogger, transactionLogger);
        byte[] responseBytes = responseInformation.getOcspResponse();
        assertNotNull("OCSP resonder replied null", responseBytes);

        OCSPResp response = new OCSPResp(responseBytes);
        assertEquals("Response status not zero.", response.getStatus(), 0);
        BasicOCSPResp basicOcspResponse = (BasicOCSPResp) response.getResponseObject();
        assertTrue("OCSP response was not signed correctly.",
                basicOcspResponse.isSignatureValid(new JcaContentVerifierProviderBuilder().build(ocspSigningCertificate.getPublicKey())));
        SingleResp[] singleResponses = basicOcspResponse.getResponses();
        assertEquals("Delivered some thing else than one and exactly one response.", 1, singleResponses.length);
        assertEquals("Response cert did not match up with request cert", ocspSigningCertificate.getSerialNumber(), singleResponses[0].getCertID()
                .getSerialNumber());
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
