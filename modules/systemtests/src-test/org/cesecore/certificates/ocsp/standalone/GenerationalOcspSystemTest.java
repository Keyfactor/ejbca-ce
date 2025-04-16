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

import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.ocsp.OcspTestUtils;
import org.cesecore.certificates.ocsp.logging.AuditLogger;
import org.cesecore.certificates.ocsp.logging.GuidHolder;
import org.cesecore.certificates.ocsp.logging.TransactionCounter;
import org.cesecore.certificates.ocsp.logging.TransactionLogger;
import org.cesecore.config.GlobalOcspConfiguration;
import org.cesecore.config.OcspConfiguration;
import org.cesecore.configuration.CesecoreConfigurationProxySessionRemote;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.junit.util.CryptoTokenRunner;
import org.cesecore.junit.util.PKCS12TestRunner;
import org.cesecore.keybind.InternalKeyBindingMgmtSessionRemote;
import org.cesecore.keybind.InternalKeyBindingStatus;
import org.cesecore.keybind.impl.OcspKeyBinding;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.TraceLogMethodsRule;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ocsp.OcspResponseGeneratorSessionRemote;
import org.ejbca.core.ejb.ocsp.PresignResponseValidity;
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
import com.keyfactor.util.SHA1DigestCalculator;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;

/**
 * System tests for the generational OCSP feature, where a different generation of the certificate chain than the expected one is expected in the OCSP response. 
 */
@RunWith(Parameterized.class)
public class GenerationalOcspSystemTest {

    @Parameters(name = "{0}")
    public static Collection<CryptoTokenRunner> runners() {
        return Arrays.asList(new PKCS12TestRunner());
    }

    private static final String TESTCLASSNAME = GenerationalOcspSystemTest.class.getSimpleName();

    private final AuthenticationToken authenticationToken = new TestAlwaysAllowLocalAuthenticationToken(TESTCLASSNAME);

    private final CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
    private final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private final CesecoreConfigurationProxySessionRemote cesecoreConfigurationProxySession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CesecoreConfigurationProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private final InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(
            InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private final GlobalConfigurationSessionRemote globalConfigurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);
    private final InternalKeyBindingMgmtSessionRemote internalKeyBindingMgmtSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(InternalKeyBindingMgmtSessionRemote.class);
    private final OcspResponseGeneratorSessionRemote ocspResponseGeneratorSession = EjbRemoteHelper.INSTANCE.getRemoteSession(OcspResponseGeneratorSessionRemote.class);

    @Rule
    public TestRule traceLogMethodsRule = new TraceLogMethodsRule();

    @Rule
    public TestName testName = new TestName();

    private CryptoTokenRunner cryptoTokenRunner;
    private String originalSigningTruststoreValidTime;

    public GenerationalOcspSystemTest(CryptoTokenRunner cryptoTokenRunner) throws Exception {
        this.cryptoTokenRunner = cryptoTokenRunner;

    }

    @Before
    public void setUp() throws Exception {
        originalSigningTruststoreValidTime = cesecoreConfigurationProxySession.getConfigurationValue(OcspConfiguration.SIGNING_TRUSTSTORE_VALID_TIME);
        //Make sure timers don't run while we debug
        cesecoreConfigurationProxySession.setConfigurationValue(OcspConfiguration.SIGNING_TRUSTSTORE_VALID_TIME,
                Integer.toString(Integer.MAX_VALUE / 1000));
    }

    @After
    public void tearDown() throws Exception {
        cryptoTokenRunner.cleanUp();
        cesecoreConfigurationProxySession.setConfigurationValue(OcspConfiguration.SIGNING_TRUSTSTORE_VALID_TIME, originalSigningTruststoreValidTime);
    }

    /**
     * Performs a test on the generational CA feature by performing an OCSP request (on the CA cert itself) first on a 
     * renewed CA without the feature enabled on the responder (expecting the latest CA cert in the chain) and then with it enabled to verify sanity,
     * expecting the previous generation's chain to be returned in the response. 
     */
    @Test
    public void testGenerationalOcsp() throws Exception {
        final String issuingCaName = testName.getMethodName();
        final String rootCaName = issuingCaName + "Root";
        final String rootSubjectDn = "CN=" + rootCaName;
        //Create a root CA  - returned chains don't contain the root, so we need a structure to be able to analyze the chain
        X509CAInfo rootX509Ca = cryptoTokenRunner.createX509Ca(rootSubjectDn, rootCaName);
        //Create an issuing CA
        X509CAInfo issuingX509Ca = cryptoTokenRunner.createX509Ca("CN=" + issuingCaName, rootSubjectDn, issuingCaName, "1y");
        X509Certificate gen0CaCertificate = (X509Certificate) issuingX509Ca.getCertificateChain().get(0);
        //Renew this CA
        caAdminSession.renewCA(authenticationToken, issuingX509Ca.getCAId(), false, null, false);
        X509Certificate gen1CaCertificate = (X509Certificate) caSession.getCaChain(authenticationToken, issuingCaName).get(0).getCertificate();
        //Create an ocsp responder that uses this CA – verify that the current chain is included
        int cryptoTokenId = cryptoTokenRunner.createCryptoToken(testName.getMethodName());
        X509Certificate ocspSigningCertificate = null;
        int internalKeyBindingId = OcspTestUtils.createInternalKeyBinding(authenticationToken, cryptoTokenId, OcspKeyBinding.IMPLEMENTATION_ALIAS,
                TESTCLASSNAME, "RSA2048", AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        //Make sure cert chain is included in the response    
        OcspKeyBinding ocspResponder = (OcspKeyBinding) internalKeyBindingMgmtSession.getInternalKeyBinding(authenticationToken, internalKeyBindingId);
        ocspResponder.setIncludeCertChain(true);
        ocspResponder.setIncludeSignCert(true);
        internalKeyBindingMgmtSession.persistInternalKeyBinding(authenticationToken, ocspResponder);
        
        
        String signerDN = "CN=" + testName.getMethodName() + "Signer";
        ocspSigningCertificate = OcspTestUtils.createOcspSigningCertificate(authenticationToken,  testName.getMethodName() + "Signer",
                signerDN, internalKeyBindingId, issuingX509Ca.getCAId());
        activateKeyBinding(internalKeyBindingId, ocspSigningCertificate);
        //Now delete the original CA, making this test completely standalone.
        OcspTestUtils.deleteCa(authenticationToken, rootX509Ca);
        OcspTestUtils.deleteCa(authenticationToken, issuingX509Ca);
        ocspResponseGeneratorSession.reloadOcspSigningCache();
        try {
   
            final GlobalOcspConfiguration configuration = (GlobalOcspConfiguration) globalConfigurationSession
                    .getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
            final int localTransactionId = TransactionCounter.INSTANCE.getTransactionNumber();
            TransactionLogger transactionLogger = new TransactionLogger(localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "", configuration);
            AuditLogger auditLogger = new AuditLogger("", localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "", configuration);
            //Perform a check to verify sanity         
            {
                OCSPReqBuilder gen = new OCSPReqBuilder();
                gen.addRequest(
                        new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), gen0CaCertificate, gen0CaCertificate.getSerialNumber()));
                OCSPReq sanityRequest = gen.build();

                byte[] sanityResponseBytes = ocspResponseGeneratorSession.getOcspResponse(sanityRequest.getEncoded(), null, "", null, null,
                        auditLogger, transactionLogger, false, PresignResponseValidity.CONFIGURATION_BASED, false).getOcspResponse();
                OCSPResp sanityResponse = new OCSPResp(sanityResponseBytes);
                assertEquals("Response status not zero (ok).", OCSPRespBuilder.SUCCESSFUL, sanityResponse.getStatus());
                BasicOCSPResp sanityBasicOcspResponse = (BasicOCSPResp) sanityResponse.getResponseObject();
                List<X509Certificate> sanitySigningChain = CertTools.convertToX509CertificateList(Arrays.asList(sanityBasicOcspResponse.getCerts()));
                //Verify that the current chain is in use      
                if (!CertTools.getSerialNumber(sanitySigningChain.get(1)).equals(CertTools.getSerialNumber(gen1CaCertificate))) {
                    throw new IllegalStateException("Latest signing chain is not in use, sanity not verified. Test cannot continue.");
                }
            }
            //Change the responder to use the old chain 
            ocspResponder = (OcspKeyBinding) internalKeyBindingMgmtSession.getInternalKeyBinding(authenticationToken, internalKeyBindingId);
            ocspResponder.setCaGeneration(CertTools.getSerialNumberAsString(gen0CaCertificate));
            internalKeyBindingMgmtSession.persistInternalKeyBinding(authenticationToken, ocspResponder);
            ocspResponseGeneratorSession.reloadOcspSigningCache();
            
            //Perform a check to verify that the old chain is being returned      
            {
                OCSPReqBuilder gen = new OCSPReqBuilder();
                gen.addRequest(
                        new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), gen0CaCertificate, gen0CaCertificate.getSerialNumber()));
                OCSPReq generationalRequest = gen.build();

                byte[] generationalResponseBytes = ocspResponseGeneratorSession.getOcspResponse(generationalRequest.getEncoded(), null, "", null, null,
                        auditLogger, transactionLogger, false, PresignResponseValidity.CONFIGURATION_BASED, false).getOcspResponse();
                OCSPResp generationalResponse = new OCSPResp(generationalResponseBytes);
                assertEquals("Response status not zero (ok).", OCSPRespBuilder.SUCCESSFUL, generationalResponse.getStatus());
                BasicOCSPResp generationalBasicOcspResponse = (BasicOCSPResp) generationalResponse.getResponseObject();
                List<X509Certificate> generationalSigningChain = CertTools.convertToX509CertificateList(Arrays.asList(generationalBasicOcspResponse.getCerts()));
                //Verify that the current chain is in use    
                assertEquals("Previous CA chain was not used.", CertTools.getSerialNumber(gen0CaCertificate), CertTools.getSerialNumber(generationalSigningChain.get(1)));
      
            }

            //Test and verify to make sure that the returned chain is the previous and not the current one. 
        } finally {
            internalKeyBindingMgmtSession.deleteInternalKeyBinding(authenticationToken, internalKeyBindingId);
            internalCertificateStoreSession.removeCertificate(ocspSigningCertificate);
        }
    }
    
    /** Ask the OcspKeyBinding to search the database for the latest certificate matching its public key and set the status to ACTIVE */
    private void activateKeyBinding(int internalKeyBindingId, X509Certificate ocspSigningCertificate) throws Exception {
        // Ask the key binding to search the database for a new certificate matching its public key
        final String ocspSigningCertificateFingerprint = internalKeyBindingMgmtSession.updateCertificateForInternalKeyBinding(authenticationToken,
                internalKeyBindingId);
        if (!CertTools.getFingerprintAsString(ocspSigningCertificate).equals(ocspSigningCertificateFingerprint)) {
            throw new IllegalStateException("Wrong certificate was found for InternalKeyBinding");
        }
        OcspTestUtils.setInternalKeyBindingStatus(authenticationToken, internalKeyBindingId, InternalKeyBindingStatus.ACTIVE);
    }
}
