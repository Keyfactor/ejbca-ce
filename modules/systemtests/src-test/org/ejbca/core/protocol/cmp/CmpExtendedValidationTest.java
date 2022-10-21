/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.protocol.cmp;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.List;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.operator.OperatorCreationException;
import org.cesecore.CaTestUtils;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.core.model.era.TestRaMasterApiProxySessionRemote;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Tests that "Extended Validation" works and is performed on the RA side,
 * before the requests reach the CA.  
 */
public class CmpExtendedValidationTest extends CmpTestCase {

    private static final Logger log = Logger.getLogger(CmpExtendedValidationTest.class);

    private static final String ISSUER_CA_NAME = "CmpExternalValidationTestCA";
    private static final String ISSUER_DN = "CN=" + ISSUER_CA_NAME + ",O=CmpTests,OU=FoooUåäö";
    private static final int KEYUSAGE = X509KeyUsage.digitalSignature + X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign;
    private static final String ALIAS = "CmpExtendedValidationTest";
    private static final String PBEPASSWORD = "pbe123";

    private static final X509CA testx509ca;
    private static final X509Certificate cacert;
    private static final KeyPair keys;
    static { // runs only once for all test cases
        try {
            testx509ca = CaTestUtils.createTestX509CA(ISSUER_DN, null, false, KEYUSAGE);
            cacert = (X509Certificate) testx509ca.getCACertificate();
            keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        } catch (CertificateParsingException | CryptoTokenOfflineException | OperatorCreationException | InvalidAlgorithmParameterException e) {
            throw new IllegalStateException("Failed to create test CA and keys.", e);
        }
    }

    private final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private final TestRaMasterApiProxySessionRemote testRaMasterApiProxyBean = EjbRemoteHelper.INSTANCE
            .getRemoteSession(TestRaMasterApiProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private final CmpConfiguration cmpConfiguration;

    public CmpExtendedValidationTest() {
        super();
        cmpConfiguration = (CmpConfiguration) globalConfigurationSession.getCachedConfiguration(CmpConfiguration.CMP_CONFIGURATION_ID);
    }

    @BeforeClass
    public static void beforeClass() {
        CryptoProviderTools.installBCProvider();
    }

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();

        caSession.addCA(ADMIN, testx509ca);
        cmpConfiguration.addAlias(ALIAS);
        cmpConfiguration.setRAMode(ALIAS, true);
        cmpConfiguration.setAllowRAVerifyPOPO(ALIAS, true);
        cmpConfiguration.setResponseProtection(ALIAS, "pbe");
        cmpConfiguration.setRACertProfile(ALIAS, CP_DN_OVERRIDE_NAME);
        cmpConfiguration.setRAEEProfile(ALIAS, String.valueOf(eepDnOverrideId));
        cmpConfiguration.setRACAName(ALIAS, testx509ca.getName());
        cmpConfiguration.setAuthenticationModule(ALIAS, CmpConfiguration.AUTHMODULE_REG_TOKEN_PWD + ";" + CmpConfiguration.AUTHMODULE_HMAC);
        cmpConfiguration.setAuthenticationParameters(ALIAS, "-;" + PBEPASSWORD);
        globalConfigurationSession.saveConfiguration(ADMIN, cmpConfiguration);

        testRaMasterApiProxyBean.enableFunctionTracingForTest();
    }

    @Override
    @After
    public void tearDown() throws Exception {
        super.tearDown();
        CaTestUtils.removeCa(ADMIN, testx509ca.getCAInfo());
        cmpConfiguration.removeAlias(ALIAS);
        globalConfigurationSession.saveConfiguration(ADMIN, cmpConfiguration);
    }

    @Override
    public String getRoleName() {
        return "CmpExtendedValidationTest";
    }

    /**
     * This test will verify that unsigned messages are rejected if signature is required.   
     */
    @Test
    public void testUnSignedMessageRejected() throws Exception {
        log.trace(">testUnSignedMessageRejected");
        final PKIMessage req = genCertReq("C=SE,O=PrimeKey,CN=testVerifyUnSignedMessageRejected");
        // Send CMP request
        byte[] resp = sendCmpHttp(req.getEncoded(), 200, ALIAS);
//        checkCmpResponseGeneral(resp, ISSUER_DN, USER_DN, cacert, nonce, transid, true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        checkCmpFailMessage(resp, "PKI Message is not authenticated properly. No HMAC protection was found.", PKIBody.TYPE_ERROR, 0, PKIFailureInfo.badRequest);
        // Check that the request was blocked
        checkCalled("isAuthorizedNoLogging");  // Always called. Sanity check.
        //checkNotCalled("cmpDispatch"); // TODO enable when check has been added to CmpServlet
        log.trace("<testUnSignedMessageRejected");
    }

//    /**
//     * This test will verify that a signed message not containing the signing certificate as payload is rejected.    
//     */
//    @Test
//    public void testRejectBadPayload() throws InvalidAlgorithmParameterException, OperatorCreationException, CertificateException, IOException,
//            NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchProviderException, SecurityException, IllegalAccessException, IllegalArgumentException, InvocationTargetException {
//        log.trace(">testRejectBadPayload");
////        //Create a CA certificate to issue the signer
////        final String caSubjectDn = "CN="+ISSUER_CA_NAME;
////        KeyPair caKeys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
////        Certificate caCertificate = CertTools.genSelfCert(caSubjectDn, 3650, null, caKeys.getPrivate(), caKeys.getPublic(),
////                "SHA256WithRSA", false);
////        //Write it to disk 
////        FileOutputStream fos = new FileOutputStream(caCertificateFile);
////        fos.write(CertTools.getPemFromCertificateChain(Arrays.asList(caCertificate)));
////        fos.close();     
////        if(!caCertificateFile.exists()) {
////            throw new IllegalStateException("Ca Certificate file was not created properly.");
////        }
////        
////        //Make sure to point out the issuer chain
////        File cmpPropertiesFile = folder.newFile();
////        Properties cmpProxyProperties = new Properties();
////        cmpProxyProperties.put(CmpProxyConfig.SIGNATURE_REQUIRED_KEY, "true");
////        cmpProxyProperties.put(CmpProxyConfig.ISSUER_CHAIN_PATH_KEY, caCertificateFile.getAbsolutePath());
////        cmpProxyProperties.store(new FileOutputStream(cmpPropertiesFile), "");
////        CmpProxyConfig cmpProxyConfig = CmpProxyConfig.getNewInstance(cmpPropertiesFile.getAbsolutePath());
////        this.cmpProxyConfig.set(cmpProxyServlet, cmpProxyConfig);
//
//        
//        final PKIMessage req = genCertReq("C=SE,O=PrimeKey,CN=testRejectBadPayload");
//        
//        final ArrayList<Certificate> signCertColl = new ArrayList<Certificate>();
//        final byte[] messageBytes = CmpMessageHelper.signPKIMessage(req, signCertColl, keys.getPrivate(), CMSSignedGenerator.DIGEST_SHA1,
//                BouncyCastleProvider.PROVIDER_NAME);
//        // Send CMP request
//        byte[] resp = sendCmpHttp(messageBytes, 200, ALIAS);
//        checkCmpFailMessage(resp, "PKI Message is not authenticated properly. No HMAC protection was found.", PKIBody.TYPE_ERROR, 0, PKIFailureInfo.badRequest);
//        // Check that the request was blocked
//        checkCalled("isAuthorizedNoLogging");  // Always called. Sanity check.
//        //checkNotCalled("cmpDispatch"); // TODO enable when check has been added to CmpServlet
//        log.trace("<testRejectBadPayload");
//    }

    private void checkCalled(final String methodName) {
        final List<String> calledMethods = testRaMasterApiProxyBean.getFunctionTraceForTest();
        assertTrue("Method '" + methodName + "' should have been called",
                calledMethods.contains(methodName + RaMasterApiProxyBeanLocal.TEST_TRACE_SUFFIX_LOCAL) ||
                calledMethods.contains(methodName + RaMasterApiProxyBeanLocal.TEST_TRACE_SUFFIX_REMOTE));
    }

    private void checkNotCalled(final String methodName) {
        final List<String> calledMethods = testRaMasterApiProxyBean.getFunctionTraceForTest();
        assertFalse("Method '" + methodName + "' should NOT have been called", calledMethods.contains(methodName + RaMasterApiProxyBeanLocal.TEST_TRACE_SUFFIX_LOCAL));
        assertFalse("Method '" + methodName + "' (remote) should not have been called", calledMethods.contains(methodName + RaMasterApiProxyBeanLocal.TEST_TRACE_SUFFIX_REMOTE));
    }

    private PKIMessage genCertReq(final String userDN) throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, IOException {
        final byte[] nonce = CmpMessageHelper.createSenderNonce();
        final byte[] transid = CmpMessageHelper.createSenderNonce();
        return genCertReq(ISSUER_DN, new X500Name(userDN), keys, cacert, nonce, transid, false, null, null, null, null, null, null);
    }

}
