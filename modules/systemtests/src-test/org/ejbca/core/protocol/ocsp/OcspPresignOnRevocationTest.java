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
package org.ejbca.core.protocol.ocsp;

import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.CaMsCompatibilityIrreversibleException;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.ca.IllegalValidityException;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.SignRequestSignatureException;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.CertificateCreateSessionRemote;
import org.cesecore.certificates.certificate.CertificateRevokeException;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificate.exception.CustomCertificateSerialNumberException;
import org.cesecore.certificates.certificate.request.SimpleRequestMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
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
import org.cesecore.junit.util.PKCS12TestRunner;
import org.cesecore.keybind.InternalKeyBindingNonceConflictException;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.oscp.OcspResponseData;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.TraceLogMethodsRule;
import org.ejbca.core.ejb.ca.revoke.RevocationSessionRemote;
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
import com.keyfactor.util.SHA1DigestCalculator;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.keys.KeyTools;
import com.keyfactor.util.keys.token.CryptoTokenOfflineException;

/**
 * Tests the canning-on-revocation feature on OCSP
 */
@RunWith(Parameterized.class)
public class OcspPresignOnRevocationTest {

    @Parameters(name = "{0}")
    public static Collection<CryptoTokenRunner> runners() {
        return Arrays.asList(new PKCS12TestRunner());
    }

    @Rule
    public TestName testName = new TestName();

    @Rule
    public TestRule traceLogMethodsRule = new TraceLogMethodsRule();

    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private CertificateCreateSessionRemote certificateCreateSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateCreateSessionRemote.class);
    private CesecoreConfigurationProxySessionRemote cesecoreConfigurationProxySession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CesecoreConfigurationProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private GlobalConfigurationSessionRemote globalConfigurationSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(GlobalConfigurationSessionRemote.class);
    private OcspResponseGeneratorSessionRemote ocspResponseGeneratorSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(OcspResponseGeneratorSessionRemote.class);
    private OcspDataSessionRemote ocspDataSession = EjbRemoteHelper.INSTANCE.getRemoteSession(OcspDataSessionRemote.class);
    private OcspResponseGeneratorTestSessionRemote ocspResponseGeneratorTestSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(OcspResponseGeneratorTestSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private RevocationSessionRemote revocationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RevocationSessionRemote.class);
    private SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);

    private final AuthenticationToken internalAdmin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("Internal Admin"));

    private CryptoTokenRunner cryptoTokenRunner;
    private X509CAInfo testx509ca;
    private String originalDefaultResponder;
    private X509Certificate caCertificate;
    private X509Certificate ocspCertificate;

    public OcspPresignOnRevocationTest(CryptoTokenRunner cryptoTokenRunner) throws Exception {
        this.cryptoTokenRunner = cryptoTokenRunner;

    }

    @Before
    public void setUp() throws Exception {
        assumeTrue("Test with runner " + cryptoTokenRunner.getSimpleName() + " cannot run on this platform.", cryptoTokenRunner.canRun());
        testx509ca = cryptoTokenRunner.createX509Ca("CN=" + testName.getMethodName(), testName.getMethodName());
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
    public void testPreProduceOnRevocation() throws CADoesntExistsException, InternalKeyBindingNonceConflictException,
            CaMsCompatibilityIrreversibleException, AuthorizationDeniedException, CertificateEncodingException, OCSPException,
            MalformedRequestException, IOException, InvalidAlgorithmParameterException, CustomCertificateSerialNumberException, IllegalKeyException,
            CertificateCreateException, CryptoTokenOfflineException, SignRequestSignatureException, IllegalNameException, CertificateRevokeException,
            CertificateSerialNumberException, IllegalValidityException, CAOfflineException, InvalidAlgorithmException, CertificateExtensionException {
        int nextUpdateTime = 3600;
        final String originalNextUpdateTime = setOcspDefaultNextUpdateTime(Integer.toString(nextUpdateTime));
        //Set up the CA to use pre produced responses
        testx509ca.setDoPreProduceOcspResponses(true);
        testx509ca.setDoPreProduceOcspResponseUponIssuanceAndRevocation(true);
        caSession.editCA(internalAdmin, testx509ca);
        ocspResponseGeneratorTestSession.reloadOcspSigningCache();
        final String endEntityName = testName.getMethodName() + "_ee";
        //Produce an end entity cert to test on 
        final EndEntityInformation endEntity = new EndEntityInformation(endEntityName, "CN=" + endEntityName, testx509ca.getCAId(), null, null,
                EndEntityTypes.ENDUSER.toEndEntityType(), 0, 0, EndEntityConstants.TOKEN_USERGEN, null);
        endEntity.setPassword("foo123");
        KeyPair keys = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        SimpleRequestMessage req = new SimpleRequestMessage(keys.getPublic(), endEntity.getUsername(), endEntity.getPassword());
        X509Certificate eeCertificate = (X509Certificate) (((X509ResponseMessage) certificateCreateSession.createCertificate(internalAdmin, endEntity,
                req, X509ResponseMessage.class, signSession.fetchCertGenParams())).getCertificate());
        // Prepare OCSP request
        final int localTransactionId = TransactionCounter.INSTANCE.getTransactionNumber();
        final GlobalOcspConfiguration configuration = (GlobalOcspConfiguration) globalConfigurationSession
                .getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
        TransactionLogger transactionLogger = new TransactionLogger(localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "", configuration);
        AuditLogger auditLogger = new AuditLogger("", localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "", configuration);
        final OCSPReqBuilder gen = new OCSPReqBuilder();
        gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), caCertificate, eeCertificate.getSerialNumber()));
        OCSPReq ocspRequest = gen.build();
        //Revoke the poor cert, which should trigger the production of a canned ocps response
        revocationSession.revokeCertificate(internalAdmin, eeCertificate, null, null, RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE, null);
        //Verify that revocation data has been pre-generated
        OcspResponseData ocspResponseData = ocspDataSession.findOcspDataByCaIdSerialNumber(testx509ca.getCAId(),
                CertTools.getSerialNumber(eeCertificate).toString());
        assertNotNull("Canned OCSP was not triggered by revocation.", ocspResponseData);

        //Verify the nextUpdate time in the response
        long nextUpdate = ocspResponseData.getNextUpdate();
        //Regression test: Make sure that we didn't produce a forever valid response
        assertNotEquals(
                "Pre producing an ocsp response on revocation led to an ocsp response with unlimited validity. This is a serious compliance issue.",
                253402300799000L, nextUpdate);

        try {

            byte[] ocspResponseBytes = ocspResponseGeneratorSession
                    .getOcspResponse(ocspRequest.getEncoded(), null, "", null, null, auditLogger, transactionLogger, false, false, false)
                    .getOcspResponse();
            // Verify response objects. First response should have been stored and used as reply to the second request.
            assertNotNull("OCSP responder replied null", ocspResponseBytes);
            OCSPResp response = new OCSPResp(ocspResponseBytes);
            BasicOCSPResp basicOCSPResp = (BasicOCSPResp) response.getResponseObject();
            SingleResp singleResponse = basicOCSPResp.getResponses()[0];
            assertNotEquals(
                    "Pre producing an ocsp response on revocation led to an ocsp response with unlimited validity. This is a serious compliance issue.",
                    253402300799000L, singleResponse.getNextUpdate().getTime());
            //Assert that nextUpdate is between now and an hour plus change from now. 
            Calendar nextUpdateDate = Calendar.getInstance();
            nextUpdateDate.setTimeInMillis(singleResponse.getNextUpdate().getTime());
            Calendar inAnHour = Calendar.getInstance();
            inAnHour.setTime(new Date());
            inAnHour.add(Calendar.SECOND, nextUpdateTime + 60);
            assertTrue("nextUpdate was not set after now", nextUpdateDate.getTime().after(new Date()));
            assertTrue("nextUpdate was not set before now plus 3650 seconds", nextUpdateDate.getTime().before(inAnHour.getTime()));
        } finally {
            internalCertificateStoreSession.removeCertificate(eeCertificate);
            ocspDataSession.deleteOcspDataByCaId(testx509ca.getCAId());
            setOcspDefaultNextUpdateTime(originalNextUpdateTime);
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
}
