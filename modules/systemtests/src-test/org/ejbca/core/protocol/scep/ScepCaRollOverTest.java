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
package org.ejbca.core.protocol.scep;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Random;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.smime.SMIMECapability;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.SignerInformationVerifierProvider;
import org.bouncycastle.cms.jcajce.JcaSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;
import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.CertificateGenerationParams;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateCreateSessionRemote;
import org.cesecore.certificates.certificate.CertificateData;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.request.PKCS10RequestMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.junit.util.CryptoTokenRunner;
import org.cesecore.junit.util.PKCS12TestRunner;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.TraceLogMethodsRule;
import org.cesecore.util.ValidityDate;
import org.ejbca.config.ScepConfiguration;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestName;
import org.junit.rules.TestRule;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import com.keyfactor.util.Base64;
import com.keyfactor.util.CertTools;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.keys.KeyTools;

/**
 * Test CA rollover functionality in SCEP, i.e. when a CA cert is renewed and clients gets a new cert from the new CA
 */
@RunWith(Parameterized.class)
public class ScepCaRollOverTest extends ScepTestBase {

    @Parameters(name = "{0}")
    public static Collection<CryptoTokenRunner> runners() {
        return Arrays.asList(new PKCS12TestRunner());
    }

    private static final String ROLLOVER_USER_NAME = "sceprolloveruser";
    private static final String ROLLOVER_USER_DN = "C=SE,O=PrimeKey,CN=" + ROLLOVER_USER_NAME;
    private static final String ROLLOVER_SUB_CA = "RolloverSubCA";
    private static final String ROLLOVER_SUB_CA_DN = "CN=RolloverSubCA";
    private static final String SCEP_ALIAS = "ScepCaRollOverTest";
    private static final String RESOURCE_SCEP = "publicweb/apply/scep/" + SCEP_ALIAS + "/pkiclient.exe";
    
    private static final String CERTIFICATE_PROFILE_NAME = "TestScepCARollover";
    private static final String END_ENTITY_NAME = "TestScepCARollover";

    private static final Logger log = Logger.getLogger(ScepCaRollOverTest.class);

    private static final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("ScepCaRollOverTest"));

    private final CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
    private final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private final CertificateCreateSessionRemote certificateCreateSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CertificateCreateSessionRemote.class);
    private final CertificateProfileSessionRemote certificateProfileSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CertificateProfileSessionRemote.class);
    private final CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CertificateStoreSessionRemote.class);
    private final EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    private final GlobalConfigurationSessionRemote globalConfigSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(GlobalConfigurationSessionRemote.class);
    private final InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);

    private long rolloverStartTime;
    private X509CAInfo x509ca;
    private X509Certificate cacert;
    private KeyPair keyTestRollover;
    private String senderNonce = null;
    private String transId = null;
    private Random rand = new Random();
    
    private Certificate currentSubCaCert;
    private Certificate rolloverCert;

    private ScepConfiguration scepConfiguration;

    @Rule
    public TestRule traceLogMethodsRule = new TraceLogMethodsRule();

    @Rule
    public TestName testName = new TestName();

    private CryptoTokenRunner cryptoTokenRunner;

    public ScepCaRollOverTest(CryptoTokenRunner cryptoTokenRunner) throws Exception {
        super();
        this.cryptoTokenRunner = cryptoTokenRunner;

    }

    @Before
    public void setUp() throws Exception {
        // Pre-generate key for all requests to speed things up a bit
        assumeTrue("Test with runner " + cryptoTokenRunner.getSimpleName() + " cannot run on this platform.", cryptoTokenRunner.canRun());
        try {
            keyTestRollover = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }

        x509ca = cryptoTokenRunner.createX509Ca("CN=" + testName.getMethodName(), testName.getMethodName());
        
        //Allow the default CA to have non-unique DNs 
        x509ca.setDoEnforceUniqueDistinguishedName(false);
        caSession.editCA(admin, x509ca);
        
        cacert = (X509Certificate) x509ca.getCertificateChain().get(0);


        scepConfiguration = (ScepConfiguration) globalConfigSession.getCachedConfiguration(ScepConfiguration.SCEP_CONFIGURATION_ID);
        scepConfiguration.addAlias(SCEP_ALIAS);
        globalConfigSession.saveConfiguration(admin, scepConfiguration);
        
        rolloverStartTime = System.currentTimeMillis() + 7L * 24L * 3600L * 1000L;

        // Clean up old certificates first
        internalCertificateStoreSession.removeCertificatesBySubject(ROLLOVER_SUB_CA_DN);
        internalCertificateStoreSession.removeCertificatesBySubject(ROLLOVER_USER_DN);

        // Create sub CA
        final int cryptoTokenId = CryptoTokenTestUtils.createCryptoTokenForCA(null, "foo123".toCharArray(), true, false, ROLLOVER_SUB_CA, "1024",
                "1024", CAToken.SOFTPRIVATESIGNKEYALIAS, CAToken.SOFTPRIVATEDECKEYALIAS);
        final CAToken caToken = CaTestUtils.createCaToken(cryptoTokenId, AlgorithmConstants.SIGALG_SHA256_WITH_RSA,
                AlgorithmConstants.SIGALG_SHA256_WITH_RSA, CAToken.SOFTPRIVATESIGNKEYALIAS, CAToken.SOFTPRIVATEDECKEYALIAS);
        X509CAInfo cainfo = X509CAInfo.getDefaultX509CAInfo(ROLLOVER_SUB_CA_DN, ROLLOVER_SUB_CA, CAConstants.CA_ACTIVE,
                CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA, "1000d", CAInfo.SIGNEDBYEXTERNALCA, null, caToken);
        cainfo.setDescription("JUnit Test Sub CA for SCEP GetNextCACert test");
        cainfo.setSignedBy(x509ca.getCAId());
        cainfo.setCertificateProfileId(CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA);
        cainfo.setEncodedValidity("14d");
        cainfo.setDoEnforceUniqueDistinguishedName(false);
        if (caSession.existsCa(ROLLOVER_SUB_CA)) {
            CaTestUtils.removeCa(admin, caSession.getCAInfo(admin, ROLLOVER_SUB_CA));
        }
        caAdminSession.createCA(admin, cainfo);
        if(CAConstants.CA_ACTIVE != caSession.getCAInfo(admin, ROLLOVER_SUB_CA).getStatus()) {
            throw new IllegalStateException("Wrong state of test Sub CA");
        };

        // CA should NOT have any rollover certificate yet
        String reqUrl = httpReqPath + '/' + RESOURCE_SCEP + "?operation=GetNextCACert&message=" + URLEncoder.encode(ROLLOVER_SUB_CA, "UTF-8");
        URL url = new URL(reqUrl);
        HttpURLConnection con = (HttpURLConnection) url.openConnection();
        con.setRequestMethod("GET");
        con.getDoOutput();
        con.connect();
        if( 403 != con.getResponseCode()) {
            throw new IllegalStateException("Should get an error response code if no rollover certificate exists");
        }
        checkCACaps(ROLLOVER_SUB_CA, "POSTPKIOperation\nRenewal\nSHA-512\nSHA-256\nSHA-1\nDES3\nAES\nSCEPStandard");

        // Create a rollover certificate
        final int subCAId = cainfo.getCAId();
        final byte[] requestbytes = caAdminSession.makeRequest(admin, subCAId, null, null);
        final CertificateProfile certProf = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        certProf.setAllowValidityOverride(true);
        certProf.setEncodedValidity("14d");
        final int certProfId = certificateProfileSession.addCertificateProfile(admin, CERTIFICATE_PROFILE_NAME, certProf);
        final EndEntityInformation endentity = new EndEntityInformation(END_ENTITY_NAME, ROLLOVER_SUB_CA_DN, x509ca.getCAId(), null, null,
                new EndEntityType(EndEntityTypes.ENDUSER), EndEntityConstants.EMPTY_END_ENTITY_PROFILE, certProfId,
                EndEntityConstants.TOKEN_USERGEN, null);
        endentity.setStatus(EndEntityConstants.STATUS_NEW);
        endentity.setPassword("foo123");
        final ExtendedInformation ei = new ExtendedInformation();
        ei.setCustomData(ExtendedInformation.CUSTOM_STARTTIME, ValidityDate.formatAsUTC(rolloverStartTime));
        ei.setCustomData(ExtendedInformation.CUSTOM_ENDTIME, ValidityDate.formatAsUTC(rolloverStartTime + 14L * 24L * 3600L * 1000L));
        endentity.setExtendedInformation(ei);
        final PKCS10RequestMessage req = new PKCS10RequestMessage(requestbytes);
        final X509ResponseMessage respmsg = (X509ResponseMessage) certificateCreateSession.createCertificate(admin, endentity, req,
                X509ResponseMessage.class, new CertificateGenerationParams());
        internalCertificateStoreSession.removeCertificate(respmsg.getCertificate()); // Don't store this certificate. In a real world scenario it would have been generated by a different CA.

        cainfo = (X509CAInfo) caSession.getCAInfo(admin, subCAId);
        final String nextKeyAlias = cainfo.getCAToken().getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN_NEXT);
        caAdminSession.receiveResponse(admin, subCAId, respmsg, null, nextKeyAlias, true/*rollover*/);
        // Sub CA certificate is first
        currentSubCaCert = cainfo.getCertificateChain().iterator().next();
        rolloverCert = caSession.getFutureRolloverCertificate(subCAId);

        // Check that the certificate has the correct status
        final CertificateData certData = certificateStoreSession
                .getCertificateDataByIssuerAndSerno(CertTools.getIssuerDN(rolloverCert), CertTools.getSerialNumber(rolloverCert))
                .getCertificateData();
        if (CertificateConstants.CERT_ROLLOVERPENDING != certData.getStatus()) {
            throw new IllegalStateException("Rollover certificate should have status CERT_ROLLOVERPENDING");
        }

    }

    @After
    public void tearDown() throws Exception {

        try {
            endEntityManagementSession.deleteUser(admin, ROLLOVER_USER_NAME);
            log.debug("deleted user: " + ROLLOVER_USER_NAME);
        } catch (Exception e) {
            // NOPMD: ignore
        }

        scepConfiguration.removeAlias(SCEP_ALIAS);
        globalConfigSession.saveConfiguration(admin, scepConfiguration);

        cryptoTokenRunner.cleanUp();
        
        if (endEntityManagementSession.existsUser(END_ENTITY_NAME)) {
            endEntityManagementSession.deleteUser(admin, END_ENTITY_NAME);
        }

        // Done with all of the rollover tests
        if (caSession.existsCa(ROLLOVER_SUB_CA)) {
            CaTestUtils.removeCa(admin, caSession.getCAInfo(admin, ROLLOVER_SUB_CA));
        }
        internalCertificateStoreSession.removeCertificatesBySubject(ROLLOVER_SUB_CA_DN);
        internalCertificateStoreSession.removeCertificatesBySubject(ROLLOVER_USER_DN);
        certificateProfileSession.removeCertificateProfile(admin, CERTIFICATE_PROFILE_NAME);
    }
    
    /**
     * Tests creating and receiving a rollover certificate for a CA. Note that the subsequent tests depend on this one.
     */
    @Test
    public void testScepGetNextCACertSubCA() throws Exception {
        x509ca.setDoEnforceUniqueDistinguishedName(false);
        caAdminSession.editCA(admin, x509ca);

            
        // Now we should get the certificate chain of the rollover cert
        checkCACaps(ROLLOVER_SUB_CA, "POSTPKIOperation\nGetNextCACert\nRenewal\nSHA-512\nSHA-256\nSHA-1\nDES3\nAES\nSCEPStandard");
        final List<Certificate> nextChain = sendGetNextCACert(ROLLOVER_SUB_CA, currentSubCaCert);
        assertEquals("should return a certificate chain with the rollover certificate", 2, nextChain.size());
        final Certificate nextCert = nextChain.get(0);
        final Certificate nextRootCert = nextChain.get(1);
        assertEquals("should get the leaf CA certificate first in the chain", ROLLOVER_SUB_CA_DN, CertTools.getSubjectDN(nextCert));
        assertEquals("should get the root CA certiticate second in the chain", x509ca.getSubjectDN(), CertTools.getSubjectDN(nextRootCert));
        assertEquals("should get the rollover certificate", CertTools.getSerialNumberAsString(rolloverCert),
                CertTools.getSerialNumberAsString(nextCert));

        long certValidityStart = ((X509Certificate) rolloverCert).getNotBefore().getTime();
        if (Math.abs(certValidityStart - rolloverStartTime) > 60L * 1000L) {
            assertEquals("rollover certificate has the wrong validity start time", rolloverStartTime, certValidityStart);
        } else {
            rolloverStartTime = certValidityStart;
        }

    }

    /**
     * Tests creating a rollover end-user certificate.
     */
    @Test
    public void testScepRequestRolloverCert() throws Exception {

        final X509CAInfo subcainfo = (X509CAInfo) caSession.getCAInfo(admin, ROLLOVER_SUB_CA);

        final int subCAId = subcainfo.getCAId();
        final X509Certificate subcaRolloverCert = (X509Certificate) caSession.getFutureRolloverCertificate(subCAId);
        final X509Certificate subcaCurrentCert = (X509Certificate) caSession.getCAInfo(admin, subCAId).getCertificateChain().iterator().next();
        assumeTrue("Not running test since test13ScepGetNextCACertSubCA failed to create a rollover CA certificate", subcaRolloverCert != null);

        scepConfiguration.setIncludeCA(SCEP_ALIAS, true);
        scepConfiguration.setAllowLegacyDigestAlgorithm(SCEP_ALIAS, true);
        globalConfigSession.saveConfiguration(admin, scepConfiguration);

        // Clean up certificates first
        internalCertificateStoreSession.removeCertificatesBySubject(ROLLOVER_USER_DN);

        // Make a request with the current CA certificate. Should work as usual
        createScepUser(ROLLOVER_USER_NAME, ROLLOVER_USER_DN, subCAId);
        byte[] msgBytes = genScepRolloverCARequest(subcaCurrentCert, CMSSignedGenerator.DIGEST_SHA1, ROLLOVER_USER_DN);
        byte[] retMsg = sendScep(false, msgBytes);
        assertNotNull(retMsg);
        checkScepResponse(retMsg, ROLLOVER_USER_DN, -1L, senderNonce, transId, false, CMSSignedGenerator.DIGEST_SHA1, false, subcaCurrentCert,
                keyTestRollover, PKCSObjectIdentifiers.rsaEncryption, SMIMECapability.dES_CBC);

        // Clean up
        try {
            endEntityManagementSession.deleteUser(admin, ROLLOVER_USER_NAME);
            log.debug("deleted user: " + ROLLOVER_USER_NAME);
        } catch (Exception e) {
            // NOPMD: ignore
        }

        // Now request a certificate signed by the roll over CA certificate
        createScepUser(ROLLOVER_USER_NAME, ROLLOVER_USER_DN, subCAId);
        byte[] msgBytes2 = genScepRolloverCARequest(subcaRolloverCert, CMSSignedGenerator.DIGEST_SHA256, ROLLOVER_USER_DN);
        byte[] retMsg2 = sendScep(false, msgBytes2);
        assertNotNull(retMsg2);
        checkScepResponse(retMsg2, ROLLOVER_USER_DN, rolloverStartTime, senderNonce, transId, false, CMSSignedGenerator.DIGEST_SHA256, false,
                subcaRolloverCert, keyTestRollover, PKCSObjectIdentifiers.rsaEncryption, SMIMECapability.dES_CBC);

    }


    /** Makes a request to the Rollover CA, signed with the given CA certificate (current or next/rollover). */
    private byte[] genScepRolloverCARequest(X509Certificate caRolloverCert, String digestoid, String userDN)
            throws IOException, CMSException, OperatorCreationException, CertificateException {
        assertNotNull(keyTestRollover);
        assertNotNull(caRolloverCert);

        ScepRequestGenerator gen = new ScepRequestGenerator();
        gen.setKeys(keyTestRollover, BouncyCastleProvider.PROVIDER_NAME);
        gen.setDigestOid(digestoid);
        // Create a transactionId
        byte[] randBytes = new byte[16];
        this.rand.nextBytes(randBytes);
        byte[] digest = CertTools.generateMD5Fingerprint(randBytes);
        transId = new String(Base64.encode(digest));
        final X509Certificate senderCertificate = CertTools.genSelfCert("CN=SenderCertificate", 24 * 60 * 60 * 1000, null,
                keyTestRollover.getPrivate(), keyTestRollover.getPublic(), AlgorithmConstants.SIGALG_SHA256_WITH_RSA, false);
        final byte[] msgBytes = gen.generateCertReq(userDN, "foo123", transId, caRolloverCert, senderCertificate, keyTestRollover.getPrivate(),
                PKCSObjectIdentifiers.rsaEncryption, SMIMECapability.dES_CBC);
        assertNotNull(msgBytes);
        senderNonce = gen.getSenderNonce();
        byte[] nonceBytes = Base64.decode(senderNonce.getBytes());
        assertTrue(nonceBytes.length == 16);
        return msgBytes;
    }

    private List<Certificate> sendGetNextCACert(final String caName, Certificate currentCACert) throws Exception {
        String reqUrl = httpReqPath + '/' + RESOURCE_SCEP + "?operation=GetNextCACert&message=" + URLEncoder.encode(caName, "UTF-8");
        URL url = new URL(reqUrl);
        HttpURLConnection con = (HttpURLConnection) url.openConnection();
        con.setRequestMethod("GET");
        con.getDoOutput();
        con.connect();
        assertEquals("Response code is not 200 (OK)", 200, con.getResponseCode());
        assertTrue(con.getContentType().startsWith("application/x-x509-next-ca-cert"));
        final ByteArrayOutputStream respBaos = new ByteArrayOutputStream();
        // This works for small requests, and SCEP requests are small enough
        InputStream in = con.getInputStream();
        int b = in.read();
        while (b != -1) {
            respBaos.write(b);
            b = in.read();
        }
        respBaos.flush();
        in.close();
        byte[] respBytes = respBaos.toByteArray();
        assertNotNull("Response can not be null.", respBytes);
        assertTrue("Response can not be empty.", respBytes.length > 0);

        // Verify PKCS7. It should be signed by the current CA
        final ContentInfo ci = ContentInfo.getInstance(respBytes);
        //System.out.println(ASN1Dump.dumpAsString(ci));
        final CMSSignedData signedData = new CMSSignedData(ci);
        // Check correct signer
        Collection<SignerInformation> signers = signedData.getSignerInfos().getSigners();
        assertEquals("Should be only one signer", 1, signers.size());
        SignerInformation signer = signers.iterator().next();
        // Verify that the CMS is signed by the current CA certificate
        BigInteger sigSerno = signer.getSID().getSerialNumber();
        BigInteger signerSerno = CertTools.getSerialNumber(currentCACert);
        assertEquals("CMS message should be signed by current CA", signerSerno, sigSerno);
        // Verify signature
        assertTrue("CMS should be signed by rollover CA certificate",
                signedData.verifySignatures(new ScepVerifierProvider(currentCACert.getPublicKey())));
        final Store<?> certStore = signedData.getCertificates();
        final List<Certificate> ret = new ArrayList<>();
        for (final Object obj : certStore.getMatches(null)) {
            log.debug("Received an item of type " + obj.getClass().getName() + ": " + obj);
            if (obj instanceof X509CertificateHolder) {
                final byte[] certbytes = ((X509CertificateHolder) obj).getEncoded();
                final Certificate cert = CertTools.getCertfromByteArray(certbytes, Certificate.class);
                ret.add(cert);
            }
        }
        return ret;
    }


    private static class ScepVerifierProvider implements SignerInformationVerifierProvider {

        private final SignerInformationVerifier signerInformationVerifier;

        public ScepVerifierProvider(PublicKey publicKey) throws OperatorCreationException {
            JcaDigestCalculatorProviderBuilder calculatorProviderBuilder = new JcaDigestCalculatorProviderBuilder()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME);
            JcaSignerInfoVerifierBuilder signerInfoVerifierBuilder = new JcaSignerInfoVerifierBuilder(calculatorProviderBuilder.build())
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME);
            signerInformationVerifier = signerInfoVerifierBuilder.build(publicKey);
        }

        @Override
        public SignerInformationVerifier get(SignerId signerId) throws OperatorCreationException {
            return signerInformationVerifier;
        }

    }

    @Override
    protected String getResourceScep() {
        return RESOURCE_SCEP;
    }

    @Override
    protected String getTransactionId() {
        return transId;
    }

    @Override
    protected X509Certificate getCaCertificate() {
        return cacert;
    }
}
