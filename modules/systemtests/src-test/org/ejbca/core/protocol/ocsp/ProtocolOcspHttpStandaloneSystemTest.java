/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLEncoder;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.io.IOUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.ocsp.OcspResponseGeneratorTestSessionRemote;
import org.cesecore.certificates.ocsp.OcspTestUtils;
import org.cesecore.config.GlobalOcspConfiguration;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.keybind.InternalKeyBindingMgmtSessionRemote;
import org.cesecore.keybind.InternalKeyBindingStatus;
import org.cesecore.keybind.impl.OcspKeyBinding;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.TraceLogMethodsRule;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;

import com.keyfactor.util.Base64;
import com.keyfactor.util.CertTools;
import com.keyfactor.util.EJBTools;
import com.keyfactor.util.SHA1DigestCalculator;
import com.keyfactor.util.certificate.DnComponents;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;

import jakarta.ejb.CreateException;

/**
 * 
 */
public class ProtocolOcspHttpStandaloneSystemTest extends ProtocolOcspTestBase {

    private static final Logger log = Logger.getLogger(ProtocolOcspHttpStandaloneSystemTest.class);
    
    private static final String TESTCLASSNAME = ProtocolOcspHttpStandaloneSystemTest.class.getSimpleName();
    private static final String CA_DN = "CN=OcspDefaultTestCA,O=Foo,C=SE";

    private GlobalConfigurationSessionRemote globalConfigurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);
    private OcspResponseGeneratorTestSessionRemote ocspResponseGeneratorTestSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(OcspResponseGeneratorTestSessionRemote.class, EjbRemoteHelper.MODULE_TEST);

    private static final AuthenticationToken authenticationToken = new TestAlwaysAllowLocalAuthenticationToken(TESTCLASSNAME);
    private static X509CA x509ca;
    private static int cryptoTokenId;
    private static int internalKeyBindingId;
    private static X509Certificate ocspSigningCertificate;
    private static X509Certificate caCertificate;

    @Rule
    public TestRule traceLogMethodsRule = new TraceLogMethodsRule();

    public ProtocolOcspHttpStandaloneSystemTest() throws MalformedURLException, URISyntaxException {
    	super("http", "ejbca", "publicweb/status/ocsp");
    }
  
    @BeforeClass
    public static void beforeClass() throws Exception {
        x509ca = CryptoTokenTestUtils.createTestCAWithSoftCryptoToken(authenticationToken, CA_DN);
        cryptoTokenId = CryptoTokenTestUtils.createSoftCryptoToken(authenticationToken, TESTCLASSNAME);
        internalKeyBindingId = OcspTestUtils.createInternalKeyBinding(authenticationToken, cryptoTokenId,
                OcspKeyBinding.IMPLEMENTATION_ALIAS, TESTCLASSNAME, "RSA2048", AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        String signerDN = "CN=ocspTestSigner,O=Foo,C=SE";
        ocspSigningCertificate = OcspTestUtils.createOcspSigningCertificate(authenticationToken, OcspTestUtils.OCSP_END_USER_NAME, signerDN, internalKeyBindingId, x509ca.getCAId());
        OcspTestUtils.updateInternalKeyBindingCertificate(authenticationToken, internalKeyBindingId);
        OcspTestUtils.setInternalKeyBindingStatus(authenticationToken, internalKeyBindingId, InternalKeyBindingStatus.ACTIVE);
        caCertificate = createCaCertificate(authenticationToken, x509ca.getCACertificate());
        setupTestCertificates(x509ca.getCAId());
    }
    
    @AfterClass
    public static void afterClass() throws Exception {
        removeTestCertifices(CERTIFICATE_USERNAME);
        removeTestCertifices(CERTIFICATE_WITH_NO_REVOKE_REASON_USERNAME);
        InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE
                .getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);       
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
        
        InternalKeyBindingMgmtSessionRemote internalKeyBindingMgmtSession = EjbRemoteHelper.INSTANCE
                .getRemoteSession(InternalKeyBindingMgmtSessionRemote.class);
        CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE
                .getRemoteSession(CryptoTokenManagementSessionRemote.class);
        AuthenticationToken authenticationToken = new TestAlwaysAllowLocalAuthenticationToken(TESTCLASSNAME);
        internalKeyBindingMgmtSession.deleteInternalKeyBinding(authenticationToken, internalKeyBindingId);
        cryptoTokenManagementSession.deleteCryptoToken(authenticationToken, cryptoTokenId);
        OcspTestUtils.deleteCa(authenticationToken, x509ca);
    }
   
    @Before
    public void setUp() throws Exception {
        caid = ISSUER_DN.hashCode();
        unknowncacert = CertTools.getCertfromByteArray(unknowncacertBytes, X509Certificate.class);
    }
    
    @Test
    public void test01Access() throws Exception {
        super.test01Access();
    }

    /**
     * Tests ocsp message
     * 
     * @throws Exception error
     */
    @Test
    public void test02OcspGood() throws Exception {
        @SuppressWarnings("unused")
        String subjectDnCA = CertTools.getSubjectDN(unknowncacert);
        // And an OCSP request
        OCSPReqBuilder gen = new OCSPReqBuilder();
        final X509Certificate ocspTestCert = getActiveTestCert();
        gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), getCaCert(ocspTestCert), ocspTestCert.getSerialNumber()));
        OCSPReq req = gen.build();
        helper.reloadKeys();
        // Send the request and receive a singleResponse
        SingleResp[] singleResps = helper.sendOCSPPost(req.getEncoded(), null, 0, 200);
        assertEquals("No of SingResps should be 1.", 1, singleResps.length);
        SingleResp singleResp = singleResps[0];

        CertificateID certId = singleResp.getCertID();
        assertEquals("Serno in response does not match serno in request.", certId.getSerialNumber(), ocspTestCert.getSerialNumber());
        Object status = singleResp.getCertStatus();
        assertEquals("Status is not null (good)", null, status);
    }

    /**
     * Tests ocsp message
     * 
     * @throws Exception
     *             error
     */
    @Test
    public void test03OcspRevoked() throws Exception {
        ocspResponseGeneratorTestSession.reloadOcspSigningCache();
        
        setupTestCertificateRevocationReasonUnspecified(x509ca.getCAId());
        
        final X509Certificate ocspTestCert = getRevokedTestCert(CERTIFICATE_WITH_NO_REVOKE_REASON_USERNAME);
        // And an OCSP request
        OCSPReqBuilder gen = new OCSPReqBuilder();
        gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), getCaCert(ocspTestCert), ocspTestCert.getSerialNumber()));
        OCSPReq req = gen.build();

        // Send the request and receive a singleResponse
        SingleResp[] singleResps = helper.sendOCSPPost(req.getEncoded(), null, 0, 200);
        assertEquals("No of SingResps should be 1.", 1, singleResps.length);
        SingleResp singleResp = singleResps[0];

        CertificateID certId = singleResp.getCertID();
        assertEquals("Serno in response does not match serno in request.", certId.getSerialNumber(), ocspTestCert.getSerialNumber());
        Object status = singleResp.getCertStatus();
        assertTrue("Status ("+status+") is not RevokedStatus", status instanceof RevokedStatus);
        RevokedStatus rev = (RevokedStatus) status;
        assertFalse("Status does have a reason", rev.hasRevocationReason());
    }

    @Test
    public void test04OcspUnknown() throws Exception {
        loadUserCert(this.caid);
        super.test04OcspUnknown();
    }

    @Test
    public void test05OcspUnknownCA() throws Exception {
        final String issuerDN = CertTools.getIssuerDN(ocspSigningCertificate);
        GlobalOcspConfiguration ocspConfiguration = (GlobalOcspConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
        ocspConfiguration.setOcspDefaultResponderReference(issuerDN);
        globalConfigurationSession.saveConfiguration(authenticationToken, ocspConfiguration);
        ocspResponseGeneratorTestSession.reloadOcspSigningCache();
        super.test05OcspUnknownCA();
        // Reverted issuer DN should work as well, we are independent of the order here
        final String revertedIssuerDN = DnComponents.reverseDN(issuerDN);
        assertNotEquals("Reverting DN should produce a different result.", issuerDN, revertedIssuerDN);
        ocspConfiguration.setOcspDefaultResponderReference(revertedIssuerDN);
        globalConfigurationSession.saveConfiguration(authenticationToken, ocspConfiguration);
        ocspResponseGeneratorTestSession.reloadOcspSigningCache();
        super.test05OcspUnknownCA();
        ocspConfiguration.setOcspDefaultResponderReference("CN=error");
        globalConfigurationSession.saveConfiguration(authenticationToken, ocspConfiguration);
        ocspResponseGeneratorTestSession.reloadOcspSigningCache();
        testOcspUnauthorized();
    }

    private void testOcspUnauthorized() throws Exception { // NOPMD, this is not a test class itself
        log.trace(">testocspInternalError()");
        loadUserCert(this.caid);
        // An OCSP request for a certificate from an unknwon CA
        this.helper.verifyResponseUnauthorized(this.caid, this.unknowncacert, new BigInteger("1"));
        log.trace("<testocspInternalError()");
    }
    
    @Test
    public void test06OcspSendWrongContentType() throws Exception {
        super.test06OcspSendWrongContentType();
    }

    @Test
    public void test10MultipleRequests() throws Exception {
        super.test10MultipleRequests();
    }

    @Test
    public void test11MalformedRequest() throws Exception {
        super.test11MalformedRequest();
    }

    @Test
    public void test12CorruptRequests() throws Exception {
        super.test12CorruptRequests();
    }

    /**
     * Just verify that a both escaped and non-encoded GET requests work.
     */
    @Test
    public void test13GetRequests() throws Exception {
        super.test13GetRequests();
        // See if the OCSP Servlet can also read escaped requests
        final String urlEncReq = httpReqPath
                + '/'
                + resourceOcsp
                + '/'
                + "MGwwajBFMEMwQTAJBgUrDgMCGgUABBRBRfilzPB%2BAevx0i1AoeKTkrHgLgQUFJw5gwk9BaEgsX3pzsRF9iso29ICCCzdx5N0v9XwoiEwHzAdBgkrBgEFBQcwAQIEECrZswo%2Fa7YW%2Bhyi5Sn85fs%3D";
        URL url = new URL(urlEncReq);
        log.info(url.toString()); // Dump the exact string we use for access
        HttpURLConnection con = (HttpURLConnection) url.openConnection();
        assertEquals(
                "Response code did not match. (Make sure you allow encoded slashes in your appserver.. add -Dorg.apache.tomcat.util.buf.UDecoder.ALLOW_ENCODED_SLASH=true in Tomcat)",
                200, con.getResponseCode());
        assertNotNull(con.getContentType());
        assertTrue(con.getContentType().startsWith("application/ocsp-response"));
        OCSPResp response = new OCSPResp(IOUtils.toByteArray(con.getInputStream()));
        assertNotNull("Response should not be null.", response);
        assertTrue("Should not be concidered malformed.", OCSPRespBuilder.MALFORMED_REQUEST != response.getStatus());
        final String dubbleSlashEncReq = httpReqPath
                + '/'
                + resourceOcsp
                + '/'
                + "MGwwajBFMEMwQTAJBgUrDgMCGgUABBRBRfilzPB%2BAevx0i1AoeKTkrHgLgQUFJw5gwk9BaEgsX3pzsRF9iso29ICCAvB%2F%2FHJyKqpoiEwHzAdBgkrBgEFBQcwAQIEEOTzT2gv3JpVva22Vj8cuKo%3D";
        url = new URL(dubbleSlashEncReq);
        log.info(url.toString()); // Dump the exact string we use for access
        con = (HttpURLConnection) url.openConnection();
        assertEquals("Response code did not match. ", 200, con.getResponseCode());
        assertNotNull(con.getContentType());
        assertTrue(con.getContentType().startsWith("application/ocsp-response"));
        response = new OCSPResp(IOUtils.toByteArray(con.getInputStream()));
        assertNotNull("Response should not be null.", response);
        assertTrue("Should not be concidered malformed.", OCSPRespBuilder.MALFORMED_REQUEST != response.getStatus());
    }

    @Test
    public void test14CorruptGetRequests() throws Exception {
        super.test14CorruptGetRequests();
    }

    @Test
    public void test15MultipleGetRequests() throws Exception {
        super.test15MultipleGetRequests();
    }

    /** Verify the RFC5019 headers of a successful GET request with untilNextUpdate and maxAge. */
    @Test
    public void test17VerifyHttpGetHeaders() throws Exception {
        GlobalOcspConfiguration globalOcspConfiguration = (GlobalOcspConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
        final long oldConfigurationValue1 = globalOcspConfiguration.getDefaultValidityTime();
        final long oldConfigurationValue2 = globalOcspConfiguration.getDefaultResponseMaxAge();
        globalOcspConfiguration.setDefaultValidityTime(5L);
        globalOcspConfiguration.setDefaultResponseMaxAge(30L);
        globalOcspConfiguration.setUseMaxValidityForExpiration(false);
        globalConfigurationSession.saveConfiguration(authenticationToken, globalOcspConfiguration);
        
        
        
        // Make sure that we run the test with a CA where this is no OcspKeyBinding
        OcspTestUtils.setInternalKeyBindingStatus(authenticationToken, internalKeyBindingId, InternalKeyBindingStatus.DISABLED);
        ocspResponseGeneratorTestSession.reloadOcspSigningCache();
        try {
            testVerifyHttpGetHeaders(caCertificate, ocspSigningCertificate);
            // Test with expires/nextUpdate after ocsp signing certificate expire date (value is set in seconds)
            long expires = (ocspSigningCertificate.getNotAfter().getTime() - System.currentTimeMillis() + 10000) / 1000; 
            globalOcspConfiguration.setDefaultValidityTime(expires);
            globalConfigurationSession.saveConfiguration(authenticationToken, globalOcspConfiguration);
            testVerifyHttpGetHeaders(caCertificate, ocspSigningCertificate);
        } finally {
            globalOcspConfiguration.setDefaultValidityTime(oldConfigurationValue1);
            globalOcspConfiguration.setDefaultValidityTime(oldConfigurationValue2);
            globalConfigurationSession.saveConfiguration(authenticationToken, globalOcspConfiguration);
            OcspTestUtils.setInternalKeyBindingStatus(authenticationToken, internalKeyBindingId, InternalKeyBindingStatus.ACTIVE);
        }
    }

    @Test
    public void test17VerifyHttpGetHeadersOcspKeyBinding() throws Exception {
        final long oldValue1 = OcspTestUtils.setOcspKeyBindingUntilNextUpdate(authenticationToken, internalKeyBindingId, 5L);
        final long oldValue2 = OcspTestUtils.setOcspKeyBindingMaxAge(authenticationToken, internalKeyBindingId, 30L);
        GlobalOcspConfiguration globalOcspConfiguration = (GlobalOcspConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
        globalOcspConfiguration.setUseMaxValidityForExpiration(false);
        globalConfigurationSession.saveConfiguration(authenticationToken, globalOcspConfiguration);
        try {
            ocspResponseGeneratorTestSession.reloadOcspSigningCache();
            testVerifyHttpGetHeaders(caCertificate, ocspSigningCertificate);
        } finally {
            OcspTestUtils.setOcspKeyBindingUntilNextUpdate(authenticationToken, internalKeyBindingId, oldValue1);
            OcspTestUtils.setOcspKeyBindingMaxAge(authenticationToken, internalKeyBindingId, oldValue2);
        }
    }

    private void testVerifyHttpGetHeaders(X509Certificate caCertificate, X509Certificate ocspSigningCertificate) throws Exception {
        BigInteger serialNumber = ocspSigningCertificate.getSerialNumber();
        // An OCSP request, ocspTestCert is already created in earlier tests
        OCSPReqBuilder gen = new OCSPReqBuilder();
        gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), caCertificate, serialNumber));
        OCSPReq req = gen.build();
        String reqString = new String(Base64.encode(req.getEncoded(), false));
        URL url = new URL(httpReqPath + '/' + resourceOcsp + '/' + URLEncoder.encode(reqString, "UTF-8"));
        log.debug("OCSP Request: " + url.toExternalForm());
        HttpURLConnection con = (HttpURLConnection) url.openConnection();
        assertEquals("Response code did not match. (Make sure you allow encoded slashes in your appserver.. add -Dorg.apache.tomcat.util.buf.UDecoder.ALLOW_ENCODED_SLASH=true in Tomcat)", 200, con.getResponseCode());
        // Some appserver (Weblogic) responds with
        // "application/ocsp-response; charset=UTF-8"
        assertNotNull(con.getContentType());
        assertTrue(con.getContentType().startsWith("application/ocsp-response"));
        OCSPResp response = new OCSPResp(IOUtils.toByteArray(con.getInputStream()));
        assertEquals("Response status not the expected.", OCSPRespBuilder.SUCCESSFUL, response.getStatus());
        BasicOCSPResp brep = (BasicOCSPResp) response.getResponseObject();
        // Just output the headers to stdout so we can visually inspect them if
        // something goes wrong
        Set<String> keys = con.getHeaderFields().keySet();
        for (String field : keys) {
            List<String> values = con.getHeaderFields().get(field);
            for (String value : values) {
                log.info(field + ": " + value);
            }
        }
        String eTag = con.getHeaderField("ETag");
        assertNotNull("RFC 5019 6.2: No 'ETag' HTTP header present as it SHOULD. (Make sure ocsp.untilNextUpdate and ocsp.maxAge are configured for this test)",
                eTag);
        assertTrue("ETag is messed up.",
                ("\"" + new String(Hex.encode(MessageDigest.getInstance("SHA-1", "BC").digest(response.getEncoded()))) + "\"").equals(eTag));
        long date = con.getHeaderFieldDate("Date", -1);
        assertTrue("RFC 5019 6.2: No 'Date' HTTP header present as it SHOULD.", date != -1);
        long lastModified = con.getHeaderFieldDate("Last-Modified", -1);
        assertTrue("RFC 5019 6.2: No 'Last-Modified' HTTP header present as it SHOULD.", lastModified != -1);
        // assertTrue("Last-Modified is after response was sent",
        // lastModified<=date); This will not hold on JBoss AS due to the
        // caching of the Date-header
        long expires = con.getExpiration();
        assertTrue("Expires is before response was sent", expires >= date);
        assertTrue("RFC 5019 6.2: No 'Expires' HTTP header present as it SHOULD.", expires != 0);
        // Expires should always be lower than ocsp signing certificate notAfter
        assertTrue("Expires is after signing certificate notAfter: "+expires+", "+ocspSigningCertificate.getNotAfter().getTime(), expires <= ocspSigningCertificate.getNotAfter().getTime());
        String cacheControl = con.getHeaderField("Cache-Control");
        assertNotNull("RFC 5019 6.2: No 'Cache-Control' HTTP header present as it SHOULD.", cacheControl);
        assertTrue("RFC 5019 6.2: No 'public' HTTP header Cache-Control present as it SHOULD.", cacheControl.contains("public"));
        assertTrue("RFC 5019 6.2: No 'no-transform' HTTP header Cache-Control present as it SHOULD.", cacheControl.contains("no-transform"));
        assertTrue("RFC 5019 6.2: No 'must-revalidate' HTTP header Cache-Control present as it SHOULD.", cacheControl.contains("must-revalidate"));
        Matcher matcher = Pattern.compile(".*max-age\\s*=\\s*(\\d+).*").matcher(cacheControl);
        assertTrue("RFC 5019 6.2: No 'max-age' HTTP header Cache-Control present as it SHOULD.", matcher.matches());
        int maxAge = Integer.parseInt(matcher.group(1));
        log.debug("maxAge="+maxAge + " (expires-lastModified)/1000=" + ((expires - lastModified) / 1000));
        assertTrue("thisUpdate and nextUpdate should not be the same (Make sure untilNextUpdate and maxAge are configured in OcspGlobalConfiguration for this test)",
                expires != lastModified);
        assertTrue("RFC 5019 6.2: [maxAge] SHOULD be 'later than thisUpdate but earlier than nextUpdate'.", maxAge < (expires - lastModified) / 1000);
        // assertTrue("Response cannot be produced after it was sent.",
        // brep.getProducedAt().getTime() <= date); This might not hold on JBoss
        // AS due to the caching of the Date-header
        X509CertificateHolder[] chain = brep.getCerts();
        boolean verify = brep.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build(chain[0]));
        assertTrue("Response failed to verify.", verify);
        assertNull("No nonce should be present.", brep.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce));
        SingleResp[] singleResps = brep.getResponses();
        assertNotNull("SingleResps should not be null.", singleResps);
        assertEquals("Expected a single SingleResp in the repsonse.", 1, singleResps.length);
        assertEquals("Serno in response does not match serno in request.", singleResps[0].getCertID().getSerialNumber(), serialNumber);
        assertEquals("Status is not null (null is 'good')", singleResps[0].getCertStatus(), null);
        assertEquals("RFC 5019 6.2: Last-Modified SHOULD 'be the same as the thisUpdate timestamp in the request itself'", lastModified, singleResps[0]
                .getThisUpdate().getTime());
        assertEquals("RFC 5019 6.2: Expires SHOULD 'be the same as the nextUpdate timestamp in the request itself'", expires, singleResps[0].getNextUpdate()
                .getTime());
        assertTrue("Response cannot be produced before it was last modified..", brep.getProducedAt().getTime() >= singleResps[0].getThisUpdate()
                .getTime());
    }

    /** Verify the response of a successful GET request with untilNextUpdate and maxAge. */
    @Test
    public void test18NextUpdateThisUpdate() throws Exception {
        GlobalOcspConfiguration globalOcspConfiguration = (GlobalOcspConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
        final long oldConfigurationValue1 = globalOcspConfiguration.getDefaultValidityTime();
        final long oldConfigurationValue2 = globalOcspConfiguration.getDefaultResponseMaxAge();
        globalOcspConfiguration.setDefaultValidityTime(5L);
        globalOcspConfiguration.setDefaultResponseMaxAge(30L);
        globalConfigurationSession.saveConfiguration(authenticationToken, globalOcspConfiguration);
        // Make sure that we run the test with a CA where this is no OcspKeyBinding
        OcspTestUtils.setInternalKeyBindingStatus(authenticationToken, internalKeyBindingId, InternalKeyBindingStatus.DISABLED);
        ocspResponseGeneratorTestSession.reloadOcspSigningCache();
        try {
            testNextUpdateThisUpdate(caCertificate, ocspSigningCertificate.getSerialNumber());
        } finally {
            globalOcspConfiguration.setDefaultValidityTime(oldConfigurationValue1);
            globalOcspConfiguration.setDefaultResponseMaxAge(oldConfigurationValue2);
            globalConfigurationSession.saveConfiguration(authenticationToken, globalOcspConfiguration);
            OcspTestUtils.setInternalKeyBindingStatus(authenticationToken, internalKeyBindingId, InternalKeyBindingStatus.ACTIVE);
        }
    }

    @Test
    public void test18NextUpdateThisUpdateOcspKeyBinding() throws Exception {
        final long oldValue = OcspTestUtils.setOcspKeyBindingUntilNextUpdate(authenticationToken, internalKeyBindingId, 5L);
        try {
            ocspResponseGeneratorTestSession.reloadOcspSigningCache();
            testNextUpdateThisUpdate(caCertificate, ocspSigningCertificate.getSerialNumber());
        } finally {
            OcspTestUtils.setOcspKeyBindingUntilNextUpdate(authenticationToken, internalKeyBindingId, oldValue);
        }
    }

    private void testNextUpdateThisUpdate(X509Certificate caCertificate, BigInteger serialNumber) throws Exception {
        // And an OCSP request
        OCSPReqBuilder gen = new OCSPReqBuilder();
        gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), caCertificate, serialNumber));
        OCSPReq req = gen.build();
        // POST the request and receive a singleResponse
        URL url = new URL(httpReqPath + '/' + resourceOcsp);
        HttpURLConnection con = (HttpURLConnection) url.openConnection();
        con.setDoOutput(true);
        con.setRequestMethod("POST");
        con.setRequestProperty("Content-Type", "application/ocsp-request");
        OutputStream os = con.getOutputStream();
        os.write(req.getEncoded());
        os.close();
        assertEquals("Response code", 200, con.getResponseCode());
        // Some appserver (Weblogic) responds with
        // "application/ocsp-response; charset=UTF-8"
        assertNotNull(con.getContentType());
        assertTrue(con.getContentType().startsWith("application/ocsp-response"));
        OCSPResp response = new OCSPResp(IOUtils.toByteArray(con.getInputStream()));
        assertEquals("Response status not the expected.", 0, response.getStatus());
        BasicOCSPResp brep = (BasicOCSPResp) response.getResponseObject();
        X509CertificateHolder[] chain = brep.getCerts();
        boolean verify = brep.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build(chain[0]));
        assertTrue("Response failed to verify.", verify);
        SingleResp[] singleResps = brep.getResponses();
        assertEquals("No of SingResps should be 1.", 1, singleResps.length);
        CertificateID certId = singleResps[0].getCertID();
        assertEquals("Serno in response does not match serno in request.", certId.getSerialNumber(), serialNumber);
        assertNull("Status is not null.", singleResps[0].getCertStatus());
        Date thisUpdate = singleResps[0].getThisUpdate();
        Date nextUpdate = singleResps[0].getNextUpdate();
        Date producedAt = brep.getProducedAt();
        assertNotNull("thisUpdate was not set.", thisUpdate);
        assertNotNull("nextUpdate was not set. (This test requires ocsp.untilNextUpdate to be configured.)", nextUpdate);
        assertNotNull("producedAt was not set.", producedAt);
        assertTrue("nextUpdate cannot be before thisUpdate.", !nextUpdate.before(thisUpdate));
        assertTrue("producedAt cannot be before thisUpdate.", !producedAt.before(thisUpdate));
    }
    
    public static X509Certificate createCaCertificate(AuthenticationToken authenticationToken, Certificate certificate) throws CreateException, AuthorizationDeniedException {
        final CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE
                .getRemoteSession(CertificateStoreSessionRemote.class);
        X509Certificate caCertificate = (X509Certificate) certificate;
        //Store the CA Certificate.
        certificateStoreSession.storeCertificateRemote(authenticationToken, EJBTools.wrap(caCertificate), "foo", "1234", CertificateConstants.CERT_ACTIVE,
                CertificateConstants.CERTTYPE_ROOTCA, CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, EndEntityConstants.NO_END_ENTITY_PROFILE,
                CertificateConstants.NO_CRL_PARTITION, "footag", new Date().getTime(), null);
        return caCertificate;
    }

}
