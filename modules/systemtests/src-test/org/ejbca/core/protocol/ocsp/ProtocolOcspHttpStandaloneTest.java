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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLEncoder;
import java.security.MessageDigest;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
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
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.certificates.ocsp.SHA1DigestCalculator;
import org.cesecore.certificates.ocsp.cache.CryptoTokenAndChain;
import org.cesecore.certificates.ocsp.standalone.StandaloneOcspResponseGeneratorTestSessionRemote;
import org.cesecore.config.OcspConfiguration;
import org.cesecore.configuration.CesecoreConfigurationProxySessionRemote;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.EjbRemoteHelper;
import org.junit.Before;
import org.junit.Test;

/**
 * Tests HTTP pages of a stand-alone OCSP To run this test you must create a
 * user named ocspTest that has at least two certificates and at least one of
 * them must be revoked.
 * 
 * Change the address 127.0.0.1 to where you stand-alone OCSP server is running.
 * Change myCaId to the CA that ocspTest belongs to
 **/
public class ProtocolOcspHttpStandaloneTest extends ProtocolOcspTestBase {

    private static final Logger log = Logger.getLogger(ProtocolOcspHttpStandaloneTest.class);
    
    private CesecoreConfigurationProxySessionRemote configurationSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CesecoreConfigurationProxySessionRemote.class);
    private StandaloneOcspResponseGeneratorTestSessionRemote standaloneOcspResponseGeneratorTestSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(StandaloneOcspResponseGeneratorTestSessionRemote.class);

   public ProtocolOcspHttpStandaloneTest() throws MalformedURLException, URISyntaxException {
    	super("http", "127.0.0.1", 8080, "ejbca", "publicweb/status/ocsp");
    }
    // Required to override check in baseclass
    @Before
    public void setUp() throws Exception {
        //super.setUp(); We don't want to initialize roles etc, since this is a standalone test!
        
        // We are not using the same testCA set in ProtocolOcspTestBase.java because this will cause this test to fail.
        // This could possibly be due to the fact that the OCSP system tests and the OCSP standalone tests create 
        // a new testCA (The standalone tests does that through 'ant runocsp.setuptest') and a conflict occurs when
        // both tests try to create the same testCA twice. 
        issuerDN = "CN=OcspDefaultTestCA";
        caid = issuerDN.hashCode();
        unknowncacert = (X509Certificate) CertTools.getCertfromByteArray(unknowncacertBytes);
    }
    
    @Test
    public void test01Access() throws Exception {
        super.test01Access();
    }

    /**
     * Tests ocsp message
     * 
     * @throws Exception
     *             error
     */
    @Test
    public void test02OcspGood() throws Exception {
        log.trace(">test02OcspGood()");
        @SuppressWarnings("unused")
        String subjectDnCA = CertTools.getSubjectDN(unknowncacert);
        // And an OCSP request
        OCSPReqBuilder gen = new OCSPReqBuilder();
        final X509Certificate ocspTestCert = getTestCert(false);
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
        log.trace("<test02OcspGood()");
    }

    /**
     * Tests ocsp message
     * 
     * @throws Exception
     *             error
     */
    @Test
    public void test03OcspRevoked() throws Exception {
        log.trace(">test03OcspRevoked()");
        final X509Certificate ocspTestCert = getTestCert(true);
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
        assertTrue("Status is not RevokedStatus", status instanceof RevokedStatus);
        RevokedStatus rev = (RevokedStatus) status;
        assertTrue("Status does not have reason", rev.hasRevocationReason());
        log.trace("<test03OcspRevoked()");
    }

    @Test
    public void test04OcspUnknown() throws Exception {
        log.trace(">test04OcspUnknown()");
        loadUserCert(caid);
        super.test04OcspUnknown();
    }

    @Test
    public void test05OcspUnknownCA() throws Exception {
        log.trace(">test05OcspUnknownCA()");
        super.test05OcspUnknownCA();
    }

    @Test
    public void test06OcspSendWrongContentType() throws Exception {
        log.trace(">test06OcspSendWrongContentType()");
        super.test06OcspSendWrongContentType();
    }

    @Test
    public void test10MultipleRequests() throws Exception {
        log.trace(">test10MultipleRequests()");
        super.test10MultipleRequests();
    }

    @Test
    public void test11MalformedRequest() throws Exception {
        log.trace(">test11MalformedRequest()");
        super.test11MalformedRequest();
    }

    @Test
    public void test12CorruptRequests() throws Exception {
        log.trace(">test12CorruptRequests()");
        super.test12CorruptRequests();
    }

    /**
     * Just verify that a both escaped and non-encoded GET requests work.
     */
    @Test
    public void test13GetRequests() throws Exception {
        log.trace(">test13GetRequests()");
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
        log.trace(">test14CorruptGetRequests()");
        super.test14CorruptGetRequests();
    }

    @Test
    public void test15MultipleGetRequests() throws Exception {
        log.trace(">test15MultipleGetRequests()");
        super.test15MultipleGetRequests();
    }

    /**
     * Verify the headers of a successful GET request. ocsp.untilNextUpdate has
     * to be configured for this test.
     */
    @Test
    public void test17VerifyHttpGetHeaders() throws Exception {
        log.error(">test17VerifyHttpGetHeaders()");
        loadUserCert(caid);
        // An OCSP request, ocspTestCert is already created in earlier tests
        OCSPReqBuilder gen = new OCSPReqBuilder();
        gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), cacert, ocspTestCert.getSerialNumber()));
        OCSPReq req = gen.build();
        String reqString = new String(Base64.encode(req.getEncoded(), false));
        URL url = new URL(httpReqPath + '/' + resourceOcsp + '/' + URLEncoder.encode(reqString, "UTF-8"));
        HttpURLConnection con = (HttpURLConnection) url.openConnection();
        assertEquals("Response code did not match. ", 200, con.getResponseCode());
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
        assertNotNull("RFC 5019 6.2: No 'ETag' HTTP header present as it SHOULD. (Make sure ocsp.untilNextUpdate is configured for this test)", eTag);
        assertTrue("ETag is messed up.", ("\"" + new String(Hex.encode(MessageDigest.getInstance("SHA-1", "BC").digest(response.getEncoded()))) + "\"")
                .equals(eTag));
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
        String cacheControl = con.getHeaderField("Cache-Control");
        assertNotNull("RFC 5019 6.2: No 'Cache-Control' HTTP header present as it SHOULD.", cacheControl);
        assertTrue("RFC 5019 6.2: No 'public' HTTP header Cache-Control present as it SHOULD.", cacheControl.contains("public"));
        assertTrue("RFC 5019 6.2: No 'no-transform' HTTP header Cache-Control present as it SHOULD.", cacheControl.contains("no-transform"));
        assertTrue("RFC 5019 6.2: No 'must-revalidate' HTTP header Cache-Control present as it SHOULD.", cacheControl.contains("must-revalidate"));
        Matcher matcher = Pattern.compile(".*max-age\\s*=\\s*(\\d+).*").matcher(cacheControl);
        assertTrue("RFC 5019 6.2: No 'max-age' HTTP header Cache-Control present as it SHOULD.", matcher.matches());
        int maxAge = Integer.parseInt(matcher.group(1));
        assertTrue("RFC 5019 6.2: SHOULD be 'later than thisUpdate but earlier than nextUpdate'.", maxAge < (expires - lastModified) / 1000);
        // assertTrue("Response cannot be produced after it was sent.",
        // brep.getProducedAt().getTime() <= date); This might not hold on JBoss
        // AS due to the caching of the Date-header
        X509CertificateHolder[] chain = brep.getCerts();
        boolean verify = brep.isSignatureValid(new JcaContentVerifierProviderBuilder().build(chain[0]));
        assertTrue("Response failed to verify.", verify);
        assertNull("No nonce should be present.", brep.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce));
        SingleResp[] singleResps = brep.getResponses();
        assertNotNull("SingleResps should not be null.", singleResps);
        assertTrue("Expected a single SingleResp in the repsonse.", singleResps.length == 1);
        assertEquals("Serno in response does not match serno in request.", singleResps[0].getCertID().getSerialNumber(), ocspTestCert.getSerialNumber());
        assertEquals("Status is not null (null is 'good')", singleResps[0].getCertStatus(), null);
        assertTrue("RFC 5019 6.2: Last-Modified SHOULD 'be the same as the thisUpdate timestamp in the request itself'", singleResps[0].getThisUpdate()
                .getTime() == lastModified);
        assertTrue("RFC 5019 6.2: Expires SHOULD 'be the same as the nextUpdate timestamp in the request itself'",
                singleResps[0].getNextUpdate().getTime() == expires);
        assertTrue("Response cannot be produced before it was last modified..", brep.getProducedAt().getTime() >= singleResps[0].getThisUpdate().getTime());
    }

    /**
     * Tests nextUpdate and thisUpdate ocsp.untilNextUpdate has to be configured
     * for this test.
     */
    @Test
    public void test18NextUpdateThisUpdate() throws Exception {
        log.trace(">test18NextUpdateThisUpdate()");
        loadUserCert(caid);
        // And an OCSP request
        OCSPReqBuilder gen = new OCSPReqBuilder();
        gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), cacert, ocspTestCert.getSerialNumber()));
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
        boolean verify = brep.isSignatureValid(new JcaContentVerifierProviderBuilder().build(chain[0]));
        assertTrue("Response failed to verify.", verify);
        SingleResp[] singleResps = brep.getResponses();
        assertEquals("No of SingResps should be 1.", 1, singleResps.length);
        CertificateID certId = singleResps[0].getCertID();
        assertEquals("Serno in response does not match serno in request.", certId.getSerialNumber(), ocspTestCert.getSerialNumber());
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
    
    @Test
    public void testKeyRenewal() throws Exception {
        //Add localhost to list of rekeying triggering hosts.
        Set<String> originalHosts = OcspConfiguration.getRekeyingTriggingHosts();
        String originalRekeyingPassword = OcspConfiguration.getRekeyingTriggingPassword();
        configurationSession.setConfigurationValue(OcspConfiguration.REKEYING_TRIGGERING_HOSTS, "127.0.0.1");
        configurationSession.setConfigurationValue(OcspConfiguration.REKEYING_TRIGGERING_PASSWORD, "foo123");
        Collection<CryptoTokenAndChain> oldValues = standaloneOcspResponseGeneratorTestSession.getCacheValues();
        try {
            X509Certificate cert = getTestCert(false);
            X509Certificate caCertificate = getCaCert(cert);

            helper.renewAllKeys();
            List<CryptoTokenAndChain> newValues = new ArrayList<CryptoTokenAndChain>(standaloneOcspResponseGeneratorTestSession.getCacheValues());
            //Make sure that cache contains one and only one value
            assertEquals("Cache contains a different amount of values after rekeying than before. This indicates a test failure", oldValues.size(),
                    newValues.size());
            //Make check that the certificate has changed (sanity check)
            X509Certificate newSigningCertificate = newValues.get(0).getChain()[0];
            assertNotEquals("The same certificate was returned after the renewal process. Key renewal failed", cert.getSerialNumber(),
                    newSigningCertificate.getSerialNumber());
            //Make sure that the new certificate is signed by the CA certificate
            try {
                newSigningCertificate.verify(caCertificate.getPublicKey());
            } catch (SignatureException e) {
                fail("The new signing certificate was not signed correctly.");
            }

        } finally {
            StringBuilder originalHostsString = new StringBuilder();
            for (String host : originalHosts.toArray(new String[originalHosts.size()])) {
                originalHostsString.append(host + ";");
            }
            configurationSession.setConfigurationValue(OcspConfiguration.REKEYING_TRIGGERING_HOSTS, originalHostsString.toString());
            configurationSession.setConfigurationValue(OcspConfiguration.REKEYING_TRIGGERING_PASSWORD, originalRekeyingPassword);
        }
    }

}
