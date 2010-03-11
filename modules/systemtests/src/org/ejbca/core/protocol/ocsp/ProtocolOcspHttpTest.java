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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.Socket;
import java.net.URL;
import java.rmi.RemoteException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Hashtable;

import javax.ejb.DuplicateKeyException;
import javax.ejb.ObjectNotFoundException;

import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTags;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.provider.JCEECPublicKey;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.CertificateID;
import org.bouncycastle.ocsp.CertificateStatus;
import org.bouncycastle.ocsp.OCSPReq;
import org.bouncycastle.ocsp.OCSPReqGenerator;
import org.bouncycastle.ocsp.OCSPResp;
import org.bouncycastle.ocsp.OCSPRespGenerator;
import org.bouncycastle.ocsp.RevokedStatus;
import org.bouncycastle.ocsp.SingleResp;
import org.bouncycastle.ocsp.UnknownStatus;
import org.ejbca.core.model.AlgorithmConstants;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.ca.AuthStatusException;
import org.ejbca.core.model.ca.IllegalKeyException;
import org.ejbca.core.model.ca.SignRequestException;
import org.ejbca.core.model.ca.SignRequestSignatureException;
import org.ejbca.core.model.ca.caadmin.CADoesntExistsException;
import org.ejbca.core.model.ca.caadmin.CAExistsException;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.caadmin.X509CAInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.OCSPCAServiceInfo;
import org.ejbca.core.model.ca.catoken.SoftCATokenInfo;
import org.ejbca.core.model.ca.certificateprofiles.CertificatePolicy;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.ejbca.ui.web.LimitLengthASN1Reader;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.ejbca.util.CryptoProviderTools;
import org.ejbca.util.TestTools;
import org.ejbca.util.keystore.KeyTools;

import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.WebConnection;
import com.gargoylesoftware.htmlunit.WebRequestSettings;
import com.gargoylesoftware.htmlunit.WebResponse;

/** Tests http pages of ocsp
 **/
public class ProtocolOcspHttpTest extends TestCase {
    private static Logger log = Logger.getLogger(ProtocolOcspHttpTest.class);

    protected final String httpReqPath;
    protected final String resourceOcsp;

    protected static byte[] unknowncacertBytes = Base64.decode(("MIICLDCCAZWgAwIBAgIIbzEhUVZYO3gwDQYJKoZIhvcNAQEFBQAwLzEPMA0GA1UE" +
            "AxMGVGVzdENBMQ8wDQYDVQQKEwZBbmFUb20xCzAJBgNVBAYTAlNFMB4XDTAyMDcw" +
            "OTEyNDc1OFoXDTA0MDgxNTEyNTc1OFowLzEPMA0GA1UEAxMGVGVzdENBMQ8wDQYD" +
            "VQQKEwZBbmFUb20xCzAJBgNVBAYTAlNFMIGdMA0GCSqGSIb3DQEBAQUAA4GLADCB" +
            "hwKBgQDZlACHRwJnQKlgpMqlZQmxvCrJPpPFyhxvjDHlryhp/AQ6GCm+IkGUVlwL" +
            "sCnjgZH5BXDNaVXpkmME8334HFsxVlXqmZ2GqyP6kptMjbWZ2SRLBRKjAcI7EJIN" +
            "FPDIep9ZHXw1JDjFGoJ4TLFd99w9rQ3cB6zixORoyCZMw+iebwIBEaNTMFEwDwYD" +
            "VR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUY3v0dqhUJI6ldKV3RKb0Xg9XklEwHwYD" +
            "VR0jBBgwFoAUY3v0dqhUJI6ldKV3RKb0Xg9XklEwDQYJKoZIhvcNAQEFBQADgYEA" +
            "i1P53jnSPLkyqm7i3nLNi+hG7rMgF+kRi6ZLKhzIPyKcAWV8iZCI8xl/GurbZ8zd" +
            "nTiIOfQIP9eD/nhIIo7n4JOaTUeqgyafPsEgKdTiZfSdXjvy6rj5GiZ3DaGZ9SNK" +
            "FgrCpX5kBKVbbQLO6TjJKCjX29CfoJ2TbP1QQ6UbBAY=").getBytes());

    protected static int caid = TestTools.getTestCAId();
    protected static final Admin admin = new Admin(Admin.TYPE_BATCHCOMMANDLINE_USER);
    protected static X509Certificate cacert = null;
    protected static X509Certificate ocspTestCert = null;
    private static X509Certificate unknowncacert = null;

    protected OcspJunitHelper helper = null;

    public static void main(String args[]) {
        junit.textui.TestRunner.run(suite());
    }

    public static TestSuite suite() {
        return new TestSuite(ProtocolOcspHttpTest.class);
    }

    public ProtocolOcspHttpTest(String name) throws Exception {
        this(name,"http://127.0.0.1:8080/ejbca", "publicweb/status/ocsp");
    }

    protected  ProtocolOcspHttpTest(String name, String reqP, String res) throws Exception {
        super(name);
        httpReqPath = reqP;
        resourceOcsp = res;
        helper = new OcspJunitHelper(reqP, res); 
        // Install BouncyCastle provider
        CryptoProviderTools.installBCProvider();
        unknowncacert = (X509Certificate)CertTools.getCertfromByteArray(unknowncacertBytes);
    }

    protected void setUp() throws Exception {
    }

    protected void tearDown() throws Exception {
    }

    public void test00Setup() throws Exception {
    	assertTrue("This test can only be run on a full EJBCA installation.", ((HttpURLConnection) new URL(httpReqPath + '/').openConnection()).getResponseCode() == 200);
        assertTrue("Failed to create test CA.", TestTools.createTestCA());
        cacert = (X509Certificate) TestTools.getTestCACert();
    }
    
    public void test01Access() throws Exception {
        // Hit with GET does work since EJBCA 3.8.2
        final WebClient webClient = new WebClient();
        WebConnection con = webClient.getWebConnection();
        WebRequestSettings settings = new WebRequestSettings(new URL(httpReqPath + '/' + resourceOcsp));
        WebResponse resp = con.getResponse(settings);
        assertEquals( "Response code", 200, resp.getStatusCode() );
    }

    /** Tests ocsp message
     * @throws Exception error
     */
    public void test02OcspGood() throws Exception {
        log.trace(">test02OcspGood()");

        // find a CA (TestCA?) create a user and generate his cert
        // send OCSP req to server and get good response
        // change status of cert to bad status
        // send OCSP req and get bad status
        // (send crap message and get good error)

        // Get user and ocspTestCert that we know...
        loadUserCert(caid);

        // And an OCSP request
        OCSPReqGenerator gen = new OCSPReqGenerator();
        gen.addRequest(new CertificateID(CertificateID.HASH_SHA1, cacert, ocspTestCert.getSerialNumber()));
        log.debug("ocspTestCert.getSerialNumber() = " + ocspTestCert.getSerialNumber());
        Hashtable exts = new Hashtable();
        X509Extension ext = new X509Extension(false, new DEROctetString("123456789".getBytes()));
        exts.put(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, ext);
        gen.setRequestExtensions(new X509Extensions(exts));
        OCSPReq req = gen.generate();

        // Send the request and receive a singleResponse
        SingleResp[] singleResps = helper.sendOCSPPost(req.getEncoded(), "123456789", 0, 200);
        assertEquals("No of SingleResps should be 1.", 1, singleResps.length);
        SingleResp singleResp = singleResps[0];

        CertificateID certId = singleResp.getCertID();
        assertEquals("Serno in response does not match serno in request.", certId.getSerialNumber(), ocspTestCert.getSerialNumber());
        Object status = singleResp.getCertStatus();
        if (status != CertificateStatus.GOOD) {
        	log.debug("Certificate status: " + status.getClass().getName());
        }
        assertEquals("Status is not null (good)", null, status);
        log.trace("<test02OcspGood()");
    }

    /** Tests ocsp message
     * @throws Exception error
     */
    public void test03OcspRevoked() throws Exception {
        log.trace(">test03OcspRevoked()");
        // Now revoke the certificate and try again
        TestTools.getCertificateStoreSession().revokeCertificate(admin, ocspTestCert,null,RevokedCertInfo.REVOKATION_REASON_KEYCOMPROMISE, null);
        // And an OCSP request
        OCSPReqGenerator gen = new OCSPReqGenerator();
        gen.addRequest(new CertificateID(CertificateID.HASH_SHA1, cacert, ocspTestCert.getSerialNumber()));
        OCSPReq req = gen.generate();

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
        int reason = rev.getRevocationReason();
        assertEquals("Wrong revocation reason", reason, RevokedCertInfo.REVOKATION_REASON_KEYCOMPROMISE);
        log.trace("<test03OcspRevoked()");
    }

    /** Tests ocsp message
     * @throws Exception error
     */
    public void test04OcspUnknown() throws Exception {
        log.trace(">test04OcspUnknown()");
        // An OCSP request for an unknown certificate (not exist in db)
        OCSPReqGenerator gen = new OCSPReqGenerator();
        gen.addRequest(new CertificateID(CertificateID.HASH_SHA1, cacert, new BigInteger("1")));
        OCSPReq req = gen.generate();
        
        // Send the request and receive a singleResponse
        SingleResp[] singleResps = helper.sendOCSPPost(req.getEncoded(), null, 0, 200);
        assertEquals("No of SingResps should be 1.", 1, singleResps.length);
        SingleResp singleResp = singleResps[0];

        CertificateID certId = singleResp.getCertID();
        assertEquals("Serno in response does not match serno in request.", certId.getSerialNumber(), new BigInteger("1"));
        Object status = singleResp.getCertStatus();
        assertTrue("Status is not Unknown", status instanceof UnknownStatus);

        log.trace("<test04OcspUnknown()");
    }

    /** Tests ocsp message
     * @throws Exception error
     */
    public void test05OcspUnknownCA() throws Exception {
        log.trace(">test05OcspUnknownCA()");
        // An OCSP request for a certificate from an unknwon CA
        OCSPReqGenerator gen = new OCSPReqGenerator();
        gen.addRequest(new CertificateID(CertificateID.HASH_SHA1, unknowncacert, new BigInteger("1")));
        OCSPReq req = gen.generate();
        
        // Send the request and receive a singleResponse
        SingleResp[] singleResps = helper.sendOCSPPost(req.getEncoded(), null, 0, 200);
        assertEquals("No of SingResps should be 1.", 1, singleResps.length);
        SingleResp singleResp = singleResps[0];

        CertificateID certId = singleResp.getCertID();
        assertEquals("Serno in response does not match serno in request.", certId.getSerialNumber(), new BigInteger("1"));
        Object status = singleResp.getCertStatus();
        assertTrue("Status is not Unknown", status instanceof UnknownStatus);

        log.trace("<test05OcspUnknownCA()");
    }
    
    public void test06OcspSendWrongContentType() throws Exception {
        // An OCSP request for a certificate from an unknwon CA
        OCSPReqGenerator gen = new OCSPReqGenerator();
        gen.addRequest(new CertificateID(CertificateID.HASH_SHA1, unknowncacert, new BigInteger("1")));
        OCSPReq req = gen.generate();
        // POST the OCSP request
        URL url = new URL(httpReqPath + '/' + resourceOcsp);
        HttpURLConnection con = (HttpURLConnection)url.openConnection();
        // we are going to do a POST
        con.setDoOutput(true);
        con.setRequestMethod("POST");
        // POST it, but don't add content type
        OutputStream os = con.getOutputStream();
        os.write(req.getEncoded());
        os.close();
        assertEquals("Response code", 400, con.getResponseCode());
        
    }

    public void test07SignedOcsp() throws Exception {
    	assertTrue("This test can only be run on a full EJBCA installation.", ((HttpURLConnection) new URL(httpReqPath + '/').openConnection()).getResponseCode() == 200);

        // find a CA (TestCA?) create a user and generate his cert
        // send OCSP req to server and get good response
        // change status of cert to bad status
        // send OCSP req and get bad status
        // (send crap message and get good error)

        KeyPair keys = createUserCert(caid);

        // And an OCSP request
        OCSPReqGenerator gen = new OCSPReqGenerator();
        gen.addRequest(new CertificateID(CertificateID.HASH_SHA1, cacert, ocspTestCert.getSerialNumber()));
        Hashtable exts = new Hashtable();
        X509Extension ext = new X509Extension(false, new DEROctetString("123456789".getBytes()));
        exts.put(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, ext);
        gen.setRequestExtensions(new X509Extensions(exts));
        X509Certificate chain[] = new X509Certificate[2];
        chain[0] = ocspTestCert;
        chain[1] = cacert;
        gen.setRequestorName(ocspTestCert.getSubjectX500Principal());
        OCSPReq req = gen.generate("SHA1WithRSA", keys.getPrivate(), chain, "BC");

        // First test with a signed OCSP request that can be verified
        Collection cacerts = new ArrayList();
        cacerts.add(cacert);
        CertificateCache certcache = new CertificateCache(cacerts);
        X509Certificate signer = OCSPUtil.checkRequestSignature("127.0.0.1", req, certcache);
        assertNotNull(signer);
        assertEquals(ocspTestCert.getSerialNumber().toString(16), signer.getSerialNumber().toString(16));
        
        // Try with an unsigned request, we should get a SignRequestException
        req = gen.generate();
        boolean caught = false;
        try {
        	signer = OCSPUtil.checkRequestSignature("127.0.0.1", req, certcache);
        } catch (SignRequestException e) {
        	caught = true;
        }
        assertTrue(caught);
        
        // sign with a keystore where the CA-certificate is not known
        KeyStore store = KeyStore.getInstance("PKCS12", "BC");
        ByteArrayInputStream fis = new ByteArrayInputStream(ks3);
        store.load(fis, "foo123".toCharArray());
        Certificate[] certs = KeyTools.getCertChain(store, "privateKey");
        chain[0] = (X509Certificate)certs[0];
        chain[1] = (X509Certificate)certs[1];
        PrivateKey pk = (PrivateKey)store.getKey("privateKey", "foo123".toCharArray());
        req = gen.generate("SHA1WithRSA", pk, chain, "BC");
        // Send the request and receive a singleResponse, this response should throw an SignRequestSignatureException
        caught = false;
        try {
        	signer = OCSPUtil.checkRequestSignature("127.0.0.1", req, certcache);
        } catch (SignRequestSignatureException e) {
        	caught = true;
        }
        assertTrue(caught);

        // sign with a keystore where the signing certificate has expired
        store = KeyStore.getInstance("PKCS12", "BC");
        fis = new ByteArrayInputStream(ksexpired);
        store.load(fis, "foo123".toCharArray());
        certs = KeyTools.getCertChain(store, "ocspclient");
        chain[0] = (X509Certificate)certs[0];
        chain[1] = (X509Certificate)certs[1];
        pk = (PrivateKey)store.getKey("ocspclient", "foo123".toCharArray());
        req = gen.generate("SHA1WithRSA", pk, chain, "BC");
        // Send the request and receive a singleResponse, this response should throw an SignRequestSignatureException
        caught = false;
        try {
        	signer = OCSPUtil.checkRequestSignature("127.0.0.1", req, certcache);
        } catch (SignRequestSignatureException e) {
        	caught = true;
        }
        assertTrue(caught);
        
    } // test07SignedOcsp

    /** Tests ocsp message
     * @throws Exception error
     */
    public void test08OcspEcdsaGood() throws Exception {
    	assertTrue("This test can only be run on a full EJBCA installation.", ((HttpURLConnection) new URL(httpReqPath + '/').openConnection()).getResponseCode() == 200);
    	
        int ecdsacaid = "CN=OCSPECDSATEST".hashCode();
        X509Certificate ecdsacacert = addECDSACA("CN=OCSPECDSATEST", "prime192v1");
        helper.reloadKeys();
        
        // Make user and ocspTestCert that we know...
        createUserCert(ecdsacaid);

        // And an OCSP request
        OCSPReqGenerator gen = new OCSPReqGenerator();
        gen.addRequest(new CertificateID(CertificateID.HASH_SHA1, ecdsacacert, ocspTestCert.getSerialNumber()));
        Hashtable exts = new Hashtable();
        X509Extension ext = new X509Extension(false, new DEROctetString("123456789".getBytes()));
        exts.put(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, ext);
        gen.setRequestExtensions(new X509Extensions(exts));
        OCSPReq req = gen.generate();

        // Send the request and receive a singleResponse
        SingleResp[] singleResps = helper.sendOCSPPost(req.getEncoded(), "123456789", 0, 200);
        assertEquals("No of SingResps should be 1.", 1, singleResps.length);
        SingleResp singleResp = singleResps[0];

        CertificateID certId = singleResp.getCertID();
        assertEquals("Serno in response does not match serno in request.", certId.getSerialNumber(), ocspTestCert.getSerialNumber());
        Object status = singleResp.getCertStatus();
        assertEquals("Status is not null (good)", status, null);
        
    } // test08OcspEcdsaGood

    /** Tests ocsp message
     * @throws Exception error
     */
    public void test09OcspEcdsaImplicitlyCAGood() throws Exception {
    	assertTrue("This test can only be run on a full EJBCA installation.", ((HttpURLConnection) new URL(httpReqPath + '/').openConnection()).getResponseCode() == 200);
    	
        int ecdsacaid = "CN=OCSPECDSAIMPCATEST".hashCode();
        X509Certificate ecdsacacert = addECDSACA("CN=OCSPECDSAIMPCATEST", "implicitlyCA");
        helper.reloadKeys();
        
        // Make user and ocspTestCert that we know...
        createUserCert(ecdsacaid);
        
        // And an OCSP request
        OCSPReqGenerator gen = new OCSPReqGenerator();
        gen.addRequest(new CertificateID(CertificateID.HASH_SHA1, ecdsacacert, ocspTestCert.getSerialNumber()));
        Hashtable exts = new Hashtable();
        X509Extension ext = new X509Extension(false, new DEROctetString("123456789".getBytes()));
        exts.put(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, ext);
        gen.setRequestExtensions(new X509Extensions(exts));
        OCSPReq req = gen.generate();

        // Send the request and receive a singleResponse
        SingleResp[] singleResps = helper.sendOCSPPost(req.getEncoded(), "123456789", 0, 200);
        assertEquals("No of SingResps should be 1.", 1, singleResps.length);
        SingleResp singleResp = singleResps[0];
        
        CertificateID certId = singleResp.getCertID();
        assertEquals("Serno in response does not match serno in request.", certId.getSerialNumber(), ocspTestCert.getSerialNumber());
        Object status = singleResp.getCertStatus();
        assertEquals("Status is not null (good)", status, null);
        
    } // test09OcspEcdsaImplicitlyCAGood

    
    public void test10MultipleRequests() throws Exception {
    	// Tests that we handle multiple requests in one OCSP request message
    	
        // An OCSP request for a certificate from an unknown CA
        OCSPReqGenerator gen = new OCSPReqGenerator();
        gen.addRequest(new CertificateID(CertificateID.HASH_SHA1, unknowncacert, new BigInteger("1")));

        // Get user and ocspTestCert that we know...
        loadUserCert(caid);
        gen.addRequest(new CertificateID(CertificateID.HASH_SHA1, cacert, ocspTestCert.getSerialNumber()));
        Hashtable exts = new Hashtable();
        X509Extension ext = new X509Extension(false, new DEROctetString("123456789".getBytes()));
        exts.put(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, ext);
        gen.setRequestExtensions(new X509Extensions(exts));

        OCSPReq req = gen.generate();
        
        // Send the request and receive a singleResponse
        SingleResp[] singleResps = helper.sendOCSPPost(req.getEncoded(), null, 0, 200);
        assertEquals("No of SingleResps should be 2.", 2, singleResps.length);
        SingleResp singleResp1 = singleResps[0];

        CertificateID certId = singleResp1.getCertID();
        assertEquals("Serno in response does not match serno in request.", certId.getSerialNumber(), new BigInteger("1"));
        Object status = singleResp1.getCertStatus();
        assertTrue("Status is not Unknown", status instanceof UnknownStatus);

        SingleResp singleResp2 = singleResps[1];
        certId = singleResp2.getCertID();
        assertEquals("Serno in response does not match serno in request.", certId.getSerialNumber(), ocspTestCert.getSerialNumber());
        status = singleResp2.getCertStatus();
        assertEquals("Status is not null (good)", status, null);

    }

    /**
     * In compliance with RFC 2560 on "ASN.1 Specification of the OCSP Response": If the value
     * of responseStatus is one of the error conditions, responseBytes are not set.
     *  
     * OCSPResponse ::= SEQUENCE {
     * responseStatus OCSPResponseStatus,
     * responseBytes [0] EXPLICIT ResponseBytes OPTIONAL }
     */
    public void test11MalformedRequest() throws Exception {
        OCSPReqGenerator gen = new OCSPReqGenerator();
        // Add 101 OCSP requests.. the Servlet will consider a request with more than 100 malformed..
        // This does not mean that we only should allow 100 in the future, just that we if so need to find
        // another way make the Servlet return OCSPRespGenerator.MALFORMED_REQUEST
        for (int i=0; i<101; i++) {
            gen.addRequest(new CertificateID(CertificateID.HASH_SHA1, cacert, ocspTestCert.getSerialNumber()));
        }
        Hashtable exts = new Hashtable();
        X509Extension ext = new X509Extension(false, new DEROctetString("123456789".getBytes()));
        exts.put(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, ext);
        gen.setRequestExtensions(new X509Extensions(exts));
        OCSPReq req = gen.generate();
        // Send the request and receive null
        SingleResp[] singleResps = helper.sendOCSPPost(req.getEncoded(), "123456789", OCSPRespGenerator.MALFORMED_REQUEST, 200);
        assertNull("No SingleResps should be returned.", singleResps);
    }

    public void test12CorruptRequests() throws Exception {
        log.trace(">test12CorruptRequests()");

        // An OCSP request, ocspTestCert is already created in earlier tests
        OCSPReqGenerator gen = new OCSPReqGenerator();
        gen.addRequest(new CertificateID(CertificateID.HASH_SHA1, cacert, ocspTestCert.getSerialNumber()));
        Hashtable exts = new Hashtable();
        X509Extension ext = new X509Extension(false, new DEROctetString("123456789".getBytes()));
        exts.put(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, ext);
        gen.setRequestExtensions(new X509Extensions(exts));
        OCSPReq req = gen.generate();

        // Request 1
        //
        // Send the request and receive a singleResponse
        byte[] orgbytes = req.getEncoded(); // Save original bytes, so we can make different strange values
        byte[] bytes = req.getEncoded();
        // Switch the first byte, now it's a really corrupted request
        bytes[0]=0x44;
        SingleResp[] singleResps = helper.sendOCSPPost(bytes, "123456789", OCSPRespGenerator.MALFORMED_REQUEST, 200); // error code 1 means malformed request
        assertNull("SingleResps should be null.", singleResps);

        // Request 2
        //
        // Remove the last byte, should still be quite corrupted
        //bytes = Arrays.copyOf(orgbytes, orgbytes.length-1); only works in Java 6
        bytes = ArrayUtils.remove(orgbytes, orgbytes.length-1);
        singleResps = helper.sendOCSPPost(bytes, "123456789", OCSPRespGenerator.MALFORMED_REQUEST, 200); // error code 1 means malformed request
        assertNull("SingleResps should be null.", singleResps);

        // Request 3
        //
        // more than 1 million bytes
        //bytes = Arrays.copyOf(orgbytes, 1000010); only works in Java 6
        bytes = ArrayUtils.addAll(orgbytes, new byte[1000010]);
        singleResps = helper.sendOCSPPost(bytes, "123456789", OCSPRespGenerator.MALFORMED_REQUEST, 200); // // error code 1 means malformed request
        assertNull("SingleResps should be null.", singleResps);

        // Request 4
        // 
        //
        // A completely empty request with no question in it
        gen = new OCSPReqGenerator();
        req = gen.generate();
        bytes = req.getEncoded();
        singleResps = helper.sendOCSPPost(bytes, "123456789", 1, 200); // 
        assertNull("SingleResps should be null.", singleResps);

        log.trace("<test12CorruptRequests()");
    }

    /**
     * Just verify that a simple GET works.
     */
    public void test13GetRequests() throws Exception {
    	// See if the OCSP Servlet can read non-encoded requests
    	final String plainReq = httpReqPath + '/' + resourceOcsp + '/' + "MGwwajBFMEMwQTAJBgUrDgMCGgUABBRBRfilzPB+Aevx0i1AoeKTkrHgLgQUFJw5gwk9BaEgsX3pzsRF9iso29ICCCzdx5N0v9XwoiEwHzAdBgkrBgEFBQcwAQIEECrZswo/a7YW+hyi5Sn85fs=";
        URL url = new URL(plainReq);
        log.info(url.toString());	// Dump the exact string we use for access
        HttpURLConnection con = (HttpURLConnection)url.openConnection();
        assertEquals("Response code did not match. ", 200, con.getResponseCode());
        assertNotNull(con.getContentType());
        assertTrue(con.getContentType().startsWith("application/ocsp-response"));
        OCSPResp response = new OCSPResp(new ByteArrayInputStream(OcspJunitHelper.inputStreamToBytes(con.getInputStream())));
        assertNotNull("Response should not be null.", response);
        assertTrue("Should not be concidered malformed.", OCSPRespGenerator.MALFORMED_REQUEST != response.getStatus());
    	final String dubbleSlashNonEncReq = "http://127.0.0.1:8080/ejbca/publicweb/status/ocsp/MGwwajBFMEMwQTAJBgUrDgMCGgUABBRBRfilzPB%2BAevx0i1AoeKTkrHgLgQUFJw5gwk9BaEgsX3pzsRF9iso29ICCAvB//HJyKqpoiEwHzAdBgkrBgEFBQcwAQIEEOTzT2gv3JpVva22Vj8cuKo%3D";
        url = new URL(dubbleSlashNonEncReq);
        log.info(url.toString());	// Dump the exact string we use for access
        con = (HttpURLConnection)url.openConnection();
        assertEquals("Response code did not match. ", 200, con.getResponseCode());
        assertNotNull(con.getContentType());
        assertTrue(con.getContentType().startsWith("application/ocsp-response"));
        response = new OCSPResp(new ByteArrayInputStream(OcspJunitHelper.inputStreamToBytes(con.getInputStream())));
        assertNotNull("Response should not be null.", response);
        assertTrue("Should not be concidered malformed.", OCSPRespGenerator.MALFORMED_REQUEST != response.getStatus());
        // An OCSP request, ocspTestCert is already created in earlier tests
        OCSPReqGenerator gen = new OCSPReqGenerator();
        loadUserCert(caid);
        gen.addRequest(new CertificateID(CertificateID.HASH_SHA1, cacert, ocspTestCert.getSerialNumber()));
        OCSPReq req = gen.generate();
        SingleResp[] singleResps = helper.sendOCSPGet(req.getEncoded(), null, OCSPRespGenerator.SUCCESSFUL, 200);
        assertNotNull("SingleResps should not be null.", singleResps);
        CertificateID certId = singleResps[0].getCertID();
        assertEquals("Serno in response does not match serno in request.", certId.getSerialNumber(), ocspTestCert.getSerialNumber());
        Object status = singleResps[0].getCertStatus();
        assertEquals("Status is not null (null is 'good')", null, status);
    }

    /**
     * Send a bunch of faulty requests
     */
    public void test14CorruptGetRequests() throws Exception {
    	// An array of zeros cannot be right..
        helper.sendOCSPGet(new byte[4096], null, OCSPRespGenerator.MALFORMED_REQUEST, 200);
    	// Send an empty GET request: .../ocsp/{nothing}
        helper.sendOCSPGet(new byte[0], null, OCSPRespGenerator.MALFORMED_REQUEST, 200);
    	// Test too large requests
        /*try {
        	// When we use an URL of length ~ 8100 chars on JBoss we get a "Connection reset",
        	// JBoss 5 considers this a bad request (400)
        	// so we cannot test the real Malformed response we want here
            helper.sendOCSPGet(new byte[6020], null, OCSPRespGenerator.MALFORMED_REQUEST, 200);
        } catch (IOException e) {
        	log.info(e.getMessage());
        }
        try {
        	// When we use an URL of length ~ > 500000 chars on JBoss we get a "Error writing to server",
        	// so we cannot test the real Malformed response we want here caused by to large requests
            helper.sendOCSPGet(new byte[1000001], null, OCSPRespGenerator.MALFORMED_REQUEST, 200);
        } catch (IOException e) {
        	log.info(e.getMessage());
        }*/
    }

    /**
     * Send multiple requests in one GET request. RFC 5019 2.1.1 prohibits clients from this, but the server should
     * be RFC 2560 compatible and support this as long as the total request URL is smaller than 256 bytes.
     */
    public void test15MultipleGetRequests() throws Exception {
        loadUserCert(caid);
        // An OCSP request, ocspTestCert is already created in earlier tests
        OCSPReqGenerator gen = new OCSPReqGenerator();
        gen.addRequest(new CertificateID(CertificateID.HASH_SHA1, cacert, ocspTestCert.getSerialNumber()));
        gen.addRequest(new CertificateID(CertificateID.HASH_SHA1, cacert, new BigInteger("1")));
        OCSPReq req = gen.generate();
        SingleResp[] singleResps = helper.sendOCSPGet(req.getEncoded(), null, OCSPRespGenerator.SUCCESSFUL, 200);
        assertNotNull("SingleResps should not be null.", singleResps);
        assertEquals("Serno in response does not match serno in request.", singleResps[0].getCertID().getSerialNumber(), ocspTestCert.getSerialNumber());
        assertTrue("Serno in response does not match serno in request.", singleResps[1].getCertID().getSerialNumber().toString().equals("1"));
        assertEquals("Status is not null (null is 'good')", null, singleResps[0].getCertStatus());
        assertTrue("Status is not unknown", singleResps[1].getCertStatus() instanceof UnknownStatus);
    }

     /** Tests ocsp message
     * @throws Exception error
     */
    public void test16OcspDsaGood() throws Exception {
    	assertTrue("This test can only be run on a full EJBCA installation.", ((HttpURLConnection) new URL(httpReqPath + '/').openConnection()).getResponseCode() == 200);
    	
        int dsacaid = "CN=OCSPDSATEST".hashCode();
        X509Certificate ecdsacacert = addDSACA("CN=OCSPDSATEST", "1024");
        helper.reloadKeys();
        
        // Make user and ocspTestCert that we know...
        createUserCert(dsacaid);

        // And an OCSP request
        OCSPReqGenerator gen = new OCSPReqGenerator();
        gen.addRequest(new CertificateID(CertificateID.HASH_SHA1, ecdsacacert, ocspTestCert.getSerialNumber()));
        Hashtable exts = new Hashtable();
        X509Extension ext = new X509Extension(false, new DEROctetString("123456789".getBytes()));
        exts.put(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, ext);
        gen.setRequestExtensions(new X509Extensions(exts));
        OCSPReq req = gen.generate();

        // Send the request and receive a singleResponse
        SingleResp[] singleResps = helper.sendOCSPPost(req.getEncoded(), "123456789", 0, 200);
        assertEquals("No of SingResps should be 1.", 1, singleResps.length);
        SingleResp singleResp = singleResps[0];

        CertificateID certId = singleResp.getCertID();
        assertEquals("Serno in response does not match serno in request.", certId.getSerialNumber(), ocspTestCert.getSerialNumber());
        Object status = singleResp.getCertStatus();
        assertEquals("Status is not null (good)", status, null);
        
    } // test16OcspDsaGood 

	/**
	 * Verify that Internal OCSP responses are signed by CA signing key.
	 */
	public void test17OCSPResponseSignature() throws Exception {

		// Get user and ocspTestCert that we know...
		loadUserCert(caid);

		// And an OCSP request
		OCSPReqGenerator gen = new OCSPReqGenerator();
		gen.addRequest(new CertificateID(CertificateID.HASH_SHA1, cacert, ocspTestCert.getSerialNumber()));

		Hashtable exts = new Hashtable();
		X509Extension ext = new X509Extension(false, new DEROctetString(
				"123456789".getBytes()));
		exts.put(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, ext);
		gen.setRequestExtensions(new X509Extensions(exts));
		OCSPReq req = gen.generate();

		// POST the OCSP request
		URL url = new URL(httpReqPath + '/' + resourceOcsp);
		HttpURLConnection con = (HttpURLConnection) url.openConnection();
		// we are going to do a POST
		con.setDoOutput(true);
		con.setRequestMethod("POST");

		// POST it
		con.setRequestProperty("Content-Type", "application/ocsp-request");
		OutputStream os = con.getOutputStream();
		os.write(req.getEncoded());
		os.close();
		assertTrue("HTTP error", con.getResponseCode() == 200);

		// Some appserver (Weblogic) responds with
		// "application/ocsp-response; charset=UTF-8"
		assertNotNull("No Content-Type in reply.", con.getContentType());
		assertTrue(con.getContentType().startsWith("application/ocsp-response"));
		OCSPResp response = new OCSPResp(new ByteArrayInputStream(
				OcspJunitHelper.inputStreamToBytes(con.getInputStream())));
		assertTrue("Response status not the expected.",
				response.getStatus() != 200);

		BasicOCSPResp brep = (BasicOCSPResp) response.getResponseObject();
		boolean verify = brep.verify(cacert.getPublicKey(), "BC");
		assertTrue("Signature verification", verify);
	}

	/**
	 * Verify OCSP response for a malicious request. Uses nonsense payload.
	 *  
	 * HTTP Content-length:    1000 byte
	 * ASN1 sequence length: 199995 byte
	 * Payload size:         200000 byte (not including HTTP header)
	 */
	public void test18MaliciousOcspRequest() throws Exception {
		log.trace(">test18MaliciousOcspRequest");
		int i=0;
		//Construct the fake data.
		byte data[] = new byte[LimitLengthASN1Reader.MAX_REQUEST_SIZE*2];
		//The first byte indicate that this is a sequence. Necessary to past the first test as an accepted OCSP object.
		data[0] = (byte) DERTags.SEQUENCE;
		//The second byte indicates the number of the following bytes are more than can be represented by one byte and will be represented by 3 bytes instead.
		data[1] = (byte) 0x83;
		//The third through the forth bytes are the number of the following bytes. (0x030D3B = 199995)
		data[2] = (byte) 0x03;	// MSB
		data[3] = (byte) 0x0D;
		data[4] = (byte) 0x3B;	// LSB
		//Fill the rest of the array with some fake data.
		for (i=5; i<data.length; i++) {
			data[i] = (byte)i;
		}
		/*
		*/
		// Create the HTTP header 
		String path = "/ejbca/"+ resourceOcsp;
		String headers = "POST "+path+" HTTP/1.1\r\n" + 
			"Host: 127.0.0.1\r\n" + 
			"Content-Type: application/ocsp-request\r\n" +
			"Content-Length: 1000\r\n" +
			"\r\n";
		//Merge the HTTP headers and the raw data into one package.
		byte input[] = concatByteArrays(headers.getBytes(), data);
		//Create the socket.
		Socket socket = new Socket(InetAddress.getByName("127.0.0.1"), 8080);
		// Send data byte for byte. 
		OutputStream os = socket.getOutputStream();
		try {
			for(i=0; i<input.length; i++){
				os.write(input[i]);
			}
		} catch(IOException e){
			log.info("Socket wrote " + i + " bytes before throwing an IOException.");
		}
		//Reading the response.
		InputStream ins = socket.getInputStream();
		byte ret[] = new byte[1024];
		ins.read(ret);
		socket.close();
		//Removing the HTTP headers. The HTTP headers end at the last occurrence of "\r\n".
		for (i=ret.length-1; i>0; i--) {
			if ((ret[i]==0x0A) && (ret[i-1] ==0x0D)) {
				break;
			}
		}
		int start = i+1;
		byte respa[] = new byte[ret.length-start];
		for (i=start; i<ret.length; i++) {
			respa[i-start] = ret[i];	
		}
		log.info("response contains: " + respa.length + " bytes.");
		//Reading the response as a OCSPResp. When the input data array is longer than allowed the OCSP response will return as an internal error.
		OCSPResp response = new OCSPResp(respa);
		assertEquals("Incorrect response status.", OCSPRespGenerator.INTERNAL_ERROR, response.getStatus());
		log.trace("<test18MaliciousOcspRequest");
	}

	/**
	 * Verify OCSP response for a malicious request. Uses nonsense payload.
	 *  
	 * HTTP Content-length:  200000 byte
	 * ASN1 sequence length:   9996 byte
	 * Payload size:         200000 byte (not including HTTP header)
	 */
	public void test19MaliciousOcspRequest() throws Exception {
		log.trace(">test19MaliciousOcspRequest");
		int i=0;
		//Construct the fake data.
		byte data[] = new byte[LimitLengthASN1Reader.MAX_REQUEST_SIZE*2];
		//The first byte indicate that this is a sequence. Necessary to past the first test as an accepted OCSP object.
		data[0] = (byte) DERTags.SEQUENCE;
		//The second byte indicates the number of the following bytes are more than can be represented by one byte and will be represented by 2 bytes instead.
		data[1] = (byte) 0x82;
		//The third through the forth bytes are the number of the following bytes. (0x270C = 9996)
		data[2] = (byte) 0x27;	// MSB
		data[3] = (byte) 0x0C;	// LSB
		//Fill the rest of the array with some fake data.
		for (i=4; i<data.length; i++) {
			data[i] = (byte)i;
		}
		// Create the HTTP header 
		String path = "/ejbca/"+ resourceOcsp;
		String headers = "POST "+path+" HTTP/1.1\r\n" + 
			"Host: 127.0.0.1\r\n" + 
			"Content-Type: application/ocsp-request\r\n" +
			"Content-Length: 200000\r\n" +
			"\r\n";
		//Merge the HTTP headers and the raw data into one package.
		byte input[] = concatByteArrays(headers.getBytes(), data);
		//Create the socket.
		Socket socket = new Socket(InetAddress.getByName("127.0.0.1"), 8080);
		// Send data byte for byte. 
		OutputStream os = socket.getOutputStream();
		try {
			for(i=0; i<input.length; i++){
				os.write(input[i]);
			}
		} catch(IOException e){
			log.info("Socket wrote " + i + " bytes before throwing an IOException.");
		}
		//Reading the response.
		InputStream ins = socket.getInputStream();
		byte ret[] = new byte[1024];
		ins.read(ret);
		socket.close();
		//Removing the HTTP headers. The HTTP headers end at the last occurrence of "\r\n".
		for (i=ret.length-1; i>0; i--) {
			if ((ret[i]==0x0A) && (ret[i-1] ==0x0D)) {
				break;
			}
		}
		int start = i+1;
		byte respa[] = new byte[ret.length-start];
		for (i=start; i<ret.length; i++) {
			respa[i-start] = ret[i];
		}
		log.info("response contains: " + respa.length + " bytes.");
		//Reading the response as a OCSPResp. When the input data array is longer than allowed the OCSP response will return as an internal error.
		OCSPResp response = new OCSPResp(respa);			
		assertEquals("Incorrect response status.", OCSPRespGenerator.MALFORMED_REQUEST, response.getStatus());
		log.trace("<test19MaliciousOcspRequest");
	}

	/**
	 * Verify OCSP response for a malicious request where the POST data starts with a proper OCSP request.
	 */
	public void test20MaliciousOcspRequest() throws Exception {
		log.trace(">test20MaliciousOcspRequest");
		// Start by sending a valid OCSP requests so we know the helpers work
		byte validOcspReq[] = getValidOcspRequest();
		OCSPResp response = sendRawRequestToOcsp(validOcspReq.length, validOcspReq, false);
		assertEquals("Incorrect response status.", OCSPRespGenerator.SUCCESSFUL, response.getStatus());
		// Try sending a valid request and then keep sending some more data.
		byte[] buf = new byte[LimitLengthASN1Reader.MAX_REQUEST_SIZE*2];
		Arrays.fill(buf, (byte)123);
		buf = concatByteArrays(validOcspReq, buf);
		response = sendRawRequestToOcsp(buf.length, buf, false);
		assertEquals("Incorrect response status.", OCSPRespGenerator.MALFORMED_REQUEST, response.getStatus());
		// Now try with a fake HTTP content-length header
		try {
			response = sendRawRequestToOcsp(validOcspReq.length, buf, false);
			fail("Was able to send a lot of data with a fake HTTP Content-length without any error.");
		} catch (IOException e) {
		}
		// Try sneaking through a payload that is just under the limit. The responder will answer politely, but log a warning.
		buf = new byte[LimitLengthASN1Reader.MAX_REQUEST_SIZE-validOcspReq.length];
		Arrays.fill(buf, (byte)123);
		buf = concatByteArrays(validOcspReq, buf);
		response = sendRawRequestToOcsp(buf.length, buf, false);
		assertEquals("Server rejected malicious request. (This might be a good thing!)", OCSPRespGenerator.SUCCESSFUL, response.getStatus());
		log.trace("<test20MaliciousOcspRequest");
	}
	
    /**
     * removes DSA CA
     *
     * @throws Exception error
     */
    public void test98RemoveDSACA() throws Exception {
        log.trace(">test98RemoveDSACA()");
    	assertTrue("This test can only be run on a full EJBCA installation.", ((HttpURLConnection) new URL(httpReqPath + '/').openConnection()).getResponseCode() == 200);
        try {
        	TestTools.getCAAdminSession().removeCA(admin, "CN=OCSPDSATEST".hashCode());
        } catch(Exception e) {
        	log.info("Could not remove CA with SubjectDN CN=OCSPDSATEST");
        }
        try {
        	TestTools.getCAAdminSession().removeCA(admin, "CN=OCSPDSAIMPCATEST".hashCode());
        } catch(Exception e) {
        	log.info("Could not remove CA with SubjectDN CN=OCSPDSAIMPCATEST");
        }
        log.trace("<test98RemoveDSACA()");
    } // test98OcspDsaGood
    
    /**
     * removes ECDSA CA
     *
     * @throws Exception error
     */
    public void test99RemoveECDSACA() throws Exception {
        log.trace(">test08RemoveECDSACA()");
    	assertTrue("This test can only be run on a full EJBCA installation.", ((HttpURLConnection) new URL(httpReqPath + '/').openConnection()).getResponseCode() == 200);
        try {
        	TestTools.getCAAdminSession().removeCA(admin, "CN=OCSPECDSATEST".hashCode());
        } catch(Exception e) {
        	log.info("Could not remove CA with SubjectDN CN=OCSPECDSATEST");
        }
        try {
        	TestTools.getCAAdminSession().removeCA(admin, "CN=OCSPECDSAIMPCATEST".hashCode());
        } catch(Exception e) {
        	log.info("Could not remove CA with SubjectDN CN=OCSPECDSAIMPCATEST");
        }
        log.trace("<test99RemoveECDSACA()");
    }

    public void testZZZTearDown() throws Exception {
    	assertTrue("This test can only be run on a full EJBCA installation.", ((HttpURLConnection) new URL(httpReqPath + '/').openConnection()).getResponseCode() == 200);
        TestTools.removeTestCA();
    }

    //
    // Private helper methods
    //
    
    /**
     * Generate a simple OCSP Request object
     */
    private byte[] getValidOcspRequest() throws Exception {
		// Get user and ocspTestCert that we know...
		loadUserCert(caid);
		// And an OCSP request
		OCSPReqGenerator gen = new OCSPReqGenerator();
		gen.addRequest(new CertificateID(CertificateID.HASH_SHA1, cacert, ocspTestCert.getSerialNumber()));
		Hashtable exts = new Hashtable();
		X509Extension ext = new X509Extension(false, new DEROctetString("123456789".getBytes()));
		exts.put(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, ext);
		gen.setRequestExtensions(new X509Extensions(exts));
		OCSPReq req = gen.generate();
		return req.getEncoded();
    }
    
    /**
     * Sends the payload to the OCSP Servlet using TCP. Can be used for testing malformed or
     * malicious requests.
     * 
     * @param contentLength The HTTP 'Content-Length' header to send to the server.
     * @return the OCSP Response from the server
     * @throws IOException if the is a IO problem 
     */
    private OCSPResp sendRawRequestToOcsp(int contentLength, byte[] payload, boolean writeByteByByte) throws IOException {
		// Create the HTTP header 
		String headers = "POST "+"/ejbca/"+ resourceOcsp+" HTTP/1.1\r\n" + 
        				 "Host: 127.0.0.1\r\n" + 
        				 "Content-Type: application/ocsp-request\r\n" +
        				 "Content-Length: "+contentLength+"\r\n" +
        				 "\r\n";
		// Merge the HTTP headers, the OCSP request and the raw data into one package.
		byte[] input = concatByteArrays(headers.getBytes(), payload);
		log.debug("HTTP request headers: " + headers);
		log.debug("HTTP headers size: " + headers.getBytes().length);
		log.debug("Size of data to send: " + input.length);
		// Create the socket.
		Socket socket = new Socket(InetAddress.getByName("127.0.0.1"), 8080);
		// Send data byte for byte. 
		OutputStream os = socket.getOutputStream();
		if (writeByteByByte) {
			int i=0;
			try {
				for(i=0; i<input.length; i++){
					os.write(input[i]);
				}
			} catch(IOException e){
				log.info("Socket wrote " + i + " bytes before throwing an IOException.");
			}
		} else {
			try {
				os.write(input);
			} catch (IOException e) {
				log.info("Could not write to TCP Socket " + e.getMessage());
			}
		}
		// Reading the response.
		byte rawResponse[] = getHttpResponse(socket.getInputStream());
		log.info("Response contains: " + rawResponse.length + " bytes.");
		socket.close();
		return new OCSPResp(rawResponse);			
	}

    /**
     * Read the payload of a HTTP response as a byte array.
     */
    private byte[] getHttpResponse(InputStream ins) throws IOException {
		byte buf[] = OcspJunitHelper.inputStreamToBytes(ins);
		int i=0;
		//Removing the HTTP headers. The HTTP headers end at the last occurrence of "\r\n".
		for (i=buf.length-1; i>0; i--) {
			if ((buf[i]==0x0A) && (buf[i-1] ==0x0D)) {
				break;
			}
		}
		byte[] header = Arrays.copyOfRange(buf, 0, i+1);
		log.debug("HTTP reponse header: " + new String(header));
		log.debug("HTTP reponse header size: " + header.length);
		log.debug("Stream length: " + buf.length);
		log.debug("HTTP payload length: " + (buf.length-header.length));
		return Arrays.copyOfRange(buf, header.length, buf.length);
    }
    
    /**
     * @return a new byte array with the two arguments concatenated.
     */
    private byte[] concatByteArrays(byte[] array1, byte[] array2) {
    	byte[] ret = new byte[array1.length + array2.length];
    	for (int i=0; i<array1.length; i++) {
    		ret[i] = array1[i];
    	}
    	for (int i=0; i<array2.length; i++) {
    		ret[array1.length+i] = array2[i];
    	}
    	return ret;
    }
    
    /**
     * adds a CA Using ECDSA keys to the database.
     *
     * It also checks that the CA is stored correctly.
     *
     * @throws Exception error
     */
    private X509Certificate addECDSACA(String dn, String keySpec) throws Exception {
        log.trace(">addECDSACA()");
        boolean ret = false;
        X509Certificate cacert = null;
        try {
        	TestTools.getAuthorizationSession().initialize(admin, dn.hashCode());

            SoftCATokenInfo catokeninfo = new SoftCATokenInfo();
            catokeninfo.setSignKeySpec(keySpec);
            catokeninfo.setEncKeySpec("1024");
            catokeninfo.setSignKeyAlgorithm(AlgorithmConstants.KEYALGORITHM_ECDSA);
            catokeninfo.setEncKeyAlgorithm(AlgorithmConstants.KEYALGORITHM_RSA);
            catokeninfo.setSignatureAlgorithm(AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA);
            catokeninfo.setEncryptionAlgorithm(AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
            // Create and active OSCP CA Service.
            ArrayList extendedcaservices = new ArrayList();
            extendedcaservices.add(new OCSPCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE));

            ArrayList policies = new ArrayList(1);
            policies.add(new CertificatePolicy("2.5.29.32.0", "", ""));
            
            X509CAInfo cainfo = new X509CAInfo(dn,
                    dn, SecConst.CA_ACTIVE, new Date(),
                    "", SecConst.CERTPROFILE_FIXED_ROOTCA,
                    365,
                    null, // Expiretime
                    CAInfo.CATYPE_X509,
                    CAInfo.SELFSIGNED,
                    (Collection) null,
                    catokeninfo,
                    "JUnit ECDSA CA",
                    -1, null,
                    policies, // PolicyId
                    24, // CRLPeriod
                    0, // CRLIssueInterval
                    10, // CRLOverlapTime
                    0, // DeltaCRLPeriod
                    new ArrayList(),
                    true, // Authority Key Identifier
                    false, // Authority Key Identifier Critical
                    true, // CRL Number
                    false, // CRL Number Critical
                    null, // defaultcrldistpoint 
                    null, // defaultcrlissuer 
                    null, // defaultocsplocator
                    null, // defaultfreshestcrl
                    true, // Finish User
                    extendedcaservices,
                    false, // use default utf8 settings
                    new ArrayList(), // Approvals Settings
                    1, // Number of Req approvals
                    false, // Use UTF8 subject DN by default 
                    true, // Use LDAP DN order by default
                    false, // Use CRL Distribution Point on CRL
                    false,  // CRL Distribution Point on CRL critical
                    true, // Include in Health Check
                    true, // isDoEnforceUniquePublicKeys
                    true // isDoEnforceUniqueDistinguishedName
                    );

            TestTools.getCAAdminSession().createCA(admin, cainfo);

            CAInfo info = TestTools.getCAAdminSession().getCAInfo(admin, dn);

            X509Certificate cert = (X509Certificate) info.getCertificateChain().iterator().next();
            assertTrue("Error in created ca certificate", cert.getSubjectDN().toString().equals(dn));
            assertTrue("Creating CA failed", info.getSubjectDN().equals(dn));
            PublicKey pk = cert.getPublicKey();
            if (pk instanceof JCEECPublicKey) {
				JCEECPublicKey ecpk = (JCEECPublicKey) pk;
				assertEquals(ecpk.getAlgorithm(), "EC");
				org.bouncycastle.jce.spec.ECParameterSpec spec = ecpk.getParameters();
				if (StringUtils.equals(keySpec, "implicitlyCA")) {
					assertNull("ImplicitlyCA must have null spec", spec);					
				} else {
					assertNotNull("prime192v1 must not have null spec", spec);
				}
			} else {
				assertTrue("Public key is not EC", false);
			}

            ret = true;
            Collection coll = info.getCertificateChain();
            Object[] certs = coll.toArray();
            cacert = (X509Certificate)certs[0];
        } catch (CAExistsException pee) {
            log.info("CA exists.");
        }

        assertTrue("Creating ECDSA CA failed", ret);
        log.trace("<addECDSACA()");
        return cacert;
    }
    
    
    /**
     * adds a CA Using DSA keys to the database.
     *
     * It also checks that the CA is stored correctly.
     *
     * @throws Exception error
     */
    private X509Certificate addDSACA(String dn, String keySpec) throws Exception {
        log.trace(">addDSACA()");
        boolean ret = false;
        X509Certificate cacert = null;
        try {
        	TestTools.getAuthorizationSession().initialize(admin, dn.hashCode());

            SoftCATokenInfo catokeninfo = new SoftCATokenInfo();
            catokeninfo.setSignKeySpec(keySpec);
            catokeninfo.setEncKeySpec("1024");
            catokeninfo.setSignKeyAlgorithm(AlgorithmConstants.KEYALGORITHM_DSA);
            catokeninfo.setEncKeyAlgorithm(AlgorithmConstants.KEYALGORITHM_RSA);
            catokeninfo.setSignatureAlgorithm(AlgorithmConstants.SIGALG_SHA1_WITH_DSA);
            catokeninfo.setEncryptionAlgorithm(AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
            // Create and active OSCP CA Service.
            ArrayList extendedcaservices = new ArrayList();
            extendedcaservices.add(new OCSPCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE));

            ArrayList policies = new ArrayList(1);
            policies.add(new CertificatePolicy("2.5.29.32.0", "", ""));
            
            X509CAInfo cainfo = new X509CAInfo(dn,
                    dn, SecConst.CA_ACTIVE, new Date(),
                    "", SecConst.CERTPROFILE_FIXED_ROOTCA,
                    365,
                    null, // Expiretime
                    CAInfo.CATYPE_X509,
                    CAInfo.SELFSIGNED,
                    (Collection) null,
                    catokeninfo,
                    "JUnit DSA CA",
                    -1, null,
                    policies, // PolicyId
                    24, // CRLPeriod
                    0, // CRLIssueInterval
                    10, // CRLOverlapTime
                    0, // DeltaCRLPeriod
                    new ArrayList(),
                    true, // Authority Key Identifier
                    false, // Authority Key Identifier Critical
                    true, // CRL Number
                    false, // CRL Number Critical
                    null, // defaultcrldistpoint 
                    null, // defaultcrlissuer 
                    null, // defaultocsplocator
                    null, // defaultfreshestcrl
                    true, // Finish User
                    extendedcaservices,
                    false, // use default utf8 settings
                    new ArrayList(), // Approvals Settings
                    1, // Number of Req approvals
                    false, // Use UTF8 subject DN by default 
                    true, // Use LDAP DN order by default
                    false, // Use CRL Distribution Point on CRL
                    false,  // CRL Distribution Point on CRL critical
                    true, // Include in Health Check
                    true, // isDoEnforceUniquePublicKeys
                    true // isDoEnforceUniqueDistinguishedName
                    );

            TestTools.getCAAdminSession().createCA(admin, cainfo);

            CAInfo info = TestTools.getCAAdminSession().getCAInfo(admin, dn);

            X509Certificate cert = (X509Certificate) info.getCertificateChain().iterator().next();
            assertTrue("Error in created ca certificate", cert.getSubjectDN().toString().equals(dn));
            assertTrue("Creating CA failed", info.getSubjectDN().equals(dn));
            assertTrue(cert.getPublicKey() instanceof DSAPublicKey);

            ret = true;
            Collection coll = info.getCertificateChain();
            Object[] certs = coll.toArray();
            cacert = (X509Certificate)certs[0];
        } catch (CAExistsException pee) {
            log.info("CA exists.");
        }

        assertTrue("Creating DSA CA failed", ret);
        log.trace("<addDSACA()");
        return cacert;
    }
    
    protected void loadUserCert(int caid) throws Exception {
    	createUserCert(caid);
    }
    
    private KeyPair createUserCert(int caid) throws AuthorizationDeniedException,
    UserDoesntFullfillEndEntityProfile, ApprovalException,
    WaitingForApprovalException, RemoteException, Exception,
    ObjectNotFoundException, AuthStatusException, AuthLoginException,
    IllegalKeyException, CADoesntExistsException {
    	boolean userExists = false;
    	try {
    		TestTools.getUserAdminSession().addUser(admin,"ocsptest","foo123","C=SE,O=AnaTom,CN=OCSPTest",null,"ocsptest@anatom.se",false,SecConst.EMPTY_ENDENTITYPROFILE,SecConst.CERTPROFILE_FIXED_ENDUSER,SecConst.USER_ENDUSER,SecConst.TOKEN_SOFT_PEM,0,caid);
    		log.debug("created user: ocsptest, foo123, C=SE, O=AnaTom, CN=OCSPTest");
    	} catch (RemoteException re) {
    		userExists = true;
    	} catch (DuplicateKeyException dke) {
    		userExists = true;
    	}

    	if (userExists) {
    		log.debug("User ocsptest already exists.");
    		TestTools.getUserAdminSession().changeUser(admin, "ocsptest", "foo123", "C=SE,O=AnaTom,CN=OCSPTest",null,"ocsptest@anatom.se",false, SecConst.EMPTY_ENDENTITYPROFILE,SecConst.CERTPROFILE_FIXED_ENDUSER,SecConst.USER_ENDUSER,SecConst.TOKEN_SOFT_PEM,0,UserDataConstants.STATUS_NEW, caid);
    		//usersession.setUserStatus(admin,"ocsptest",UserDataConstants.STATUS_NEW);
    		log.debug("Reset status to NEW");
    	}
//  	Generate certificate for the new user
    	KeyPair keys = KeyTools.genKeys("512","RSA");

//  	user that we know exists...
    	ocspTestCert = (X509Certificate) TestTools.getSignSession().createCertificate(admin, "ocsptest", "foo123", keys.getPublic());
    	assertNotNull("Failed to create new certificate", ocspTestCert);
    	return keys;
    }



    static private byte[] ks3 = Base64.decode(("MIACAQMwgAYJKoZIhvcNAQcBoIAkgASCAyYwgDCABgkqhkiG9w0BBwGggCSABIID"
            + "DjCCAwowggMGBgsqhkiG9w0BDAoBAqCCAqkwggKlMCcGCiqGSIb3DQEMAQMwGQQU"
            + "/h0pQXq7ZVjYWlDvzEwwmiJ8O8oCAWQEggJ4MZ12+kTVGd1w7SP4ZWlq0bCc4MsJ"
            + "O0FFSX3xeVp8Bx16io1WkEFOW3xfqjuxKOL6YN9atoOZdfhlOMhmbhglm2PJSzIg"
            + "JSDHvWk2xKels5vh4hY1iXWOh48077Us4wP4Qt94iKglCq4xwxYcSCW8BJwbu93F"
            + "uxE1twnWXbH192nMhaeIAy0v4COdduQamJEtHRmIJ4GZwIhH+lNHj/ARdIfNw0Dm"
            + "uPspuSu7rh6rQ8SrRsjg63EoxfSH4Lz6zIJKF0OjNX07T8TetFgznCdGCrqOZ1fK"
            + "5oRzXIA9hi6UICiuLSm4EoHzEpifCObpiApwNj3Kmp2uyz2uipU0UKhf/WqvmU96"
            + "yJj6j1JjZB6p+9sgecPFj1UMWhEFTwxMEwR7iZDvjkKDNWMit+0cQyeS7U0Lxn3u"
            + "m2g5e6C/1akwHZsioLC5OpFq/BkPtnbtuy4Kr5Kwb2y7vSiKpjFr7sKInjdAsgCi"
            + "8kyUV8MyaIfZdtREjwqBe0imfP+IPVqAsl1wGW95YXsLlK+4P1bspAgeHdDq7Q91"
            + "bJJQAS5OTD38i1NY6MRtt/fWsShVBLjf2FzNpw6siHHl2N7BDNyO3ALtgfp50e0Z"
            + "Dsw5WArgKLiXfwZIrIKbYA73RFc10ReDqnJSF+NXgBo1/i4WhZLHC1Osl5UoKt9q"
            + "UoXIUmYhAwdAT5ZKVw6A8yp4e270yZTXNsDz8u/onEwNc1iM0v0RnPQhNE5sKEZH"
            + "QrMxttiwbKe3YshCjbruz/27XnNA51t2p1M6eC1HRab4xSHAyH5NTxGJ8yKhOfiT"
            + "aBKqdTH3P7QzlcoCUDVDDe7aLMaZEf+a2Te63cZTuUVpkysxSjAjBgkqhkiG9w0B"
            + "CRQxFh4UAHAAcgBpAHYAYQB0AGUASwBlAHkwIwYJKoZIhvcNAQkVMRYEFCfeHSg6"
            + "EdeP5A1IC8ydjyrjyFSdAAQBAAQBAAQBAAQBAASCCBoAMIAGCSqGSIb3DQEHBqCA"
            + "MIACAQAwgAYJKoZIhvcNAQcBMCcGCiqGSIb3DQEMAQYwGQQURNy47tUcttscSleo"
            + "8gY6ZAPFOl0CAWSggASCB8jdZ+wffUP1B25Ys48OFBMg/itT0EBS6J+dYVofZ84c"
            + "x41q9U+CRMZJwVNZbkqfRZ+F3tLORSwuIcwyioa2/JUpv8uJCjQ2tru5+HtqCrzR"
            + "Huh7TfdiMqvjkKpnXi69DPPjQdCSPwYMy1ahZrP5KgEZg4S92xpU2unF1kKQ30Pq"
            + "PTEBueDlFC39rojp51Wsnqb1QzjPo53YvJQ8ztCoG0yk+0omELyPbc/qMKe5/g5h"
            + "Lx7Q+2D0PC/ZHtoDkCRfMDKwgwALFsSj2uWNJsCplspmc7YgIzSr/GqqeSXHp4Ue"
            + "dwVJAswrhpkXZTlp1rtl/lCSFl9akwjY1fI144zfpYKpLqfoHL1uI1c3OumrFzHd"
            + "ZldZYgsM/h3qjgu8qcXqI0sKVXsffcftCaVs+Bxmdu9vpY15rlx1e0an/O05nMKU"
            + "MBU2XpGkmWxuy0tOKs3QtGzHUJR5+RdEPURctRyZocEjJgTvaIMq1dy/FIaBhi+d"
            + "IeAbFmjBu7cv9C9v/jMuUjLroycmo7QW9jGgyTOQ68J+6w2/PtqiqIo3Ry9WC0SQ"
            + "8+fVNOGLr5O2YPpw17sDQa/+2gjozngvL0OHiABwQ3EbXAQLF046VYkTi5R+8iGV"
            + "3jlTvvStIKY06E/s/ih86bzwJWAQENCazXErN69JO+K3IUiwxac+1AOO5WyR9qyv"
            + "6m/yHdIdbOVE21M2RARbI8UiDpRihCzk4duPfj/x2bZyFqLclIMhbTd2UOQQvr+W"
            + "4etpMJRtyFGhdLmNgYAhYrbUgmdL1kRkzPzOs77PqleMpfkii7HPk3HlVkM7NIqd"
            + "dN0WQaQwGJuh5f1ynhyqtsaw6Gu/X56H7hpziAh0eSDQ5roRE7yy98h2Mcwb2wtY"
            + "PqVFTmoKuRWR2H5tT6gCaAM3xiSC7RLa5SF1hYQGaqunqBaNPYyUIg/r03dfwF9r"
            + "AkOhh6Mq7Z2ktzadWTxPl8OtIZFVeyqIOtSKBHhJyGDGiz3+SSnTnSX81NaTSJYZ"
            + "7YTiXkXvSYNpjpPckIKfjpBw0T4pOva3a6s1z5p94Dkl4kz/zOmgveGd3dal6wUV"
            + "n3TR+2cyv51WcnvB9RIp58SJOc+CvCvYTvkEdvE2QtRw3wt4ngGJ5pxmC+7+8fCf"
            + "hRDzw9LBNz/ry88y/0Bidpbhwr8gEkmHuaLp43WGQQsQ+cWYJ8AeLZMvKplbCWqy"
            + "iuks0MnKeaC5dcB+3BL55OvcTfGkMtz0oYBkcGBTbbR8BKJZgkIAx7Q+/rCaqv6H"
            + "HN/cH5p8iz5k+R3MkmR3gi6ktelQ2zx1pbPz3IqR67cTX3IyTX56F2aY54ueY17m"
            + "7hFwSy4aMen27EO06DXn/b6vPKj73ClE2B/IPHO/H2e8r04JWMltFWuStV0If5x0"
            + "5ZImXx068Xw34eqSWvoMzr97xDxUwdlFgrKrkMKNoTDhA4afrZ/lwHdUbNzh6cht"
            + "jHW/IfIaMo3NldN/ihO851D399FMsWZW7YA7//RrWzBDiLvh+RfwkMOfEpbujy0G"
            + "73rO/Feed2MoVXvmuKBRpTNyFuBVvFDwIzBT4m/RaVf5m1pvprSk3lo43aumdN9f"
            + "NDETktVZ/CYaKlYK8rLcNBKJicM5+maiQSTa06XZXDMY84Q0xtCqJ/aUH4sa/z8j"
            + "KukVUSyUZDJk/O82B3NA4+CoP3Xyc9LAUKucUvoOmGt2JCw6goB/vqeZEg9Tli0Q"
            + "+aRer720QdVRkPVXKSshL2FoXHWUMaBF8r//zT6HbjTNQEdxbRcBNvkUXUHzITfl"
            + "YjQcEn+FGrF8+HVdXCKzSXSgu7mSouYyJmZh42spUFCa4j60Ks1fhQb2H1p72nJD"
            + "n1mC5sZkU68ITVu1juVl/L2WJPmWfasb1Ihnm9caJ/mEE/i1iKp7qaY9DPTw5hw4"
            + "3QplYWFv47UA/sOmnWwupRuPk7ISdimuUnih8OYR75rJ0z6OYexvj/2svx9/O5Mw"
            + "654jFF2hAq69jt7GJo6VZaeCRCAxEU7N97l3EjqaKJVrpIPQ+3yLmqHit/CWxImB"
            + "iIl3sW7MDEHgPdQy3QiZmAYNLQ0Te0ygcIHwtPyzhFoFmjbQwib2vxDqWaMQpUM1"
            + "/W96R/vbCjA7tfKYchImwAPCyRM5Je2FHewErG413kZct5tJ1JqkcjPsP7Q8kmgw"
            + "Ec5QNq1/PZOzL1ZLr6ryfA4gLBXa6bJmf43TUkdFYTvIYbvH2jp4wpAtA152YgPI"
            + "FL19/Tv0B3Bmb1qaK+FKiiQmYfVOm/J86i/L3b8Z3jj8dRWEBztaI/KazZ/ZVcs/"
            + "50bF9jH7y5+2uZxByjkM/kM/Ov9zIHbYdxLw2KHnHsGKTCooSSWvPupQLBGgkd6P"
            + "M9mgE6MntS+lk9ucpP5j1LXo5zlZaLSwrvSzE3/bbWJKsJuomhRbKeZ+qSYOWvPl"
            + "/1RqREyZHbSDKzVk39oxH9EI9EWKlCbrz5EHWiSv0+9HPczxbO3q+YfqcY8plPYX"
            + "BvgxHUeDR+LxaAEcVEX6wd2Pky8pVwxQydU4cEgohrgZnKhxxLAvCp5sb9kgqCrh"
            + "luvBsHpmiUSCi/r0PNXDgApvTrVS/Yv0jTpX9u9IWMmNMrnskdcP7tpEdkw8/dpf"
            + "RFLLgqwmNEhCggfbyT0JIUxf2rldKwd6N1wZozaBg1uKjNmAhJc1RxsABAEABAEA"
            + "BAEABAEABAEABAEABAEABAEABAEABAEABAEAAAAAAAAAMDwwITAJBgUrDgMCGgUA"
            + "BBSS2GOUxqv3IT+aesPrMPNn9RQ//gQUYhjCLPh/h2ULjh+1L2s3f5JIZf0CAWQA"
            + "AA==").getBytes());

    static private byte[] ksexpired = Base64.decode(("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"
    		+"AAA=").getBytes());
}
