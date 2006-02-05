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

package se.anatom.ejbca.protocol;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.KeyStore;
import java.security.NoSuchProviderException;
import java.security.cert.X509Certificate;

import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.CertificateID;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.ocsp.OCSPReq;
import org.bouncycastle.ocsp.OCSPReqGenerator;
import org.bouncycastle.ocsp.OCSPResp;
import org.bouncycastle.ocsp.SingleResp;
import org.bouncycastle.ocsp.UnknownStatus;
import org.ejbca.util.CertTools;

/** Tests http pages of ocsp lookup server.
 * This test requires a lot of setup. 
 * - The lookup service must be active
 * - There must be a database for the unid-fnr mapping
 * - You must have a CA that has issued certificates with serialNumber in the DN matching the unid
 * - You should have four certificates:
 *    - issuing CA cert (/lookup-ca.pem) 
 *    - one with a valid unid (/lookup-valid.pem), 
 *    - one with a unid that is not in the mapping database (/lookup-invalid.pem), 
 *    - one without serialNumber in the DN (/lookup-noserno.pem)
 * - You also need a keystore issued by the CA for TLS communication, the keystore cert must be configured in the lookup extension as trusted
 *    - /lookup-kstrust.p12 (password lookup)
 * - You also need a keystore as above but not configured as trusted in the lookup extension
 *    - /lookup-ksnotrust.p12 (password lookup)
 **/
public class ProtocolLookupServerHttpTest extends TestCase {
    private static Logger log = Logger.getLogger(ProtocolLookupServerHttpTest.class);

    private static final String httpReqPath = "http://127.0.0.1:8080/ejbca";
    private static final String resourceOcsp = "publicweb/status/ocsp";


    private static X509Certificate cacert = null;
    private static X509Certificate validunid = null;
    private static X509Certificate invalidunid = null;
    private static X509Certificate noserno = null;
    private static KeyStore kstrust = null;
    private static KeyStore ksnotrust = null;


    public ProtocolLookupServerHttpTest(String name) {
        super(name);

        // Install BouncyCastle provider
        CertTools.installBCProvider();
        
        try {
			cacert = (X509Certificate) CertTools.getCertsFromPEM(
					"/lookup-ca.pem").iterator().next();
			validunid = (X509Certificate) CertTools.getCertsFromPEM(
					"/lookup-valid.pem").iterator().next();
			invalidunid = (X509Certificate) CertTools.getCertsFromPEM(
					"/lookup-invalid.pem").iterator().next();
			noserno = (X509Certificate) CertTools.getCertsFromPEM(
					"/lookup-noserno.pem").iterator().next();
			kstrust = KeyStore.getInstance("PKCS12", "BC");
			FileInputStream fis = new FileInputStream("/lookup-kstrust.p12");
			kstrust.load(fis, "lookup".toCharArray());
			fis.close();
			ksnotrust = KeyStore.getInstance("PKCS12", "BC");
			fis = new FileInputStream("/lookup-ksnotrust.p12");
			ksnotrust.load(fis, "lookup".toCharArray());
			fis.close();
		} catch (Exception e) {
			log.error("Exception during construction: ", e);
			assertTrue(e.getMessage(), false);
		}

    }

    protected void setUp() throws Exception {
        log.debug(">setUp()");

        log.debug("<setUp()");
    }

    protected void tearDown() throws Exception {
    }

    /** Tests ocsp message with good status and a valid unid
     * @throws Exception error
     */
    public void test01OcspGoodWithFnr() throws Exception {

        // And an OCSP request
        OCSPReqGenerator gen = new OCSPReqGenerator();
        gen.addRequest(new CertificateID(CertificateID.HASH_SHA1, cacert, validunid.getSerialNumber()));
        OCSPReq req = gen.generate();

        // Send the request and receive a singleResponse
        SingleResp singleResp = sendOCSPPost(req.getEncoded());
        
        CertificateID certId = singleResp.getCertID();
        assertEquals("Serno in response does not match serno in request.", certId.getSerialNumber(), validunid.getSerialNumber());
        Object status = singleResp.getCertStatus();
        assertEquals("Status is not null (good)", status, null);
    }

    /** Tests ocsp message with good status and invalid unid
     * @throws Exception error
     */
    public void test02OcspGoodWithNoFnr() throws Exception {
        // And an OCSP request
        OCSPReqGenerator gen = new OCSPReqGenerator();
        gen.addRequest(new CertificateID(CertificateID.HASH_SHA1, cacert, invalidunid.getSerialNumber()));
        OCSPReq req = gen.generate();

        // Send the request and receive a singleResponse
        SingleResp singleResp = sendOCSPPost(req.getEncoded());

        CertificateID certId = singleResp.getCertID();
        assertEquals("Serno in response does not match serno in request.", certId.getSerialNumber(), invalidunid.getSerialNumber());
        Object status = singleResp.getCertStatus();
        assertEquals("Status is not null (good)", status, null);
    }

    /** Tests ocsp message with good status but no serialNnumber in the DN
     * @throws Exception error
     */
    public void test03OcspGoodNoSerialNo() throws Exception {
        // And an OCSP request
        OCSPReqGenerator gen = new OCSPReqGenerator();
        gen.addRequest(new CertificateID(CertificateID.HASH_SHA1, cacert, noserno.getSerialNumber()));
        OCSPReq req = gen.generate();

        // Send the request and receive a singleResponse
        SingleResp singleResp = sendOCSPPost(req.getEncoded());

        CertificateID certId = singleResp.getCertID();
        assertEquals("Serno in response does not match serno in request.", certId.getSerialNumber(), noserno.getSerialNumber());
        Object status = singleResp.getCertStatus();
        assertEquals("Status is not null (good)", status, null);
    }

    /** test a lookup request with regular http, should not work
     * 
     * @throws Exception
     */
    public void test04HttpNotAuthorized() throws Exception {
        // An OCSP request for an unknown certificate (not exist in db)
        OCSPReqGenerator gen = new OCSPReqGenerator();
        gen.addRequest(new CertificateID(CertificateID.HASH_SHA1, cacert, new BigInteger("1")));
        OCSPReq req = gen.generate();
        
        // Send the request and receive a singleResponse
        SingleResp singleResp = sendOCSPPost(req.getEncoded());

        CertificateID certId = singleResp.getCertID();
        assertEquals("Serno in response does not match serno in request.", certId.getSerialNumber(), new BigInteger("1"));
        Object status = singleResp.getCertStatus();
        assertTrue("Status is not Unknown", status instanceof UnknownStatus);
    }

    /** test a lookup message from an untrusted requestor, shoudl not work
     * 
     * @throws Exception
     */
    public void test05HttpsNotAuthorized() throws Exception {
        // An OCSP request for an unknown certificate (not exist in db)
        OCSPReqGenerator gen = new OCSPReqGenerator();
        gen.addRequest(new CertificateID(CertificateID.HASH_SHA1, cacert, new BigInteger("1")));
        OCSPReq req = gen.generate();
        
        // Send the request and receive a singleResponse
        SingleResp singleResp = sendOCSPPost(req.getEncoded());

        CertificateID certId = singleResp.getCertID();
        assertEquals("Serno in response does not match serno in request.", certId.getSerialNumber(), new BigInteger("1"));
        Object status = singleResp.getCertStatus();
        assertTrue("Status is not Unknown", status instanceof UnknownStatus);
    }
    //
    // Private helper methods
    //
    
    private SingleResp sendOCSPPost(byte[] ocspPackage) throws IOException, OCSPException, NoSuchProviderException {
        // POST the OCSP request
        URL url = new URL(httpReqPath + '/' + resourceOcsp);
        HttpURLConnection con = (HttpURLConnection)url.openConnection();
        // we are going to do a POST
        con.setDoOutput(true);
        con.setRequestMethod("POST");

        // POST it
        con.setRequestProperty("Content-Type", "application/ocsp-request");
        OutputStream os = con.getOutputStream();
        os.write(ocspPackage);
        os.close();
        assertEquals("Response code", 200, con.getResponseCode());
        assertEquals("Content-Type", "application/ocsp-response", con.getContentType());
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        // This works for small requests, and OCSP requests are small
        InputStream in = con.getInputStream();
        int b = in.read();
        while (b != -1) {
            baos.write(b);
            b = in.read();
        }
        baos.flush();
        in.close();
        byte[] respBytes = baos.toByteArray();
        OCSPResp response = new OCSPResp(new ByteArrayInputStream(respBytes));
        assertEquals("Response status not zero.", response.getStatus(), 0);
        BasicOCSPResp brep = (BasicOCSPResp) response.getResponseObject();
        X509Certificate[] chain = brep.getCerts("BC");
        boolean verify = brep.verify(chain[0].getPublicKey(), "BC");
        assertTrue("Response failed to verify.", verify);
        SingleResp[] singleResps = brep.getResponses();
        assertEquals("No of SingResps shoudl be 1.", singleResps.length, 1);
        SingleResp singleResp = singleResps[0];
        return singleResp;
    }
}
