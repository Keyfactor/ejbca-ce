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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID;
import org.bouncycastle.ocsp.OCSPRespGenerator;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateStatus;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.ocsp.cache.SHA1DigestCalculator;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.junit.After;

import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.WebConnection;
import com.gargoylesoftware.htmlunit.WebRequestSettings;
import com.gargoylesoftware.htmlunit.WebResponse;

/**
 *
 * @version $Id$
 *
 */
public abstract class ProtocolOcspTestBase extends CaTestCase {

	private static final Logger log = Logger.getLogger(ProtocolOcspTestBase.class);

	protected static final String issuerDN = "CN=AdminCA1,O=EJBCA Sample,C=SE";
	protected static final byte[] unknowncacertBytes = Base64.decode(("MIICLDCCAZWgAwIBAgIIbzEhUVZYO3gwDQYJKoZIhvcNAQEFBQAwLzEPMA0GA1UE"
			+ "AxMGVGVzdENBMQ8wDQYDVQQKEwZBbmFUb20xCzAJBgNVBAYTAlNFMB4XDTAyMDcw" + "OTEyNDc1OFoXDTA0MDgxNTEyNTc1OFowLzEPMA0GA1UEAxMGVGVzdENBMQ8wDQYD"
			+ "VQQKEwZBbmFUb20xCzAJBgNVBAYTAlNFMIGdMA0GCSqGSIb3DQEBAQUAA4GLADCB" + "hwKBgQDZlACHRwJnQKlgpMqlZQmxvCrJPpPFyhxvjDHlryhp/AQ6GCm+IkGUVlwL"
			+ "sCnjgZH5BXDNaVXpkmME8334HFsxVlXqmZ2GqyP6kptMjbWZ2SRLBRKjAcI7EJIN" + "FPDIep9ZHXw1JDjFGoJ4TLFd99w9rQ3cB6zixORoyCZMw+iebwIBEaNTMFEwDwYD"
			+ "VR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUY3v0dqhUJI6ldKV3RKb0Xg9XklEwHwYD" + "VR0jBBgwFoAUY3v0dqhUJI6ldKV3RKb0Xg9XklEwDQYJKoZIhvcNAQEFBQADgYEA"
			+ "i1P53jnSPLkyqm7i3nLNi+hG7rMgF+kRi6ZLKhzIPyKcAWV8iZCI8xl/GurbZ8zd" + "nTiIOfQIP9eD/nhIIo7n4JOaTUeqgyafPsEgKdTiZfSdXjvy6rj5GiZ3DaGZ9SNK"
			+ "FgrCpX5kBKVbbQLO6TjJKCjX29CfoJ2TbP1QQ6UbBAY=").getBytes());


	final protected String httpPort;
	final protected String httpReqPath;
	final protected String resourceOcsp;
	final protected OcspJunitHelper helper;

	protected X509Certificate cacert = null;
	protected X509Certificate ocspTestCert = null;
	protected X509Certificate unknowncacert = null;

	protected int caid;

	private CertificateStoreSessionRemote certificateStoreOnlyDataSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class); // Stand alone OCSP version..

	ProtocolOcspTestBase(String protocol, String host, int port, String applicationPath, String _resourceOcsp) throws MalformedURLException, URISyntaxException {
		this.httpPort = Integer.toString(port);
		this.httpReqPath = protocol+"://"+host+":" + port + "/" + applicationPath;
		this.resourceOcsp = _resourceOcsp;
		this.helper = new OcspJunitHelper(this.httpReqPath, this.resourceOcsp);

	}

	@After
	public void restoreConfig() throws Exception {
		this.helper.restoreConfig();
	}

	protected void test01Access() throws Exception { // NOPMD, this is not a test class itself
		// Hit with GET does work since EJBCA 3.8.2
		final WebClient webClient = new WebClient();
		WebConnection con = webClient.getWebConnection();
		WebRequestSettings settings = new WebRequestSettings(new URL(httpReqPath + '/' + resourceOcsp));
		WebResponse resp = con.getResponse(settings);
		assertEquals("Response code", 200, resp.getStatusCode());
	}

	/**
	 * Tests ocsp message
	 *
	 * @throws Exception
	 *			 error
	 */
	protected void test04OcspUnknown() throws Exception { // NOPMD, this is not a test class itself
		log.trace(">test04OcspUnknown()");
		loadUserCert(this.caid);
		// An OCSP request for an unknown certificate (not exist in db)
		this.helper.verifyStatusUnknown( this.caid, this.cacert, new BigInteger("1"));
		log.trace("<test04OcspUnknown()");
	}

	/**
	 * Tests ocsp message
	 *
	 * @throws Exception
	 *			 error
	 */
	protected void test05OcspUnknownCA() throws Exception { // NOPMD, this is not a test class itself
		log.trace(">test05OcspUnknownCA()");
		loadUserCert(this.caid);
		// An OCSP request for a certificate from an unknwon CA
		this.helper.verifyStatusUnknown( this.caid, this.unknowncacert, new BigInteger("1"));

		log.trace("<test05OcspUnknownCA()");
	}

	protected void test06OcspSendWrongContentType() throws Exception { // NOPMD, this is not a test class itself
		loadUserCert(this.caid);
		// An OCSP request for a certificate from an unknwon CA
		OCSPReqBuilder gen = new OCSPReqBuilder();
		gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), unknowncacert, new BigInteger("1")));
		OCSPReq req = gen.build();
		// POST the OCSP request
		URL url = new URL(httpReqPath + '/' + resourceOcsp);
		HttpURLConnection con = (HttpURLConnection) url.openConnection();
		// we are going to do a POST
		con.setDoOutput(true);
		con.setRequestMethod("POST");
		// POST it, but don't add content type
		OutputStream os = con.getOutputStream();
		os.write(req.getEncoded());
		os.close();
		assertEquals("Response code", 400, con.getResponseCode());

	}

	protected void test10MultipleRequests() throws Exception { // NOPMD, this is not a test class itself
		// Tests that we handle multiple requests in one OCSP request message

		loadUserCert(this.caid);
		// An OCSP request for a certificate from an unknown CA
		OCSPReqBuilder gen = new OCSPReqBuilder();
		gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), unknowncacert, new BigInteger("1")));

		// Get user and ocspTestCert that we know...
		loadUserCert(this.caid);
		gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), cacert, ocspTestCert.getSerialNumber()));
		Extension[] extensions = new Extension[0];
		extensions[0] = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString("123456789".getBytes()));
		gen.setRequestExtensions(new Extensions(extensions));
		
		OCSPReq req = gen.build();

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
	 * In compliance with RFC 2560 on
	 * "ASN.1 Specification of the OCSP Response": If the value of
	 * responseStatus is one of the error conditions, responseBytes are not set.
	 *
	 * OCSPResponse ::= SEQUENCE { responseStatus OCSPResponseStatus,
	 * responseBytes [0] EXPLICIT ResponseBytes OPTIONAL }
	 */
	protected void test11MalformedRequest() throws Exception { // NOPMD, this is not a test class itself
		loadUserCert(this.caid);
		OCSPReqBuilder gen = new OCSPReqBuilder();
		// Add 101 OCSP requests.. the Servlet will consider a request with more
		// than 100 malformed..
		// This does not mean that we only should allow 100 in the future, just
		// that we if so need to find
		// another way make the Servlet return
		// OCSPRespGenerator.MALFORMED_REQUEST
		for (int i = 0; i < 101; i++) {
			gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), cacert, ocspTestCert.getSerialNumber()));
		}
		Extension[] extensions = new Extension[0];
		extensions[0] = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString("123456789".getBytes()));
		gen.setRequestExtensions(new Extensions(extensions));
		OCSPReq req = gen.build();
		// Send the request and receive null
		SingleResp[] singleResps = helper.sendOCSPPost(req.getEncoded(), "123456789", OCSPRespBuilder.MALFORMED_REQUEST, 200);
		assertNull("No SingleResps should be returned.", singleResps);
	}

	protected void test12CorruptRequests() throws Exception { // NOPMD, this is not a test class itself
		log.trace(">test12CorruptRequests()");
		loadUserCert(this.caid);
		// An OCSP request, ocspTestCert is already created in earlier tests
		OCSPReqBuilder gen = new OCSPReqBuilder();
		gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), cacert, ocspTestCert.getSerialNumber()));
		Extension[] extensions = new Extension[0];
		extensions[0] = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString("123456789".getBytes()));
		gen.setRequestExtensions(new Extensions(extensions));
		OCSPReq req = gen.build();

		// Request 1
		//
		// Send the request and receive a singleResponse
		byte[] orgbytes = req.getEncoded(); // Save original bytes, so we can
		// make different strange values
		byte[] bytes = req.getEncoded();
		// Switch the first byte, now it's a really corrupted request
		bytes[0] = 0x44;
		SingleResp[] singleResps = helper.sendOCSPPost(bytes, "123456789", OCSPRespGenerator.MALFORMED_REQUEST, 200); // error
		// code
		// 1
		// means
		// malformed
		// request
		assertNull("SingleResps should be null.", singleResps);

		// Request 2
		//
		// Remove the last byte, should still be quite corrupted
		// bytes = Arrays.copyOf(orgbytes, orgbytes.length-1); only works in
		// Java 6
		bytes = ArrayUtils.remove(orgbytes, orgbytes.length - 1);
		singleResps = helper.sendOCSPPost(bytes, "123456789", OCSPRespGenerator.MALFORMED_REQUEST, 200); // error
		// code
		// 1
		// means
		// malformed
		// request
		assertNull("SingleResps should be null.", singleResps);

		// Request 3
		//
		// more than 1 million bytes
		// bytes = Arrays.copyOf(orgbytes, 1000010); only works in Java 6
		bytes = ArrayUtils.addAll(orgbytes, new byte[1000010]);
		singleResps = helper.sendOCSPPost(bytes, "123456789", OCSPRespGenerator.MALFORMED_REQUEST, 200); // //
		// error
		// code
		// 1
		// means
		// malformed
		// request
		assertNull("SingleResps should be null.", singleResps);

		// Request 4
		//
		//
		// A completely empty request with no question in it
		gen = new OCSPReqBuilder();
		req = gen.build();
		bytes = req.getEncoded();
		singleResps = helper.sendOCSPPost(bytes, "123456789", 1, 200); //
		assertNull("SingleResps should be null.", singleResps);

		log.trace("<test12CorruptRequests()");
	}

	/**
	 * Just verify that a simple GET works.
	 */
	protected void test13GetRequests() throws Exception { // NOPMD, this is not a test class itself
		loadUserCert(this.caid);
		// See if the OCSP Servlet can read non-encoded requests
		final String plainReq = httpReqPath
				+ '/'
				+ resourceOcsp
				+ '/'
				+ "MGwwajBFMEMwQTAJBgUrDgMCGgUABBRBRfilzPB+Aevx0i1AoeKTkrHgLgQUFJw5gwk9BaEgsX3pzsRF9iso29ICCCzdx5N0v9XwoiEwHzAdBgkrBgEFBQcwAQIEECrZswo/a7YW+hyi5Sn85fs=";
		URL url = new URL(plainReq);
		log.info(url.toString()); // Dump the exact string we use for access
		HttpURLConnection con = (HttpURLConnection) url.openConnection();
		assertEquals("Response code did not match. ", 200, con.getResponseCode());
		assertNotNull(con.getContentType());
		assertTrue(con.getContentType().startsWith("application/ocsp-response"));
		OCSPResp response = new OCSPResp(IOUtils.toByteArray(con.getInputStream()));
		assertNotNull("Response should not be null.", response);
		assertTrue("Should not be concidered malformed.", OCSPRespBuilder.MALFORMED_REQUEST != response.getStatus());
		final String dubbleSlashNonEncReq = "http://127.0.0.1:"
				+ httpPort
				+ "/ejbca/publicweb/status/ocsp/MGwwajBFMEMwQTAJBgUrDgMCGgUABBRBRfilzPB%2BAevx0i1AoeKTkrHgLgQUFJw5gwk9BaEgsX3pzsRF9iso29ICCAvB//HJyKqpoiEwHzAdBgkrBgEFBQcwAQIEEOTzT2gv3JpVva22Vj8cuKo%3D";
		url = new URL(dubbleSlashNonEncReq);
		log.info(url.toString()); // Dump the exact string we use for access
		con = (HttpURLConnection) url.openConnection();
		assertEquals("Response code did not match. ", 200, con.getResponseCode());
		assertNotNull(con.getContentType());
		assertTrue(con.getContentType().startsWith("application/ocsp-response"));
		response = new OCSPResp(IOUtils.toByteArray(con.getInputStream()));
		assertNotNull("Response should not be null.", response);
		assertTrue("Should not be concidered malformed.", OCSPRespBuilder.MALFORMED_REQUEST != response.getStatus());
		// An OCSP request, ocspTestCert is already created in earlier tests
		OCSPReqBuilder gen = new OCSPReqBuilder();
		loadUserCert(this.caid);
		gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), cacert, ocspTestCert.getSerialNumber()));
		OCSPReq req = gen.build();
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
	protected void test14CorruptGetRequests() throws Exception { // NOPMD, this is not a test class itself
		// An array of zeros cannot be right..
		// A GET request larger than 2048 works on JBoss but not on Glassfish,
		// GF only gives "unexpected end of file", i.e. it closes the connection
		helper.sendOCSPGet(new byte[2048], null, OCSPRespGenerator.MALFORMED_REQUEST, 200);
		// Send an empty GET request: .../ocsp/{nothing}
		helper.sendOCSPGet(new byte[0], null, OCSPRespGenerator.MALFORMED_REQUEST, 200);
		// Test too large requests
		/*
		 * try { // When we use an URL of length ~ 8100 chars on JBoss we get a
		 * "Connection reset", // JBoss 5 considers this a bad request (400) //
		 * so we cannot test the real Malformed response we want here
		 * helper.sendOCSPGet(new byte[6020], null,
		 * OCSPRespGenerator.MALFORMED_REQUEST, 200); } catch (IOException e) {
		 * log.info(e.getMessage()); } try { // When we use an URL of length ~ >
		 * 500000 chars on JBoss we get a "Error writing to server", // so we
		 * cannot test the real Malformed response we want here caused by to
		 * large requests helper.sendOCSPGet(new byte[1000001], null,
		 * OCSPRespGenerator.MALFORMED_REQUEST, 200); } catch (IOException e) {
		 * log.info(e.getMessage()); }
		 */
	}

	/**
	 * Send multiple requests in one GET request. RFC 5019 2.1.1 prohibits
	 * clients from this, but the server should be RFC 2560 compatible and
	 * support this as long as the total request URL is smaller than 256 bytes.
	 */
	protected void test15MultipleGetRequests() throws Exception { // NOPMD, this is not a test class itself
		loadUserCert(this.caid);
		this.helper.reloadKeys();
		// An OCSP request, ocspTestCert is already created in earlier tests
		OCSPReqBuilder gen = new OCSPReqBuilder();
		gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), cacert, ocspTestCert.getSerialNumber()));
		gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), cacert, new BigInteger("1")));
		OCSPReq req = gen.build();
		SingleResp[] singleResps = helper.sendOCSPGet(req.getEncoded(), null, OCSPRespBuilder.SUCCESSFUL, 200);
		assertNotNull("SingleResps should not be null.", singleResps);
		assertEquals("Serno in response does not match serno in request.", singleResps[0].getCertID().getSerialNumber(), ocspTestCert.getSerialNumber());
		assertTrue("Serno in response does not match serno in request.", singleResps[1].getCertID().getSerialNumber().toString().equals("1"));
		assertEquals("Status is not null (null is 'good')", null, singleResps[0].getCertStatus());
		assertTrue("Status is not unknown", singleResps[1].getCertStatus() instanceof UnknownStatus);
	}


	protected void loadUserCert(int caid) throws Exception {
		ocspTestCert = getTestCert(false);
		cacert = getCaCert(ocspTestCert);
	}

	protected X509Certificate getTestCert(boolean isRevoked) {
		try {
			Collection<Certificate> certs = certificateStoreOnlyDataSession.findCertificatesByUsername("ocspTest");
			Iterator<Certificate> i = certs.iterator();
			while (i.hasNext()) {
				X509Certificate cert = (X509Certificate) i.next();
				CertificateStatus cs = certificateStoreOnlyDataSession.getStatus(issuerDN, CertTools.getSerialNumber(cert));
				if (isRevoked == cs.equals(CertificateStatus.REVOKED)) {
					return cert;
				}
			}
		} catch (Exception e) {
			log.debug("", e);
		}
		assertNotNull("To run this test you must have at least one active and one revoked end user cert in the database. (Could not fetch certificate.)", null);
		return null;
	}

	protected X509Certificate getCaCert(X509Certificate cert) throws Exception {
		Collection<Certificate> certs = certificateStoreOnlyDataSession.findCertificatesByType(CertificateConstants.CERTTYPE_ROOTCA, CertTools.getIssuerDN(cert));
		assertTrue("Could not determine or find the CA cert.", certs != null && !certs.isEmpty());
		return (X509Certificate) certs.iterator().next();
	}

}