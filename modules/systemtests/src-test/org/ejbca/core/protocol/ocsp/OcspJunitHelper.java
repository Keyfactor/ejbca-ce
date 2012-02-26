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

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.X509Certificate;
import java.util.Hashtable;
import java.util.Map;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.CertificateID;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.ocsp.OCSPReq;
import org.bouncycastle.ocsp.OCSPReqGenerator;
import org.bouncycastle.ocsp.OCSPResp;
import org.bouncycastle.ocsp.RevokedStatus;
import org.bouncycastle.ocsp.SingleResp;
import org.bouncycastle.ocsp.UnknownStatus;
import org.cesecore.util.Base64;

/**
 * 
 * @version $Id$
 */
public class OcspJunitHelper {

	private static Logger log = Logger.getLogger(OcspJunitHelper.class);

	final private String sBaseURL;
	final private URI baseURI;
	private String urlEnding = "";

	public OcspJunitHelper(String httpReqPath, String resourceOcsp) throws MalformedURLException, URISyntaxException {
		this.sBaseURL = httpReqPath + '/' + resourceOcsp;
		this.baseURI = new URL(this.sBaseURL).toURI();
	}

	public void setURLEnding(String ending) {
		this.urlEnding = "/" + ending;
	}
	/**
	 *
	 * @param ocspPackage
	 * @param nonce
	 * @param respCode expected response code, OK = 0, if not 0, response checking will not continue after response code is checked.
	 * @param httpCode, normally 200 for OK or OCSP error. Can be 400 is more than 1 million bytes is sent for example
	 * @return a SingleResp or null if respCode != 0
	 * @throws IOException
	 * @throws OCSPException
	 * @throws NoSuchProviderException
	 */
	protected SingleResp[] sendOCSPPost(byte[] ocspPackage, String nonce, int respCode, int httpCode) throws IOException, OCSPException, NoSuchProviderException {
		// POST the OCSP request
		URL url = new URL(this.sBaseURL + this.urlEnding);
		HttpURLConnection con = (HttpURLConnection)url.openConnection();
		// we are going to do a POST
		con.setDoOutput(true);
		con.setRequestMethod("POST");

		// POST it
		con.setRequestProperty("Content-Type", "application/ocsp-request");
		OutputStream os = con.getOutputStream();
		os.write(ocspPackage);
		os.close();
		assertEquals("Response code", httpCode, con.getResponseCode());
		if (con.getResponseCode() != 200) {
			return null; // if it is an http error code we don't need to test any more
		}
		// Some appserver (Weblogic) responds with "application/ocsp-response; charset=UTF-8"
		assertNotNull("No Content-Type in reply.", con.getContentType());
		assertTrue(con.getContentType().startsWith("application/ocsp-response"));
		OCSPResp response = new OCSPResp(con.getInputStream());
		assertEquals("Response status not the expected.", respCode, response.getStatus());
		if (respCode != 0) {
			assertNull("According to RFC 2560, responseBytes are not set on error.", response.getResponseObject());
			return null; // it messes up testing of invalid signatures... but is needed for the unsuccessful responses
		}
		BasicOCSPResp brep = (BasicOCSPResp) response.getResponseObject();
		X509Certificate[] chain = brep.getCerts("BC");
		boolean verify = brep.verify(chain[0].getPublicKey(), "BC");
		assertTrue("Response failed to verify.", verify);
		// Check nonce (if we sent one)
		if (nonce != null) {
			byte[] noncerep = brep.getExtensionValue(OCSPObjectIdentifiers.id_pkix_ocsp_nonce.getId());
			assertNotNull(noncerep);
			ASN1InputStream ain = new ASN1InputStream(noncerep);
			ASN1OctetString oct = ASN1OctetString.getInstance(ain.readObject());
			assertEquals(nonce, new String(oct.getOctets()));
		}
		SingleResp[] singleResps = brep.getResponses();
		return singleResps;
	}

	/**
	 *
	 * @param ocspPackage
	 * @param nonce
	 * @param respCode expected response code, OK = 0, if not 0, response checking will not continue after response code is checked.
	 * @param httpCode, normally 200 for OK or OCSP error. Can be 400 is more than 1 million bytes is sent for example
	 * @return a SingleResp or null if respCode != 0
	 * @throws IOException
	 * @throws OCSPException
	 * @throws NoSuchProviderException
	 * @throws NoSuchAlgorithmException
	 */
	protected SingleResp[] sendOCSPGet(byte[] ocspPackage, String nonce, int respCode, int httpCode) throws IOException, OCSPException, NoSuchProviderException, NoSuchAlgorithmException {
		// GET the OCSP request
		String b64 = new String(Base64.encode(ocspPackage, false));
		//String urls = URLEncoder.encode(b64, "UTF-8");	// JBoss/Tomcat will not accept escaped '/'-characters by default
		URL url = new URL(this.sBaseURL + '/' + b64 + this.urlEnding);
		HttpURLConnection con = (HttpURLConnection)url.openConnection();
		if (con.getResponseCode() != httpCode) {
			log.info("URL when request gave unexpected result: " + url.toString() + " Message was: " + con.getResponseMessage());
		}
		assertEquals("Response code did not match. ", httpCode, con.getResponseCode());
		if (con.getResponseCode() != 200) {
			return null; // if it is an http error code we don't need to test any more
		}
		// Some appserver (Weblogic) responds with "application/ocsp-response; charset=UTF-8"
		assertNotNull(con.getContentType());
		assertTrue(con.getContentType().startsWith("application/ocsp-response"));
		OCSPResp response = new OCSPResp(con.getInputStream());
		assertNotNull("Response should not be null.", response);
		assertEquals("Response status not the expected.", respCode, response.getStatus());
		if (respCode != 0) {
			assertNull("According to RFC 2560, responseBytes are not set on error.", response.getResponseObject());
			return null; // it messes up testing of invalid signatures... but is needed for the unsuccessful responses
		}
		BasicOCSPResp brep = (BasicOCSPResp) response.getResponseObject();
		X509Certificate[] chain = brep.getCerts("BC");
		boolean verify = brep.verify(chain[0].getPublicKey(), "BC");
		assertTrue("Response failed to verify.", verify);
		// Check nonce (if we sent one)
		if (nonce != null) {
			byte[] noncerep = brep.getExtensionValue(OCSPObjectIdentifiers.id_pkix_ocsp_nonce.getId());
			assertNotNull(noncerep);
			ASN1InputStream ain = new ASN1InputStream(noncerep);
			ASN1OctetString oct = ASN1OctetString.getInstance(ain.readObject());
			assertEquals(nonce, new String(oct.getOctets()));
		}
		SingleResp[] singleResps = brep.getResponses();
		return singleResps;
	}

	private enum Status {
		Unknown,
		Good,
		Revoked
	}

	/**
	 * Verify that the status is "Unknown"
	 * @param caid
	 * @param cacert
	 * @param certSerial
	 * @throws NoSuchProviderException
	 * @throws IOException
	 * @throws OCSPException
	 */
	public void testStatusUnknown(int caid, X509Certificate cacert, BigInteger certSerial) throws NoSuchProviderException, IOException, OCSPException {
		testStatus(caid, cacert, certSerial, Status.Unknown, Integer.MIN_VALUE);
	}
	/**
	 * Verify that the status is "Good"
	 * @param caid
	 * @param cacert
	 * @param certSerial
	 * @throws NoSuchProviderException
	 * @throws IOException
	 * @throws OCSPException
	 */
	public void testStatusGood(int caid, X509Certificate cacert, BigInteger certSerial) throws NoSuchProviderException, IOException, OCSPException {
		testStatus(caid, cacert, certSerial, Status.Good, Integer.MIN_VALUE);
	}

	/**
	 * Verify that the status is "Revoked" and checks the revocation reason.
	 * @param caid
	 * @param cacert
	 * @param certSerial
	 * @param expectedReason
	 * @throws NoSuchProviderException
	 * @throws IOException
	 * @throws OCSPException
	 */
	public void testStatusRevoked(int caid, X509Certificate cacert, BigInteger certSerial, int expectedReason) throws NoSuchProviderException, IOException, OCSPException {
		testStatus(caid, cacert, certSerial, Status.Revoked, expectedReason);
	}

	private void testStatus(int caid, X509Certificate cacert, BigInteger certSerial, Status expectedStatus, 
			int expectedReason) throws NoSuchProviderException, IOException, OCSPException {
		// And an OCSP request
		final OCSPReqGenerator gen = new OCSPReqGenerator();
		gen.addRequest(new CertificateID(CertificateID.HASH_SHA1, cacert, certSerial));
		log.debug("ocspTestCert.getSerialNumber() = " + certSerial);
		final Hashtable<DERObjectIdentifier, X509Extension> exts = new Hashtable<DERObjectIdentifier, X509Extension>();
		final String sNonce = "123456789";
		final X509Extension ext = new X509Extension(false, new DEROctetString(sNonce.getBytes()));
		exts.put(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, ext);
		gen.setRequestExtensions(new X509Extensions(exts));
		final OCSPReq req = gen.generate();

		// Send the request and receive a singleResponse
		final SingleResp[] singleResps = sendOCSPPost(req.getEncoded(), sNonce, 0, 200);
		assertEquals("No of SingleResps should be 1.", 1, singleResps.length);
		final SingleResp singleResp = singleResps[0];

		final CertificateID certId = singleResp.getCertID();
		assertEquals("Serno in response does not match serno in request.", certId.getSerialNumber(), certSerial);
		final Object status = singleResp.getCertStatus();
		switch ( expectedStatus ) {
		case Unknown:
			assertTrue("Status is not Unknown", status instanceof UnknownStatus);
			break;
		case Good:
			if ( status!=org.bouncycastle.ocsp.CertificateStatus.GOOD ) {
				log.debug("Certificate status: " + status.getClass().getName());
			}
			assertEquals("Status is not Good", org.bouncycastle.ocsp.CertificateStatus.GOOD, status);
			break;
		case Revoked:
			assertTrue("Status is not Revoked", status instanceof RevokedStatus);
			final int reason = ((RevokedStatus)status).getRevocationReason();
			assertEquals("Wrong revocation reason", expectedReason, reason);
			break;
		}
	}

	public void reloadKeys() throws IOException, URISyntaxException {
		servletGetWithParam("reloadkeys=true");
	}

	public void alterConfig(final Map<String, String> config) throws IOException, URISyntaxException {
		if ( config==null || config.size()<1 ) {
			return;
		}
		final StringBuffer sb = new StringBuffer("newConfig=");
		for( Map.Entry<String, String> entry : config.entrySet() ) {
			sb.append(entry.getKey());
			sb.append('=');
			sb.append(entry.getValue());
			sb.append("||");
		}
		sb.delete(sb.length()-2,sb.length());// remove last "<>
		servletGetWithParam(sb.toString());
	}

	private void servletGetWithParam(String param) throws IOException, URISyntaxException {
		final URI uriWithParam = new URI(
				this.baseURI.getScheme(), this.baseURI.getUserInfo(), this.baseURI.getHost(),
				this.baseURI.getPort(), this.baseURI.getPath(), param, this.baseURI.getFragment());
		final URL url = uriWithParam.toURL();
		final HttpURLConnection con = (HttpURLConnection)url.openConnection();
		assertEquals("Response code", HttpURLConnection.HTTP_OK, con.getResponseCode());
		con.disconnect();
	}
}
