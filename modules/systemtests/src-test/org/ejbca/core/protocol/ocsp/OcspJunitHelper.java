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
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Map;

import org.apache.commons.io.IOUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.cesecore.certificates.ocsp.SHA1DigestCalculator;
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
		log.info("sBaseURL="+sBaseURL);
		this.baseURI = new URL(this.sBaseURL).toURI();
	}

	public void setURLEnding(String ending) {
		if ( ending==null || ending.length()<1 ) {
			this.urlEnding = "";
		}
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
	 * @throws CertificateException on parsing errors.
	 * @throws OperatorCreationException 
	 */
	protected SingleResp[] sendOCSPPost(byte[] ocspPackage, String nonce, int respCode, int httpCode) throws IOException, OCSPException, NoSuchProviderException, OperatorCreationException, CertificateException {
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
		OCSPResp response = new OCSPResp(IOUtils.toByteArray(con.getInputStream()));
		assertEquals("Response status not the expected.", respCode, response.getStatus());
		if (respCode != 0) {
			assertNull("According to RFC 2560, responseBytes are not set on error.", response.getResponseObject());
			return null; // it messes up testing of invalid signatures... but is needed for the unsuccessful responses
		}
		BasicOCSPResp brep = (BasicOCSPResp) response.getResponseObject();
		X509CertificateHolder[] chain = brep.getCerts();
		assertNotNull("No certificate chain returned in response (chain == null), is ocsp.includesignercert=false in ocsp.properties?. It should be set to default value for test to run.", chain);
		boolean verify = brep.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build(chain[0]));
		assertTrue("Response failed to verify.", verify);
		// Check nonce (if we sent one)
		if (nonce != null) {
			byte[] noncerep = brep.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce).getExtnValue().getEncoded();
			assertNotNull(noncerep);
			ASN1InputStream ain = new ASN1InputStream(noncerep);
			ASN1OctetString oct = ASN1OctetString.getInstance(ain.readObject());
			ain.close();
			assertEquals(nonce, new String(oct.getOctets()));
		}
		SingleResp[] singleResps = brep.getResponses();
		return singleResps;
	}
	
	protected  BasicOCSPResp sendOCSPGet(byte[] ocspPackage, String nonce, int respCode, int httpCode) 
	            throws IOException, OCSPException, NoSuchProviderException, NoSuchAlgorithmException, 
	            OperatorCreationException, CertificateException {
	    return sendOCSPGet(ocspPackage, nonce, respCode, httpCode, true, null);
	}

	/**
	 *
	 * @param ocspPackage
	 * @param nonce
	 * @param respCode expected response code, OK = 0, if not 0, response checking will not continue after response code is checked.
	 * @param httpCode, normally 200 for OK or OCSP error. Can be 400 is more than 1 million bytes is sent for example
	 * @return a BasicOCSPResp or null if not found
	 * @throws IOException
	 * @throws OCSPException
	 * @throws NoSuchProviderException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException on parsing errors.
	 * @throws OperatorCreationException 
	 */
	protected  BasicOCSPResp sendOCSPGet(byte[] ocspPackage, String nonce, int respCode, int httpCode, boolean shouldIncludeSignCert,
	            X509Certificate signCert) throws IOException, OCSPException, NoSuchProviderException, NoSuchAlgorithmException, 
	            OperatorCreationException, CertificateException {
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
		OCSPResp response = new OCSPResp(IOUtils.toByteArray(con.getInputStream()));
		assertNotNull("Response should not be null.", response);
		assertEquals("Response status not the expected.", respCode, response.getStatus());
		if (respCode != 0) {
			assertNull("According to RFC 2560, responseBytes are not set on error.", response.getResponseObject());
			return null; // it messes up testing of invalid signatures... but is needed for the unsuccessful responses
		}
		BasicOCSPResp brep = (BasicOCSPResp) response.getResponseObject();
		
		final X509CertificateHolder signCertHolder;
		if(!shouldIncludeSignCert) {
		    assertEquals("The signing certificate should not be included in the OCSP response ", 0, brep.getCerts().length);
		    signCertHolder = new JcaX509CertificateHolder(signCert);
		} else {
		    X509CertificateHolder[] chain = brep.getCerts();
		    signCertHolder = chain[0];
		}
		boolean verify = brep.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build(signCertHolder));
		
		assertTrue("Response failed to verify.", verify);
		// Check nonce (if we sent one)
		if (nonce != null) {
			byte[] noncerep = brep.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce).getExtnValue().getEncoded();
			assertNotNull(noncerep);
			ASN1InputStream ain = new ASN1InputStream(noncerep);
			ASN1OctetString oct = ASN1OctetString.getInstance(ain.readObject());
			ain.close();
			assertEquals(nonce, new String(oct.getOctets()));
		}
		return brep;
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
	 * @throws CertificateException 
	 * @throws OperatorCreationException 
	 */
	public void verifyStatusUnknown(int caid, X509Certificate cacert, BigInteger certSerial) throws NoSuchProviderException, IOException, OCSPException, OperatorCreationException, CertificateException {
		verifyStatus(caid, cacert, certSerial, OCSPRespBuilder.SUCCESSFUL, Status.Unknown, Integer.MIN_VALUE, null);
	}

   /**
     * Verify that the OCSP response code is Internal Error.
     * @param caid
     * @param cacert
     * @param certSerial
     * @throws NoSuchProviderException
     * @throws IOException
     * @throws OCSPException
     * @throws CertificateException 
     * @throws OperatorCreationException 
     */
    public void verifyResponseInternalError(int caid, X509Certificate cacert, BigInteger certSerial) throws NoSuchProviderException, IOException, OCSPException, OperatorCreationException, CertificateException {
        verifyStatus(caid, cacert, certSerial, OCSPRespBuilder.INTERNAL_ERROR, Status.Unknown, Integer.MIN_VALUE, null);
    }
    
    public void verifyResponseUnauthorized(int caid, X509Certificate cacert, BigInteger certSerial) throws NoSuchProviderException, OperatorCreationException, CertificateException, IOException, OCSPException {
        verifyStatus(caid, cacert, certSerial, OCSPRespBuilder.UNAUTHORIZED, Status.Unknown, Integer.MIN_VALUE, null);
    }

	/**
	 * Verify that the status is "Good"
	 * @param caid
	 * @param cacert
	 * @param certSerial
	 * @throws NoSuchProviderException
	 * @throws IOException
	 * @throws OCSPException
	 * @throws CertificateException 
	 * @throws OperatorCreationException 
	 */
	public void verifyStatusGood(int caid, X509Certificate cacert, BigInteger certSerial) throws NoSuchProviderException, IOException, OCSPException, OperatorCreationException, CertificateException {
		verifyStatus(caid, cacert, certSerial, OCSPRespBuilder.SUCCESSFUL, Status.Good, Integer.MIN_VALUE, null);
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
	 * @throws CertificateException 
	 * @throws OperatorCreationException 
	 */
	public void verifyStatusRevoked(int caid, X509Certificate cacert, BigInteger certSerial, int expectedReason, Date expectedRevTime) throws NoSuchProviderException, IOException, OCSPException, OperatorCreationException, CertificateException {
		verifyStatus(caid, cacert, certSerial, OCSPRespBuilder.SUCCESSFUL, Status.Revoked, expectedReason, expectedRevTime);
	}

	private void verifyStatus(int caid, X509Certificate cacert, BigInteger certSerial, int ocspResponseStatus, Status expectedStatus, 
			int expectedReason, Date expectedRevTime) throws NoSuchProviderException, IOException, OCSPException, OperatorCreationException, CertificateException {
		// And an OCSP request
		final OCSPReqBuilder gen = new OCSPReqBuilder();
		gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), cacert, certSerial));
		log.debug("ocspTestCert.getSerialNumber() = " + certSerial);
		final String sNonce = "123456789";
		Extension[] extensions = new Extension[1];
		extensions[0] = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString(sNonce.getBytes()));
		gen.setRequestExtensions(new Extensions(extensions));
		
		final OCSPReq req = gen.build();

		// Send the request and receive a singleResponse
		final SingleResp[] singleResps = sendOCSPPost(req.getEncoded(), sNonce, ocspResponseStatus, 200);
		// if we expected internal error, we should not expect any data, and can not make any more tests
		if (ocspResponseStatus == OCSPRespBuilder.INTERNAL_ERROR) {
		    return;
		}
		
		if (ocspResponseStatus == OCSPRespBuilder.UNAUTHORIZED) {
            return;
        }
		assertEquals("No of SingleResps should be 1.", 1, singleResps.length);
		final SingleResp singleResp = singleResps[0];

		final CertificateID certId = singleResp.getCertID();
		assertEquals("Serno in response does not match serno in request.", certId.getSerialNumber(), certSerial);
		final Object status = singleResp.getCertStatus();
		final String statusClassName = status!=null ? status.getClass().getName() : "GOOD";// status==null means GOOD
		switch ( expectedStatus ) {
		case Unknown:
			assertTrue("Status is not Unknown: "+statusClassName, status instanceof UnknownStatus);
			break;
		case Good:
            if (status != CertificateStatus.GOOD) {
                log.debug("Certificate status: " + status.getClass().getName());
            }
			assertEquals("Status is not Good, was: " + statusClassName +".", CertificateStatus.GOOD, status);
			break;
		case Revoked:
			assertTrue("Status is not Revoked: "+statusClassName, status instanceof RevokedStatus);
			final int reason = ((RevokedStatus)status).getRevocationReason();
			assertEquals("Wrong revocation reason", expectedReason, reason);
			if(expectedRevTime != null) {
			    final Date revTime = ((RevokedStatus) status).getRevocationTime();
			    assertEquals("Wrong revocation time", expectedRevTime, revTime);
			}
			break;
		}
	}

	public void reloadKeys() throws IOException, URISyntaxException {
		servletGetWithParam("reloadkeys=true");
	}

	public void restoreConfig() throws IOException, URISyntaxException {
		servletGetWithParam("restoreConfig=");
	}

	public void renewAllKeys() throws IOException, URISyntaxException {
	    servletGetWithParam("renewSigner=all\\&password=foo123");
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
		sb.delete(sb.length()-2,sb.length());// remove last "||"
		servletGetWithParam(sb.toString());
	}

	/** Send command  */
	private void servletGetWithParam(String param) throws IOException, URISyntaxException {
	    /* Only localhost is allowed as sender, so no fancy external target used here
		final URI uriWithParam = new URI(
				this.baseURI.getScheme(), this.baseURI.getUserInfo(), this.baseURI.getHost(),
				this.baseURI.getPort(), this.baseURI.getPath(), param, this.baseURI.getFragment());
				*/
        final URI uriWithParam = new URI(
                this.baseURI.getScheme(), this.baseURI.getUserInfo(), "127.0.0.1",
                8080, this.baseURI.getPath(), param, this.baseURI.getFragment());
		final URL url = uriWithParam.toURL();
		final HttpURLConnection con = (HttpURLConnection)url.openConnection();
		log.debug("Connection to " + url.toExternalForm() + " resulted in HTTP " + con.getResponseCode());
		assertEquals("Response code", HttpURLConnection.HTTP_OK, con.getResponseCode());
		con.disconnect();
	}
}
