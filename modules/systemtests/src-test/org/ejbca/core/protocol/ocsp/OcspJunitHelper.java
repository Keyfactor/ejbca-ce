package org.ejbca.core.protocol.ocsp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.X509Certificate;

import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.ocsp.OCSPResp;
import org.bouncycastle.ocsp.SingleResp;
import org.ejbca.util.Base64;

public class OcspJunitHelper extends TestCase {
	
	private static Logger log = Logger.getLogger(OcspJunitHelper.class);

	private String httpReqPath = "";
	private String resourceOcsp = "";
	
	public OcspJunitHelper(String httpReqPath, String resourceOcsp) {
		this.httpReqPath = httpReqPath;
		this.resourceOcsp = resourceOcsp;
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
        assertEquals("Response code", httpCode, con.getResponseCode());
        if (con.getResponseCode() != 200) {
            return null; // if it is an http error code we don't need to test any more
        }
        // Some appserver (Weblogic) responds with "application/ocsp-response; charset=UTF-8"
        assertNotNull("No Content-Type in reply.", con.getContentType());
        assertTrue(con.getContentType().startsWith("application/ocsp-response"));
        OCSPResp response = new OCSPResp(new ByteArrayInputStream(inputStreamToBytes(con.getInputStream())));
        assertEquals("Response status not the expected.", respCode, response.getStatus());
        if (respCode != 0) {
            assertNull("According to RFC 2560, responseBytes are not set on error.", (BasicOCSPResp) response.getResponseObject());
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
    	URL url = new URL(httpReqPath + '/' + resourceOcsp + '/' + b64);
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
        OCSPResp response = new OCSPResp(new ByteArrayInputStream(inputStreamToBytes(con.getInputStream())));
        assertNotNull("Response should not be null.", response);
        assertEquals("Response status not the expected.", respCode, response.getStatus());
        if (respCode != 0) {
            assertNull("According to RFC 2560, responseBytes are not set on error.", (BasicOCSPResp) response.getResponseObject());
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
    
    protected void reloadKeys() throws IOException, OCSPException, NoSuchProviderException {
        URL url = new URL(httpReqPath + '/' + resourceOcsp+"?reloadkeys=true");
        HttpURLConnection con = (HttpURLConnection)url.openConnection();
        assertEquals("Response code", 200, con.getResponseCode());
        con.disconnect();
    }

    /**
     * For small streams only.
     */
    static byte[] inputStreamToBytes(InputStream in) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        int b = in.read();
        while (b != -1) {
        	baos.write(b);
        	b = in.read();
        }
        baos.flush();
        in.close();
        return  baos.toByteArray();
    }
}
