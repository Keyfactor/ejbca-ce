package se.anatom.ejbca.protocol;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.NoSuchProviderException;
import java.security.cert.X509Certificate;

import junit.framework.TestCase;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.ocsp.OCSPResp;
import org.bouncycastle.ocsp.SingleResp;

public class OcspJunitHelper extends TestCase {

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
	 * @return a SingleResp or null if respCode != 0
	 * @throws IOException
	 * @throws OCSPException
	 * @throws NoSuchProviderException
	 */
    protected SingleResp sendOCSPPost(byte[] ocspPackage, String nonce, int respCode) throws IOException, OCSPException, NoSuchProviderException {
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
        assertEquals("Response status not zero.", respCode, response.getStatus());
        if (respCode != 0) {
        	return null;
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
        assertEquals("No of SingResps should be 1.", singleResps.length, 1);
        SingleResp singleResp = singleResps[0];
        return singleResp;
    }
    
    protected void reloadKeys() throws IOException, OCSPException, NoSuchProviderException {
        // POST the OCSP request
        URL url = new URL(httpReqPath + '/' + resourceOcsp+"?reloadkeys=true");
        HttpURLConnection con = (HttpURLConnection)url.openConnection();
        // we are going to do a POST
        con.setDoOutput(true);
        con.setRequestMethod("GET");

        // POST it
        con.setRequestProperty("reloadkeys", "true");
        con.connect();
        assertEquals("Response code", 405, con.getResponseCode());
        con.disconnect();
    }

}
