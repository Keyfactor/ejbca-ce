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
import java.io.OutputStream;
import java.lang.reflect.Method;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import junit.framework.TestSuite;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.CertificateID;
import org.bouncycastle.ocsp.OCSPReq;
import org.bouncycastle.ocsp.OCSPReqGenerator;
import org.bouncycastle.ocsp.OCSPResp;
import org.bouncycastle.ocsp.OCSPRespGenerator;
import org.bouncycastle.ocsp.RevokedStatus;
import org.bouncycastle.ocsp.SingleResp;
import org.bouncycastle.util.encoders.Hex;
import org.ejbca.core.ejb.ServiceLocator;
import org.ejbca.core.ejb.ca.store.CertificateStatus;
import org.ejbca.core.ejb.ca.store.ICertificateStoreOnlyDataSessionHome;
import org.ejbca.core.ejb.ca.store.ICertificateStoreOnlyDataSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;

/** Tests HTTP pages of a stand-alone OCSP
 * To run this test you must create a user named ocspTest that has at least two certificates and
 * at least one of them must be revoked.
 * 
 * Change the address 127.0.0.1 to where you stand-alone OCSP server is running.
 * Change myCaId to the CA that ocspTest belongs to
 **/
public class ProtocolOcspHttpStandaloneTest extends ProtocolOcspHttpTest {

	private static final Logger log = Logger.getLogger(ProtocolOcspHttpStandaloneTest.class);
	private static final String issuerDN = "CN=AdminCA1,O=EJBCA Sample,C=SE";

	private static ICertificateStoreOnlyDataSessionRemote certificateStoreOnlyDataSession;

    private static final int myCaId = issuerDN.hashCode();	
    private static final String myOcspIp = "127.0.0.1";
    
    public static void main(String args[]) {
        junit.textui.TestRunner.run(suite());
    }

    public static TestSuite suite() {
    	// Only include "test*"-methods from this class, not from the parent class
    	TestSuite ret = new TestSuite();
    	try {
    		Method[] methods = ProtocolOcspHttpStandaloneTest.class.getDeclaredMethods();
    		for (int i=0; i<methods.length; i++) {
    			String name = methods[i].getName();
    			if (name.startsWith("test")) {
    	    		ret.addTest(new ProtocolOcspHttpStandaloneTest(name));
    			}
    		}
    	} catch(Exception e) {
    		log.error("",e);
    	}
    	return ret;
    }

    public ProtocolOcspHttpStandaloneTest(String name) throws Exception {
        super(name, "http://"+myOcspIp+":8080/ejbca", "publicweb/status/ocsp");
        caid = myCaId;
    }
    
	private static ICertificateStoreOnlyDataSessionRemote getCertificateStoreOnlyDataSession() {
		try {
			if (certificateStoreOnlyDataSession == null) {
				certificateStoreOnlyDataSession = ((ICertificateStoreOnlyDataSessionHome) ServiceLocator.getInstance().getRemoteHome(ICertificateStoreOnlyDataSessionHome.JNDI_NAME, ICertificateStoreOnlyDataSessionHome.class)).create();
			}
		} catch (Exception e) {
			log.error("", e);
			return null;
		}
		return certificateStoreOnlyDataSession;
	}

    protected void loadUserCert(int caid) throws Exception {
    	ocspTestCert = getTestCert(false);
    	cacert = getCaCert(ocspTestCert);
    }
    
	public void test01Access() throws Exception {
        super.test01Access();
    }

    /** Tests ocsp message
     * @throws Exception error
     */
    public void test02OcspGood() throws Exception {
        log.trace(">test02OcspGood()");

        // And an OCSP request
        OCSPReqGenerator gen = new OCSPReqGenerator();
        final X509Certificate ocspTestCert = getTestCert(false);
        gen.addRequest(new CertificateID(CertificateID.HASH_SHA1, getCaCert(ocspTestCert), ocspTestCert.getSerialNumber()));
        OCSPReq req = gen.generate();

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

    /** Tests ocsp message
     * @throws Exception error
     */
    public void test03OcspRevoked() throws Exception {
        log.trace(">test03OcspRevoked()");
        final X509Certificate ocspTestCert = getTestCert(true);
        // And an OCSP request
        OCSPReqGenerator gen = new OCSPReqGenerator();
        gen.addRequest(new CertificateID(CertificateID.HASH_SHA1, getCaCert(ocspTestCert), ocspTestCert.getSerialNumber()));
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
        log.trace("<test03OcspRevoked()");
    }
    
    public void test04OcspUnknown() throws Exception {
    	loadUserCert(caid);
    	super.test04OcspUnknown();
    }

    public void test05OcspUnknownCA() throws Exception {
    	super.test05OcspUnknownCA();
    }

    public void test06OcspSendWrongContentType() throws Exception {
    	super.test06OcspSendWrongContentType();
    }

    public void test10MultipleRequests() throws Exception {
    	super.test10MultipleRequests();
    }
    
    public void test11MalformedRequest() throws Exception {
    	super.test11MalformedRequest();
    }

    public void test12CorruptRequests() throws Exception {
    	super.test12CorruptRequests();
    }

    /**
     * Just verify that a both escaped and non-encoded GET requests work.
     */
    public void test13GetRequests() throws Exception {
    	super.test13GetRequests();
    	// See if the OCSP Servlet can also read escaped requests
    	final String urlEncReq = httpReqPath + '/' + resourceOcsp + '/' + "MGwwajBFMEMwQTAJBgUrDgMCGgUABBRBRfilzPB%2BAevx0i1AoeKTkrHgLgQUFJw5gwk9BaEgsX3pzsRF9iso29ICCCzdx5N0v9XwoiEwHzAdBgkrBgEFBQcwAQIEECrZswo%2Fa7YW%2Bhyi5Sn85fs%3D";
        URL url = new URL(urlEncReq);
        log.info(url.toString());	// Dump the exact string we use for access
        HttpURLConnection con = (HttpURLConnection)url.openConnection();
        assertEquals("Response code did not match. (Make sure you allow encoded slashes in your appserver.. add -Dorg.apache.tomcat.util.buf.UDecoder.ALLOW_ENCODED_SLASH=true in Tomcat)", 200, con.getResponseCode());
        assertNotNull(con.getContentType());
        assertTrue(con.getContentType().startsWith("application/ocsp-response"));
        OCSPResp response = new OCSPResp(new ByteArrayInputStream(OcspJunitHelper.inputStreamToBytes(con.getInputStream())));
        assertNotNull("Response should not be null.", response);
        assertTrue("Should not be concidered malformed.", OCSPRespGenerator.MALFORMED_REQUEST != response.getStatus());
    	final String dubbleSlashEncReq = httpReqPath + '/' + resourceOcsp + '/' + "MGwwajBFMEMwQTAJBgUrDgMCGgUABBRBRfilzPB%2BAevx0i1AoeKTkrHgLgQUFJw5gwk9BaEgsX3pzsRF9iso29ICCAvB%2F%2FHJyKqpoiEwHzAdBgkrBgEFBQcwAQIEEOTzT2gv3JpVva22Vj8cuKo%3D";
        url = new URL(dubbleSlashEncReq);
        log.info(url.toString());	// Dump the exact string we use for access
        con = (HttpURLConnection)url.openConnection();
        assertEquals("Response code did not match. ", 200, con.getResponseCode());
        assertNotNull(con.getContentType());
        assertTrue(con.getContentType().startsWith("application/ocsp-response"));
        response = new OCSPResp(new ByteArrayInputStream(OcspJunitHelper.inputStreamToBytes(con.getInputStream())));
        assertNotNull("Response should not be null.", response);
        assertTrue("Should not be concidered malformed.", OCSPRespGenerator.MALFORMED_REQUEST != response.getStatus());
    }

    public void test14CorruptGetRequests() throws Exception {
    	super.test14CorruptGetRequests();
    }
    
    public void test15MultipleGetRequests() throws Exception {
    	super.test15MultipleGetRequests();
    }

    /**
     * Verify the headers of a successful GET request.
     * ocsp.untilNextUpdate has to be configured for this test.
     */
    public void test17VerifyHttpGetHeaders() throws Exception {
        final X509Certificate ocspTestCert = getTestCert(false);
        // An OCSP request, ocspTestCert is already created in earlier tests
        OCSPReqGenerator gen = new OCSPReqGenerator();
        gen.addRequest(new CertificateID(CertificateID.HASH_SHA1, cacert, ocspTestCert.getSerialNumber()));
        OCSPReq req = gen.generate();
    	String reqString = new String(Base64.encode(req.getEncoded(), false));
    	URL url = new URL(httpReqPath + '/' + resourceOcsp + '/' + URLEncoder.encode(reqString, "UTF-8"));
        HttpURLConnection con = (HttpURLConnection)url.openConnection();
        assertEquals("Response code did not match. ", 200, con.getResponseCode());
        // Some appserver (Weblogic) responds with "application/ocsp-response; charset=UTF-8"
        assertNotNull(con.getContentType());
        assertTrue(con.getContentType().startsWith("application/ocsp-response"));
        OCSPResp response = new OCSPResp(new ByteArrayInputStream(OcspJunitHelper.inputStreamToBytes(con.getInputStream())));
        assertEquals("Response status not the expected.", OCSPRespGenerator.SUCCESSFUL, response.getStatus());
        BasicOCSPResp brep = (BasicOCSPResp) response.getResponseObject();
        // Just output the headers to stdout so we can visually inspect them if something goes wrong
        Set<String> keys = con.getHeaderFields().keySet();
        for (String field : keys) {
        	List<String> values = con.getHeaderFields().get(field);
        	for (String value : values) {
        		log.info(field + ": " + value);
        	}
        }
        String eTag = con.getHeaderField("ETag");
        assertNotNull("RFC 5019 6.2: No 'ETag' HTTP header present as it SHOULD. (Make sure ocsp.untilNextUpdate is configured for this test)", eTag);
        assertTrue("ETag is messed up.", ("\"" + new String(Hex.encode(MessageDigest.getInstance("SHA-1", "BC").digest(response.getEncoded()))) + "\"").equals(eTag));
        long date = con.getHeaderFieldDate("Date", -1);
        assertTrue("RFC 5019 6.2: No 'Date' HTTP header present as it SHOULD.", date != -1);
        long lastModified = con.getHeaderFieldDate("Last-Modified", -1);
        assertTrue("RFC 5019 6.2: No 'Last-Modified' HTTP header present as it SHOULD.", lastModified != -1);
        //assertTrue("Last-Modified is after response was sent", lastModified<=date);	This will not hold on JBoss AS due to the caching of the Date-header
        long expires = con.getExpiration();
        assertTrue("Expires is before response was sent", expires>=date);
        assertTrue("RFC 5019 6.2: No 'Expires' HTTP header present as it SHOULD.", expires != 0);
        String cacheControl = con.getHeaderField("Cache-Control");
        assertNotNull("RFC 5019 6.2: No 'Cache-Control' HTTP header present as it SHOULD.", cacheControl);
        assertTrue("RFC 5019 6.2: No 'public' HTTP header Cache-Control present as it SHOULD.", cacheControl.contains("public"));
        assertTrue("RFC 5019 6.2: No 'no-transform' HTTP header Cache-Control present as it SHOULD.", cacheControl.contains("no-transform"));
        assertTrue("RFC 5019 6.2: No 'must-revalidate' HTTP header Cache-Control present as it SHOULD.", cacheControl.contains("must-revalidate"));
        Matcher matcher = Pattern.compile(".*max-age\\s*=\\s*(\\d+).*").matcher(cacheControl);
        assertTrue("RFC 5019 6.2: No 'max-age' HTTP header Cache-Control present as it SHOULD.", matcher.matches());
        int maxAge = Integer.parseInt(matcher.group(1));
        assertTrue("RFC 5019 6.2: SHOULD be 'later than thisUpdate but earlier than nextUpdate'.", maxAge < (expires-lastModified)/1000);
        //assertTrue("Response cannot be produced after it was sent.", brep.getProducedAt().getTime() <= date);	This might not hold on JBoss AS due to the caching of the Date-header
        X509Certificate[] chain = brep.getCerts("BC");
        boolean verify = brep.verify(chain[0].getPublicKey(), "BC");
        assertTrue("Response failed to verify.", verify);
    	assertNull("No nonce should be present.", brep.getExtensionValue(OCSPObjectIdentifiers.id_pkix_ocsp_nonce.getId()));
        SingleResp[] singleResps = brep.getResponses();
        assertNotNull("SingleResps should not be null.", singleResps);
        assertTrue("Expected a single SingleResp in the repsonse.", singleResps.length == 1);
        assertEquals("Serno in response does not match serno in request.", singleResps[0].getCertID().getSerialNumber(), ocspTestCert.getSerialNumber());
        assertEquals("Status is not null (null is 'good')", singleResps[0].getCertStatus(), null);
        assertTrue("RFC 5019 6.2: Last-Modified SHOULD 'be the same as the thisUpdate timestamp in the request itself'", singleResps[0].getThisUpdate().getTime() == lastModified);
        assertTrue("RFC 5019 6.2: Expires SHOULD 'be the same as the nextUpdate timestamp in the request itself'", singleResps[0].getNextUpdate().getTime() == expires);
        assertTrue("Response cannot be produced before it was last modified..", brep.getProducedAt().getTime() >= singleResps[0].getThisUpdate().getTime());
    }

    /**
     * Tests nextUpdate and thisUpdate
     * ocsp.untilNextUpdate has to be configured for this test.
     */
    public void test18NextUpdateThisUpdate() throws Exception {
        final X509Certificate ocspTestCert = getTestCert(false);
        // And an OCSP request
        OCSPReqGenerator gen = new OCSPReqGenerator();
        gen.addRequest(new CertificateID(CertificateID.HASH_SHA1, cacert, ocspTestCert.getSerialNumber()));
        OCSPReq req = gen.generate();
        // POST the request and receive a singleResponse
        URL url = new URL(httpReqPath + '/' + resourceOcsp);
        HttpURLConnection con = (HttpURLConnection)url.openConnection();
        con.setDoOutput(true);
        con.setRequestMethod("POST");
        con.setRequestProperty("Content-Type", "application/ocsp-request");
        OutputStream os = con.getOutputStream();
        os.write(req.getEncoded());
        os.close();
        assertEquals("Response code", 200, con.getResponseCode());
        // Some appserver (Weblogic) responds with "application/ocsp-response; charset=UTF-8"
        assertNotNull(con.getContentType());
        assertTrue(con.getContentType().startsWith("application/ocsp-response"));
        OCSPResp response = new OCSPResp(new ByteArrayInputStream(OcspJunitHelper.inputStreamToBytes(con.getInputStream())));
        assertEquals("Response status not the expected.", 0, response.getStatus());
        BasicOCSPResp brep = (BasicOCSPResp) response.getResponseObject();
        X509Certificate[] chain = brep.getCerts("BC");
        boolean verify = brep.verify(chain[0].getPublicKey(), "BC");
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

    private X509Certificate getTestCert( boolean isRevoked ) throws Exception {
    	try {
            Collection certs = getCertificateStoreOnlyDataSession().findCertificatesByUsername(admin, "ocspTest");
    		Iterator i = certs.iterator();
    		while (i.hasNext()) {
    			X509Certificate cert = (X509Certificate)i.next();
    			CertificateStatus cs = getCertificateStoreOnlyDataSession().getStatus(issuerDN, CertTools.getSerialNumber(cert)); 
    			if (isRevoked == cs.equals(CertificateStatus.REVOKED)) {
    				return cert;
    			}
    		}
    	} catch (Throwable e) {
    		log.debug("",e);
    	}
        assertNotNull("To run this test you must have at least one active and one revoked end user cert in the database. (Could not fetch certificate.)", null);
        return null;
    }

    private X509Certificate getCaCert(X509Certificate cert) throws Exception {
    	Collection certs = getCertificateStoreOnlyDataSession().findCertificatesByType(admin, SecConst.CERTTYPE_ROOTCA, CertTools.getIssuerDN(cert));
    	assertTrue("Could not determine or find the CA cert.", certs!=null && !certs.isEmpty());
    	return (X509Certificate) certs.iterator().next();
	}

}
