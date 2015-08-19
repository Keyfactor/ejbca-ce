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

package org.ejbca.ui.web.pub;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.net.URLEncoder;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.apache.xml.security.utils.Base64;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.cesecore.SystemTestsConfiguration;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.config.ConfigurationSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityExistsException;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ra.NotFoundException;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Tests http servlet for certificate request
 * 
 * @version $Id$
 */
public class CertRequestHttpTest extends CaTestCase {
    private static Logger log = Logger.getLogger(CertRequestHttpTest.class);

    private static final String TEST_USERNAME = "reqtest";
    private String httpReqPath;
    private String resourceReq;

    private int caid = getTestCAId();
    private static final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CertRequestHttpTest"));

    private final ConfigurationSessionRemote configurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ConfigurationSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private final EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    private final EndEntityAccessSessionRemote endEntityAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityAccessSessionRemote.class);

    @BeforeClass
    public static void beforeClass() {    
        // Install BouncyCastle provider
        CryptoProviderTools.installBCProvider();
        
    }

    @Before
    public void setUp() throws Exception {
        super.setUp();
        final String remoteHost = SystemTestsConfiguration.getRemoteHost("127.0.0.1");
        final String remotePort = SystemTestsConfiguration.getRemotePortHttp(configurationSession.getProperty(WebConfiguration.CONFIG_HTTPSERVERPUBHTTP));
        httpReqPath = "http://" + remoteHost + ":" + remotePort + "/ejbca";
        resourceReq = "certreq";
    }

    @After
    public void tearDown() throws Exception {
        super.tearDown();
    	try {
    		endEntityManagementSession.deleteUser(admin, TEST_USERNAME);
    	} catch (NotFoundException e) {
    		// NOPMD:ignore if the user was not created
    	}
    }

    /**
     * Tests request for a pkcs12
     * 
     * @throws Exception error
     */
    @Test
    public void test01RequestPKCS12() throws Exception {
        log.trace(">test01RequestPKCS12()");

        // find a CA (TestCA?) create a user
        // Send certificate request for a server generated PKCS12
        setupUser(SecConst.TOKEN_SOFT_P12);
        setupUserStatus(EndEntityConstants.STATUS_NEW);

        // POST the OCSP request
        URL url = new URL(httpReqPath + '/' + resourceReq);
        HttpURLConnection con = (HttpURLConnection) url.openConnection();
        // we are going to do a POST
        con.setDoOutput(true);
        con.setRequestMethod("POST");

        // POST it
        con.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        OutputStream os = con.getOutputStream();
        os.write(("user="+TEST_USERNAME+"&password=foo123&keylength=2048").getBytes("UTF-8"));
        os.close();
        assertEquals("Response code", 200, con.getResponseCode());
        // Some appserver (Weblogic) responds with
        // "application/x-pkcs12; charset=UTF-8"
        String contentType = con.getContentType();
        boolean contentTypeIsPkcs12 = contentType.startsWith("application/x-pkcs12");
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        // This works for small requests, and PKCS12 requests are small
        InputStream in = con.getInputStream();
        int b = in.read();
        while (b != -1) {
            baos.write(b);
            b = in.read();
        }
        baos.flush();
        in.close();
        byte[] respBytes = baos.toByteArray();
        assertTrue(respBytes.length > 0);
        if (!contentTypeIsPkcs12 && log.isDebugEnabled()) {
            // If the content-type isn't application/x-pkcs12 we like to know what we got back..
            log.debug(new String(respBytes));
        }
        assertTrue("contentType was " + contentType, contentTypeIsPkcs12);

        KeyStore store = KeyStore.getInstance("PKCS12", "BC");
        ByteArrayInputStream is = new ByteArrayInputStream(respBytes);
        store.load(is, "foo123".toCharArray());
        assertTrue(store.containsAlias("ReqTest"));
        X509Certificate cert = (X509Certificate) store.getCertificate("ReqTest");
        PublicKey pk = cert.getPublicKey();
        if (pk instanceof RSAPublicKey) {
            RSAPublicKey rsapk = (RSAPublicKey) pk;
            assertEquals(rsapk.getAlgorithm(), "RSA");
            assertEquals(2048, rsapk.getModulus().bitLength());
        } else {
            assertTrue("Public key is not RSA", false);
        }

        log.trace("<test01RequestPKCS12()");
    }

    /**
     * Tests request for a unknown user
     * 
     * @throws Exception error
     */
    @Test
    public void test02RequestUnknownUser() throws Exception {
        log.trace(">test02RequestUnknownUser()");

        // POST the OCSP request
        URL url = new URL(httpReqPath + '/' + resourceReq);
        HttpURLConnection con = (HttpURLConnection) url.openConnection();
        // we are going to do a POST
        con.setDoOutput(true);
        con.setRequestMethod("POST");
        con.setInstanceFollowRedirects(false);
        con.setAllowUserInteraction(false);

        // POST it
        con.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        OutputStream os = con.getOutputStream();
        os.write("user=reqtestunknown&password=foo123&keylength=2048".getBytes("UTF-8"));
        os.close();
        final int responseCode = con.getResponseCode();
        if (responseCode != HttpURLConnection.HTTP_OK) {
            log.info("ResponseMessage: " + con.getResponseMessage());
            assertEquals("Response code", HttpURLConnection.HTTP_OK, responseCode);
        }
        log.info("Content-Type: " + con.getContentType());
        boolean ok = false;
        // Some containers return the content type with a space and some
        // without...
        if ("text/html;charset=UTF-8".equals(con.getContentType())) {
            ok = true;
        }
        if ("text/html; charset=UTF-8".equals(con.getContentType())) {
            ok = true;
        }
        assertTrue(con.getContentType(), ok);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        // This works for small requests, and PKCS12 requests are small
        InputStream in = con.getInputStream();
        int b = in.read();
        while (b != -1) {
            baos.write(b);
            b = in.read();
        }
        baos.flush();
        in.close();
        byte[] respBytes = baos.toByteArray();
        String error = new String(respBytes);
        int index = error.indexOf("<pre>");
        int index2 = error.indexOf("</pre>");
        String errormsg = error.substring(index + 5, index2);
        log.info(errormsg);
        String expectedErrormsg = "Username: reqtestunknown\nWrong username or password\n";
        assertEquals(expectedErrormsg.replaceAll("\\s", ""), errormsg.replaceAll("\\s", ""));
        log.trace("<test02RequestUnknownUser()");
    }

    /**
     * Tests request for a wrong password
     * 
     * @throws Exception error
     */
    @Test
    public void test03RequestWrongPwd() throws Exception {
        log.trace(">test03RequestWrongPwd()");

        setupUser(SecConst.TOKEN_SOFT_P12);

        // POST the OCSP request
        URL url = new URL(httpReqPath + '/' + resourceReq);
        HttpURLConnection con = (HttpURLConnection) url.openConnection();
        // we are going to do a POST
        con.setDoOutput(true);
        con.setRequestMethod("POST");
        con.setInstanceFollowRedirects(false);
        con.setAllowUserInteraction(false);

        // POST it
        con.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        OutputStream os = con.getOutputStream();
        os.write(("user="+TEST_USERNAME+"&password=foo456&keylength=2048").getBytes("UTF-8"));
        os.close();
        final int responseCode = con.getResponseCode();
        if (responseCode != HttpURLConnection.HTTP_OK) {
            log.info("ResponseMessage: " + con.getResponseMessage());
            assertEquals("Response code", HttpURLConnection.HTTP_OK, responseCode);
        }
        boolean ok = false;
        // Some containers return the content type with a space and some
        // without...
        if ("text/html;charset=UTF-8".equals(con.getContentType())) {
            ok = true;
        }
        if ("text/html; charset=UTF-8".equals(con.getContentType())) {
            ok = true;
        }
        assertTrue(con.getContentType(), ok);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        // This works for small requests, and PKCS12 requests are small
        InputStream in = con.getInputStream();
        int b = in.read();
        while (b != -1) {
            baos.write(b);
            b = in.read();
        }
        baos.flush();
        in.close();
        byte[] respBytes = baos.toByteArray();
        String error = new String(respBytes);
        int index = error.indexOf("<pre>");
        int index2 = error.indexOf("</pre>");
        String errormsg = error.substring(index + 5, index2);
        String expectedErrormsg = "Username: "+TEST_USERNAME+"\nWrong username or password";
        assertEquals(expectedErrormsg.replaceAll("\\s", ""), errormsg.replaceAll("\\s", ""));
        log.info(errormsg);
        log.trace("<test03RequestWrongPwd()");
    }

    /**
     * Tests request with wrong status
     * 
     * @throws Exception error
     */
    @Test
    public void test04RequestWrongStatus() throws Exception {
        log.trace(">test04RequestWrongStatus()");

        setupUser(SecConst.TOKEN_SOFT_P12);
        setupUserStatus(EndEntityConstants.STATUS_GENERATED);

        // POST the OCSP request
        URL url = new URL(httpReqPath + '/' + resourceReq);
        HttpURLConnection con = (HttpURLConnection) url.openConnection();
        // we are going to do a POST
        con.setDoOutput(true);
        con.setRequestMethod("POST");
        con.setInstanceFollowRedirects(false);
        con.setAllowUserInteraction(false);

        // POST it
        con.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        OutputStream os = con.getOutputStream();
        os.write(("user="+TEST_USERNAME+"&password=foo456&keylength=2048").getBytes("UTF-8"));
        os.close();
        final int responseCode = con.getResponseCode();
        if (responseCode != HttpURLConnection.HTTP_OK) {
            log.info("ResponseMessage: " + con.getResponseMessage());
            assertEquals("Response code", HttpURLConnection.HTTP_OK, responseCode);
        }
        boolean ok = false;
        // Some containers return the content type with a space and some
        // without...
        if ("text/html;charset=UTF-8".equals(con.getContentType())) {
            ok = true;
        }
        if ("text/html; charset=UTF-8".equals(con.getContentType())) {
            ok = true;
        }
        assertTrue(con.getContentType(), ok);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        // This works for small requests, and PKCS12 requests are small
        InputStream in = con.getInputStream();
        int b = in.read();
        while (b != -1) {
            baos.write(b);
            b = in.read();
        }
        baos.flush();
        in.close();
        byte[] respBytes = baos.toByteArray();
        String error = new String(respBytes);
        int index = error.indexOf("<pre>");
        int index2 = error.indexOf("</pre>");
        String errormsg = error.substring(index + 5, index2);
        String expectedErrormsg = "Username: "+TEST_USERNAME+"\nWrong user status! To generate a certificate for a user the user must have status New, Failed or In process.\n";

        assertEquals(expectedErrormsg.replaceAll("\\s", ""), errormsg.replaceAll("\\s", ""));
        log.info(errormsg);
        log.trace("<test04RequestWrongStatus()");
    }

    @Test
    public void test05RequestIE() throws Exception {
        // find a CA (TestCA?) create a user
        // Send certificate request for a server generated PKCS12
        setupUser(SecConst.TOKEN_SOFT_BROWSERGEN);

        String resp = sendCsrRequest(1);
        // This is a string with VB script and all
        // System.out.println(resp);
        assertTrue("Response does not contain 'cert ='", resp.contains("cert ="));
    }

    /** Tries to send a browser certificate request when the user on the server side has been 
     * added using a P12 token type. This means server generated token, which should be wrong for a browser request.
     * We should receive an error back.
     */
    @Test
    public void test06RequestIEWrongTokenType() throws Exception {
        // find a CA (TestCA?) create a user
        // Send certificate request for a server generated PKCS12
        setupUser(SecConst.TOKEN_SOFT_PEM);

        String resp = sendCsrRequest(1);
        // This is a string with VB script and all
        // System.out.println(resp);
        assertTrue("Response does not contain 'User was configured for server generated token but a CSR was sent in the request'", resp.contains("User was configured for server generated token but a CSR was sent in the request"));
    }

    /** Tries to send a CSR and gets a certificate back 
     * added using a P12 token type. This means server generated token, which should be wrong for a CSR request.
     * We should receive an error back.
     */
    @Test
    public void test07RequestCsr() throws Exception {
        // find a CA (TestCA?) create a user
        // Send certificate request for a server generated PKCS12
        setupUser(SecConst.TOKEN_SOFT_BROWSERGEN);

        String resp = sendCsrRequest(2);
        // This is a string with VB script and all
        // System.out.println(resp);
        assertTrue("Response does not start with '-----BEGIN CERTIFICATE-----'", resp.startsWith("-----BEGIN CERTIFICATE-----"));
    }

    /** Tries to send a CSR when the user on the server side has been 
     * added using a P12 token type. This means server generated token, which should be wrong for a CSR request.
     * We should receive an error back.
     */
    @Test
    public void test08RequestCsrWrongTokenType() throws Exception {
        // find a CA (TestCA?) create a user
        // Send certificate request for a server generated PKCS12
        setupUser(SecConst.TOKEN_SOFT_PEM);

        String resp = sendCsrRequest(2);
        // This is a string with VB script and all
        // System.out.println(resp);
        assertTrue("Response does not contain 'User was configured for server generated token but a CSR was sent in the request'", resp.contains("User was configured for server generated token but a CSR was sent in the request"));
    }
    
    /**
     * Tests request for a pkcs12 with a clear-text password
     */
    @Test
    public void test09RequestPKCS12ClearPassword() throws Exception {
        log.trace(">test01RequestPKCS12()");

        // Create a user with a clear-text password
        setupUser(SecConst.TOKEN_SOFT_P12, true);
        assertEquals("end entity password wasn't set", "foo123", findPassword(TEST_USERNAME));

        // POST the OCSP request
        URL url = new URL(httpReqPath + '/' + resourceReq);
        HttpURLConnection con = (HttpURLConnection) url.openConnection();
        // we are going to do a POST
        con.setDoOutput(true);
        con.setRequestMethod("POST");

        // POST it
        con.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        OutputStream os = con.getOutputStream();
        os.write(("user="+TEST_USERNAME+"&password=foo123&keylength=2048").getBytes("UTF-8"));
        os.close();
        assertEquals("Response code", 200, con.getResponseCode());
        // Some appserver (Weblogic) responds with
        // "application/x-pkcs12; charset=UTF-8"
        String contentType = con.getContentType();
        assertTrue("contentType was " + contentType, contentType.startsWith("application/x-pkcs12"));
        
        // First read the response and then close the connection
        try {
            con.getInputStream().skip(99999);
        } catch (EOFException e) { /* Ignore */ }
        con.disconnect();

        assertTrue("password wasn't cleared", StringUtils.isEmpty(findPassword(TEST_USERNAME)));
        log.trace("<test01RequestPKCS12()");
    }

    /** type 1 = ie (pkcs10)
     *  type 2 = csr (pkcs10req)
     */
    private String sendCsrRequest(int type) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, IOException,
            InvalidKeyException, SignatureException, OperatorCreationException, MalformedURLException, ProtocolException,
            UnsupportedEncodingException {
        // Create a PKCS10 request
        KeyPair rsakeys = KeyTools.genKeys("512", "RSA");
        PKCS10CertificationRequest req = CertTools.genPKCS10CertificationRequest("SHA1WithRSA", CertTools.stringToBcX500Name("C=SE, O=AnaTom, CN=foo"),
                rsakeys.getPublic(), new DERSet(), rsakeys.getPrivate(), null);
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        DEROutputStream dOut = new DEROutputStream(bOut);
        dOut.writeObject(req.toASN1Structure());
        dOut.close();
        final StringBuilder request = new StringBuilder();
        if (type == 2) {
            request.append("-----BEGIN CERTIFICATE REQUEST-----\n");
        }
        request.append(new String(Base64.encode(bOut.toByteArray())));
        if (type == 2) {
            request.append("\n-----END CERTIFICATE REQUEST-----\n");
        }
        String p10 = request.toString();
        // System.out.println(p10);

        // POST the OCSP request
        URL url = new URL(httpReqPath + '/' + resourceReq);
        HttpURLConnection con = (HttpURLConnection) url.openConnection();
        // we are going to do a POST
        con.setDoOutput(true);
        con.setRequestMethod("POST");

        // POST it
        con.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        OutputStream os = con.getOutputStream();
        final StringBuilder buf = new StringBuilder("user="+TEST_USERNAME+"&password=foo123&");
        switch (type) {
        case 1:
            buf.append("pkcs10=");
            break;
        case 2:
            buf.append("resulttype=1&pkcs10req=");
            break;
        default:
            break;
        }
        buf.append(URLEncoder.encode(p10, "UTF-8"));
        os.write(buf.toString().getBytes("UTF-8"));
        os.close();
        assertEquals("Response code", 200, con.getResponseCode());

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        // This works for small requests, and PKCS7 responses are small
        InputStream in = con.getInputStream();
        int b = in.read();
        while (b != -1) {
            baos.write(b);
            b = in.read();
        }
        baos.flush();
        in.close();
        byte[] respBytes = baos.toByteArray();
        assertTrue(respBytes.length > 0);

        String resp = new String(respBytes);
        return resp;
    }


    //
    // Private helper methods
    //
    
    private void setupUser(int tokentype) throws Exception {
        setupUser(tokentype, false); // without clear text password
    }

    private void setupUser(int tokentype, boolean clearpwd) throws Exception {
        // Make user that we know...
        boolean userExists = false;
        try {
            endEntityManagementSession.addUser(admin, TEST_USERNAME, "foo123", "C=SE,O=PrimeKey,CN=ReqTest", null, "reqtest@primekey.se", clearpwd,
                    SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, EndEntityTypes.ENDUSER.toEndEntityType(), tokentype, 0, caid);
            log.debug("created user: "+TEST_USERNAME+", foo123, C=SE, O=PrimeKey, CN=ReqTest");
        } catch (EndEntityExistsException e) {
            userExists = true; // This is what we want
        }
        if (userExists) {
            log.debug("User "+TEST_USERNAME+" already exists.");
            EndEntityInformation endEntityInformation = new EndEntityInformation(TEST_USERNAME, "C=SE,O=PrimeKey,CN=ReqTest", caid, null, "reqtest@anatom.se", EndEntityTypes.ENDUSER.toEndEntityType(), 
                    SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, tokentype, 0, null);
            endEntityInformation.setPassword("foo123");
            endEntityInformation.setStatus(EndEntityConstants.STATUS_NEW);
            endEntityManagementSession.changeUser(admin, endEntityInformation, false);
            log.debug("Reset status to NEW");
        }
    }

    private void setupUserStatus(int status) throws Exception {
        EndEntityInformation endEntityInformation = new EndEntityInformation(TEST_USERNAME, "C=SE,O=PrimeKey,CN=ReqTest", caid, null, "reqtest@anatom.se", EndEntityTypes.ENDUSER.toEndEntityType(), 
                SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_P12, 0, null);
        endEntityInformation.setPassword("foo123");
        endEntityInformation.setStatus(status);
        endEntityManagementSession.changeUser(admin, endEntityInformation, false);
        log.debug("Set status to: " + status);
    }
    
    private String findPassword(String user) throws Exception {
        EndEntityInformation ei = endEntityAccessSession.findUser(admin, user);
        if (ei == null) {
            log.info(InternalEjbcaResources.getInstance().getLocalizedMessage("ra.errorentitynotexist", user));
            throw new NotFoundException(InternalEjbcaResources.getInstance().getLocalizedMessage("ra.wrongusernameorpassword"));
        }
        return ei.getPassword(); // This is the clear text password. See UserData.toEndEntityInformation
    }

    public String getRoleName() {
        return this.getClass().getSimpleName(); 
    }
}
