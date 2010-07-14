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

package org.ejbca.ui.web.pub;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.rmi.RemoteException;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;

import javax.ejb.DuplicateKeyException;

import junit.framework.TestSuite;

import org.apache.log4j.Logger;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ra.IUserAdminSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.util.CryptoProviderTools;
import org.ejbca.util.TestTools;

/**
 * Tests http servlet for certificate request
 * 
 * @version $Id$
 */
public class CertRequestHttpTest extends CaTestCase {
    private static Logger log = Logger.getLogger(CertRequestHttpTest.class);

    protected final String httpReqPath;
    protected final String resourceReq;

    private static IUserAdminSessionRemote usersession;
    protected int caid = getTestCAId();
    protected static final Admin admin = new Admin(Admin.TYPE_BATCHCOMMANDLINE_USER);
    protected static X509Certificate cacert = null;

    protected final static String httpPort;
    static {
        String tmp;
        try {
            tmp = TestTools.getConfigurationSession().getProperty(WebConfiguration.CONFIG_HTTPSERVERPUBHTTP, "8080");
        } catch (RemoteException e) {
            tmp = "8080";
            log.error("Not possible to get property " + WebConfiguration.CONFIG_HTTPSERVERPUBHTTP, e);
        }
        httpPort = tmp;
    }

    public static TestSuite suite() {
        return new TestSuite(CertRequestHttpTest.class);
    }

    public CertRequestHttpTest(String name) throws Exception {
        this(name, "http://127.0.0.1:" + httpPort + "/ejbca", "certreq");
    }

    protected CertRequestHttpTest(String name, String reqP, String res) throws Exception {
        super(name);
        httpReqPath = reqP;
        resourceReq = res;
        // Install BouncyCastle provider
        CryptoProviderTools.installBCProvider();
        createTestCA();
        cacert = (X509Certificate) getTestCACert();
        usersession = TestTools.getUserAdminSession();
    }

    public void setUp() throws Exception {
        super.setUp();
    }

    public void tearDown() throws Exception {
    }

    /**
     * Tests request for a pkcs12
     * 
     * @throws Exception
     *             error
     */
    public void test01RequestPKCS12() throws Exception {
        log.trace(">test01RequestPKCS12()");

        // find a CA (TestCA?) create a user
        // Send certificate request for a server generated PKCS12
        setupUser();

        // POST the OCSP request
        URL url = new URL(httpReqPath + '/' + resourceReq);
        HttpURLConnection con = (HttpURLConnection) url.openConnection();
        // we are going to do a POST
        con.setDoOutput(true);
        con.setRequestMethod("POST");

        // POST it
        con.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        OutputStream os = con.getOutputStream();
        os.write("user=reqtest&password=foo123&keylength=2048".getBytes("UTF-8"));
        os.close();
        assertEquals("Response code", 200, con.getResponseCode());
        // Some appserver (Weblogic) responds with
        // "application/x-pkcs12; charset=UTF-8"
        assertTrue(con.getContentType().startsWith("application/x-pkcs12"));
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
     * @throws Exception
     *             error
     */
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
        assertEquals("Response code", 200, con.getResponseCode());
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
        String expectedErrormsg = "Username: reqtestunknown\nNon existent username. To generate a certificate a valid username and password must be supplied.\n";
        assertEquals(expectedErrormsg.replaceAll("\\s", ""), errormsg.replaceAll("\\s", ""));
        log.trace("<test02RequestUnknownUser()");
    }

    /**
     * Tests request for a wrong password
     * 
     * @throws Exception
     *             error
     */
    public void test03RequestWrongPwd() throws Exception {
        log.trace(">test03RequestWrongPwd()");

        setupUser();

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
        os.write("user=reqtest&password=foo456&keylength=2048".getBytes("UTF-8"));
        os.close();
        assertEquals("Response code", 200, con.getResponseCode());
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
        String expectedErrormsg = "Username: reqtest\nWrong username or password! To generate a certificate a valid username and password must be supplied.\n";
        assertEquals(expectedErrormsg.replaceAll("\\s", ""), errormsg.replaceAll("\\s", ""));
        log.info(errormsg);
        log.trace("<test03RequestWrongPwd()");
    }

    /**
     * Tests request with wrong status
     * 
     * @throws Exception
     *             error
     */
    public void test04RequestWrongStatus() throws Exception {
        log.trace(">test04RequestWrongStatus()");

        setupUser();
        setupUserStatus(UserDataConstants.STATUS_GENERATED);

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
        os.write("user=reqtest&password=foo456&keylength=2048".getBytes("UTF-8"));
        os.close();
        assertEquals("Response code", 200, con.getResponseCode());
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
        String expectedErrormsg = "Username: reqtest\nWrong user status! To generate a certificate for a user the user must have status New, Failed or In process.\n";

        assertEquals(expectedErrormsg.replaceAll("\\s", ""), errormsg.replaceAll("\\s", ""));
        log.info(errormsg);
        log.trace("<test04RequestWrongStatus()");
    }

    /**
     * removes test user
     * 
     * @throws Exception
     *             error
     */
    public void test99Cleanup() throws Exception {
        log.trace(">test99Cleanup()");
        removeTestCA();
        usersession.deleteUser(admin, "reqtest");
        log.trace("<test99Cleanup()");
    }

    //
    // Private helper methods
    //

    private void setupUser() throws Exception {
        // Make user that we know...
        boolean userExists = false;
        try {
            usersession.addUser(admin, "reqtest", "foo123", "C=SE,O=PrimeKey,CN=ReqTest", null, "reqtest@primekey.se", false, SecConst.EMPTY_ENDENTITYPROFILE,
                    SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.USER_ENDUSER, SecConst.TOKEN_SOFT_P12, 0, caid);
            log.debug("created user: reqtest, foo123, C=SE, O=PrimeKey, CN=ReqTest");
        } catch (RemoteException re) {
            userExists = true;
        } catch (DuplicateKeyException dke) {
            userExists = true;
        }

        if (userExists) {
            log.debug("User reqtest already exists.");
            usersession.changeUser(admin, "reqtest", "foo123", "C=SE,O=PrimeKey,CN=ReqTest", null, "reqtest@anatom.se", false, SecConst.EMPTY_ENDENTITYPROFILE,
                    SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.USER_ENDUSER, SecConst.TOKEN_SOFT_P12, 0, UserDataConstants.STATUS_NEW, caid);
            log.debug("Reset status to NEW");
        }
    }

    private void setupUserStatus(int status) throws Exception {
        usersession.changeUser(admin, "reqtest", "foo123", "C=SE,O=PrimeKey,CN=ReqTest", null, "reqtest@anatom.se", false, SecConst.EMPTY_ENDENTITYPROFILE,
                SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.USER_ENDUSER, SecConst.TOKEN_SOFT_P12, 0, status, caid);
        log.debug("Set status to: " + status);
    }

}
