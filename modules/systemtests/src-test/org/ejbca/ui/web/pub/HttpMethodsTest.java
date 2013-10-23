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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.URL;

import org.apache.log4j.Logger;
import org.bouncycastle.jce.X509KeyUsage;
import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.keys.token.CryptoTokenManagementSessionTest;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.ejb.config.ConfigurationSessionRemote;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.gargoylesoftware.htmlunit.SubmitMethod;
import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.WebConnection;
import com.gargoylesoftware.htmlunit.WebRequestSettings;
import com.gargoylesoftware.htmlunit.WebResponse;

/**
 * Try HTTP methods that should be disabled, like HTTP DELETE, for all public
 * web modules.
 * 
 * @version $Id$
 */
public class HttpMethodsTest {

    final private static Logger log = Logger.getLogger(WebdistHttpTest.class);

    private static final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("HttpMethodsTest"));
    
    private String httpBaseUrl;
    private String httpPort;
    private CA testx509ca;
    
    private ConfigurationSessionRemote configurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ConfigurationSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);

    @Before
    public void setUp() throws Exception {
        httpPort = configurationSession.getProperty(WebConfiguration.CONFIG_HTTPSERVERPUBHTTP);
        httpBaseUrl = "http://127.0.0.1:" + httpPort;
        
        int keyusage = X509KeyUsage.digitalSignature + X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign;
        testx509ca = CaTestUtils.createTestX509CA("CN=TestCA", null, false, keyusage);
        caSession.addCA(admin, testx509ca);
    }
    
    @After
    public void tearDown() throws Exception {
        CryptoTokenManagementSessionTest.removeCryptoToken(null, testx509ca.getCAToken().getCryptoTokenId());
        caSession.removeCA(admin, testx509ca.getCAId());
    }

    /** Test the doc.war module. */
    @Test
    public void testDocs() throws Exception {
        performResourceTest("/ejbca/doc/index.html");
    }

    /** Test the publicweb.war module. */
    @Test
    public void testPublicWeb() throws Exception {
        performResourceTest("/ejbca/index.jsp");
    }

    /** Test the webdist.war module. */
    @Test
    public void testWebDist() throws Exception {
        performResourceTest("/ejbca/publicweb/webdist/certdist?cmd=cacert&issuer=CN%3dTestCA&level=0");
    }

    /** Test the status.war module. */
    @Test
    public void testStatus() throws Exception {
        performResourceTest("/ejbca/publicweb/status/ocsp");
    }

    /** Test the scep.war module. */
    @Test
    public void testScep() throws Exception {
        performResourceTest("/ejbca/publicweb/apply/scep/pkiclient.exe?operation=GetCACert&message=TestCA");
    }

    /** Test the healthcheck.war module. */
    @Test
    public void testHealthCheck() throws Exception {
        performResourceTest("/ejbca/publicweb/healthcheck/ejbcahealth");
    }

    /** Test the cmp.war module. */
    @Test
    public void testCmp() throws Exception {
        // Servlet only answers to POST
        String resourceName = "/ejbca/publicweb/cmp";
        log.info("Started tests of " + resourceName);
        assertFalse("HTTP OPTIONS is supported.", allowHttpOptions(resourceName, httpPort));
    }

    // TODO: Renew bundle

    /** Perform basic HTTP method tests on the specified resource */
    private void performResourceTest(String resourceName) throws Exception {
        log.info("Started tests of " + resourceName);
        assertEquals("HTTP GET is not supported. (This test expects " + httpBaseUrl+resourceName + " to exist)", 200, getUrl(httpBaseUrl + resourceName));
        assertFalse("HTTP DELETE is supported.", allowsDeleteHttpRequest(resourceName, httpPort));
        assertFalse("HTTP PUT is supported.", allowsPutHttpRequest(resourceName + ".2", httpPort));
        assertFalse("HTTP TRACE is supported.", allowsTraceHttpRequest(resourceName, httpPort));
        assertFalse("HTTP OPTIONS is supported.haha ", allowHttpOptions(resourceName, httpPort));
    }

    /** Try an HTTP OPTIONS and return true if it was successful. */
    private boolean allowHttpOptions(String resource, String httpPort) throws IOException {
        // Create the HTTP header
        String headers = "OPTIONS " + resource + " HTTP/1.1\r\n" + "Host: 127.0.0.1\r\n\r\n";
        // Create the socket.
        Socket socket = new Socket(InetAddress.getByName("127.0.0.1"), Integer.parseInt(httpPort));
        // Send data byte for byte.
        OutputStream os = socket.getOutputStream();
        os.write(headers.getBytes());
        BufferedReader br = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        String nextLine;
        boolean allowsHttpOptions = false;
        while ((nextLine = br.readLine()) != null) {
            log.info("OPTIONS response contains: " + nextLine);
            if (nextLine.startsWith("Allow:")) {
                allowsHttpOptions = true;
        		break;
        	} else if (nextLine.equals("")) {
        		log.debug("Got a pure newline.. we only care about the hearders to skipping the rest..");
        		break;
            }
        }
        socket.close();
        return allowsHttpOptions;
    }

    /** Try to perform an HTTP DELETE. */
    private boolean allowsDeleteHttpRequest(String resource, String httpPort) throws IOException {
        String headers = "DELETE " + resource + " HTTP/1.1\r\n" + "Host: 127.0.0.1\r\n\r\n";
        Socket socket = new Socket(InetAddress.getByName("127.0.0.1"), Integer.parseInt(httpPort));
        OutputStream os = socket.getOutputStream();
        os.write(headers.getBytes());
        InputStream is = socket.getInputStream();
        byte[] b = new byte[4096];
        is.read(b);
        socket.close();
        log.info("DELETE response contains: " + new String(b));
        return getUrl(httpBaseUrl + resource) != 200;
    }

    /** Try to upload some XML content. */
    private boolean allowsPutHttpRequest(String resource, String httpPort) throws IOException {
        String xml = "<dummy/>";
        String headers = "PUT " + resource + " HTTP/1.1\r\n" + "Host: 127.0.0.1\r\n" + "Content-Type: text/xml\r\n" + "Content-Length: " + xml.length()
                + "\r\n" + "\r\n";
        Socket socket = new Socket(InetAddress.getByName("127.0.0.1"), Integer.parseInt(httpPort));
        OutputStream os = socket.getOutputStream();
        os.write((headers + xml).getBytes());
        InputStream is = socket.getInputStream();
        byte[] b = new byte[4096];
        is.read(b);
        socket.close();
        log.info("PUT response contains: " + new String(b));
        int responseCode = getUrl(httpBaseUrl + resource);
        return responseCode == 200;
    }

    /** Try to perform an HTTP TRACE. */
    private boolean allowsTraceHttpRequest(String resource, String httpPort) throws IOException {
        String headers = "TRACE " + resource + " HTTP/1.1\r\n" + "Host: 127.0.0.1\r\n" + "A: qwertyuiop\r\n" + "\r\n";
        Socket socket = new Socket(InetAddress.getByName("127.0.0.1"), Integer.parseInt(httpPort));
        OutputStream os = socket.getOutputStream();
        os.write(headers.getBytes());
        InputStream is = socket.getInputStream();
        byte[] b = new byte[4096];
        is.read(b);
        socket.close();
        log.info("TRACE response contains: " + new String(b));
        return new String(b).indexOf("qwertyuiop") != -1;
    }

    /** Do a HTTP GET. */
    private int getUrl(String url) throws IOException {
        final WebClient webClient = new WebClient();
        WebConnection con = webClient.getWebConnection();
        WebRequestSettings settings = new WebRequestSettings(new URL(url));
        settings.setSubmitMethod(SubmitMethod.GET);
        WebResponse resp = con.getResponse(settings);
        log.debug(resp.getContentAsString());
        return resp.getStatusCode();
    }
}
