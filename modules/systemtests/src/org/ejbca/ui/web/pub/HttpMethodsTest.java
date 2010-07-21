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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.URL;

import javax.ejb.EJB;

import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.ejb.upgrade.ConfigurationSessionRemote;

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
public class HttpMethodsTest extends TestCase {

    final private static Logger log = Logger.getLogger(WebdistHttpTest.class);

    private final String httpBaseUrl;
    private String httpPort;

    @EJB
    private ConfigurationSessionRemote configurationSession;

    public HttpMethodsTest() {
        httpPort = configurationSession.getProperty(WebConfiguration.CONFIG_HTTPSERVERPUBHTTP, "8080");
        httpBaseUrl = "http://127.0.0.1:" + httpPort;
    }

    /** Test the doc.war module. */
    public void testDocs() throws Exception {
        testResource("/ejbca/doc/index.html");
    }

    /** Test the publicweb.war module. */
    public void testPublicWeb() throws Exception {
        testResource("/ejbca/index.jsp");
    }

    /** Test the webdist.war module. */
    public void testWebDist() throws Exception {
        testResource("/ejbca/publicweb/webdist/certdist?cmd=cacert&issuer=CN%3dAdminCA1%2cO%3dEJBCA+Sample%2cC%3dSE&level=0");
    }

    /** Test the status.war module. */
    public void testStatus() throws Exception {
        testResource("/ejbca/publicweb/status/ocsp");
    }

    /** Test the scep.war module. */
    public void testScep() throws Exception {
        testResource("/ejbca/publicweb/apply/scep/pkiclient.exe?operation=GetCACert&message=AdminCA1");
    }

    /** Test the healthcheck.war module. */
    public void testHealthCheck() throws Exception {
        testResource("/ejbca/publicweb/healthcheck/ejbcahealth");
    }

    /** Test the cmp.war module. */
    public void testCmp() throws Exception {
        // Servlet only answers to POST
        String resourceName = "/ejbca/publicweb/cmp";
        log.info("Started tests of " + resourceName);
        assertFalse("HTTP OPTIONS is supported.", allowHttpOptions(resourceName, httpPort));
    }

    // TODO: Renew bundle

    /** Perform basic HTTP method tests on the specified resource */
    private void testResource(String resourceName) throws Exception {
        log.info("Started tests of " + resourceName);
        assertTrue("HTTP GET is not supported. (This test expects " + resourceName + " to exist)", getUrl(httpBaseUrl + resourceName) == 200);
        assertFalse("HTTP DELETE is supported.", allowsDeleteHttpRequest(resourceName, httpPort));
        assertFalse("HTTP PUT is supported.", allowsPutHttpRequest(resourceName + ".2", httpPort));
        assertFalse("HTTP TRACE is supported.", allowsTraceHttpRequest(resourceName, httpPort));
        assertFalse("HTTP OPTIONS is supported.", allowHttpOptions(resourceName, httpPort));
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
        return resp.getStatusCode();
    }
}
