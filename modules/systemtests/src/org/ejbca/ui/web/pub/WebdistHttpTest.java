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

import java.net.URL;
import java.util.Iterator;
import java.util.List;

import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.apache.commons.httpclient.NameValuePair;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.ejb.config.ConfigurationSessionRemote;
import org.ejbca.util.InterfaceCache;

import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.WebConnection;
import com.gargoylesoftware.htmlunit.WebRequestSettings;
import com.gargoylesoftware.htmlunit.WebResponse;

/**
 * Tests http pages of public webdist
 **/
public class WebdistHttpTest extends TestCase {

    final private static Logger log = Logger.getLogger(WebdistHttpTest.class);

    private final String httpPort;

    private ConfigurationSessionRemote configurationSessionRemote = InterfaceCache.getConfigurationSession();
    
    public static TestSuite suite() {
        return new TestSuite(WebdistHttpTest.class);
    }

    public WebdistHttpTest(String name) {
        super(name);
        httpPort = configurationSessionRemote.getProperty(WebConfiguration.CONFIG_HTTPSERVERPUBHTTP, "8080");
    }

    public void testJspCompile() throws Exception {
        // We hit the pages and see that they return a 200 value, so we know
        // they at least compile correctly
        String httpReqPath = "http://127.0.0.1:" + httpPort + "/ejbca";
        String resourceName = "publicweb/webdist/certdist";
        String resourceName1 = "publicweb/webdist/certdist?cmd=cacert&issuer=CN%3dAdminCA1%2cO%3dEJBCA+Sample%2cC%3dSE&level=0";

        final WebClient webClient = new WebClient();
        WebConnection con = webClient.getWebConnection();
        WebRequestSettings settings = new WebRequestSettings(new URL(httpReqPath + '/' + resourceName));
        WebResponse resp = con.getResponse(settings);
        assertEquals("Response code", 400, resp.getStatusCode());

        settings = new WebRequestSettings(new URL(httpReqPath + '/' + resourceName1));
        resp = con.getResponse(settings);
        assertEquals("Response code", 200, resp.getStatusCode());

    }

    public void testPublicWeb() throws Exception {
        // We hit the pages and see that they return a 200 value, so we know
        // they at least compile correctly
        String httpReqPath = "http://127.0.0.1:" + httpPort + "/ejbca";
        String resourceName = "retrieve/ca_crls.jsp";
        String resourceName1 = "retrieve/ca_certs.jsp";
        String resourceName2 = "retrieve/latest_cert.jsp";
        String resourceName3 = "retrieve/list_certs.jsp";
        String resourceName4 = "retrieve/check_status.jsp";
        String resourceName5 = "enrol/browser.jsp";
        String resourceName6 = "enrol/server.jsp";
        String resourceName7 = "enrol/keystore.jsp";

        final WebClient webClient = new WebClient();
        WebConnection con = webClient.getWebConnection();
        WebRequestSettings settings = new WebRequestSettings(new URL(httpReqPath + '/' + resourceName));
        WebResponse resp = con.getResponse(settings);
        assertEquals("Response code", 200, resp.getStatusCode());

        settings = new WebRequestSettings(new URL(httpReqPath + '/' + resourceName1));
        resp = con.getResponse(settings);
        assertEquals("Response code", 200, resp.getStatusCode());

        settings = new WebRequestSettings(new URL(httpReqPath + '/' + resourceName2));
        resp = con.getResponse(settings);
        assertEquals("Response code", 200, resp.getStatusCode());

        settings = new WebRequestSettings(new URL(httpReqPath + '/' + resourceName3));
        resp = con.getResponse(settings);
        assertEquals("Response code", 200, resp.getStatusCode());

        settings = new WebRequestSettings(new URL(httpReqPath + '/' + resourceName4));
        resp = con.getResponse(settings);
        assertEquals("Response code", 200, resp.getStatusCode());

        settings = new WebRequestSettings(new URL(httpReqPath + '/' + resourceName5));
        resp = con.getResponse(settings);
        assertEquals("Response code", 200, resp.getStatusCode());

        settings = new WebRequestSettings(new URL(httpReqPath + '/' + resourceName6));
        resp = con.getResponse(settings);
        assertEquals("Response code", 200, resp.getStatusCode());

        settings = new WebRequestSettings(new URL(httpReqPath + '/' + resourceName7));
        resp = con.getResponse(settings);
        assertEquals("Response code", 200, resp.getStatusCode());

    }

    public void testPublicWebChainDownload() throws Exception {
    	
    	// This test assumes we have a default AdminCA1 installed with CAId=-1688117755
        String httpReqPathPem = "http://localhost:" + httpPort + "/ejbca/publicweb/webdist/certdist?cmd=cachain&caid=-1688117755&format=pem";
        String httpReqPathJks = "http://localhost:" + httpPort + "/ejbca/publicweb/webdist/certdist?cmd=cachain&caid=-1688117755&format=jks";

        final WebClient webClient = new WebClient();
        WebConnection con = webClient.getWebConnection();
        WebRequestSettings settings = new WebRequestSettings(new URL(httpReqPathPem));
        WebResponse resp = con.getResponse(settings);
        assertEquals("Response code", 200, resp.getStatusCode());
        String ctype = resp.getContentType();
        assertTrue(StringUtils.startsWith(ctype, "application/octet-stream"));
        List<NameValuePair> list = resp.getResponseHeaders();
        Iterator<NameValuePair> iter = list.iterator();
        boolean found = false;
        while (iter.hasNext()) {
        	NameValuePair pair = iter.next();
        	log.debug(pair.getName() + ": " + pair.getValue());
        	if (StringUtils.equalsIgnoreCase("Content-disposition", pair.getName())) {
        		assertEquals("attachment; filename=\"chain.pem\"", pair.getValue());
        		found = true;
        	}
        }
        assertTrue("Unable find AdminCA1 in certificate chain or parsing the response wrong.", found);

        settings = new WebRequestSettings(new URL(httpReqPathJks));
        resp = con.getResponse(settings);
        assertEquals("Response code", 200, resp.getStatusCode());
        ctype = resp.getContentType();
        assertTrue(StringUtils.startsWith(ctype, "application/octet-stream"));
        list = resp.getResponseHeaders();
        iter = list.iterator();
        found = false;
        while (iter.hasNext()) {
        	NameValuePair pair = (NameValuePair)iter.next();
        	if (StringUtils.equals("Content-disposition", pair.getName())) {
        		assertEquals("attachment; filename=\"chain.jks\"", pair.getValue());
        		found = true;
        	}
        }
        assertTrue(found);
    }
}
