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

import java.net.URL;
import java.util.Iterator;
import java.util.List;

import org.apache.commons.httpclient.NameValuePair;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.jce.X509KeyUsage;
import org.cesecore.CaTestUtils;
import org.cesecore.SystemTestsConfiguration;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.ejb.config.ConfigurationSessionRemote;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.WebConnection;
import com.gargoylesoftware.htmlunit.WebRequestSettings;
import com.gargoylesoftware.htmlunit.WebResponse;

/**
 * Tests http pages of public webdist
 **/
public class WebdistHttpTest {

    final private static Logger log = Logger.getLogger(WebdistHttpTest.class);
    final private AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("WebdistHttpTest"));

    private String httpPort;
    private String remoteHost;
    private CA testx509ca;

    private ConfigurationSessionRemote configurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ConfigurationSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);

    @Before
    public void setUp() throws Exception {
        httpPort = SystemTestsConfiguration.getRemotePortHttp(configurationSession.getProperty(WebConfiguration.CONFIG_HTTPSERVERPUBHTTP));
        remoteHost = SystemTestsConfiguration.getRemoteHost("127.0.0.1");
        int keyusage = X509KeyUsage.digitalSignature + X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign;
        testx509ca = CaTestUtils.createTestX509CA("CN=TestCA", null, false, keyusage);
        caSession.addCA(admin, testx509ca);
    }

    @After
    public void tearDown() throws Exception {
        CryptoTokenTestUtils.removeCryptoToken(null, testx509ca.getCAToken().getCryptoTokenId());
        caSession.removeCA(admin, testx509ca.getCAId());
    }
    
    @Test
    public void testJspCompile() throws Exception {
        
        // We hit the pages and see that they return a 200 value, so we know
        // they at least compile correctly
        String httpReqPath = "http://"+remoteHost+":" + httpPort + "/ejbca";
        String resourceName = "publicweb/webdist/certdist";
        String resourceName1 = "publicweb/webdist/certdist?cmd=cacert&issuer=CN%3dTestCA&level=0";

        final WebClient webClient = new WebClient();
        WebConnection con = webClient.getWebConnection();
        WebRequestSettings settings = new WebRequestSettings(new URL(httpReqPath + '/' + resourceName));
        WebResponse resp = con.getResponse(settings);
        assertEquals("Response code", 400, resp.getStatusCode());

        settings = new WebRequestSettings(new URL(httpReqPath + '/' + resourceName1));
        resp = con.getResponse(settings);
        assertEquals("Response code", 200, resp.getStatusCode());
    }

    @Test
    public void testPublicWeb() throws Exception {
        // We hit the pages and see that they return a 200 value, so we know
        // they at least compile correctly
        String httpReqPath = "http://"+remoteHost+":" + httpPort + "/ejbca";
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
    
    @SuppressWarnings("unchecked")
    @Test
    public void testPublicWebChainDownload() throws Exception {
    	
        String httpReqPathPem = "http://"+remoteHost+":" + httpPort + "/ejbca/publicweb/webdist/certdist?cmd=cachain&caid=" + testx509ca.getCAId() + "&format=pem";        
        String httpReqPathJks = "http://"+remoteHost+":" + httpPort + "/ejbca/publicweb/webdist/certdist?cmd=cachain&caid=" + testx509ca.getCAId() + "&format=jks";

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
        		assertEquals("attachment; filename=\"TestCA-chain.pem\"", pair.getValue());
        		found = true;
        	}
        }
        assertTrue("Unable find TestCA in certificate chain or parsing the response wrong.", found);

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
        	if (StringUtils.equalsIgnoreCase("Content-disposition", pair.getName())) {
        		assertEquals("attachment; filename=\"TestCA-chain.jks\"", pair.getValue());
        		found = true;
        	}
        }
        assertTrue(found);
    }
}
