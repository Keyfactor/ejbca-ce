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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.apache.commons.lang.StringUtils;
import org.apache.http.Header;
import org.apache.http.HttpResponse;
import org.apache.log4j.Logger;
import org.bouncycastle.jce.X509KeyUsage;
import org.cesecore.CaTestUtils;
import org.cesecore.SystemTestsConfiguration;
import org.cesecore.WebTestUtils;
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
        log.trace(">testJspCompile");
        // We hit the pages and see that they return a 200 value, so we know
        // they at least compile correctly
        String httpReqPath = "http://"+remoteHost+":" + httpPort + "/ejbca";
        assertEquals("Response code", 200, WebTestUtils.sendGetRequest(httpReqPath + "/publicweb/webdist/certdist?cmd=cacert&issuer=CN%3dTestCA&level=0").getStatusLine().getStatusCode());
        assertEquals("Response code", 400, WebTestUtils.sendGetRequest(httpReqPath + "/publicweb/webdist/certdist").getStatusLine().getStatusCode());
        log.trace("<testJspCompile");
    }

    @Test
    public void testPublicWeb() throws Exception {
        log.trace(">testPublicWeb");
        // We hit the pages and see that they return a 200 value, so we know
        // they at least compile correctly
        String httpReqPath = "http://"+remoteHost+":" + httpPort + "/ejbca";
        String[] resourceNames = {
                "retrieve/ca_crls.jsp", "retrieve/ca_certs.jsp", "retrieve/latest_cert.jsp", "retrieve/list_certs.jsp", "retrieve/check_status.jsp",
                "enrol/browser.jsp", "enrol/server.jsp", "enrol/keystore.jsp"
        };

        for (final String resourceName : resourceNames) {
            assertEquals("Response code", 200, WebTestUtils.sendGetRequest(httpReqPath + '/' + resourceName).getStatusLine().getStatusCode());
        }
        log.trace("<testPublicWeb");
    }
    
    @Test
    public void testPublicWebChainDownload() throws Exception {
        log.trace(">testPublicWebChainDownload");
        String httpReqPathPem = "http://"+remoteHost+":" + httpPort + "/ejbca/publicweb/webdist/certdist?cmd=cachain&caid=" + testx509ca.getCAId() + "&format=pem";        
        String httpReqPathJks = "http://"+remoteHost+":" + httpPort + "/ejbca/publicweb/webdist/certdist?cmd=cachain&caid=" + testx509ca.getCAId() + "&format=jks";

        HttpResponse resp = WebTestUtils.sendGetRequest(httpReqPathPem);
        assertEquals("Response code", 200, resp.getStatusLine().getStatusCode());
        assertNotNull("No response body was sent", resp.getEntity());
        String ctype = resp.getEntity().getContentType().getValue();
        assertTrue("Wrong content type: " + ctype, StringUtils.startsWith(ctype, "application/octet-stream"));
        Header header = resp.getFirstHeader("Content-disposition");
        assertNotNull("Missing Content-disposition header.", header);
        assertEquals("attachment; filename=\"TestCA-chain.pem\"", header.getValue());

        resp = WebTestUtils.sendGetRequest(httpReqPathJks);
        assertEquals("Response code", 200, resp.getStatusLine().getStatusCode());
        assertNotNull("No response body was sent", resp.getEntity());
        ctype = resp.getEntity().getContentType().getValue();
        assertTrue("Wrong content type: " + ctype, StringUtils.startsWith(ctype, "application/octet-stream"));
        header = resp.getFirstHeader("Content-disposition");
        assertNotNull("Missing Content-disposition header.", header);
        assertEquals("attachment; filename=\"TestCA-chain.jks\"", header.getValue());
        log.trace("<testPublicWebChainDownload");
    }
}
