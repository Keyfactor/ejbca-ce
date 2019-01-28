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

package org.ejbca.ui.web.pub.cluster;

import static org.junit.Assert.assertEquals;
import static org.junit.Assume.assumeTrue;

import java.io.IOException;
import java.net.ConnectException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;

import org.apache.log4j.Logger;
import org.cesecore.SystemTestsConfiguration;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.ejb.config.ConfigurationSessionRemote;
import org.junit.Before;
import org.junit.Test;

/**
 * Tests the ClearCacheServlet 
 *
 * @version $Id$
 */
public class WebEjbcaClearCacheTest {
    private static final Logger log = Logger.getLogger(WebEjbcaClearCacheTest.class);

    private ConfigurationSessionRemote configurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ConfigurationSessionRemote.class, EjbRemoteHelper.MODULE_TEST);

    private String httpPort;
    private String httpReqPath;
    private String httpReqPathNoCommand;

    @Before
    public void setUp() throws Exception {
        // Clear cache is only available when sent from localhost or a resolved IP, so there is no point in trying to go through a proxy
        httpPort = SystemTestsConfiguration.getRemotePortHttp(configurationSession.getProperty(WebConfiguration.CONFIG_HTTPSERVERPUBHTTP));
        httpReqPath = "http://localhost:" + httpPort + "/ejbca/clearcache/?command=clearcaches";
        httpReqPathNoCommand = "http://localhost:" + httpPort + "/ejbca/clearcache/";
    }

    @Test
    public void testEjbcaClearCacheHttp() throws Exception {
        log.trace(">testEjbcaHealthHttp()");

        HttpURLConnection con = openConnection(httpReqPath);
        final int responseCode = con.getResponseCode();
        if (responseCode != HttpURLConnection.HTTP_OK) {
            log.info("ResponseMessage: " + con.getResponseMessage());
            assertEquals("Response code", HttpURLConnection.HTTP_OK, responseCode);
        }

        con = openConnection(httpReqPathNoCommand);
        // SC_BAD_REQUEST returned if we do not gove the command=clearcaches parameter in the request
        final int responseCodeBad = con.getResponseCode();
        if (responseCodeBad != HttpURLConnection.HTTP_BAD_REQUEST) {
            log.info("ResponseMessage: " + con.getResponseMessage());
            assertEquals("Response code", HttpURLConnection.HTTP_BAD_REQUEST, responseCodeBad);
        }

        log.trace("<testEjbcaHealthHttp()");
    }

    private HttpURLConnection openConnection(final String url) throws MalformedURLException, ConnectException, IOException {
        try {
            HttpURLConnection con = (HttpURLConnection) new URL(url).openConnection();
            con.getResponseCode(); // trigger a connection
            return con;
        } catch (ConnectException e) {
            log.debug("Failed to connect to localhost:" + httpPort);
            if (isEjbcaRunningExternally()) {
                assumeTrue("Ignoring test failure since EJBCA is running externally at " + SystemTestsConfiguration.getRemoteHost(null), false);
            }
            log.debug("Target hostname does NOT appear to be local, re-throwing exception.");
            throw e;
        }
    }

    private boolean isEjbcaRunningExternally() {
        final String targetHostname = SystemTestsConfiguration.getRemoteHost("localhost");
        log.debug("Checking if target hostname '" + targetHostname + "' is external (this check might not be 100% reliable)");
        return !"localhost".equals(targetHostname) && !"127.0.0.1".equals(targetHostname) && !"::1".equals(targetHostname);
    }
}
