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

package org.ejbca.ui.web.pub.cluster;

import java.net.URL;

import org.apache.log4j.Logger;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.ejb.upgrade.ConfigurationSessionRemote;
import org.ejbca.util.InterfaceCache;

import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.WebConnection;
import com.gargoylesoftware.htmlunit.WebRequestSettings;
import com.gargoylesoftware.htmlunit.WebResponse;

/**
 *
 * @version $Id$
 */
public class WebEjbcaHealthCheckTest extends WebHealthTestAbstract {
    private static final Logger log = Logger.getLogger(WebEjbcaHealthCheckTest.class);

    private ConfigurationSessionRemote configurationSession = InterfaceCache.getConfigurationSession();

    /**
     * Creates a new TestSignSession object.
     *
     * @param name name
     */
    public WebEjbcaHealthCheckTest(String name) {
        super(name);
        httpPort = configurationSession.getProperty(WebConfiguration.CONFIG_HTTPSERVERPUBHTTP, "8080");
        httpReqPath = "http://localhost:" + httpPort + "/ejbca/publicweb/healthcheck/ejbcahealth";
    }

    public void setUp() throws Exception {
    }

    public void tearDown() throws Exception {
    }

    /**
     * Creates a number of threads that bombards the health check servlet 1000
     * times each
     */
    public void testEjbcaHealthHttp() throws Exception {
        log.trace(">testEjbcaHealthHttp()");

        // Make a quick test first that it works at all before starting all
        // threads
        final WebClient webClient = new WebClient();
        WebRequestSettings settings = new WebRequestSettings(new URL(httpReqPath));
        WebConnection con = webClient.getWebConnection();
        WebResponse resp = con.getResponse(settings);
        assertEquals("Response code", 200, resp.getStatusCode());
        assertEquals("ALLOK", resp.getContentAsString());
        long before = System.currentTimeMillis();
        createThreads();
        long after = System.currentTimeMillis();
        long diff = after - before;
        log.info("All threads finished. Total time: " + diff + " ms");
        log.trace("<testEjbcaHealthHttp()");
    }

}
