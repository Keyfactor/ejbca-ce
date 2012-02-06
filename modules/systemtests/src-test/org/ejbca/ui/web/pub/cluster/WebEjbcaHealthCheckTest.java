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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.apache.log4j.Logger;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.ejb.config.ConfigurationSessionRemote;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.WebResponse;

/**
 *
 * @version $Id$
 */
public class WebEjbcaHealthCheckTest extends WebHealthTestAbstract {

	private static final Logger log = Logger.getLogger(WebEjbcaHealthCheckTest.class);

    private ConfigurationSessionRemote configurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ConfigurationSessionRemote.class);

    @Before
    public void setUp() throws Exception {
        httpPort = configurationSession.getProperty(WebConfiguration.CONFIG_HTTPSERVERPUBHTTP);
        httpReqPath = "http://localhost:" + httpPort + "/ejbca/publicweb/healthcheck/ejbcahealth";
    }

    @After
    public void tearDown() throws Exception {
    }

    /**
     * Creates a number of threads that bombards the health check servlet 1000
     * times each
     */
    @Test
    public void testEjbcaHealthHttp() throws Exception {
        log.trace(">testEjbcaHealthHttp()");

        // Make a quick test first that it works at all before starting all threads
        final WebClient webClient = new WebClient();
		webClient.setTimeout(31*1000);
        WebResponse resp = webClient.getPage(httpReqPath).getWebResponse();
        assertEquals("Response code", 200, resp.getStatusCode());
        assertEquals("ALLOK", resp.getContentAsString());
        long before = System.currentTimeMillis();
        createThreads();
        long after = System.currentTimeMillis();
        long diff = after - before;
        log.info("All threads finished. Total time: " + diff + " ms");
        assertTrue("Healt check test(s) timed out!", diff < 30L*1000L);
        log.trace("<testEjbcaHealthHttp()");
    }

}
