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

import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.ejbca.config.WebConfiguration;
import org.ejbca.util.TestTools;

import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.WebConnection;
import com.gargoylesoftware.htmlunit.WebRequestSettings;
import com.gargoylesoftware.htmlunit.WebResponse;

/**
 *
 * @version $Id$
 */
public class WebEjbcaHealthCheckTest extends TestCase {
    private static final Logger log = Logger.getLogger(WebEjbcaHealthCheckTest.class);

	protected final static String httpPort;
	static {
		String tmp;
		try {
			tmp = TestTools.getConfigurationSession().getProperty(WebConfiguration.CONFIG_HTTPSERVERPUBHTTP, "8080");
		} catch (Exception e) {
			tmp = "8080";
			log.error("Not possible to get property "+WebConfiguration.CONFIG_HTTPSERVERPUBHTTP, e);
		}
		httpPort = tmp;
	}

	private static final String httpReqPath = "http://localhost:" + httpPort + "/ejbca/publicweb/healthcheck/ejbcahealth";

    /**
     * Creates a new TestSignSession object.
     *
     * @param name name
     */
    public WebEjbcaHealthCheckTest(String name) {
        super(name);
    }

    protected void setUp() throws Exception {
    }

    protected void tearDown() throws Exception {
    }

    /**
     * Creates a number of threads that bombards the health check servlet 1000 times each
     */
    public void test01EjbcaHealthHttp() throws Exception {
        log.trace(">test01EjbcaHealthHttp()");

        // Make a quick test first that it works at all before starting all threads
        final WebClient webClient = new WebClient();
        WebRequestSettings settings = new WebRequestSettings(new URL(httpReqPath));
        WebConnection con = webClient.getWebConnection();
        WebResponse resp = con.getResponse(settings);
        assertEquals( "Response code", 200, resp.getStatusCode() );
        assertEquals("ALLOK", resp.getContentAsString());

		long before = System.currentTimeMillis();
        Thread no1 = new Thread(new WebEjbcaHealthRunner(httpReqPath),"no1");
        Thread no2 = new Thread(new WebEjbcaHealthRunner(httpReqPath),"no2");
        Thread no3 = new Thread(new WebEjbcaHealthRunner(httpReqPath),"no3");
        Thread no4 = new Thread(new WebEjbcaHealthRunner(httpReqPath),"no4");
        Thread no5 = new Thread(new WebEjbcaHealthRunner(httpReqPath),"no5");
        no1.start();
        log.info("Started no1");
        no2.start();
        log.info("Started no2");
        no3.start();
        log.info("Started no3");
        no4.start();
        log.info("Started no4");
        no5.start();
        log.info("Started no5");
        no1.join();
        no2.join();
        no3.join();
        no4.join();
        no5.join();
		long after = System.currentTimeMillis();
		long diff = after - before;
		log.info("All threads finished. Total time: "+diff+" ms");
        log.trace("<test01EjbcaHealthHttp()");
    }
    
}
