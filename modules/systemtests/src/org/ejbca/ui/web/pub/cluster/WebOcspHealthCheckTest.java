package org.ejbca.ui.web.pub.cluster;

import org.apache.log4j.Logger;

import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.WebResponse;

/**
 *
 * @version $Id: WebOcspHealthCheckTest.java 9566 2010-07-29 23:12:16Z jeklund $
 */
public class WebOcspHealthCheckTest extends WebHealthTestAbstract {
    private static final Logger log = Logger.getLogger(WebOcspHealthCheckTest.class);

    /**
     * Creates a new TestSignSession object.
     *
     * @param name name
     */
    public WebOcspHealthCheckTest(String name) {
        super(name);
        httpPort = "8080"; 
        httpReqPath = "http://localhost:" + httpPort + "/ejbca/publicweb/ocsphealthcheck/extocsphealth";
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
        // Make a quick test first that it works at all before starting all threads
        final WebClient webClient = new WebClient();
		webClient.setTimeout(10*1000);	// 10 seconds timeout
        WebResponse resp = webClient.getPage(httpReqPath).getWebResponse();
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

