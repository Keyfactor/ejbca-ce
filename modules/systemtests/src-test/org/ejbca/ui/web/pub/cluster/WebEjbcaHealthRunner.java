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

import org.apache.log4j.Logger;

import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.WebResponse;

/**
 * Tests the EjbcaHealthCheck (servlet) with load.
 * 
 * @version $Id$
 */
public class WebEjbcaHealthRunner implements Runnable { // NOPMD, this is not a JEE app, only a test
	
	private static Logger log = Logger.getLogger(WebEjbcaHealthRunner.class);

	public static final int NO_TESTS=100;
	
    private String httpReqPath; 

	public WebEjbcaHealthRunner(String reqPath) {
		httpReqPath = reqPath;
	}
	
	public void run() {
		try {
			long before = System.currentTimeMillis();
			final WebClient webClient = new WebClient();
			webClient.setTimeout(31*1000);
			for (int i = 0; i<NO_TESTS;i++) {
				WebResponse resp = webClient.getPage(httpReqPath).getWebResponse();
				int ret = resp.getStatusCode();
				if (ret != 200) {
					throw new Exception("Status code is "+ret);
				}
			}
			long after = System.currentTimeMillis();
			long diff = after - before;
			log.info("Time used ("+Thread.currentThread().getName()+"): "+diff);			
		} catch (Exception e) {
			log.error("", e);
		}
	}

}
