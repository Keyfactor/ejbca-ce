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

import java.net.HttpURLConnection;
import java.net.URL;

import org.apache.log4j.Logger;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.ejb.config.ConfigurationSessionRemote;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @version $Id$
 */
public class WebEjbcaClearCacheTest {
    private static final Logger log = Logger.getLogger(WebEjbcaClearCacheTest.class);

    private ConfigurationSessionRemote configurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ConfigurationSessionRemote.class, EjbRemoteHelper.MODULE_TEST);

    protected String httpPort;
    protected String httpReqPath;
    protected String httpReqPathNoCommand;

    @Before
    public void setUp() throws Exception {
        // Clear cache is only available when sent from localhost or a resolved IP, so there is no point in trying to go through a proxy
        httpPort = configurationSession.getProperty(WebConfiguration.CONFIG_HTTPSERVERPUBHTTP);
        httpReqPath = "http://localhost:" + httpPort + "/ejbca/clearcache/?command=clearcaches";
        httpReqPathNoCommand = "http://localhost:" + httpPort + "/ejbca/clearcache/";
    }

    @After
    public void tearDown() throws Exception {
    }

    @Test
    public void testEjbcaClearCacheHttp() throws Exception {
        log.trace(">testEjbcaHealthHttp()");

		URL url = new URL(httpReqPath);
		HttpURLConnection con = (HttpURLConnection) url.openConnection();
        final int responseCode = con.getResponseCode();
        if (responseCode != HttpURLConnection.HTTP_OK) {
            log.info("ResponseMessage: " + con.getResponseMessage());
            assertEquals("Response code", HttpURLConnection.HTTP_OK, responseCode);
        }

		url = new URL(httpReqPathNoCommand);
		con = (HttpURLConnection) url.openConnection();
		// SC_BAD_REQUEST returned if we do not gove the command=clearcaches parameter in the request
        final int responseCodeBad = con.getResponseCode();
        if (responseCodeBad != HttpURLConnection.HTTP_BAD_REQUEST) {
            log.info("ResponseMessage: " + con.getResponseMessage());
            assertEquals("Response code", HttpURLConnection.HTTP_BAD_REQUEST, responseCodeBad);
        }

        log.trace("<testEjbcaHealthHttp()");
    }

}
