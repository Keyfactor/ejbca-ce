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
package org.ejbca.ui.cli;

import org.cesecore.SystemTestsConfiguration;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.ejb.config.ConfigurationSessionRemote;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.ExpectedSystemExit;
import org.junit.rules.Timeout;

/**
 * Unit tests for ClientToolBax command healthCheck
 *
 * @version $Id$
 */
public class HealthCheckCommandTest {

    @Rule
    public Timeout testTimeout = new Timeout(60_000); // per test case

    private HealthCheck command = new HealthCheck();
    private String httpReqPath;

    @Rule
    public final ExpectedSystemExit exit = ExpectedSystemExit.none();

    @Before
    public void setUp() throws Exception {
        ConfigurationSessionRemote configurationSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(ConfigurationSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
        final String httpHost = SystemTestsConfiguration.getRemoteHost(configurationSessionRemote.getProperty(WebConfiguration.CONFIG_HTTPSSERVERHOSTNAME));
        final String httpPort = SystemTestsConfiguration.getRemotePortHttp(configurationSessionRemote.getProperty(WebConfiguration.CONFIG_HTTPSERVERPUBHTTP));
        httpReqPath = "http://" + httpHost + ":" + httpPort + "/ejbca";
    }

    @Test
    public void testCommandSucceeds() {
        String[] args = new String[]{"healthCheck", httpReqPath + "/publicweb/healthcheck/ejbcahealth"};
        command.execute(args);
    }

    @Test
    public void testCommandWrongUri() {
        exit.expectSystemExitWithStatus(-1);

        String[] args = new String[]{"healthCheck", "bad.url"};
        command.execute(args);
    }
}
