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
 * Run stress tests with ClientToolBax command healthCheckTest
 *
 * @version $Id$
 */
public class HealthCheckTestCommandTest {

    @Rule
    public Timeout testTimeout = new Timeout(600_000); // per test case

    private HealthCheckTest command = new HealthCheckTest();
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
    public void testCommand() {
        exit.expectSystemExitWithStatus(0);
        int numberOfThreads = 1000;
        int numberOfTests = 100_000;
        String waitTime = "2000";
        String[] args = new String[]{"healthCheckTest", httpReqPath + "/publicweb/healthcheck/ejbcahealth",
                numberOfThreads + ":" + numberOfTests, waitTime};
        command.execute(args);
    }
}
