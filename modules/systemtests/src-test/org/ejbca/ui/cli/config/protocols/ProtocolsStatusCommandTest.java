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
package org.ejbca.ui.cli.config.protocols;

import static org.junit.Assert.assertEquals;

import java.util.LinkedHashMap;

import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.TraceLogMethodsRule;
import org.ejbca.config.AvailableProtocolsConfiguration;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;

/**
 * Test of CLI command for showing EJBCA protocol enabled/disabled status.
 * 
 * @version $Id$
 */
public class ProtocolsStatusCommandTest {

    private static GlobalConfigurationSessionRemote globalConfigurationSession = null;

    @Rule
    public TestRule traceLogMethodsRule = new TraceLogMethodsRule();

    @BeforeClass
    public static void beforeClass() {
        globalConfigurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);
    }

    private AvailableProtocolsConfiguration getAvailableProtocolsConfiguration() {
        return (AvailableProtocolsConfiguration) globalConfigurationSession.getCachedConfiguration(AvailableProtocolsConfiguration.CONFIGURATION_ID);
    }

    @Test
    public void statusForAllProtocols() {
        final LinkedHashMap<String, Boolean> before = (LinkedHashMap<String, Boolean>) getAvailableProtocolsConfiguration().getAllProtocolsAndStatus();
        final CommandResult commandResult = new ProtocolsStatusCommand().execute();
        assertEquals(CommandResult.SUCCESS, commandResult);
        assertEquals("Operation should not change anything.", before, getAvailableProtocolsConfiguration().getAllProtocolsAndStatus());
    }

    @Test
    public void statusForExistingProtocol() {
        final LinkedHashMap<String, Boolean> before = (LinkedHashMap<String, Boolean>) getAvailableProtocolsConfiguration().getAllProtocolsAndStatus();
        final CommandResult commandResult1 = new ProtocolsStatusCommand().execute("SCEP");
        assertEquals(CommandResult.SUCCESS, commandResult1);
        final CommandResult commandResult2 = new ProtocolsStatusCommand().execute("scep");
        assertEquals(CommandResult.SUCCESS, commandResult2);
        final CommandResult commandResult3 = new ProtocolsStatusCommand().execute("sCeP");
        assertEquals(CommandResult.SUCCESS, commandResult3);
        final CommandResult commandResult4 = new ProtocolsStatusCommand().execute("--name", "sCeP");
        assertEquals(CommandResult.SUCCESS, commandResult4);
        assertEquals("Operation should not change anything.", before, getAvailableProtocolsConfiguration().getAllProtocolsAndStatus());
    }

    @Test
    public void statusForNonExistingProtocol() {
        final LinkedHashMap<String, Boolean> before = (LinkedHashMap<String, Boolean>) getAvailableProtocolsConfiguration().getAllProtocolsAndStatus();
        final CommandResult commandResult1 = new ProtocolsStatusCommand().execute("PlainHttpCurlPipeToSudo");
        assertEquals(CommandResult.CLI_FAILURE, commandResult1);
        final CommandResult commandResult2 = new ProtocolsStatusCommand().execute("--name", "PlainHttpCurlPipeToSudo");
        assertEquals(CommandResult.CLI_FAILURE, commandResult2);
        final CommandResult commandResult3 = new ProtocolsStatusCommand().execute("--name");
        assertEquals(CommandResult.CLI_FAILURE, commandResult3);
        assertEquals("Operation should not change anything.", before, getAvailableProtocolsConfiguration().getAllProtocolsAndStatus());
    }
}
