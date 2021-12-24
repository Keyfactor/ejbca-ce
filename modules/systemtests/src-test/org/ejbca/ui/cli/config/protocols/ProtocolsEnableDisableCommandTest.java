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

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.TraceLogMethodsRule;
import org.ejbca.config.AvailableProtocolsConfiguration;
import org.ejbca.config.AvailableProtocolsConfiguration.AvailableProtocols;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;

/**
 * Test of CLI command for enabling/disabling EJBCA protocols.
 * 
 * @version $Id$
 */
public class ProtocolsEnableDisableCommandTest {

    private static final AuthenticationToken authenticationToken = new TestAlwaysAllowLocalAuthenticationToken(ProtocolsEnableDisableCommandTest.class.getSimpleName());

    private static GlobalConfigurationSessionRemote globalConfigurationSession = null;
    private static AvailableProtocolsConfiguration originalAvailableProtocolsConfiguration = null;

    @Rule
    public TestRule traceLogMethodsRule = new TraceLogMethodsRule();

    @BeforeClass
    public static void beforeClass() {
        globalConfigurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);
        originalAvailableProtocolsConfiguration = getAvailableProtocolsConfiguration();
    }

    @AfterClass
    public static void afterClass() throws AuthorizationDeniedException {
        globalConfigurationSession.saveConfiguration(authenticationToken, originalAvailableProtocolsConfiguration);
    }

    private static AvailableProtocolsConfiguration getAvailableProtocolsConfiguration() {
        return (AvailableProtocolsConfiguration) globalConfigurationSession.getCachedConfiguration(AvailableProtocolsConfiguration.CONFIGURATION_ID);
    }

    @Test
    public void updateStatusScep() {
        final LinkedHashMap<String, Boolean> before = (LinkedHashMap<String, Boolean>) getAvailableProtocolsConfiguration().getAllProtocolsAndStatus();
        toggleProtocol(AvailableProtocols.SCEP.getName(), "sCeP");
        toggleProtocol(AvailableProtocols.SCEP.getName(), "--name", "ScEp");
        assertEquals("Operation should not change anything.", before, getAvailableProtocolsConfiguration().getAllProtocolsAndStatus());
    }
    
    @Test
    public void updateStatusRaWeb() {
        final LinkedHashMap<String, Boolean> before = (LinkedHashMap<String, Boolean>) getAvailableProtocolsConfiguration().getAllProtocolsAndStatus();
        toggleProtocol(AvailableProtocols.RA_WEB.getName(), "RA WeB");
        toggleProtocol(AvailableProtocols.RA_WEB.getName(), "--name", "RA_wEB");
        assertEquals("Operation should not change anything.", before, getAvailableProtocolsConfiguration().getAllProtocolsAndStatus());
    }

    @Test
    public void protocolNameShouldBeMandatory() {
        final LinkedHashMap<String, Boolean> before = (LinkedHashMap<String, Boolean>) getAvailableProtocolsConfiguration().getAllProtocolsAndStatus();
        assertEquals(CommandResult.CLI_FAILURE, new ProtocolsDisableCommand().execute());
        assertEquals(CommandResult.CLI_FAILURE, new ProtocolsEnableCommand().execute());
        assertEquals(CommandResult.CLI_FAILURE, new ProtocolsDisableCommand().execute("--name"));
        assertEquals(CommandResult.CLI_FAILURE, new ProtocolsEnableCommand().execute("--name"));
        assertEquals("Operation should not change anything.", before, getAvailableProtocolsConfiguration().getAllProtocolsAndStatus());
    }

    @Test
    public void unknownProtocolNamesShouldFail() {
        final LinkedHashMap<String, Boolean> before = (LinkedHashMap<String, Boolean>) getAvailableProtocolsConfiguration().getAllProtocolsAndStatus();
        assertEquals(CommandResult.CLI_FAILURE, new ProtocolsDisableCommand().execute("PlainHttpCurlPipeToSudo"));
        assertEquals(CommandResult.CLI_FAILURE, new ProtocolsEnableCommand().execute("PlainHttpCurlPipeToSudo"));
        assertEquals(CommandResult.CLI_FAILURE, new ProtocolsDisableCommand().execute("--name", "PlainHttpCurlPipeToSudo"));
        assertEquals(CommandResult.CLI_FAILURE, new ProtocolsEnableCommand().execute("--name", "PlainHttpCurlPipeToSudo"));
        assertEquals("Operation should not change anything.", before, getAvailableProtocolsConfiguration().getAllProtocolsAndStatus());
    }

    private void toggleProtocol(final String protocolName, final String...params) {
        final boolean originalState = getAvailableProtocolsConfiguration().getAllProtocolsAndStatus().get(protocolName);
        // Performing the same action multiple times should not change anything
        for (int i=0; i<2; i++) {
            if (originalState) {
                assertEquals(CommandResult.SUCCESS, new ProtocolsDisableCommand().execute(params));
            } else {
                assertEquals(CommandResult.SUCCESS, new ProtocolsEnableCommand().execute(params));
            }
            assertEquals(!originalState, getAvailableProtocolsConfiguration().getAllProtocolsAndStatus().get(protocolName));
        }
    }
}
