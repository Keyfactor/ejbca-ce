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
package org.ejbca.ui.cli;

import static org.junit.Assert.*;
import junit.framework.Assert;

import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.jndi.JndiHelper;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.authentication.cli.CliAuthenticationTestHelperSessionRemote;
import org.ejbca.core.ejb.config.GlobalConfigurationSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionRemote;
import org.ejbca.core.ejb.ra.UserAdminSessionRemote;
import org.junit.Before;
import org.junit.Test;

/**
 * This test class tests different aspects of cli authentication using a mock
 * cli command.
 * 
 * @version $Id$
 * 
 */
public class CliCommandAuthenticationTest {

    private MockCliCommand mockCliCommand;
    private EndEntityAccessSessionRemote endEntityAccessSession = JndiHelper.getRemoteSession(EndEntityAccessSessionRemote.class);
    private GlobalConfigurationSessionRemote globalConfigurationSession = JndiHelper.getRemoteSession(GlobalConfigurationSessionRemote.class);
    private CliAuthenticationTestHelperSessionRemote cliAuthenticationTestHelperSession = JndiHelper
            .getRemoteSession(CliAuthenticationTestHelperSessionRemote.class);
    private UserAdminSessionRemote userAdminSession = JndiHelper.getRemoteSession(UserAdminSessionRemote.class);

    private final TestAlwaysAllowLocalAuthenticationToken internalAdmin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal(
            "CliAuthenticationTest"));

    @Before
    public void setUp() throws Exception {
        mockCliCommand = new MockCliCommand();
        // Just make sure that the tests can run at all
        Assert.assertNotNull("Can't run tests, default user doesn't exist.",
                endEntityAccessSession.findUser(internalAdmin, EjbcaConfiguration.getCliDefaultUser()));
    }

    public void tearDown() throws Exception {

    }

    @Test
    public void testWithoutSuppliedDefaultUser() throws ErrorAdminCommandException {
        boolean oldValue = setCliUserEnabled(true);
        try {
            mockCliCommand.execute(new String[] { "foo", "bar" });
        } catch (CliTestRuntimeException e) {
            fail("Default user was not used when allowed");
        } finally {
            setCliUserEnabled(oldValue);
        }
    }

    @Test
    public void testWithSuppliedDefaultUser() throws Exception {
        boolean oldValue = setCliUserEnabled(true);
        try {
            mockCliCommand.execute(new String[] { "foo", "-u", EjbcaConfiguration.getCliDefaultUser() });
        } catch (CliTestRuntimeException e) {
            fail("Default user was not used when allowed");
        } finally {
            setCliUserEnabled(oldValue);
        }
    }

    @Test
    public void testWithUnknownUser() throws Exception {
        try {
            mockCliCommand.execute(new String[] { "foo", "-u", "TomDickAnd", "-password=harry" });
            fail("Exception was not thrown when authenticating with unknown user.");
        } catch (CliTestRuntimeException e) {
            // All is well.
        }
    }

    @Test
    public void testWithKnownUser() throws Exception {
        cliAuthenticationTestHelperSession.createUser(CliAuthenticationTestHelperSessionRemote.USERNAME, CliAuthenticationTestHelperSessionRemote.PASSWORD);
        try {
            mockCliCommand.execute(new String[] { "foo", "-u", CliAuthenticationTestHelperSessionRemote.USERNAME,
                    "-password=" + CliAuthenticationTestHelperSessionRemote.PASSWORD });
        } catch (CliTestRuntimeException e) {
            fail("Exception was thrown when authenticating with a known user.");
        } finally {
            userAdminSession.deleteUser(internalAdmin, CliAuthenticationTestHelperSessionRemote.USERNAME);
        }
    }

    @Test
    public void testWithoutSuppliedDefaultUserAndForbidden() throws Exception {
        boolean oldValue = setCliUserEnabled(false);
        try {
            mockCliCommand.execute(new String[] { "foo", "bar" });
            fail("Use of default user should not have been allowed");
        } catch (CliTestRuntimeException e) {
            // Ignore
        } finally {
            setCliUserEnabled(oldValue);
        }
    }

    @Test
    public void testDefaultUserWhenForbidden() throws Exception {
        boolean oldValue = setCliUserEnabled(false);
        try {
            mockCliCommand.execute(new String[] { "foo", "-u", EjbcaConfiguration.getCliDefaultUser() });
            fail("Use of default user should not have been allowed");
        } catch (CliTestRuntimeException e) {
            // Ignore
        } finally {
            setCliUserEnabled(oldValue);
        }
    }

    @Test
    public void testDisableCli() throws Exception {
        boolean oldValue = setCliEnabled(false);
        try {
            mockCliCommand.execute(new String[] { "foo", "-u", EjbcaConfiguration.getCliDefaultUser() });
            fail("CLI should not have been able to have been run when disabled.");
        } catch (ErrorAdminCommandException e) {
            // Ignore
        } finally {
            setCliEnabled(oldValue);
        }
    }

    private boolean setCliEnabled(boolean enabled) {
        GlobalConfiguration config = globalConfigurationSession.getCachedGlobalConfiguration();
        boolean oldValue = config.getEnableCommandLineInterface();
        config.setEnableCommandLineInterface(enabled);
        globalConfigurationSession.saveGlobalConfigurationRemote(internalAdmin, config);
        return oldValue;
    }

    private boolean setCliUserEnabled(boolean enabled) {
        GlobalConfiguration config = globalConfigurationSession.getCachedGlobalConfiguration();
        boolean oldValue = config.getEnableCommandLineInterfaceDefaultUser();
        config.setEnableCommandLineInterfaceDefaultUser(enabled);
        globalConfigurationSession.saveGlobalConfigurationRemote(internalAdmin, config);
        return oldValue;
    }
}

class MockCliCommand extends BaseCommand {

    @Override
    public String getMainCommand() {
        return null;
    }

    @Override
    public String getSubCommand() {
        return null;
    }

    @Override
    public String getDescription() {
        return null;
    }

    @Override
    public void execute(String[] args) throws ErrorAdminCommandException {
        try {
            args = parseUsernameAndPasswordFromArgs(args);
        } catch (CliUsernameException e) {
            throw new CliTestRuntimeException();
        }
    }

}

/*
 * This exception is tossed because execute can't pass on a CliUsernameException
 */
class CliTestRuntimeException extends RuntimeException {

    private static final long serialVersionUID = 1L;

}