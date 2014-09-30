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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.io.FileWriter;
import java.security.Principal;
import java.util.HashSet;
import java.util.Set;

import javax.ejb.EJBException;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.Configuration;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.authentication.cli.CliAuthenticationProviderSessionRemote;
import org.ejbca.core.ejb.authentication.cli.CliAuthenticationTestHelperSessionRemote;
import org.ejbca.core.ejb.authentication.cli.exception.CliAuthenticationFailedException;
import org.ejbca.core.ejb.config.GlobalConfigurationSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.command.EjbcaCliUserCommandBase;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.junit.After;
import org.junit.Assert;
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

    private static final Logger log = Logger.getLogger(CliCommandAuthenticationTest.class);

    private MockCliCommand mockCliCommand;
    private EndEntityAccessSessionRemote endEntityAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityAccessSessionRemote.class);
    private GlobalConfigurationSessionRemote globalConfigurationSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(GlobalConfigurationSessionRemote.class);
    private CliAuthenticationTestHelperSessionRemote cliAuthenticationTestHelperSession = EjbRemoteHelper.INSTANCE.getRemoteSession(
            CliAuthenticationTestHelperSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(EndEntityManagementSessionRemote.class);
    private CliAuthenticationProviderSessionRemote cliAuthenticationProvider = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CliAuthenticationProviderSessionRemote.class);

    private final TestAlwaysAllowLocalAuthenticationToken internalAdmin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal(
            "CliCommandAuthenticationTest"));

    @Before
    public void setUp() throws Exception {
        mockCliCommand = new MockCliCommand();
        // Just make sure that the tests can run at all
        Assert.assertNotNull("Can't run tests, default user doesn't exist.",
                endEntityAccessSession.findUser(internalAdmin, EjbcaConfiguration.getCliDefaultUser()));
    }

    @After
    public void tearDown() throws Exception {
    }

    @Test
    public void testWithoutSuppliedDefaultUser() throws AuthorizationDeniedException {
        boolean oldValue = setCliUserEnabled(true);
        log.debug("oldValue (user): " + oldValue);
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
        log.debug("oldValue (user): " + oldValue);
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
            CommandResult result = mockCliCommand.execute(new String[] { "foo", "-u", "TomDickAnd", "--clipassword=harry" });
            assertFalse("Exception was not thrown when authenticating with unknown user.", result.equals(CommandResult.SUCCESS));
        } catch (CliTestRuntimeException e) {
            // All is well.
        }
    }

    @Test
    public void testWithKnownUser() throws Exception {
        cliAuthenticationTestHelperSession.createUser(CliAuthenticationTestHelperSessionRemote.USERNAME,
                CliAuthenticationTestHelperSessionRemote.PASSWORD);
        try {
            mockCliCommand.execute(new String[] { "foo", "-u", CliAuthenticationTestHelperSessionRemote.USERNAME,
                    "--clipassword=" + CliAuthenticationTestHelperSessionRemote.PASSWORD });
        } catch (CliTestRuntimeException e) {
            fail("Exception was thrown when authenticating with a known user.");
        } finally {
            endEntityManagementSession.deleteUser(internalAdmin, CliAuthenticationTestHelperSessionRemote.USERNAME);
        }
    }

    @Test
    public void testWithKnownUserPasswordInFile() throws Exception {
        cliAuthenticationTestHelperSession.createUser(CliAuthenticationTestHelperSessionRemote.USERNAME,
                CliAuthenticationTestHelperSessionRemote.PASSWORD);
        try {

            CommandResult result = mockCliCommand.execute(new String[] { "-u", CliAuthenticationTestHelperSessionRemote.USERNAME,
                    "--clipassword=file:/tmp/fileshouldnotexist.txt" });
            assertFalse("/tmp/fileshouldnotexist.txt should not have existed.", result.equals(CommandResult.SUCCESS));
            File f = File.createTempFile("ejbca", "txt");
            f.deleteOnExit();
            // Just insert a space, should count as not password existing in the file
            FileWriter fout = new FileWriter(f);
            fout.write(" ");
            fout.close();

            result = mockCliCommand.execute(new String[] { "-u", CliAuthenticationTestHelperSessionRemote.USERNAME,
                    "--clipassword=file:" + f.getAbsolutePath() });
            assertFalse("/tmp/fileshouldnotexist.txt should not have contained any password.", result.equals(CommandResult.SUCCESS));

            // Insert a line with a password
            fout = new FileWriter(f);
            fout.write(CliAuthenticationTestHelperSessionRemote.PASSWORD);
            fout.close();

            result = mockCliCommand.execute(new String[] {"-u", CliAuthenticationTestHelperSessionRemote.USERNAME,
                    "--clipassword=file:" + f.getAbsolutePath() });
            assertTrue("/tmp/fileshouldnotexist.txt should have contained a password, and command sould have worked. ",
                    CommandResult.SUCCESS.equals(result));

            // Insert a line with a password, some whitespace and newline should work as well
            fout = new FileWriter(f);
            fout.write(CliAuthenticationTestHelperSessionRemote.PASSWORD + "  \n");
            fout.close();

            result = mockCliCommand.execute(new String[] { "-u", CliAuthenticationTestHelperSessionRemote.USERNAME,
                    "--clipassword=file:" + f.getAbsolutePath() });
            assertTrue("/tmp/fileshouldnotexist.txt should have contained a password, and command sould have worked. ", CommandResult.SUCCESS.equals(result));

        } catch (CliTestRuntimeException e) {
            fail("Exception was thrown when authenticating with a known user.");
        } finally {
            endEntityManagementSession.deleteUser(internalAdmin, CliAuthenticationTestHelperSessionRemote.USERNAME);
        }
    }

    @Test
    public void testWithoutSuppliedDefaultUserAndForbidden() throws Exception {
        boolean oldValue = setCliUserEnabled(false);
        log.debug("oldValue (user): " + oldValue);
        try {
            CommandResult result = mockCliCommand.execute(new String[] { "foo", "bar" });
            assertFalse("Use of default user should not have been allowed", result.equals(CommandResult.SUCCESS));
        }  finally {
            setCliUserEnabled(oldValue);
        }
    }

    @Test
    public void testDefaultUserWhenForbidden() throws Exception {
        boolean oldValue = setCliUserEnabled(false);
        log.debug("oldValue (user): " + oldValue);
        try {
            CommandResult result = mockCliCommand.execute(new String[] { "foo", "-u", EjbcaConfiguration.getCliDefaultUser() });
            assertEquals("Use of default user should not have been allowed", CommandResult.CLI_FAILURE, result);
        } finally {
            setCliUserEnabled(oldValue);
        }
    }

    @Test
    public void testDisableCli() throws Exception {
        boolean oldValue = setCliEnabled(false);
        log.debug("oldValue (cli): " + oldValue);
        try {
            CommandResult result = mockCliCommand.execute(new String[] { "foo", "-u", EjbcaConfiguration.getCliDefaultUser() });
            assertFalse("CLI should not have been able to have been run when disabled.", CommandResult.SUCCESS.equals(result));
        } finally {
            setCliEnabled(oldValue);
        }
    }

    /**
     * Test that this works server side as well. 
     * @throws AuthorizationDeniedException 
     */
    @Test
    public void testCliDisabledServerSide() throws AuthorizationDeniedException {
        boolean oldValue = setCliEnabled(false);
        log.debug("oldValue (cli): " + oldValue);
        try {
            AuthenticationToken token = cliAuthenticationProvider.authenticate(null);
            assertNull("Cli should not have been able to authenticate.", token);
        } catch (EJBException e) {
            //Glassfish wraps Exceptions in a EJBException wrapping a java.rmi.ServerException wrapping a java.rmi.RemoteException
            if ((e.getCausedByException().getCause().getCause() instanceof CliAuthenticationFailedException)) {
                //NOPMD
            } else {
                throw e;
            }
        } finally {
            setCliEnabled(oldValue);
        }
    }

    /**
     * Test that this works server side as well. 
     * @throws AuthorizationDeniedException 
     */
    @Test
    public void testDefaultCliUserDisabled() throws AuthorizationDeniedException {
        boolean oldValue = setCliUserEnabled(false);
        log.debug("oldValue (user): " + oldValue);
        try {
            Set<Principal> principals = new HashSet<Principal>();
            principals.add(new UsernamePrincipal(EjbcaConfiguration.getCliDefaultUser()));
            AuthenticationToken authenticationToken = cliAuthenticationProvider.authenticate(new AuthenticationSubject(principals, null));
            assertNull("Cli should not have been able to authenticate using default cli user.", authenticationToken);
        } catch (EJBException e) {
            //Glassfish wraps Exceptions in a EJBException wrapping a java.rmi.ServerException wrapping a java.rmi.RemoteException
            if ((e.getCausedByException().getCause().getCause() instanceof CliAuthenticationFailedException)) {
                //NOPMD
            } else {
                throw e;
            }
        } finally {
            setCliUserEnabled(oldValue);
        }
    }

    private boolean setCliEnabled(boolean enabled) throws AuthorizationDeniedException {
        GlobalConfiguration config = (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(Configuration.GlobalConfigID);
        boolean oldValue = config.getEnableCommandLineInterface();
        config.setEnableCommandLineInterface(enabled);
        globalConfigurationSession.saveConfiguration(internalAdmin, config, Configuration.GlobalConfigID);
        log.debug("Updated globalconfiguration with clienabled: " + config.getEnableCommandLineInterface());
        return oldValue;
    }

    private boolean setCliUserEnabled(boolean enabled) throws AuthorizationDeniedException {
        GlobalConfiguration config = (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(Configuration.GlobalConfigID);
        boolean oldValue = config.getEnableCommandLineInterfaceDefaultUser();
        config.setEnableCommandLineInterfaceDefaultUser(enabled);
        globalConfigurationSession.saveConfiguration(internalAdmin, config, Configuration.GlobalConfigID);
        log.debug("Updated globalconfiguration with cliuserenabled: " + config.getEnableCommandLineInterfaceDefaultUser());
        return oldValue;
    }

    class MockCliCommand extends EjbcaCliUserCommandBase {

        @Override
        public String getMainCommand() {
            return null;
        }

        @Override
        public String getCommandDescription() {
            return null;
        }

        @Override
        protected CommandResult execute(ParameterContainer parameters) {
            return CommandResult.SUCCESS;
        }

        @Override
        public String getFullHelpText() {
            return null;
        }

        @Override
        protected Logger getLogger() {
            return null;
        }

    }
}

/*
 * This exception is tossed because execute can't pass on a CliUsernameException
 */
class CliTestRuntimeException extends RuntimeException {

    private static final long serialVersionUID = 1L;

}
