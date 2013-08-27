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

import static org.junit.Assert.fail;

import java.io.File;
import java.io.FileWriter;
import java.security.Principal;
import java.util.HashSet;
import java.util.Set;

import javax.ejb.EJBException;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationSubject;
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
    private GlobalConfigurationSessionRemote globalConfigurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);
    private CliAuthenticationTestHelperSessionRemote cliAuthenticationTestHelperSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CliAuthenticationTestHelperSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    private CliAuthenticationProviderSessionRemote cliAuthenticationProvider = EjbRemoteHelper.INSTANCE.getRemoteSession(CliAuthenticationProviderSessionRemote.class);

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
    public void testWithoutSuppliedDefaultUser() throws ErrorAdminCommandException, AuthorizationDeniedException {
        boolean oldValue = setCliUserEnabled(true);
        log.debug("oldValue (user): "+oldValue);
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
        log.debug("oldValue (user): "+oldValue);
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
            endEntityManagementSession.deleteUser(internalAdmin, CliAuthenticationTestHelperSessionRemote.USERNAME);
        }
    }

    @Test
    public void testWithKnownUserPasswordInFile() throws Exception {
        cliAuthenticationTestHelperSession.createUser(CliAuthenticationTestHelperSessionRemote.USERNAME, CliAuthenticationTestHelperSessionRemote.PASSWORD);
        try {
            try {
                mockCliCommand.execute(new String[] { "foo", "-u", CliAuthenticationTestHelperSessionRemote.USERNAME,
                "-password=file:/tmp/fileshouldnotexist.txt" });
                fail("/tmp/fileshouldnotexist.txt should not have existed.");
            } catch (ErrorAdminCommandException e) {
                // NOPMD: The last command should have failed, so go on with next fail test
            }
            File f = File.createTempFile("ejbca", "txt");
            f.deleteOnExit();
            // Just insert a space, should count as not password existing in the file
            FileWriter fout = new FileWriter(f);
            fout.write(" ");
            fout.close();
            try {
                mockCliCommand.execute(new String[] { "foo", "-u", CliAuthenticationTestHelperSessionRemote.USERNAME,
                "-password=file:"+f.getAbsolutePath() });
                fail("/tmp/fileshouldnotexist.txt should not have contained any password.");
            } catch (ErrorAdminCommandException e) {
                // NOPMD: The last command should have failed, so go on with successful
            }
            // Insert a line with a password
            fout = new FileWriter(f);
            fout.write(CliAuthenticationTestHelperSessionRemote.PASSWORD);
            fout.close();
            try {
                mockCliCommand.execute(new String[] { "foo", "-u", CliAuthenticationTestHelperSessionRemote.USERNAME,
                "-password=file:"+f.getAbsolutePath() });
            } catch (ErrorAdminCommandException e) {
                fail("/tmp/fileshouldnotexist.txt should not have contained a password.");
            }
            // Insert a line with a password, some whitespace and newline should work as well
            fout = new FileWriter(f);
            fout.write(CliAuthenticationTestHelperSessionRemote.PASSWORD+"  \n");
            fout.close();
            try {
                mockCliCommand.execute(new String[] { "foo", "-u", CliAuthenticationTestHelperSessionRemote.USERNAME,
                "-password=file:"+f.getAbsolutePath() });
            } catch (ErrorAdminCommandException e) {
                fail("/tmp/fileshouldnotexist.txt should not have contained a password.");
            }            
        } catch (CliTestRuntimeException e) {
            fail("Exception was thrown when authenticating with a known user.");
        } finally {
            endEntityManagementSession.deleteUser(internalAdmin, CliAuthenticationTestHelperSessionRemote.USERNAME);
        }
    }

    @Test
    public void testWithoutSuppliedDefaultUserAndForbidden() throws Exception {
        boolean oldValue = setCliUserEnabled(false);
        log.debug("oldValue (user): "+oldValue);
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
        log.debug("oldValue (user): "+oldValue);
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
        log.debug("oldValue (cli): "+oldValue);
        try {
            mockCliCommand.execute(new String[] { "foo", "-u", EjbcaConfiguration.getCliDefaultUser() });
            fail("CLI should not have been able to have been run when disabled.");
        } catch (ErrorAdminCommandException e) {
            // Ignore
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
        log.debug("oldValue (cli): "+oldValue);
        try {
            cliAuthenticationProvider.authenticate(null);
            fail("Cli should not have been able to authenticate.");
        } catch (CliAuthenticationFailedException e) {
            //NOPMD
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
        log.debug("oldValue (user): "+oldValue);
        try {
            Set<Principal> principals = new HashSet<Principal>();
            principals.add(new UsernamePrincipal(EjbcaConfiguration.getCliDefaultUser()));
            cliAuthenticationProvider.authenticate(new AuthenticationSubject(principals, null));
            fail("Cli should not have been able to authenticate using default cli user.");
        } catch (CliAuthenticationFailedException e) {
            //NOPMD
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
        log.debug("Updated globalconfiguration with clienabled: "+config.getEnableCommandLineInterface());
        return oldValue;
    }

    private boolean setCliUserEnabled(boolean enabled) throws AuthorizationDeniedException {
        GlobalConfiguration config = (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(Configuration.GlobalConfigID);
        boolean oldValue = config.getEnableCommandLineInterfaceDefaultUser();
        config.setEnableCommandLineInterfaceDefaultUser(enabled);
        globalConfigurationSession.saveConfiguration(internalAdmin, config, Configuration.GlobalConfigID);
        log.debug("Updated globalconfiguration with cliuserenabled: "+config.getEnableCommandLineInterfaceDefaultUser());
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