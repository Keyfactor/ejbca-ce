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
package org.ejbca.ui.cli.config;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

import org.apache.log4j.Logger;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.config.EstConfiguration;
import org.ejbca.core.model.UsernameGenerateMode;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.junit.Test;

/**
 * Combined test of CMP and EST configuration management via the EJB CLI.
 * 
 * @version $Id$
 */
public class CmpEstConfigCommandTest {

    private static final Logger log = Logger.getLogger(CmpEstConfigCommandTest.class);
    
    private final GlobalConfigurationSessionRemote globalConfigurationSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(GlobalConfigurationSessionRemote.class);

    @Test
    public void testCmpAliasOperations() {
        final String aliasName = "foo";
        CmpConfiguration cmpConfiguration = (CmpConfiguration) globalConfigurationSession.getCachedConfiguration(CmpConfiguration.CMP_CONFIGURATION_ID);
        if(cmpConfiguration.aliasExists(aliasName)) {
            throw new RuntimeException("Test can't continue, CMP alias already exists.");
        }
        final String[] addAliasArgs = new String[] { aliasName };
        new org.ejbca.ui.cli.config.cmp.AddAliasCommand().execute(addAliasArgs);
        cmpConfiguration = (CmpConfiguration) globalConfigurationSession.getCachedConfiguration(CmpConfiguration.CMP_CONFIGURATION_ID);
        assertTrue("No alias was added", cmpConfiguration.aliasExists(aliasName));
        final String newAliasName = "bar";
        String[] renameAliasArgs = new String[] { aliasName, newAliasName };
        new org.ejbca.ui.cli.config.cmp.RenameAliasCommand().execute(renameAliasArgs);
        cmpConfiguration = (CmpConfiguration) globalConfigurationSession.getCachedConfiguration(CmpConfiguration.CMP_CONFIGURATION_ID);
        assertFalse("Old alias is still there", cmpConfiguration.aliasExists(aliasName));
        assertTrue("No alias was renamed", cmpConfiguration.aliasExists(newAliasName));
        String[] removeAliasArgs = new String[] { newAliasName };
        new org.ejbca.ui.cli.config.cmp.RemoveAliasCommand().execute(removeAliasArgs);
        cmpConfiguration = (CmpConfiguration) globalConfigurationSession.getCachedConfiguration(CmpConfiguration.CMP_CONFIGURATION_ID);
        assertFalse("Alias was not removed", cmpConfiguration.aliasExists(newAliasName));
    }

    @Test
    public void testEstAliasOperations() throws IOException {
        final String aliasName = "estfoo";
        final String newAliasName = "estbar";
        assertUnusedAlias("Test can't proceed on this system.", aliasName);
        assertUnusedAlias("Test can't proceed on this system.", newAliasName);
        try {
            final String[] addAliasArgs = new String[] { aliasName };
            new org.ejbca.ui.cli.config.est.AddAliasCommand().execute(addAliasArgs);
            EstConfiguration estConfiguration = (EstConfiguration) globalConfigurationSession.getCachedConfiguration(EstConfiguration.EST_CONFIGURATION_ID);
            assertTrue("No alias was added", estConfiguration.aliasExists(aliasName));

            String[] renameAliasArgs = new String[] { aliasName, newAliasName };
            new org.ejbca.ui.cli.config.est.RenameAliasCommand().execute(renameAliasArgs);
            estConfiguration = (EstConfiguration) globalConfigurationSession.getCachedConfiguration(EstConfiguration.EST_CONFIGURATION_ID);
            assertFalse("Old EST alias is still there", estConfiguration.aliasExists(aliasName));
            assertTrue("No EST alias was renamed", estConfiguration.aliasExists(newAliasName));

            String[] dumpArgs = new String[] { newAliasName };
            CommandResult dumpResult = new org.ejbca.ui.cli.config.est.DumpAliasCommand().execute(dumpArgs);
            // We can't get to the output of this command to verify, because it prints with LOG.info
            assertEquals("Dump alias command didn't return successs: ", CommandResult.SUCCESS.getReturnCode(), dumpResult.getReturnCode());
            dumpArgs = new String[] { "nonExistingEstAlias" };
            dumpResult = new org.ejbca.ui.cli.config.est.DumpAliasCommand().execute(dumpArgs);
            // We can't get to the output of this command to verify, because it prints with LOG.info
            assertEquals("Dump alias command should have returned failure when alias does not exist: ", CommandResult.FUNCTIONAL_FAILURE.getReturnCode(), dumpResult.getReturnCode());

            boolean allowSameKey = estConfiguration.getKurAllowSameKey(newAliasName);
            String[] updateArgs = new String[] { newAliasName, "allowupdatewithsamekey", String.valueOf(!allowSameKey) };
            CommandResult updateResult = new org.ejbca.ui.cli.config.est.UpdateCommand().execute(updateArgs);
            // We can't get to the output of this command to verify, because it prints with LOG.info
            estConfiguration = (EstConfiguration) globalConfigurationSession.getCachedConfiguration(EstConfiguration.EST_CONFIGURATION_ID);
            assertEquals("Update command didn't return successs: ", CommandResult.SUCCESS.getReturnCode(), updateResult.getReturnCode());
            assertEquals("Update command didn't change allowupdatewithsamekey", !allowSameKey, estConfiguration.getKurAllowSameKey(newAliasName));
        } finally {
            String[] removeAliasArgs = new String[] { newAliasName };
            CommandResult removeResult = new org.ejbca.ui.cli.config.est.RemoveAliasCommand().execute(removeAliasArgs);
            assertEquals("Remove command didn't return successs: ", CommandResult.SUCCESS.getReturnCode(), removeResult.getReturnCode());
        }
        assertUnusedAlias("EST alias should have been removed when renamed.", aliasName);
        assertUnusedAlias("EST alias was not removed.", newAliasName);

        // Test to upload a file to create an alias
        File f = File.createTempFile("estconfigtest", "txt");
        f.deleteOnExit();
        try (FileWriter fw = new FileWriter(f);) {
            // Create file to upload
            fw.write(aliasName+".defaultca=Default CA");
            fw.write(aliasName+".certprofile=DM DEMO");
            fw.write(aliasName+".eeprofile=1245259972");
            fw.write(aliasName+".requirecert=false");
            fw.write(aliasName+".reqpassword=foo123");
            fw.write(aliasName+".allowupdatewithsamekey=false");
            fw.close();
            final String[] uploadFileArgs = new String[] { aliasName, f.getAbsolutePath()};
            CommandResult uploadResult = new org.ejbca.ui.cli.config.est.UploadFileCommand().execute(uploadFileArgs);
            assertEquals("Upload command didn't return successs: ", CommandResult.SUCCESS.getReturnCode(), uploadResult.getReturnCode());
            final EstConfiguration estConfiguration = (EstConfiguration) globalConfigurationSession.getCachedConfiguration(EstConfiguration.EST_CONFIGURATION_ID);
            assertTrue("No alias was added: "+aliasName, estConfiguration.aliasExists(aliasName));
        } finally {
            String[] removeAliasArgs = new String[] { aliasName };
            new org.ejbca.ui.cli.config.est.RemoveAliasCommand().execute(removeAliasArgs);
        }
        assertUnusedAlias("Clean up failed.", aliasName);
    }

    @Test
    public void estConfigurationUpdateOfRaNameGeneration() {
        final String methodName = new Object(){}.getClass().getEnclosingMethod().getName();
        log.trace(">" + methodName);
        final String alias = methodName;
        assertUnusedAlias("Test can't proceed on this system.", alias);
        try {
            new org.ejbca.ui.cli.config.est.AddAliasCommand().execute("--alias", alias);
            assertEstConfigurationRaNameGenerationParameters(alias, UsernameGenerateMode.DN.name(), "CN", "", "");
            new org.ejbca.ui.cli.config.est.UpdateCommand().execute("--alias", alias, "--key", EstConfiguration.CONFIG_RA_NAMEGENERATIONPREFIX, "--value", "prefix");
            assertEstConfigurationRaNameGenerationParameters(alias, UsernameGenerateMode.DN.name(), "CN", "prefix", "");
            new org.ejbca.ui.cli.config.est.UpdateCommand().execute("--alias", alias, "--key", EstConfiguration.CONFIG_RA_NAMEGENERATIONPOSTFIX, "--value", "postfix");
            assertEstConfigurationRaNameGenerationParameters(alias, UsernameGenerateMode.DN.name(), "CN", "prefix", "postfix");
            new org.ejbca.ui.cli.config.est.UpdateCommand().execute("--alias", alias, "--key", EstConfiguration.CONFIG_RA_NAMEGENERATIONSCHEME, "--value", UsernameGenerateMode.RANDOM.name());
            // If the next line ever fails due to expectedParams being "", this is not a bug
            assertEstConfigurationRaNameGenerationParameters(alias, UsernameGenerateMode.RANDOM.name(), "CN", "prefix", "postfix");
            new org.ejbca.ui.cli.config.est.UpdateCommand().execute("--alias", alias, "--key", EstConfiguration.CONFIG_RA_NAMEGENERATIONPARAMS, "--value", "");
            assertEstConfigurationRaNameGenerationParameters(alias, UsernameGenerateMode.RANDOM.name(), "", "prefix", "postfix");
        } finally {
            new org.ejbca.ui.cli.config.est.RemoveAliasCommand().execute("--alias", alias);
        }
        assertUnusedAlias("Clean up failed.", alias);
        log.trace("<" + methodName);
    }
    
    private void assertEstConfigurationRaNameGenerationParameters(final String alias, final String expectedScheme, final String expectedParams, final String expectedPrefix, final String expectedPostfix) {
        final EstConfiguration estConfiguration = (EstConfiguration) globalConfigurationSession.getCachedConfiguration(EstConfiguration.EST_CONFIGURATION_ID);
        assertTrue("Expected alias '" + alias + " was not present'", estConfiguration.aliasExists(alias));
        assertEquals(expectedScheme, estConfiguration.getRANameGenScheme(alias));
        assertEquals(expectedParams, estConfiguration.getRANameGenParams(alias));
        assertEquals(expectedPrefix, estConfiguration.getRANameGenPrefix(alias));
        assertEquals(expectedPostfix, estConfiguration.getRANameGenPostfix(alias));
    }

    /** Verify that the alias is not currently in use on the system where this test is run. */
    private void assertUnusedAlias(final String errorMsg, final String alias) throws IllegalStateException {
        if (((EstConfiguration) globalConfigurationSession.getCachedConfiguration(EstConfiguration.EST_CONFIGURATION_ID)).aliasExists(alias)) {
            throw new IllegalStateException("EST configuation alias '" + errorMsg + "' exists. " + errorMsg);
        }
    }
}
