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

import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.config.EstConfiguration;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.junit.Test;

/**
 * @version $Id$
 *
 */
public class CmpEstConfigCommandTest {

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
        EstConfiguration estConfiguration = (EstConfiguration) globalConfigurationSession.getCachedConfiguration(EstConfiguration.EST_CONFIGURATION_ID);
        if(estConfiguration.aliasExists(aliasName)) {
            throw new RuntimeException("Test can't continue, EST alias "+aliasName+" already exists.");
        }
        final String newAliasName = "estbar";
        try {
            final String[] addAliasArgs = new String[] { aliasName };
            new org.ejbca.ui.cli.config.est.AddAliasCommand().execute(addAliasArgs);
            estConfiguration = (EstConfiguration) globalConfigurationSession.getCachedConfiguration(EstConfiguration.EST_CONFIGURATION_ID);
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
        estConfiguration = (EstConfiguration) globalConfigurationSession.getCachedConfiguration(EstConfiguration.EST_CONFIGURATION_ID);
        assertFalse("EST alias was not removed: "+aliasName, estConfiguration.aliasExists(aliasName));
        assertFalse("EST alias was not removed: "+newAliasName, estConfiguration.aliasExists(newAliasName));

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
            estConfiguration = (EstConfiguration) globalConfigurationSession.getCachedConfiguration(EstConfiguration.EST_CONFIGURATION_ID);
            assertTrue("No alias was added: "+aliasName, estConfiguration.aliasExists(aliasName));
        } finally {
            String[] removeAliasArgs = new String[] { aliasName };
            new org.ejbca.ui.cli.config.est.RemoveAliasCommand().execute(removeAliasArgs);
        }
        estConfiguration = (EstConfiguration) globalConfigurationSession.getCachedConfiguration(EstConfiguration.EST_CONFIGURATION_ID);
        assertFalse("EST alias was not removed: "+aliasName, estConfiguration.aliasExists(aliasName));

    }

}
