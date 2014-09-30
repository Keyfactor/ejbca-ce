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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.config.Configuration;
import org.ejbca.core.ejb.config.GlobalConfigurationSessionRemote;
import org.ejbca.ui.cli.config.cmp.AddAliasCommand;
import org.ejbca.ui.cli.config.cmp.RemoveAliasCommand;
import org.ejbca.ui.cli.config.cmp.RenameAliasCommand;
import org.junit.Test;

/**
 * @version $Id$
 *
 */
public class CmpConfigCommandTest {

    private final GlobalConfigurationSessionRemote globalConfigurationSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(GlobalConfigurationSessionRemote.class);

    @Test
    public void testAliasOperations() {
        final String aliasName = "foo";
        CmpConfiguration cmpConfiguration = (CmpConfiguration) globalConfigurationSession.getCachedConfiguration(Configuration.CMPConfigID);
        if(cmpConfiguration.aliasExists(aliasName)) {
            throw new RuntimeException("Test can't continue, alias already exists.");
        }
        final String[] addAliasArgs = new String[] { aliasName };
        new AddAliasCommand().execute(addAliasArgs);
        cmpConfiguration = (CmpConfiguration) globalConfigurationSession.getCachedConfiguration(Configuration.CMPConfigID);
        assertTrue("No alias was added", cmpConfiguration.aliasExists(aliasName));
        final String newAliasName = "bar";
        String[] renameAliasArgs = new String[] { aliasName, newAliasName };
        new RenameAliasCommand().execute(renameAliasArgs);
        cmpConfiguration = (CmpConfiguration) globalConfigurationSession.getCachedConfiguration(Configuration.CMPConfigID);
        assertFalse("Old alias is still there", cmpConfiguration.aliasExists(aliasName));
        assertTrue("No alias was renamed", cmpConfiguration.aliasExists(newAliasName));
        String[] removeAliasArgs = new String[] { newAliasName };
        new RemoveAliasCommand().execute(removeAliasArgs);
        assertFalse("Alias was not removed", cmpConfiguration.aliasExists(aliasName));
    }
}
