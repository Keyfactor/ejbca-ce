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

import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.config.EstConfiguration;
import org.junit.Test;

/**
 * @version $Id$
 *
 */
public class CmpEstConfigCommandTest {

    private final GlobalConfigurationSessionRemote globalConfigurationSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(GlobalConfigurationSessionRemote.class);

    @Test
    public void testAliasOperations() {
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
        assertFalse("Alias was not removed", cmpConfiguration.aliasExists(aliasName));
    }

    @Test
    public void testEstAliasOperations() {
        final String aliasName = "estfoo";
        EstConfiguration estConfiguration = (EstConfiguration) globalConfigurationSession.getCachedConfiguration(EstConfiguration.EST_CONFIGURATION_ID);
        if(estConfiguration.aliasExists(aliasName)) {
            throw new RuntimeException("Test can't continue, EST alias already exists.");
        }
        final String[] addAliasArgs = new String[] { aliasName };
        new org.ejbca.ui.cli.config.est.AddAliasCommand().execute(addAliasArgs);
        estConfiguration = (EstConfiguration) globalConfigurationSession.getCachedConfiguration(EstConfiguration.EST_CONFIGURATION_ID);
        assertTrue("No alias was added", estConfiguration.aliasExists(aliasName));
        final String newAliasName = "estbar";
        String[] renameAliasArgs = new String[] { aliasName, newAliasName };
        new org.ejbca.ui.cli.config.est.RenameAliasCommand().execute(renameAliasArgs);
        estConfiguration = (EstConfiguration) globalConfigurationSession.getCachedConfiguration(EstConfiguration.EST_CONFIGURATION_ID);
        assertFalse("Old EST alias is still there", estConfiguration.aliasExists(aliasName));
        assertTrue("No EST alias was renamed", estConfiguration.aliasExists(newAliasName));
        String[] removeAliasArgs = new String[] { newAliasName };
        new org.ejbca.ui.cli.config.est.RemoveAliasCommand().execute(removeAliasArgs);
        assertFalse("EST alias was not removed", estConfiguration.aliasExists(aliasName));
    }

}
