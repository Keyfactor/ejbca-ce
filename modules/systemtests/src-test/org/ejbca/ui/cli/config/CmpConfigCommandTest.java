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
package org.ejbca.ui.cli.config;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.config.Configuration;
import org.ejbca.core.ejb.config.GlobalConfigurationSessionRemote;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.junit.Test;

/**
 * @version $Id$
 *
 */
public class CmpConfigCommandTest {

    private CmpConfigCommand command = new CmpConfigCommand();

    private static final String ADDALIAS = "addalias";
    private static final String REMOVEALIAS = "removealias";
    private static final String RENAMEALIAS = "renamealias";

    private final GlobalConfigurationSessionRemote globalConfigurationSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(GlobalConfigurationSessionRemote.class);

    @Test
    public void testAliasOperations() throws ErrorAdminCommandException {
        final String aliasName = "foo";
        CmpConfiguration cmpConfiguration = (CmpConfiguration) globalConfigurationSession.getCachedConfiguration(Configuration.CMPConfigID);
        if(cmpConfiguration.aliasExists(aliasName)) {
            throw new RuntimeException("Test can't continue, alias already exists.");
        }
        final String[] addAliasArgs = new String[] { "cmp", ADDALIAS, aliasName };
        command.execute(addAliasArgs);
        cmpConfiguration = (CmpConfiguration) globalConfigurationSession.getCachedConfiguration(Configuration.CMPConfigID);
        assertTrue("No alias was added", cmpConfiguration.aliasExists(aliasName));
        final String newAliasName = "bar";
        String[] renameAliasArgs = new String[] { "cmp", RENAMEALIAS, aliasName, newAliasName };
        command.execute(renameAliasArgs);
        cmpConfiguration = (CmpConfiguration) globalConfigurationSession.getCachedConfiguration(Configuration.CMPConfigID);
        assertTrue("No alias was not renamed", cmpConfiguration.aliasExists(newAliasName));
        String[] removeAliasArgs = new String[] { "cmp", REMOVEALIAS, newAliasName };
        command.execute(removeAliasArgs);
        assertFalse("Alias was not removed", cmpConfiguration.aliasExists(aliasName));
    }
}
