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

import org.apache.log4j.Logger;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.upgrade.UpgradeSessionRemote;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.command.EjbcaCommandBase;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * Implements call to the upgrade function
 * 
 * @version $Id$
 */
public class UpgradeCommand extends EjbcaCommandBase {

    private static final Logger log = Logger.getLogger(UpgradeCommand.class);

    private static final String DATABASE_KEY = "-d";
    private static final String FROM_VERSION_KEY = "-v";
    private static final String IS_POST_UPGRADE = "--post";

    {
        registerParameter(new Parameter(DATABASE_KEY, "Database type", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The database type."));
        registerParameter(new Parameter(FROM_VERSION_KEY, "From version", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "From which version of EJBCA"));
        registerParameter(new Parameter(IS_POST_UPGRADE, "Add this flag if running post upgrade", MandatoryMode.OPTIONAL, StandaloneMode.FORBID,
                ParameterMode.FLAG, "Set this flag when performing post upgrade."));
    }

    @Override
    public String getMainCommand() {
        return "upgrade";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {
        final String database = parameters.get(DATABASE_KEY);
        final String upgradeFromVersion = parameters.get(FROM_VERSION_KEY);
        final boolean isPost = parameters.get(IS_POST_UPGRADE) != null;
        log.debug(getMainCommand() + " ejbcaDB='" + database + "' ejbcaUpgradeFromVersion='" + upgradeFromVersion + "' isPost='" + isPost + "'");
        // Upgrade the database
        final boolean ret = EjbRemoteHelper.INSTANCE.getRemoteSession(UpgradeSessionRemote.class).upgrade(database, upgradeFromVersion, isPost);
        if (ret) {
            log.info("Upgrade completed.");
        } else {
            log.error("Upgrade not performed, see server log for details.");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        return CommandResult.SUCCESS;

    }

    @Override
    public String getCommandDescription() {
        return "Upgrade command. Use 'ant upgrade' instead of running this directly.";
    }

    @Override
    public String getFullHelpText() {
        return getCommandDescription();
    }
    
    @Override
    protected Logger getLogger() {
        return log;
    }
}
