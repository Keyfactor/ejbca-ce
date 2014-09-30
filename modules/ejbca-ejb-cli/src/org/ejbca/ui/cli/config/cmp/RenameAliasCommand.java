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
package org.ejbca.ui.cli.config.cmp;

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.config.Configuration;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * @version $Id$
 *
 */
public class RenameAliasCommand extends BaseCmpConfigCommand {

    private static final String OLD_ALIAS_KEY = "--oldalias";
    private static final String NEW_ALIAS_KEY = "--newalias";

    private static final Logger log = Logger.getLogger(RenameAliasCommand.class);

    {
        registerParameter(new Parameter(OLD_ALIAS_KEY, "Alias", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The old alias name."));
        registerParameter(new Parameter(NEW_ALIAS_KEY, "Alias", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The new alias name."));
    }

    @Override
    public String getMainCommand() {
        return "renamealias";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {
        String oldalias = parameters.get(OLD_ALIAS_KEY);
        String newalias = parameters.get(NEW_ALIAS_KEY);
        // We check first because it is unnecessary to call saveConfiguration when it is not needed
        if (!getCmpConfiguration().aliasExists(oldalias)) {
            log.info("Alias '" + oldalias + "' does not exist");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        getCmpConfiguration().renameAlias(oldalias, newalias);
        try {
            getGlobalConfigurationSession().saveConfiguration(getAuthenticationToken(), getCmpConfiguration(), Configuration.CMPConfigID);
            log.info("Renamed CMP alias '" + oldalias + "' to '" + newalias + "'");
            getGlobalConfigurationSession().flushConfigurationCache(Configuration.CMPConfigID);
            return CommandResult.SUCCESS;
        } catch (AuthorizationDeniedException e) {
            log.info("Failed to rename alias '" + oldalias + "' to '" + newalias + "': " + e.getLocalizedMessage());
            return CommandResult.AUTHORIZATION_FAILURE;
        }
    }

    @Override
    public String getCommandDescription() {
        return "Rename a CMP configuration alias.";
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
