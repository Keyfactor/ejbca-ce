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
public class RemoveAliasCommand extends BaseCmpConfigCommand {

    private static final String ALIAS_KEY = "--alias";

    private static final Logger log = Logger.getLogger(RemoveAliasCommand.class);

    {
        registerParameter(new Parameter(ALIAS_KEY, "Alias", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The alias to remove."));
    }

    @Override
    public String getMainCommand() {
        return "removealias";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {
        String alias = parameters.get(ALIAS_KEY);
        // We check first because it is unnecessary to call saveConfiguration when it is not needed
        if (!getCmpConfiguration().aliasExists(alias)) {
            log.info("Alias '" + alias + "' does not exist");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        getCmpConfiguration().removeAlias(alias);
        try {
            getGlobalConfigurationSession().saveConfiguration(getAuthenticationToken(), getCmpConfiguration(), Configuration.CMPConfigID);
            log.info("Removed CMP alias: " + alias);
            getGlobalConfigurationSession().flushConfigurationCache(Configuration.CMPConfigID);
            return CommandResult.SUCCESS;
        } catch (AuthorizationDeniedException e) {
            log.info("Failed to remove alias '" + alias + "': " + e.getLocalizedMessage());
            return CommandResult.AUTHORIZATION_FAILURE;
        }
    }

    @Override
    public String getCommandDescription() {
        return " Removes a CMP configuration alias.";
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
