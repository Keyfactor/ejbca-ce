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
package org.ejbca.ui.cli.config.oauth;

import org.apache.log4j.Logger;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

public class UpdateAllowedOAuthHostnames extends BaseOAuthConfigCommand{

    private static final Logger log = Logger.getLogger(UpdateAllowedOAuthHostnames.class);

    private static final String ALLOWED_OAUTH_HOST_NAMES = "--allowedoauthhostnames";

    {
        registerParameter(new Parameter(ALLOWED_OAUTH_HOST_NAMES, "Allowed OAuth Hostnames", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Semicolon separated list of allowed OAuth hostnames."));
    }

    @Override
    protected CommandResult execute(ParameterContainer parameters) {

        final String listOfAllowedOAuthHostnames = parameters.get(ALLOWED_OAUTH_HOST_NAMES);

        if (listOfAllowedOAuthHostnames != null) {
            String[] allowedHostnames = listOfAllowedOAuthHostnames.split(";");
            // Trim whitespace from each element
            for (int i = 0; i < allowedHostnames.length; i++) {
                allowedHostnames[i] = allowedHostnames[i].trim();
            }

            getOAuthConfiguration().setAllowedOauthHosts(allowedHostnames);

            if (saveGlobalConfig()) {
                log.info("Successfully updated the list of allowed OAuth hostnames!");
                return CommandResult.SUCCESS;
            } else {
                log.info("Failed to update the list of allowed OAuth host names due to authorization issue!");
                return CommandResult.AUTHORIZATION_FAILURE;
            }

        } else {
            log.error("ERROR: No allowed OAuth hostnames specified.");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
    }

    @Override
    public String getFullHelpText() {
        return getCommandDescription();
    }

    @Override
    protected Logger getLogger() {
        return log;
    }

    @Override
    public String getMainCommand() {
        return "updateallowedoauthhostnames";
    }

    @Override
    public String getCommandDescription() {
        return "Update allowed OAuth hostnames of the OAuth configuration. Separate the list with semicolon. Note that the already existing hostnames will be overwritten.";
    }
}
