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

import java.util.Collection;

import org.apache.log4j.Logger;
import org.cesecore.authentication.oauth.OAuthKeyInfo;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * Set a default Trusted OAuth Provider
 *
 */
public class SetDefaultOAuthProviderCommand extends BaseOAuthConfigCommand {

    private static final Logger log = Logger.getLogger(SetDefaultOAuthProviderCommand.class);
    
    private static final String LABEL = "--label";
    
    {
        registerParameter(new Parameter(LABEL, "Label", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Label of the Trusted OAuth Provider which is going to be set as default. "
                + "Setting it as 'none' will clear the default Trusted OAuth Provider."));
    }   
    
    @Override
    public String getMainCommand() {
        return "setdefaultoauthprovider";
    }

    @Override
    public String getCommandDescription() {
        return "Sets one of the existing Trusted OAuth Providers as default.";
    }

    @Override
    protected CommandResult execute(ParameterContainer parameters) {
        final String label = parameters.get(LABEL);
        
        if (label.isEmpty()) {
            log.info("The key identifier of the default Trusted OAuth Provider has to be specified.");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        
        final Collection<OAuthKeyInfo> oauthKeys = getOAuthConfiguration().getOauthKeys().values();
        OAuthKeyInfo defaultKey = null;
        
        for (final OAuthKeyInfo keyInfo : oauthKeys) {
            if (label.equals(keyInfo.getLabel())) {
                defaultKey = keyInfo;
            }
        }
        
        if (label.equalsIgnoreCase("none") || label.equalsIgnoreCase("null")) {
            // The user wants to clear the defaultKey entry
            defaultKey = null;
        } else if (defaultKey == null) {
            log.info("Trusted OAuth Provider with the label " + label + " doesn't exist. Can't set a nonexistent Trusted OAuth Provider as default.");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        
        getOAuthConfiguration().setDefaultOauthKey(defaultKey);
        
        if (saveGlobalConfig()) {
            if (defaultKey == null) {
                log.info("Default Trusted OAuth Provider cleared successfully.");
            } else {
                log.info("Default Trusted OAuth Provider with label " + label + " set successfully.");
            }
            return CommandResult.SUCCESS;
        } else {
            log.info("Failed to update configuration due to authorization issue!");
            return CommandResult.AUTHORIZATION_FAILURE;
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

}
