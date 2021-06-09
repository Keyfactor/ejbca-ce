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

import java.util.Iterator;
import java.util.Map;

import org.apache.log4j.Logger;
import org.cesecore.authentication.oauth.OAuthKeyInfo;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * Remove already existing Trusted OAuth Provider
 * 
 */
public class RemoveOAuthProviderCommand extends BaseOAuthConfigCommand {
    
    private static final Logger log = Logger.getLogger(RemoveOAuthProviderCommand.class);
    
    private static final String LABEL = "--label";

    {
        registerParameter(new Parameter(LABEL, "Provider name", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Trusted OAuth Provider name."));
    }
    
    @Override
    public String getMainCommand() {
        return "removeoauthprovider";
    }

    @Override
    public String getCommandDescription() {
        return "Remove an existing Trusted OAuth Provider from the list of keys.";
    }

    @Override
    protected CommandResult execute(ParameterContainer parameters) {
        
        String labelToRemove = parameters.get(LABEL);
        
        Map<String, OAuthKeyInfo> currentOAuthKeys = getOAuthConfiguration().getOauthKeys();
        OAuthKeyInfo defaultKey = getOAuthConfiguration().getDefaultOauthKey();
        
        for (Iterator<Map.Entry<String, OAuthKeyInfo>> iterator = currentOAuthKeys.entrySet().iterator(); iterator.hasNext();) {
            Map.Entry<String, OAuthKeyInfo> entry = iterator.next();
            if (entry.getValue().getLabel().equals(labelToRemove)) {
                // Found the kid to be removed!
                iterator.remove();
                getOAuthConfiguration().setOauthKeys(currentOAuthKeys);
                if (defaultKey != null && labelToRemove.equals(defaultKey.getLabel())) {
                    getOAuthConfiguration().setDefaultOauthKey(null);
                }
                if(saveGlobalConfig()) {
                    log.info("Trusted OAuth Provider with label: " + labelToRemove + " successfully removed!");
                    return CommandResult.SUCCESS;
                } else {
                    log.info("Failed to update configuration due to authorization issue!");
                    return CommandResult.AUTHORIZATION_FAILURE;
                }
            }
        }

        log.info("Trusted OAuth Provider with label: " + labelToRemove + " not found!");
        return CommandResult.FUNCTIONAL_FAILURE;
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
