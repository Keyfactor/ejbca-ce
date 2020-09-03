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
 * Set a default OAuth key
 *
 */
public class SetDefaultOAuthKeyCommand extends BaseOAuthConfigCommand {

    private static final Logger log = Logger.getLogger(SetDefaultOAuthKeyCommand.class);
    
    private static final String KEY_IDENTIFIER = "--key_identifier";
    
    {
        registerParameter(new Parameter(KEY_IDENTIFIER, "Key identifier", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Key identifier of the OAuth key which is going to be set as the default OAuth key. Setting it as 'null' will clear the default OAuth key."));
    }   
    
    @Override
    public String getMainCommand() {
        return "setdefaultoauthkey";
    }

    @Override
    public String getCommandDescription() {
        return "Sets one of the existing oauth keys as default.";
    }

    @Override
    protected CommandResult execute(ParameterContainer parameters) {
        final String kid = parameters.get(KEY_IDENTIFIER);
        
        if (kid.isEmpty()) {
            log.info("The key identifier of the default OAuth key has to be specified.");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        
        final Collection<OAuthKeyInfo> oauthKeys = getGlobalConfiguration().getOauthKeys().values();
        OAuthKeyInfo defaultKey = null;
        
        for (final OAuthKeyInfo keyInfo : oauthKeys) {
            if (kid.equals(keyInfo.getKeyIdentifier())) {
                defaultKey = keyInfo;
            }
        }
        
        if (kid.equalsIgnoreCase("null")) {
            // The user wants to clear the defaultKey entry by explicitly setting it as 'null'
            defaultKey = null;
        } else if (defaultKey == null) {
            log.info("OAuth key with the kid " + kid + " doesn't exist. Can't set a nonexistent OAuth Key as default.");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        
        getGlobalConfiguration().setDefaultOauthKey(defaultKey);
        
        if (saveGlobalConfig()) {
            log.info("Default OAuth key with kid: " + kid + " set successfuly!");
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
