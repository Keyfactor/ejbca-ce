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

import org.apache.commons.lang.ArrayUtils;
import org.apache.log4j.Logger;
import org.cesecore.authentication.oauth.OAuthKeyInfo;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * Add new OAuth key
 *
 */
public class AddOAuthKeyCommand extends BaseOAuthConfigCommand {

    private static final Logger log = Logger.getLogger(AddOAuthKeyCommand.class);
    
    private static final String KEY_IDENTIFIER = "--key_identifier";
    private static final String PUBLIC_KEY = "--public_key";
    private static final String SKEW_LIMIT = "--skew_limit";
    
    {
        registerParameter(new Parameter(KEY_IDENTIFIER, "Key identifier", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Key identifier of the OAuth key which is going to be added."));
        registerParameter(new Parameter(PUBLIC_KEY, "Public key", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Path to publickey file used by the OAuth issuer."));
        registerParameter(new Parameter(SKEW_LIMIT, "Skew limit", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Skew limit to be used."));
    }
    
    
    @Override
    public String getMainCommand() {
        return "addoauthkey";
    }

    @Override
    public String getCommandDescription() {
        return "Adds a new oauth key to the list of available keys.";
    }

    @Override
    protected CommandResult execute(ParameterContainer parameters) {
        String kid = parameters.get(KEY_IDENTIFIER);
        String publicKey = parameters.get(PUBLIC_KEY);
        String skewLimit = parameters.get(SKEW_LIMIT);
        
        byte[] publicKeyByteArray = getOauthKeyPublicKey(publicKey);
        
        if(ArrayUtils.isEmpty(publicKeyByteArray)) {
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        
        int skewLimitInt = 0;

        if(validateSkewLimit(skewLimit) >= 0) {
            skewLimitInt = validateSkewLimit(skewLimit);
        } else {
            log.info("Invalid skew limit value!");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        
        OAuthKeyInfo keyInfo = new OAuthKeyInfo(kid, publicKeyByteArray, skewLimitInt);
        
        if (!canAdd(keyInfo)) {
            log.info("OAuth key with same name or internal Id exists!");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        
        getGlobalConfiguration().addOauthKey(keyInfo);
        
        if(saveGlobalConfig()) {
            log.info("OAuth key with kid: " + kid + " added successfuly!");
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
