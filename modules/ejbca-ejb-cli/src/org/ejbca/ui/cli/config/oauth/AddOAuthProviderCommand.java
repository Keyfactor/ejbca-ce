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
 * Add new Trusted OAuth Provider
 *
 */
public class AddOAuthProviderCommand extends BaseOAuthConfigCommand {

    private static final Logger log = Logger.getLogger(AddOAuthProviderCommand.class);
    
    private static final String KEY_IDENTIFIER = "--keyidentifier";
    private static final String PUBLIC_KEY = "--publickey";
    private static final String SKEW_LIMIT = "--skewlimit";
    private static final String URL = "--url";
    private static final String LABEL = "--label";
    private static final String CLIENT = "--client";
    private static final String CLIENT_SECRET = "--clientsecret";
    private static final String REALM = "--realm";

    {
        registerParameter(new Parameter(KEY_IDENTIFIER, "Key identifier", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Key identifier of the Trusted OAuth Provider which is going to be added."));
        registerParameter(new Parameter(PUBLIC_KEY, "Public key", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Path to publickey file used by the OAuth Provider."));
        registerParameter(new Parameter(SKEW_LIMIT, "Skew limit", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Skew limit to be used."));
        registerParameter(new Parameter(URL, "Provider url", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Trusted OAuth Provider url to the login page."));
        registerParameter(new Parameter(LABEL, "Provider name", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Trusted OAuth Provider name to be shown"));
        registerParameter(new Parameter(REALM, "Realm name", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Trusted OAuth Provider realm name."));
        registerParameter(new Parameter(CLIENT, "Client name", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Client name for EJBCA in Trusted OAuth Provider."));
        registerParameter(new Parameter(CLIENT_SECRET, "Client secret", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Client secret in Trusted OAuth Provider."));
    }
    
    
    @Override
    public String getMainCommand() {
        return "addoauthprovider";
    }

    @Override
    public String getCommandDescription() {
        return "Adds a new Trusted OAuth Provider to the list of available providers.";
    }

    @Override
    protected CommandResult execute(ParameterContainer parameters) {
        String kid = parameters.get(KEY_IDENTIFIER);
        String publicKey = parameters.get(PUBLIC_KEY);
        String skewLimit = parameters.get(SKEW_LIMIT);
        String url = parameters.get(URL);
        String label = parameters.get(LABEL);
        String client = parameters.get(CLIENT);
        String clientSecret = parameters.get(CLIENT_SECRET);
        String realm = parameters.get(REALM);

        byte[] publicKeyByteArray = getOauthKeyPublicKey(publicKey);
        
        if (ArrayUtils.isEmpty(publicKeyByteArray)) {
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
        // Since the UI already saves missing values as empty strings it's better to match that behaviour
        keyInfo.setUrl(url != null ? url : "");
        keyInfo.setLabel(label != null ? label : "");
        keyInfo.setClient(client != null ? client : "");
        keyInfo.setClientSecretAndEncrypt(clientSecret != null ? clientSecret : "");
        keyInfo.setRealm(realm != null ? realm : "");
        
        if (!canAdd(keyInfo)) {
            log.info("Trusted OAuth Provider with same kid or internal Id exists!");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        
        getGlobalConfiguration().addOauthKey(keyInfo);
        
        if (saveGlobalConfig()) {
            log.info("Trusted OAuth Provider with kid: " + kid + " added successfuly!");
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
