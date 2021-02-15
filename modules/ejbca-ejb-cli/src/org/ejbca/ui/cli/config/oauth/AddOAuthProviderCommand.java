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
import org.cesecore.authentication.oauth.OAuthKeyHelper;
import org.cesecore.authentication.oauth.OAuthKeyInfo;
import org.cesecore.authentication.oauth.OAuthKeyInfo.OAuthProviderType;
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
    private static final String TYPE = "--type";
    private static final String PUBLIC_KEY = "--publickey";
    private static final String SKEW_LIMIT = "--skewlimit";
    private static final String URL = "--url";
    private static final String LABEL = "--label";
    private static final String CLIENT = "--client";
    private static final String REALM = "--realm";
    private static final String KEYCLOAK = "KEYCLOAK";
    private static final String AZURE = "AZURE";

    {
        registerParameter(new Parameter(KEY_IDENTIFIER, "Key identifier", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Key identifier of the Trusted OAuth Provider."));
        registerParameter(new Parameter(TYPE, "Provider type. Supported types are KEYCLOAK and AZURE.", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Type of the Trusted OAuth Provider."));
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
        String typeString = parameters.get(TYPE);
        String publicKey = parameters.get(PUBLIC_KEY);
        String skewLimit = parameters.get(SKEW_LIMIT);
        String url = parameters.get(URL);
        String label = parameters.get(LABEL);
        String client = parameters.get(CLIENT);
        String realm = parameters.get(REALM);
        OAuthProviderType type = null;

        byte[] publicKeyByteArray = getOauthKeyPublicKey(publicKey);
        
        switch (typeString) {
            case KEYCLOAK:
                type = OAuthProviderType.TYPE_KEYCLOAK;
                break;
            case AZURE:
                type = OAuthProviderType.TYPE_AZURE;
                break;
        }
        
        if (type == null) {
            log.info("No provider type was specified.");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        
        if (ArrayUtils.isEmpty(publicKeyByteArray)) {
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        
        int skewLimitInt = 0;

        if (validateSkewLimit(skewLimit) >= 0) {
            skewLimitInt = validateSkewLimit(skewLimit);
        } else {
            log.info("Invalid skew limit value!");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        
        OAuthKeyInfo keyInfo = new OAuthKeyInfo(kid, publicKeyByteArray, skewLimitInt, type);
        keyInfo.setUrl(url);
        keyInfo.setLabel(label);
        keyInfo.setClient(client);
        keyInfo.setRealm(realm);
        
        if (!canAdd(keyInfo)) {
            log.info("Trusted OAuth Provider with same kid or internal Id exists!");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        try {
            OAuthKeyHelper.validateProvider(keyInfo);
        } catch(Exception e) {
            log.info(e.getMessage());
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
