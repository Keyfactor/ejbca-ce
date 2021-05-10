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
import org.cesecore.authentication.oauth.OAuthProviderCliHelper;
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

    private static final String TYPE = "--type";
    private static final String SKEW_LIMIT = "--skewlimit";
    private static final String URL = "--url";
    private static final String LABEL = "--label";
    private static final String CLIENT = "--client";
    private static final String CLIENT_SECRET = "--clientsecret";
    private static final String REALM = "--realm";
    private static final String SCOPE = "--scope";
    private static final String GENERIC = "GENERIC";
    private static final String KEYCLOAK = "KEYCLOAK";
    private static final String AZURE = "AZURE";

    {
        registerParameter(new Parameter(TYPE, "Provider type.", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Type of the Trusted OAuth Provider. Supported types are GENERIC, KEYCLOAK and AZURE."));
        registerParameter(new Parameter(SKEW_LIMIT, "Skew limit", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Skew limit to be used."));
        registerParameter(new Parameter(URL, "Provider URL", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Trusted OAuth Provider authorization endpoint URL."));
        registerParameter(new Parameter(LABEL, "Provider name", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Trusted OAuth Provider name."));
        registerParameter(new Parameter(REALM, "Realm/Tenant name", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Trusted OAuth Provider realm name."));
        registerParameter(new Parameter(SCOPE, "Scope", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Trusted OAuth Provider scope. Used for Azure Trusted OAuth Providers."));
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
        String typeString = parameters.get(TYPE);
        String skewLimit = parameters.get(SKEW_LIMIT);
        String url = parameters.get(URL);
        String label = parameters.get(LABEL);
        String client = parameters.get(CLIENT);
        String clientSecret = parameters.get(CLIENT_SECRET);
        String realm = parameters.get(REALM);
        String scope = parameters.get(SCOPE);
        OAuthProviderType type = null;
        
        if (typeString != null) {
            typeString = typeString.toUpperCase();
            switch (typeString) {
                case GENERIC:
                    type = OAuthProviderType.TYPE_GENERIC;
                    break;
                case KEYCLOAK:
                    type = OAuthProviderType.TYPE_KEYCLOAK;
                    break;
                case AZURE:
                    type = OAuthProviderType.TYPE_AZURE;
                    break;
                default:
                    break;
            }
        }

        if (type == null) {
            log.info("Unsupported provider type was specified. Currently supported provider types are " + GENERIC + ", " + AZURE + " and " + KEYCLOAK);
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        
        int skewLimitInt = 0;

        if (validateSkewLimit(skewLimit) >= 0) {
            skewLimitInt = validateSkewLimit(skewLimit);
        } else {
            log.info("Invalid skew limit value!");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        
        OAuthKeyInfo keyInfo = new OAuthKeyInfo(label,  skewLimitInt, type);
        // Since the UI already saves missing values as empty strings it's better to match that behaviour
        keyInfo.setUrl(keyInfo.fixUrl(url != null ? url : ""));
        keyInfo.setClient(client != null ? client : "");
        keyInfo.setClientSecretAndEncrypt(clientSecret != null ? clientSecret : "");
        keyInfo.setRealm(realm != null ? realm : "");
        keyInfo.setScope(scope != null ? scope : "");

        if (!canAdd(keyInfo)) {
            log.info("Trusted OAuth Provider with the same label already exists!");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        try {
            OAuthProviderCliHelper.validateProvider(keyInfo);
        } catch(Exception e) {
            log.info(e.getMessage());
            return CommandResult.FUNCTIONAL_FAILURE;
        }

        getOAuthConfiguration().addOauthKey(keyInfo);
        
        if (saveGlobalConfig()) {
            log.info("Trusted OAuth Provider with label " + label + " added successfully!");
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
