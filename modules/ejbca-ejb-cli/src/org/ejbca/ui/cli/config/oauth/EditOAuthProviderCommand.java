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
 * Editing the already existing Trusted OAuth Provider.
 *
 */
public class EditOAuthProviderCommand extends BaseOAuthConfigCommand {

    private static final Logger log = Logger.getLogger(EditOAuthProviderCommand.class);

    private static final String LABEL = "--label";
    private static final String NEW_SKEW_LIMIT = "--new-skewlimit";
    private static final String NEW_URL = "--new-url";
    private static final String NEW_LABEL = "--new-label";
    private static final String NEW_CLIENT = "--new-client";
    private static final String NEW_CLIENT_SECRET = "--new-clientsecret";
    private static final String NEW_REALM = "--new-realm";

    {
        registerParameter(new Parameter(LABEL, "Key identifier", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Key identifier of the Trusted OAuth Provider to update its parameters."));
        registerParameter(new Parameter(NEW_SKEW_LIMIT, "Skew limit", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Skew limit to be updated."));
        registerParameter(new Parameter(NEW_URL, "Provider url", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Trusted OAuth Provider url to the login page to be updated."));
        registerParameter(new Parameter(NEW_LABEL, "Provider name", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Trusted OAuth Provider name to be updated"));
        registerParameter(new Parameter(NEW_REALM, "Realm name", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Trusted OAuth Provider realm name to be updated."));
        registerParameter(new Parameter(NEW_CLIENT, "Client name", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Client name for EJBCA in Trusted OAuth Provider to be updated."));
        registerParameter(new Parameter(NEW_CLIENT_SECRET, "Client secret", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Client secret in Trusted OAuth Provider to be updated."));
    }

    @Override
    public String getMainCommand() {
        return "editoauthprovider";
    }

    @Override
    public String getCommandDescription() {
        return "Edit key identifier, public key and/or skew limit for an existing Trusted OAuth Provider.";
    }

    @Override
    protected CommandResult execute(ParameterContainer parameters) {

        String label = parameters.get(LABEL);

        for (Map.Entry<String, OAuthKeyInfo> entry : getOAuthConfiguration().getOauthKeys().entrySet()) {
            if (entry.getValue().getLabel().equals(label)) {
                if (checkParametersAndSet(parameters, entry.getValue())) {
                    OAuthKeyInfo defaultKey = getOAuthConfiguration().getDefaultOauthKey();
                    if (defaultKey != null && entry.getValue().getLabel().equals(defaultKey.getLabel())) {
                        getOAuthConfiguration().setDefaultOauthKey(entry.getValue());
                    }
                    if (saveGlobalConfig()) {
                        log.info("Trusted OAuth Provider with label: " + label + " successfully updated!");
                        return CommandResult.SUCCESS;
                    } else {
                        log.info("Failed to update configuration due to authorization issue!");
                        return CommandResult.AUTHORIZATION_FAILURE;
                    }
                } else {
                    return CommandResult.FUNCTIONAL_FAILURE;
                }
            }
        }
        log.info("No Trusted OAuth Provider with given label: " + label + " exists!");
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

    private boolean checkParametersAndSet(final ParameterContainer parameters,
            final OAuthKeyInfo keyInfoToBeEdited) {
        final String newSkewLimit= parameters.get(NEW_SKEW_LIMIT);
        final String newUrl = parameters.get(NEW_URL);
        final String newLabel = parameters.get(NEW_LABEL);
        final String newClient = parameters.get(NEW_CLIENT);
        final String newClientSecret = parameters.get(NEW_CLIENT_SECRET);
        final String newRealm = parameters.get(NEW_REALM);
            
        if (newSkewLimit != null) {
            if (validateSkewLimit(newSkewLimit) >= 0) {
                keyInfoToBeEdited.setSkewLimit(validateSkewLimit(newSkewLimit));
            } else {
                log.info("New given skew limit is invalid!");
                return false;
            }
        }

        if (newLabel != null) {
            if(canEditLabel(newLabel)) {
                keyInfoToBeEdited.setLabel(newLabel);
            } else {
                log.info("Trusted OAuth Provider with same label exists!");
                return false;
            }
        }
        if (newUrl != null) {
            keyInfoToBeEdited.setUrl(newUrl);
        }
        if (newClient != null) {
            keyInfoToBeEdited.setClient(newClient);
        }
        if (newClientSecret != null) {
            keyInfoToBeEdited.setClientSecretAndEncrypt(newClientSecret);
        }
        if (newRealm != null) {
            keyInfoToBeEdited.setRealm(newRealm);
        }
            
        return true;
    }

}
