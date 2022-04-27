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
import java.util.Optional;

import org.apache.log4j.Logger;
import org.cesecore.authentication.oauth.OAuthProviderCliHelper;
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
    private static final String NEW_TOKEN_URL = "--new-tokenurl";
    private static final String NEW_LOGOUT_URL = "--new-logouturl";
    private static final String NEW_LABEL = "--new-label";
    private static final String NEW_CLIENT = "--new-client";
    private static final String NEW_CLIENT_SECRET = "--new-clientsecret";
    private static final String NEW_KEYBINDING = "--new-keybinding";
    private static final String NEW_REALM = "--new-realm";
    private static final String NEW_SCOPE = "--new-scope";
    private static final String NEW_AUDIENCE = "--new-audience";
    private static final String NEW_AUDIENCECHECKDISABLED = "--new-audiencecheckdisabled";

    {
        registerParameter(new Parameter(LABEL, "Label", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Label of the Trusted OAuth Provider to update its parameters."));
        registerParameter(new Parameter(NEW_SKEW_LIMIT, "Skew limit", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "New Skew Limit."));
        registerParameter(new Parameter(NEW_URL, "Provider URL", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "New authorization endpoint URL."));
        registerParameter(new Parameter(NEW_TOKEN_URL, "Provider Token URL", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "New token endpoint URL."));
        registerParameter(new Parameter(NEW_LOGOUT_URL, "Provider Logout URL", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "New logout endpoint URL."));
        registerParameter(new Parameter(NEW_LABEL, "Provider name", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "New Provider Label."));
        registerParameter(new Parameter(NEW_REALM, "Realm/Tenant name", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "New Realm/Tenant name."));
        registerParameter(new Parameter(NEW_SCOPE, "Scope", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "New Scope."));
        registerParameter(new Parameter(NEW_AUDIENCE, "Audience", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "New Audience."));
        registerParameter(new Parameter(NEW_AUDIENCECHECKDISABLED, "Audience Check Disabled", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "New Audience check disabled."));
        registerParameter(new Parameter(NEW_CLIENT, "Client Name", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "New Client Name."));
        registerParameter(new Parameter(NEW_CLIENT_SECRET, "Client Secret", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "New Client Secret."));
        registerParameter(new Parameter(NEW_KEYBINDING, "Key Binding", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "New Key Binding."));
    }

    @Override
    public String getMainCommand() {
        return "editoauthprovider";
    }

    @Override
    public String getCommandDescription() {
        return "Edit a Trusted OAuth Provider.";
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
                    try {
                        OAuthProviderCliHelper.validateProvider(entry.getValue());
                    } catch(Exception e) {
                        log.info(e.getMessage());
                        return CommandResult.FUNCTIONAL_FAILURE;
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
        final String newTokenUrl = parameters.get(NEW_TOKEN_URL);
        final String newLogoutUrl = parameters.get(NEW_LOGOUT_URL);
        final String newLabel = parameters.get(NEW_LABEL);
        final String newClient = parameters.get(NEW_CLIENT);
        final String newClientSecret = parameters.get(NEW_CLIENT_SECRET);
        final String newRealm = parameters.get(NEW_REALM);
        final String newScope = parameters.get(NEW_SCOPE);
        final String newAudience = parameters.get(NEW_AUDIENCE);
        final String newKeyBinding = parameters.get(NEW_KEYBINDING);
        final String newDisableAudienceCheck = parameters.get(NEW_AUDIENCECHECKDISABLED);

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
                log.info("Trusted OAuth Provider with the same label exists!");
                return false;
            }
        }
        if (newUrl != null) {
            keyInfoToBeEdited.setUrl(keyInfoToBeEdited.fixUrl(newUrl));
        }
        if (newTokenUrl != null) {
            keyInfoToBeEdited.setTokenUrl(keyInfoToBeEdited.fixUrl(newTokenUrl));
        }
        if (newLogoutUrl != null) {
            keyInfoToBeEdited.setLogoutUrl(keyInfoToBeEdited.fixUrl(newLogoutUrl));
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
        if (newScope != null) {
            keyInfoToBeEdited.setScope(newScope);
        }
        if (newAudience != null) {
            keyInfoToBeEdited.setAudience(newAudience);
        }
        if (newDisableAudienceCheck != null) {
            keyInfoToBeEdited.setAudienceCheckDisabled(Boolean.valueOf(newDisableAudienceCheck));
        }
        if (newKeyBinding != null) {
            final Optional<Integer> maybeKeyBindingId = keyBindingNameToId(newKeyBinding);
            if (!maybeKeyBindingId.isPresent()) {
                log.info("Key binding '" + newKeyBinding + "' not found");
                return false;
            }
            keyInfoToBeEdited.setKeyBinding(maybeKeyBindingId.get());
        }
            
        return true;
    }

}
