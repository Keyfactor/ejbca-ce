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
 * Editing the already existing Trusted OAuth Provider.
 *
 */
public class EditOAuthProviderCommand extends BaseOAuthConfigCommand {

    private static final Logger log = Logger.getLogger(EditOAuthProviderCommand.class);

    private static final String KEY_IDENTIFIER = "--keyidentifier";
    private static final String NEW_KEY_IDENTIFIER = "--new-keyidentifier";
    private static final String NEW_PUBLIC_KEY = "--new-publickey";
    private static final String NEW_SKEW_LIMIT = "--new-skewlimit";
    private static final String NEW_URL = "--new-url";

    {
        registerParameter(new Parameter(KEY_IDENTIFIER, "Key identifier", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Key identifier of the Trusted OAuth Provider to update its parameters."));
        registerParameter(new Parameter(NEW_KEY_IDENTIFIER, "Key identifier", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "New key identifier of the Trusted OAuth Provider."));
        registerParameter(new Parameter(NEW_PUBLIC_KEY, "Public key", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Public key to be updated."));
        registerParameter(new Parameter(NEW_SKEW_LIMIT, "Skew limit", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Skew limit to be updated."));
        registerParameter(new Parameter(NEW_URL, "Provider url", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Trusted OAuth Provider url to the login page to be updated."));
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

        String kid = parameters.get(KEY_IDENTIFIER);

        for (Map.Entry<Integer, OAuthKeyInfo> entry : getGlobalConfiguration().getOauthKeys().entrySet()) {
            if (entry.getValue().getKeyIdentifier().equals(kid)) {
                if (checkParametersAndSet(parameters.get(NEW_KEY_IDENTIFIER), parameters.get(NEW_SKEW_LIMIT),
                        parameters.get(NEW_PUBLIC_KEY), parameters.get(NEW_URL), entry.getValue())) {
                    OAuthKeyInfo defaultKey = getGlobalConfiguration().getDefaultOauthKey();
                    if (defaultKey != null && entry.getValue().getInternalId() == defaultKey.getInternalId()) {
                        getGlobalConfiguration().setDefaultOauthKey(entry.getValue());
                    }
                    if (saveGlobalConfig()) {
                        log.info("Trusted OAuth Provider with kid: " + kid + " successfully updated!");
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
        log.info("No Trusted OAuth Provider with given kid: " + kid + " exists!");
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

    private boolean checkParametersAndSet(final String newKid, final String newSkewLimit, final String newPublicKey, final String newUrl,
            final OAuthKeyInfo keyInfoToBeEdited) {
        if (newKid != null) { 
            if (canEditKid(newKid)) {
                keyInfoToBeEdited.setKeyIdentifier(newKid);
            } else {
                log.info("New given kid is null or kid with same name already exists!");
                return false;
            }
        }
            
        if (newSkewLimit != null) {
            if (validateSkewLimit(newSkewLimit) >= 0) {
                keyInfoToBeEdited.setSkewLimit(validateSkewLimit(newSkewLimit));
            } else {
                log.info("New given skew limit is invalid!");
                return false;
            }
        }

        if (newPublicKey != null) {
            if(!ArrayUtils.isEmpty(getOauthKeyPublicKey(newPublicKey))) {
                keyInfoToBeEdited.setPublicKeyBytes(getOauthKeyPublicKey(newPublicKey));
            } else {
                log.info("New given public key is invalid!");
                return false;
            }
        }
        if (newUrl != null) {
            keyInfoToBeEdited.setUrl(newUrl);
        }
            
        return true;
    }

}
