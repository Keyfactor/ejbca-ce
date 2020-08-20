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
 * Editing the already existing OAuth keys.
 *
 */
public class EditOAuthKeyCommand extends BaseOAuthConfigCommand {

    private static final Logger log = Logger.getLogger(EditOAuthKeyCommand.class);

    private static final String KEY_IDENTIFIER = "--key_identifier";
    private static final String NEW_KEY_IDENTIFIER = "--new_key_identifier";
    private static final String NEW_PUBLIC_KEY = "--new_public_key";
    private static final String NEW_SKEW_LIMIT = "--new_skew_limit";

    {
        registerParameter(new Parameter(KEY_IDENTIFIER, "Key identifier", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Key identifier of the OAuth key to update its parameters."));
        registerParameter(new Parameter(NEW_KEY_IDENTIFIER, "Key identifier", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Key identifier of the OAuth key to update its parameters."));
        registerParameter(new Parameter(NEW_PUBLIC_KEY, "Public key", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Public key to be updated."));
        registerParameter(new Parameter(NEW_SKEW_LIMIT, "Skew limit", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Skew limit to be updated."));
    }

    @Override
    public String getMainCommand() {
        return "editoauthkey";
    }

    @Override
    public String getCommandDescription() {
        return "Edit key identifier, public key and/or skew limit for an existing oauth kid.";
    }

    @Override
    protected CommandResult execute(ParameterContainer parameters) {

        String kid = parameters.get(KEY_IDENTIFIER);

        for (Map.Entry<Integer, OAuthKeyInfo> entry : getGlobalConfiguration().getOauthKeys().entrySet()) {
            if (entry.getValue().getKeyIdentifier().equals(kid)) {
                checkParametersAndSet(parameters.get(NEW_KEY_IDENTIFIER), parameters.get(NEW_SKEW_LIMIT), parameters.get(NEW_PUBLIC_KEY),
                        entry.getValue());
                if (saveGlobalConfig()) {
                    log.info("OAuth key with kid: " + kid + " successfully updated!");
                    return CommandResult.SUCCESS;
                } else {
                    log.info("Failed to update configuration due to authorization issue!");
                    return CommandResult.AUTHORIZATION_FAILURE;
                }
            }
        }
        log.info("No oauth key with given kid: " + kid + " exists!");
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

    private void checkParametersAndSet(final String newKid, final String newSkewLimit, final String newPublicKey,
            final OAuthKeyInfo keyInfoToBeEdited) {
        if (newKid != null && canEditKid(newKid)) {
            keyInfoToBeEdited.setKeyIdentifier(newKid);
        }

        if (newSkewLimit != null && validateSkewLimit(newSkewLimit) >= 0) {
            keyInfoToBeEdited.setSkewLimit(validateSkewLimit(newSkewLimit));
        }

        if (newPublicKey != null && !ArrayUtils.isEmpty(getOauthKeyPublicKey(newPublicKey))) {
            keyInfoToBeEdited.setOauthPublicKey(getOauthKeyPublicKey(newPublicKey));
        }
    }

}
