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
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authentication.oauth.OAuthKeyInfo;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * Adds or removes public keys to/from already existing Trusted OAuth Provider
 *
 */
public class ManageOauthPublicKeyCommand extends BaseOAuthConfigCommand{
    private static final Logger log = Logger.getLogger(ManageOauthPublicKeyCommand.class);

    private static final String LABEL = "--label";
    private static final String ACTION = "--action";
    private static final String KEY_IDENTIFIER = "--keyidentifier";
    private static final String PUBLIC_KEY = "--publickey";

    {
        registerParameter(new Parameter(LABEL, "Provider name", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Trusted OAuth Provider name to be shown"));
        registerParameter(new Parameter(ACTION, "Action: add or remove", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Action: add or remove"));
        registerParameter(new Parameter(KEY_IDENTIFIER, "Key identifier", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Key identifier of the key which is going to be added/removed."));
        registerParameter(new Parameter(PUBLIC_KEY, "Public key", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Path to publickey file of public key."));
    }

    @Override
    public String getCommandDescription() {
        return "Adds or removes public key of Trusted OAuth Provider with defined label.";
    }

    @Override
    public String getMainCommand() {
            return "oauthproviderkey";
    }

    @Override
    protected CommandResult execute(ParameterContainer parameters) {
        CommandResult result = null;
        String action = parameters.get(ACTION);
        String label = parameters.get(LABEL);
        String kid = parameters.get(KEY_IDENTIFIER);
        String publicKey = parameters.get(PUBLIC_KEY);

        switch (action.toLowerCase()) {
            case "add": {
                result = addKey(label, kid, publicKey);
                break;
            }
            case "remove": {
                result = removeKey(label, kid);
                break;
            }
            default: {
                log.info("Invalid action value! Valid values are 'add' or 'remove' ");
                return CommandResult.FUNCTIONAL_FAILURE;
            }
        }
        return result;
    }

    private CommandResult addKey(String label, String kid, String publicKey){
        final OAuthKeyInfo oAuthKeyInfo = getOAuthConfiguration().getOauthKeyByLabel(label);

        if (oAuthKeyInfo == null) {
            log.info("Trusted OAuth Provider with label: " + label + " not found!");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        if (StringUtils.isEmpty(publicKey)) {
            log.info("Public key file is not defined!");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        byte[] publicKeyByteArray = getOauthKeyPublicKey(publicKey);
        if (ArrayUtils.isEmpty(publicKeyByteArray)) {
            return CommandResult.FUNCTIONAL_FAILURE;
        }

        if (oAuthKeyInfo.getAllKeyIdentifiers()!= null && oAuthKeyInfo.getAllKeyIdentifiers().contains(kid)) {
            log.info("Key with identifier " + kid + " already exists.");
            return CommandResult.FUNCTIONAL_FAILURE;
        }

        oAuthKeyInfo.addPublicKey(kid, publicKeyByteArray);
        if (saveGlobalConfig()) {
            log.info("Public key with kid " +kid+ " successfuly added to Trusted OAuth Provider with label: " + label + "!");
            return CommandResult.SUCCESS;
        } else {
            log.info("Failed to update configuration due to authorization issue!");
            return CommandResult.AUTHORIZATION_FAILURE;
        }
    }

    private CommandResult removeKey(String label, String kid){
        final OAuthKeyInfo oAuthKeyInfo = getOAuthConfiguration().getOauthKeyByLabel(label);

        if (oAuthKeyInfo == null) {
            log.info("Trusted OAuth Provider with label: " + label + " not found!");
            return CommandResult.FUNCTIONAL_FAILURE;
        }

        if (oAuthKeyInfo.getAllKeyIdentifiers()== null || !oAuthKeyInfo.getAllKeyIdentifiers().contains(kid)) {
            log.info("Key with identifier " + kid + " does not exist in Trusted OAuth Provider with name " + label + ".");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        oAuthKeyInfo.getKeys().remove(kid);

        if (saveGlobalConfig()) {
            log.info("Public key with kid " +kid+ " successfuly removed from Trusted OAuth Provider with label: " + label + "!");
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
