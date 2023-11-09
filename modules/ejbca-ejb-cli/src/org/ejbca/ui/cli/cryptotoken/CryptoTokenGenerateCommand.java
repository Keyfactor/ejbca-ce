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
package org.ejbca.ui.cli.cryptotoken;

import java.util.Arrays;

import com.keyfactor.util.keys.token.CryptoTokenOfflineException;
import com.keyfactor.util.keys.token.KeyGenParams;
import com.keyfactor.util.keys.token.KeyGenParams.KeyGenParamsBuilder;
import com.keyfactor.util.keys.token.KeyGenParams.KeyPairTemplate;

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * CryptoToken EJB CLI command. See {@link #getDescription()} implementation.
 */
public class CryptoTokenGenerateCommand extends BaseCryptoTokenCommand {

    private static final Logger log = Logger.getLogger(CryptoTokenGenerateCommand.class);

    private static final String KEY_PAIR_ALIAS_KEY = "--alias";
    private static final String KEY_SPECIFICATION_KEY = "--keyspec";
    private static final String KEY_USAGE = "--key-usage";

    {
        registerParameter(new Parameter(KEY_PAIR_ALIAS_KEY, "Alias", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Key pair alias"));
        registerParameter(new Parameter(KEY_SPECIFICATION_KEY, "Key Specification", MandatoryMode.MANDATORY, StandaloneMode.ALLOW,
                ParameterMode.ARGUMENT, "Key specification, for example 2048, secp256r1, DSA1024, gost3410, dstu4145"));
        registerParameter(
                new Parameter(KEY_USAGE, "Key usage", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.ARGUMENT, 
                        "A key usage emplate, describing how the key is allowed to be used. Applicable for PKCS#11 NG Crypto Tokens and has no function "
                        + "for most other crypto tokens. Available templates: "
                        + Arrays.asList(KeyPairTemplate.values()) + ". If not provided, the default value of SIGN will be used"));
    }

    @Override
    public String getMainCommand() {
        return "generatekey";
    }

    @Override
    public CommandResult executeCommand(Integer cryptoTokenId, ParameterContainer parameters) throws AuthorizationDeniedException, CryptoTokenOfflineException {
        final String keyPairAlias = parameters.get(KEY_PAIR_ALIAS_KEY);
        final String keyPairSpecification = parameters.get(KEY_SPECIFICATION_KEY);
        // If user does not provide key usage on the command line, it defaults to SIGN (which is the same default if we don't provide any template into createKeyPair)
        final String keyUsage = parameters.get(KEY_USAGE) == null ? KeyPairTemplate.SIGN.toString() : parameters.get(KEY_USAGE);
        final KeyGenParamsBuilder paramBuilder = KeyGenParams.builder(keyPairSpecification).withKeyPairTemplate(KeyPairTemplate.valueOf(keyUsage.toUpperCase()));
        try {
            EjbRemoteHelper.INSTANCE.getRemoteSession(CryptoTokenManagementSessionRemote.class).createKeyPair(getAdmin(), cryptoTokenId,
                    keyPairAlias, paramBuilder.build());
            getLogger().info("Key pair generated successfully.");
            return CommandResult.SUCCESS;
        } catch (AuthorizationDeniedException e) {
            getLogger().info(e.getMessage());
            return CommandResult.AUTHORIZATION_FAILURE;
        } catch (CryptoTokenOfflineException e) {
            getLogger().info("CryptoToken is not active. You need to activate the CryptoToken before you can interact with its content.");
        } catch (Exception e) {
            getLogger().info("Key pair generation failed: " + e.getMessage());
        }
        return CommandResult.FUNCTIONAL_FAILURE;
    }

    @Override
    public String getCommandDescription() {
        return "Generate new key pair";
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
