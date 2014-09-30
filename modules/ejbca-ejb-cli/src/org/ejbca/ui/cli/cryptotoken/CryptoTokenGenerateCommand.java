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

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * CryptoToken EJB CLI command. See {@link #getDescription()} implementation.
 * 
 * @version $Id$
 */
public class CryptoTokenGenerateCommand extends BaseCryptoTokenCommand {

    private static final Logger log = Logger.getLogger(CryptoTokenGenerateCommand.class);

    private static final String KEY_PAIR_ALIAS_KEY = "--alias";
    private static final String KEY_SPECIFICATION_KEY = "--keyspec";

    {
        registerParameter(new Parameter(KEY_PAIR_ALIAS_KEY, "Alias", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Key pair alias"));
        registerParameter(new Parameter(KEY_SPECIFICATION_KEY, "Key Specification", MandatoryMode.MANDATORY, StandaloneMode.ALLOW,
                ParameterMode.ARGUMENT, "Key specification"));
    }

    @Override
    public String getMainCommand() {
        return "generatekey";
    }

    @Override
    public CommandResult executeCommand(Integer cryptoTokenId, ParameterContainer parameters) throws AuthorizationDeniedException, CryptoTokenOfflineException {
        final String keyPairAlias = parameters.get(KEY_PAIR_ALIAS_KEY);
        final String keyPairSpecification = parameters.get(KEY_SPECIFICATION_KEY);
        try {
            EjbRemoteHelper.INSTANCE.getRemoteSession(CryptoTokenManagementSessionRemote.class).createKeyPair(getAdmin(), cryptoTokenId,
                    keyPairAlias, keyPairSpecification);
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
