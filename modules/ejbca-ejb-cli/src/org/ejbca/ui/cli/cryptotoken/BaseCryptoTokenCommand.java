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
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.StringTools;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.command.EjbcaCliUserCommandBase;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * Base class for the CryptoToken EJB CLI providing common functionality.
 * 
 * @version $Id$
 */
public abstract class BaseCryptoTokenCommand extends EjbcaCliUserCommandBase {

    protected static final String CRYPTOTOKEN_NAME_KEY = "--token";

    {
        registerParameter(new Parameter(CRYPTOTOKEN_NAME_KEY, "Token Name", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The name of the crypto token."));
    }

    @Override
    public String[] getCommandPath() {
        return new String[] { "cryptotoken" };
    }

    /**
     * Overridable CryptoToken-specific execution methods that will parse and interpret the first parameter
     * (when present) as the name of a CryptoToken and lookup its cryptoTokenId.
     */
    public abstract CommandResult executeCommand(Integer cryptoTokenId, ParameterContainer parameters) throws AuthorizationDeniedException,
            CryptoTokenOfflineException;

    @Override
    public CommandResult execute(ParameterContainer parameters) {
        Integer cryptoTokenId = null;
        final String cryptoTokenName = parameters.get(CRYPTOTOKEN_NAME_KEY);
        cryptoTokenId = EjbRemoteHelper.INSTANCE.getRemoteSession(CryptoTokenManagementSessionRemote.class).getIdFromName(cryptoTokenName);
        if (cryptoTokenId == null) {
            getLogger().error("Unknown CryptoToken: " + cryptoTokenName);
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        try {
            return executeCommand(cryptoTokenId, parameters);
        } catch (AuthorizationDeniedException e) {
            getLogger().info(e.getMessage());
            return CommandResult.AUTHORIZATION_FAILURE;
        } catch (CryptoTokenOfflineException e) {
            getLogger().info("CryptoToken is not active. You need to activate the CryptoToken before you can interact with its content.");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
    }

    /** @return the EJB CLI admin */
    protected AuthenticationToken getAdmin() {
        return getAuthenticationToken();
    }

    /** @return a deobfuscated version of the parameter or use input if the parameter equals "null" */
    protected char[] getAuthenticationCode(final String commandLineArgument) {
        final char[] authenticationCode;
        if (commandLineArgument == null || "null".equalsIgnoreCase(commandLineArgument)) {         
            getLogger().info("Enter CryptoToken password: ");
            getLogger().info("");
            authenticationCode = StringTools.passwordDecryption(String.valueOf(System.console().readPassword()), "CryptoToken pin").toCharArray();
        } else {
            authenticationCode = StringTools.passwordDecryption(commandLineArgument, "CryptoToken pin").toCharArray();
        }
        return authenticationCode;
    }

    protected abstract Logger getLogger();
}
