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
import org.cesecore.keys.token.CryptoTokenInfo;
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
public class CryptoTokenActivateCommand extends BaseCryptoTokenCommand {

    private static final Logger log = Logger.getLogger(CryptoTokenActivateCommand.class);

    private static final String PIN_KEY = "--pin";

    {
        registerParameter(new Parameter(PIN_KEY, "Pin", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "PIN to the CryptoToken. Leave blank to prompt."));
    }

    @Override
    public String getMainCommand() {
        return "activate";
    }

    @Override
    public CommandResult executeCommand(Integer cryptoTokenId, ParameterContainer parameters) throws AuthorizationDeniedException, CryptoTokenOfflineException {

        final char[] authenticationCode = getAuthenticationCode(parameters.get(PIN_KEY));
        try {
            final CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE
                    .getRemoteSession(CryptoTokenManagementSessionRemote.class);
            final CryptoTokenInfo cryptoTokenInfo = cryptoTokenManagementSession.getCryptoTokenInfo(getAdmin(), cryptoTokenId.intValue());
            final boolean usingAutoActivation = cryptoTokenInfo.isAutoActivation();
            cryptoTokenManagementSession.activate(getAdmin(), cryptoTokenId, authenticationCode);
            if (cryptoTokenManagementSession.isCryptoTokenStatusActive(getAdmin(), cryptoTokenId)) {
                if (usingAutoActivation) {
                    getLogger().info("CryptoToken activated successfully using auto-activation PIN. (The supplied PIN was ignored.)");
                } else {
                    getLogger().info("CryptoToken activated successfully using supplied PIN.");
                }
                return CommandResult.SUCCESS;
            } else {
                if (usingAutoActivation) {
                    getLogger()
                            .error("Failed to activate CryptoToken using auto-activation PIN even though request was process successfully. (The supplied PIN was ignored.)");         
                } else {
                    getLogger().warn("CryptoToken still not active even though request was processed successfully.");
                }
                return CommandResult.FUNCTIONAL_FAILURE;
            }
        } catch (AuthorizationDeniedException e) {
            getLogger().info(e.getMessage());
            return CommandResult.AUTHORIZATION_FAILURE;
        } catch (Exception e) {
            getLogger().info("CryptoToken activation failed: " + e.getMessage());
            return CommandResult.FUNCTIONAL_FAILURE;
        }
    }

    @Override
    public String getCommandDescription() {
        return "Activate CryptoToken";
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
