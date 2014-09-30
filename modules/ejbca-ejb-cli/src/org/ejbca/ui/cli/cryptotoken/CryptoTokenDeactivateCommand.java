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
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;

/**
 * CryptoToken EJB CLI command. See {@link #getDescription()} implementation.
 * 
 * @version $Id$
 */
public class CryptoTokenDeactivateCommand extends BaseCryptoTokenCommand {

    private static final Logger log = Logger.getLogger(CryptoTokenDeactivateCommand.class);

    @Override
    public String getMainCommand() {
        return "deactivate";
    }

    @Override
    public CommandResult executeCommand(Integer cryptoTokenId, ParameterContainer parameters) throws AuthorizationDeniedException, CryptoTokenOfflineException {
        try {
            final CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE
                    .getRemoteSession(CryptoTokenManagementSessionRemote.class);
            final CryptoTokenInfo cryptoTokenInfo = cryptoTokenManagementSession.getCryptoTokenInfo(getAdmin(), cryptoTokenId.intValue());
            final boolean usingAutoActivation = cryptoTokenInfo.isAutoActivation();
            cryptoTokenManagementSession.deactivate(getAdmin(), cryptoTokenId.intValue());
            if (cryptoTokenManagementSession.isCryptoTokenStatusActive(getAdmin(), cryptoTokenId.intValue())) {
                final String msg = "CryptoToken is still active after deactivation request.";
                if (usingAutoActivation) {
                    getLogger().info(msg);
                    getLogger().info(
                            "This is the expected outcome since the CryptoTokens is instantly auto-activated after the deactivation request.");
                } else {
                    getLogger().error(msg);
                }
                return CommandResult.SUCCESS;
            } else {
                if (usingAutoActivation) {
                    getLogger().error("CryptoTokens was deactivated despite auto-activation being used. This is an unexpected outcome.");
                } else {
                    getLogger().info("CryptoToken deactivated successfully.");
                }
                return CommandResult.FUNCTIONAL_FAILURE;
            }
        } catch (AuthorizationDeniedException e) {
            getLogger().info(e.getMessage());
            return CommandResult.AUTHORIZATION_FAILURE;
        } catch (Exception e) {
            getLogger().info("CryptoToken deactivation failed: " + e.getMessage());
            return CommandResult.FUNCTIONAL_FAILURE;
        }
    }

    @Override
    public String getCommandDescription() {
        return "Deactivate CryptoToken";
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
