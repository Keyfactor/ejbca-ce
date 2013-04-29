/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
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

import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.keys.token.CryptoTokenInfo;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;

/**
 * CryptoToken EJB CLI command. See {@link #getDescription()} implementation.
 * 
 * @version $Id$
 */
public class CryptoTokenDeactivateCommand extends BaseCryptoTokenCommand {

    @Override
    public String getSubCommand() {
        return "deactivate";
    }

    @Override
    public String getDescription() {
        return "Deactivate CryptoToken";
    }

    @Override
    public void executeCommand(Integer cryptoTokenId, String[] args) {
        if (args.length < 2) {
            getLogger().info("Description: " + getDescription());
            getLogger().info("Usage: " + getCommand() + " <name of CryptoToken>");
            return;
        }
        try {
            final CryptoTokenManagementSessionRemote cryptoTokenManagementSession = ejb.getRemoteSession(CryptoTokenManagementSessionRemote.class);
            final CryptoTokenInfo cryptoTokenInfo = cryptoTokenManagementSession.getCryptoTokenInfo(getAdmin(), cryptoTokenId.intValue());
            final boolean usingAutoActivation = cryptoTokenInfo.isAutoActivation();
            cryptoTokenManagementSession.deactivate(getAdmin(), cryptoTokenId.intValue());
            if (cryptoTokenManagementSession.isCryptoTokenStatusActive(getAdmin(), cryptoTokenId.intValue())) {
                final String msg = "CryptoToken is still active after deactivation request.";
                if (usingAutoActivation) {
                    getLogger().info(msg);
                    getLogger().info("This is the expected outcome since the CryptoTokens is instantly auto-activated after the deactivation request.");
                } else {
                    getLogger().error(msg);
                }
            } else {
                if (usingAutoActivation) {
                    getLogger().error("CryptoTokens was deactivated despite auto-activation being used. This is an unexpected outcome.");
                } else {
                    getLogger().info("CryptoToken deactivated successfully.");
                }
            }
        } catch (AuthorizationDeniedException e) {
            getLogger().info(e.getMessage());
        } catch (Exception e) {
            getLogger().info("CryptoToken deactivation failed: " + e.getMessage());
        }
    }
}
