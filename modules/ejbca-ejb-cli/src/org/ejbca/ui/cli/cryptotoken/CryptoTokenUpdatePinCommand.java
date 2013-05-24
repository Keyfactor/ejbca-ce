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

import java.util.List;

import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.ejbca.util.CliTools;

/**
 * CryptoToken EJB CLI command. See {@link #getDescription()} implementation.
 * 
 * @version $Id$
 */
public class CryptoTokenUpdatePinCommand extends BaseCryptoTokenCommand {

    private static final String SWITCH_UPDATE_ONLY = "--update";
    private static final String SWITCH_REMOVE_AUTO = "--remove";
    
    @Override
    public String getSubCommand() {
        return "setpin";
    }

    @Override
    public String getDescription() {
        return "Modifies the current keystore and/or auto-activation pin.";
    }

    @Override
    public void executeCommand(Integer cryptoTokenId, String[] args) throws AuthorizationDeniedException, CryptoTokenOfflineException, Exception {
        final List<String> argsList = CliTools.getAsModifyableList(args);
        final boolean updateOnly = CliTools.getAndRemoveSwitch(SWITCH_UPDATE_ONLY, argsList);
        final boolean removeAuto = CliTools.getAndRemoveSwitch(SWITCH_REMOVE_AUTO, argsList);
        args = CliTools.getAsArgs(argsList);
        if (args.length < 3 || (!removeAuto && args.length < 4)) {
            getLogger().info("Description: " + getDescription());
            getLogger().info("Usage: " + getCommand() + " <name of CryptoToken> ["+SWITCH_UPDATE_ONLY+"] ["+SWITCH_REMOVE_AUTO+"] <current activation pin or \"null\" to prompt> <new pin or \"null\" to prompt>");
            getLogger().info(" " + SWITCH_UPDATE_ONLY+" will only set the auto-activation pin and make the token auto-activated if it was so previously.");
            getLogger().info(" " + SWITCH_REMOVE_AUTO+" will remove any auto-activation pin if present (new pin is not required when this is used).");
            getLogger().info(" For soft CryptoTokens the underlying keystore's pin will be modified and this requires the current activation PIN.");
            getLogger().info(" For PKCS#11 CryptoTokens this will only modify the auto-activation pin and requires the current (auto-activation or) activation PIN.");
            return;
        }
        final char[] currentAuthenticationCode = getAuthenticationCode(args[2]);
        final char[] newAuthenticationCode = removeAuto ? null : getAuthenticationCode(args[3]);
        try {
            final CryptoTokenManagementSessionRemote cryptoTokenManagementSession = ejb.getRemoteSession(CryptoTokenManagementSessionRemote.class);
            boolean result = cryptoTokenManagementSession.updatePin(getAdmin(), cryptoTokenId.intValue(), currentAuthenticationCode, newAuthenticationCode, updateOnly);
            if (result) {
                getLogger().info("Auto-activation is now in use for this CryptoToken.");
            } else {
                getLogger().info("Auto-activation is now not in use for this CryptoToken.");
            }
            final boolean isActive = cryptoTokenManagementSession.isCryptoTokenStatusActive(getAdmin(), cryptoTokenId.intValue());
            getLogger().info("CryptoToken is " + (isActive ? "active" : "deactivated") + ".");
        } catch (AuthorizationDeniedException e) {
            getLogger().info(e.getMessage());
        } catch (Exception e) {
            getLogger().info("CryptoToken activation failed: " + e.getMessage());
        }
    }
}
