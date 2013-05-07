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
package org.ejbca.ui.cli.keybind;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.ejbca.core.ejb.keybind.InternalKeyBindingMgmtSessionRemote;
import org.ejbca.ui.cli.BaseCommand;
import org.ejbca.ui.cli.CliUsernameException;
import org.ejbca.ui.cli.ErrorAdminCommandException;

/**
 * Base class for the InternalKeyBinding API access.
 * 
 * @version $Id$
 */
public abstract class BaseInternalKeyBindingCommand extends BaseCommand {

    @Override
    public String getMainCommand() {
        return "keybind";
    }

    /**
     * Overridable CryptoToken-specific execution methods that will parse and interpret the first parameter
     * (when present) as the name of a CryptoToken and lookup its cryptoTokenId.
     */
    public abstract void executeCommand(Integer internalKeyBindingId, String[] args) throws AuthorizationDeniedException, CryptoTokenOfflineException, Exception;
    
    @Override
    public void execute(String[] args) throws ErrorAdminCommandException {
        try {
            args = parseUsernameAndPasswordFromArgs(args);
        } catch (CliUsernameException e) {
            return;
        }
        Integer internalKeyBindingId = null;
        if (failIfInternalKeyBindIsMissing() && args.length>=2) {
            final String internalKeyBindingName = args[1];
            internalKeyBindingId = ejb.getRemoteSession(InternalKeyBindingMgmtSessionRemote.class).getIdFromName(internalKeyBindingName);
            if (internalKeyBindingId==null) {
                getLogger().info("Unknown InternalKeyBinding: " + internalKeyBindingName);
                return;
            }
        }
        try {
            executeCommand(internalKeyBindingId, args);
        } catch (AuthorizationDeniedException e) {
            getLogger().info(e.getMessage());
        } catch (CryptoTokenOfflineException e) {
            getLogger().info("CryptoToken is not active. You need to activate the CryptoToken before you can interact with its content.");
        } catch (Exception e) {
            getLogger().info("Operation failed: " + e.getMessage());
            getLogger().debug("", e);
        }
    }
    
    protected boolean failIfInternalKeyBindIsMissing() {
        return true;
    }
    
    /** @return the EJB CLI admin */
    protected AuthenticationToken getAdmin() {
        return getAdmin(cliUserName, cliPassword);
    }
}
