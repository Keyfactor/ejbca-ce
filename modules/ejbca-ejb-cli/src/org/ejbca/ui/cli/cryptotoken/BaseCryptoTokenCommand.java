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

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.util.StringTools;
import org.ejbca.ui.cli.BaseCommand;
import org.ejbca.ui.cli.CliUsernameException;
import org.ejbca.ui.cli.ErrorAdminCommandException;

/**
 * Base class for the CryptoToken EJB CLI providing common functionality.
 * 
 * @version $Id$
 */
public abstract class BaseCryptoTokenCommand extends BaseCommand {

    @Override
    public String getMainCommand() {
        return "cryptotoken";
    }

    /**
     * Overridable CryptoToken-specific execution methods that will parse and interpret the first parameter
     * (when present) as the name of a CryptoToken and lookup its cryptoTokenId.
     */
    public abstract void executeCommand(Integer cryptoTokenId, String[] args) throws AuthorizationDeniedException, CryptoTokenOfflineException, Exception;
    
    @Override
    public void execute(String[] args) throws ErrorAdminCommandException {
        try {
            args = parseUsernameAndPasswordFromArgs(args);
        } catch (CliUsernameException e) {
            return;
        }
        Integer cryptoTokenId = null;
        if (args.length>=2) {
            final String cryptoTokenName = args[1];
            cryptoTokenId = ejb.getRemoteSession(CryptoTokenManagementSessionRemote.class).getIdFromName(cryptoTokenName);
            if (cryptoTokenId==null) {
                getLogger().info("Unknown CryptoToken: " + cryptoTokenName);
                return;
            }
        }
        try {
            executeCommand(cryptoTokenId, args);
        } catch (AuthorizationDeniedException e) {
            getLogger().info(e.getMessage());
        } catch (CryptoTokenOfflineException e) {
            getLogger().info("CryptoToken is not active. You need to activate the CryptoToken before you can interact with its content.");
        } catch (Exception e) {
            getLogger().info("Operation failed: " + e.getMessage());
            getLogger().debug("", e);
        }
    }
    
    /** @return the EJB CLI admin */
    protected AuthenticationToken getAdmin() {
        return getAdmin(cliUserName, cliPassword);
    }

    /** @return a deobfuscated version of the parameter or use input if the parameter equals "null" */
    public char[] getAuthenticationCode(final String commandLineArgument) {
        final char[] authenticationCode;
        if (!"null".equalsIgnoreCase(commandLineArgument)) {
            authenticationCode = StringTools.passwordDecryption(commandLineArgument, "CryptoToken pin").toCharArray();
        } else {
            getLogger().info("Enter CryptoToken password: ");
            getLogger().info("");
            authenticationCode = StringTools.passwordDecryption(String.valueOf(System.console().readPassword()), "CryptoToken pin").toCharArray();
        }
        return authenticationCode;
    }
}
