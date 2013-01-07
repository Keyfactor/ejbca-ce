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
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.CryptoTokenOfflineException;

/**
 * CryptoToken EJB CLI command. See {@link #getDescription()} implementation.
 * 
 * @version $Id$
 */
public class CryptoTokenGenerateCommand extends BaseCryptoTokenCommand {

    @Override
    public String getSubCommand() {
        return "generatekey";
    }

    @Override
    public String getDescription() {
        return "Generate new key pair";
    }

    @Override
    public void executeCommand(Integer cryptoTokenId, String[] args) {
        if (args.length < 4) {
            getLogger().info("Description: " + getDescription());
            getLogger().info("Usage: " + getCommand() + " <name of CryptoToken> <key pair alias> <key specification>");
            getLogger().info("Example:");
            getLogger().info(" " + getCommand() + " \"My CA CryptoToken\" decryptionKey RSA2048");
            getLogger().info(" " + getCommand() + " \"My CA CryptoToken\" signatureKey secp384r1");
            getLogger().info(" " + getCommand() + " \"My CA CryptoToken\" testKey RSA1024");
            return;
        }
        final String keyPairAlias = args[2];
        final String keyPairSpecification = args[3];
        try {
            ejb.getRemoteSession(CryptoTokenManagementSessionRemote.class).createKeyPair(getAdmin(), cryptoTokenId, keyPairAlias, keyPairSpecification);
            getLogger().info("Key pair generated successfully.");
        } catch (AuthorizationDeniedException e) {
            getLogger().info(e.getMessage());
        } catch (CryptoTokenOfflineException e) {
            getLogger().info("CryptoToken is not active. You need to activate the CryptoToken before you can interact with its content.");
        } catch (Exception e) {
            getLogger().info("Key pair generation failed: " + e.getMessage());
        }
    }
}
