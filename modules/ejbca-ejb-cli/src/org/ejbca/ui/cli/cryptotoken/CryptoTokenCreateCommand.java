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

import java.io.File;
import java.util.Properties;

import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.keys.token.BaseCryptoToken;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.PKCS11CryptoToken;
import org.cesecore.keys.token.SoftCryptoToken;

/**
 * CryptoToken EJB CLI command. See {@link #getDescription()} implementation.
 * 
 * @version $Id$
 */
public class CryptoTokenCreateCommand extends BaseCryptoTokenCommand {

    @Override
    public String getSubCommand() {
        return "create";
    }

    @Override
    public String getDescription() {
        return "Create a new CryptoToken";
    }

    @Override
    public void executeCommand(Integer cryptoTokenId, String[] args) {
        if (args.length < 6) {
            getLogger().info("Description: " + getDescription());
            getLogger().info("Usage: " + getCommand() + " <name> <pin or \"null\" to prompt> <auto activate: true|false> <type> <type specific arguments...>");
            getLogger().info("   " + SoftCryptoToken.class.getSimpleName() + " arguments: <allow private key export: true|false>");
            getLogger().info(" " + PKCS11CryptoToken.class.getSimpleName() + " arguments: <PKCS#11 library file> <PKCS#11 slot> <PKCS#11 attribute file or \"null\">");
            return;
        }
        final String cryptoTokenName = args[1];
        final boolean autoActivate = Boolean.valueOf(args[3]);
        final String type = args[4];
        final String className;
        final Properties cryptoTokenPropertes = new Properties();
        if (SoftCryptoToken.class.getSimpleName().equals(type)) {
            className = SoftCryptoToken.class.getName();
            cryptoTokenPropertes.setProperty(CryptoToken.ALLOW_EXTRACTABLE_PRIVATE_KEY, Boolean.toString(Boolean.valueOf(args[5])));
            cryptoTokenPropertes.setProperty(SoftCryptoToken.NODEFAULTPWD, Boolean.TRUE.toString());
        } else if (PKCS11CryptoToken.class.getSimpleName().equals(type)) {
            className = PKCS11CryptoToken.class.getName();
            // Parse library file
            if (!new File(args[5]).exists()) {
                getLogger().info("PKCS#11 library file " + args[5] + " does not exist!");
                return;
            }
            cryptoTokenPropertes.setProperty(PKCS11CryptoToken.SHLIB_LABEL_KEY, args[5]);
            // Parse slot or slotindex
            String slotPropertyValue = args[6];
            String slotPropertyName = PKCS11CryptoToken.SLOT_LABEL_KEY;
            if (slotPropertyValue.startsWith("i")) {
                slotPropertyValue = slotPropertyValue.substring(1);
                slotPropertyName = PKCS11CryptoToken.SLOT_LIST_INDEX_LABEL_KEY;
            }
            try {
                Integer.parseInt(slotPropertyValue);
            } catch (NumberFormatException e) {
                getLogger().info("Invalid slot specification.");
                return;
            }
            cryptoTokenPropertes.setProperty(slotPropertyName, slotPropertyValue);
            // Parse attribute file
            if (!"null".equalsIgnoreCase(args[7])) {
                if (!new File(args[7]).exists()) {
                    getLogger().info("PKCS#11 attribute file " + args[7] + " does not exist!");
                    return;
                }
                cryptoTokenPropertes.setProperty(PKCS11CryptoToken.ATTRIB_LABEL_KEY, args[7]);
            }
        } else {
            getLogger().info("Invalid CryptoToken type: " + type);
            return;
        }
        final char[] authenticationCode = getAuthenticationCode(args[2]);
        if (autoActivate) {
            BaseCryptoToken.setAutoActivatePin(cryptoTokenPropertes, new String(authenticationCode), true);
        }
        try {
            final Integer cryptoTokenIdNew = ejb.getRemoteSession(CryptoTokenManagementSessionRemote.class).createCryptoToken(getAdmin(),
                    cryptoTokenName, className, cryptoTokenPropertes, null, authenticationCode);
            getLogger().info("CryptoToken with id " + cryptoTokenIdNew + " created successfully.");
        } catch (AuthorizationDeniedException e) {
            getLogger().info(e.getMessage());
        } catch (CryptoTokenOfflineException e) {
            getLogger().info("CryptoToken is not active. You need to activate the CryptoToken before you can interact with its content.");
        } catch (Exception e) {
            getLogger().info("Operation failed: " + e.getMessage());
        }
    }
}
