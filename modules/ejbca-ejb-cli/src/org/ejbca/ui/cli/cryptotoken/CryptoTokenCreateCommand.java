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
import org.cesecore.keys.token.p11.Pkcs11SlotLabelType;

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
    protected boolean failIfCryptoTokenMissing() {
        return false;   // Since we are about to create the CryptoToken, it does not yet exist
    }

    @Override
    public void executeCommand(Integer cryptoTokenId, String[] args) {
        if (args.length < 6) {
            getLogger().info("Description: " + getDescription());
            getLogger().info("Usage: " + getCommand() + " <name> <pin or \"null\" to prompt> <auto activate: true|false> <type> <type specific arguments...>");
            getLogger().info("  Available types: " + SoftCryptoToken.class.getSimpleName() + ", " + PKCS11CryptoToken.class.getSimpleName());
            getLogger().info("   " + SoftCryptoToken.class.getSimpleName() + " arguments: <allow private key export: true|false>");
            getLogger().info("   " + PKCS11CryptoToken.class.getSimpleName() + " arguments: <PKCS#11 library file> <PKCS#11 slot> <Slot Label Type> <PKCS#11 attribute file or \"null\">");
            getLogger().info("   " + PKCS11CryptoToken.class.getSimpleName() + " Slot Label Types:");
            for(Pkcs11SlotLabelType type : Pkcs11SlotLabelType.values()) {
                getLogger().info("    " + type.getKey() + " - " + type.getDescription());
            }           
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
            String slotPropertyValue = args[6];
            cryptoTokenPropertes.setProperty(PKCS11CryptoToken.SLOT_LABEL_VALUE, slotPropertyValue);
            Pkcs11SlotLabelType labelType = Pkcs11SlotLabelType.getFromKey(args[7]);
            //If an index was given, accept just numbers as well
            if(labelType.isEqual(Pkcs11SlotLabelType.SLOT_INDEX)) {
                if(slotPropertyValue.charAt(0) != 'i') {
                    slotPropertyValue = "i" + slotPropertyValue;
                }
            }
            if(!labelType.validate(slotPropertyValue)) {
                getLogger().info("Invalid value " + slotPropertyValue + " given for slot type " + labelType.getDescription());
                return;
            } else {
                cryptoTokenPropertes.setProperty(PKCS11CryptoToken.SLOT_LABEL_TYPE, labelType.getKey());
            }
            // Parse attribute file
            if (!"null".equalsIgnoreCase(args[8])) {
                if (!new File(args[8]).exists()) {
                    getLogger().info("PKCS#11 attribute file " + args[8] + " does not exist!");
                    return;
                }
                cryptoTokenPropertes.setProperty(PKCS11CryptoToken.ATTRIB_LABEL_KEY, args[8]);
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
            final CryptoTokenManagementSessionRemote cryptoTokenManagementSession = ejb.getRemoteSession(CryptoTokenManagementSessionRemote.class);
            final Integer cryptoTokenIdNew = cryptoTokenManagementSession.createCryptoToken(getAdmin(), cryptoTokenName, className,
                    cryptoTokenPropertes, null, authenticationCode);
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
