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

import java.io.Serializable;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.ejbca.core.ejb.keybind.InternalKeyBindingMgmtSessionRemote;
import org.ejbca.core.ejb.keybind.InternalKeyBindingProperty;
import org.ejbca.core.ejb.keybind.InternalKeyBindingStatus;
import org.ejbca.util.CliTools;

/**
 * See getDescription().
 * 
 * @version $Id$
 */
public class InternalKeyBindingCreateCommand extends BaseInternalKeyBindingCommand {

    @Override
    public String getSubCommand() {
        return "create";
    }

    @Override
    public String getDescription() {
        return "Creates a new InternalKeyBinding.";
    }

    @Override
    protected boolean failIfInternalKeyBindIsMissing() {
        return false;
    }

    @Override
    public void executeCommand(Integer internalKeyBindingId, String[] args) throws AuthorizationDeniedException, CryptoTokenOfflineException, Exception {
        final InternalKeyBindingMgmtSessionRemote internalKeyBindingMgmtSession = ejb.getRemoteSession(InternalKeyBindingMgmtSessionRemote.class);
        if (args.length < 7) {
            getLogger().info("Description: " + getDescription());
            getLogger().info("Usage: " + getCommand() + " <name> <type> <status> <certificate fingerprint> <crypto token name> <key pair alias> [--property key1=value1 --property key2=value2 ...]");
            // List available types and their properties
            Map<String, List<InternalKeyBindingProperty<? extends Serializable>>> typesAndProperties = internalKeyBindingMgmtSession.getAvailableTypesAndProperties(getAdmin());
            getLogger().info(" Registered implementation types and implemention specific properties:");
            for (Entry<String, List<InternalKeyBindingProperty<? extends Serializable>>> entry : typesAndProperties.entrySet()) {
                final StringBuilder sb = new StringBuilder();
                sb.append("  ").append(entry.getKey()).append(" {");
                for (InternalKeyBindingProperty<? extends Serializable> property : entry.getValue()) {
                    sb.append(property.getName()).append(",");
                }
                sb.deleteCharAt(sb.length()-1).append("}");
                getLogger().info(sb.toString());
            }
            final StringBuilder sb = new StringBuilder(" status is one of ");
            for (InternalKeyBindingStatus internalKeyBindingStatus : InternalKeyBindingStatus.values()) {
                sb.append(internalKeyBindingStatus.name()).append(",");
            }
            sb.deleteCharAt(sb.length()-1);
            getLogger().info(sb.toString());
            return;
        }
        // Start be extracting any property
        final Map<Object,Object> dataMap = new LinkedHashMap<Object,Object>();
        final List<String> argsList = CliTools.getAsModifyableList(args);
        while (true) {
            final String propertyArg = CliTools.getAndRemoveParameter("--property", argsList);
            if (propertyArg == null) {
                break;
            }
            int indexOfEqualsSign = propertyArg.indexOf('=');
            if (indexOfEqualsSign == -1) {
                getLogger().info(" Ignoring --property with value " + propertyArg + ". The correct format is \"key=value\"");
                continue;
            }
            String key = propertyArg.substring(0, indexOfEqualsSign-1);
            String value = propertyArg.substring(indexOfEqualsSign+1);
            dataMap.put(key, value);
        }
        args = CliTools.getAsArgs(argsList);
        // Parse static arguments
        final String name = args[1];
        final String type = args[2];
        final InternalKeyBindingStatus status = InternalKeyBindingStatus.valueOf(args[3].toUpperCase());
        final String certificateId = "null".equalsIgnoreCase(args[4]) ? null : args[4];
        final int cryptoTokenId = ejb.getRemoteSession(CryptoTokenManagementSessionRemote.class).getIdFromName(args[5]);
        final String keyPairAlias = args[6];
        int internalKeyBindingIdNew = internalKeyBindingMgmtSession.createInternalKeyBinding(getAdmin(), type, name, status, certificateId, cryptoTokenId, keyPairAlias, dataMap);
        getLogger().info("InternalKeyBinding with id " + internalKeyBindingIdNew + " created successfully.");
    }
}
