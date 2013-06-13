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
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.ejbca.core.ejb.keybind.InternalKeyBinding;
import org.ejbca.core.ejb.keybind.InternalKeyBindingMgmtSessionRemote;
import org.ejbca.core.ejb.keybind.InternalKeyBindingProperty;
import org.ejbca.core.ejb.keybind.InternalKeyBindingTrustEntry;
import org.ejbca.util.CliTools;

/**
 * See getDescription().
 * 
 * @version $Id$
 */
public class InternalKeyBindingModifyCommand extends BaseInternalKeyBindingCommand {

    @Override
    public String getSubCommand() {
        return "modify";
    }

    @Override
    public String getDescription() {
        return "Modify an existing InternalKeyBinding.";
    }

    @Override
    public void executeCommand(Integer internalKeyBindingId, String[] args) throws AuthorizationDeniedException, Exception {
        final InternalKeyBindingMgmtSessionRemote internalKeyBindingMgmtSession = ejb.getRemoteSession(InternalKeyBindingMgmtSessionRemote.class);
        final CaSessionRemote caSession = ejb.getRemoteSession(CaSessionRemote.class);
        if (args.length < 3) {
            getLogger().info("Description: " + getDescription());
            getLogger().info("Usage: " + getCommand() + " <name> [--nextkeypair nextKeyPairAlias or \"null\"] [--removetrust trustEntry ...] [--addtrust trustEntry ...] [--property key1=value1]");
            getLogger().info(" trustEntry is in the form <CAName[;CertificateSerialNumber]> where the serialnumber is in hex and optional.");
            getLogger().info(" Multiple --addtrust, --removetrust and --property arguments are allowed.");
            getLogger().info("");
            getLogger().info("OcspKeyBinding example: " + getCommand() + " OcspKeyBinding1 --nextkeypair nextSigningKey --property maxAge=30 --property untilNextUpdate=30");
            getLogger().info("");
            showTypesProperties();
        }
        final List<String> argsList = CliTools.getAsModifyableList(args);
        // Extract properties
        final Map<String,String> propertyMap = new HashMap<String,String>();
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
            String key = propertyArg.substring(0, indexOfEqualsSign);
            String value = propertyArg.substring(indexOfEqualsSign+1);
            propertyMap.put(key, value);
        }
        // Extract remove trust entries
        final List<InternalKeyBindingTrustEntry> removeTrustList = new ArrayList<InternalKeyBindingTrustEntry>();
        while (true) {
            final String trustArg = CliTools.getAndRemoveParameter("--removetrust", argsList);
            if (trustArg == null) {
                break;
            }
            String value;
            String key;
            int indexOfEqualsSign = trustArg.indexOf(';');
            if (indexOfEqualsSign == -1) {
                value = null;
                key = trustArg;
            } else {
                key = trustArg.substring(0, indexOfEqualsSign);
                if (trustArg.length()==indexOfEqualsSign) {
                    value = null;
                } else {
                    value = trustArg.substring(indexOfEqualsSign+1);
                }
            }
            try {
                final CAInfo caInfo = caSession.getCAInfo(getAdmin(), key);
                if (value == null) {
                    removeTrustList.add(new InternalKeyBindingTrustEntry(Integer.valueOf(caInfo.getCAId()), null));
                } else {
                    try {
                        final BigInteger serialNumber = new BigInteger(value, 16);
                        removeTrustList.add(new InternalKeyBindingTrustEntry(Integer.valueOf(caInfo.getCAId()), serialNumber));
                    } catch (NumberFormatException e) {
                        getLogger().info(" Ignoring trustEntry with invalid certificate serial number: " + value);
                    }
                }
            } catch (CADoesntExistsException e) {
                getLogger().info(" Ignoring trustEntry with unknown CA: " + key);
            }
        }
        // Extract add trust entries
        final List<InternalKeyBindingTrustEntry> addTrustList = new ArrayList<InternalKeyBindingTrustEntry>();
        while (true) {
            final String trustArg = CliTools.getAndRemoveParameter("--addtrust", argsList);
            if (trustArg == null) {
                break;
            }
            String value;
            String key;
            int indexOfEqualsSign = trustArg.indexOf(';');
            if (indexOfEqualsSign == -1) {
                value = null;
                key = trustArg;
            } else {
                key = trustArg.substring(0, indexOfEqualsSign);
                if (trustArg.length()==indexOfEqualsSign) {
                    value = null;
                } else {
                    value = trustArg.substring(indexOfEqualsSign+1);
                }
            }
            try {
                final CAInfo caInfo = caSession.getCAInfo(getAdmin(), key);
                if (value == null) {
                    addTrustList.add(new InternalKeyBindingTrustEntry(Integer.valueOf(caInfo.getCAId()), null));
                } else {
                    try {
                        final BigInteger serialNumber = new BigInteger(value, 16);
                        addTrustList.add(new InternalKeyBindingTrustEntry(Integer.valueOf(caInfo.getCAId()), serialNumber));
                    } catch (NumberFormatException e) {
                        getLogger().info(" Ignoring trustEntry with invalid certificate serial number: " + value);
                    }
                }
            } catch (CADoesntExistsException e) {
                getLogger().info(" Ignoring trustEntry with unknown CA: " + key);
            }
        }
        // Extract nextKeyPair
        final String nextKeyPairAlias = CliTools.getAndRemoveParameter("--nextkeypair", argsList);
        args = CliTools.getAsArgs(argsList);
        boolean modified = false;
        // Perform nextKeyPair changes
        final InternalKeyBinding internalKeyBinding = internalKeyBindingMgmtSession.getInternalKeyBinding(getAdmin(), internalKeyBindingId.intValue());
        if (nextKeyPairAlias!=null) {
            if ("null".equals(nextKeyPairAlias)) {
                if (internalKeyBinding.getNextKeyPairAlias()==null) {
                    getLogger().info(" No nextKeyPairAlias mapping was currently set.");
                } else {
                    getLogger().info(" Removing nextKeyPairAlias mapping.");
                    internalKeyBinding.setNextKeyPairAlias(null);
                    modified = true;
                }
            } else {
                final List<String> availableKeyPairAliases = ejb.getRemoteSession(CryptoTokenManagementSessionRemote.class).getKeyPairAliases(getAdmin(), internalKeyBinding.getCryptoTokenId());
                if (internalKeyBinding.getKeyPairAlias().equals(nextKeyPairAlias)) {
                    getLogger().info(" Ignoring --nextkeypair with value " + nextKeyPairAlias + ". The value is already used as the current keyPairAlias.");
                } else if (!availableKeyPairAliases.contains(nextKeyPairAlias)) {
                    getLogger().info(" Ignoring --nextkeypair with value " + nextKeyPairAlias + ". The alias is not present in the bound CryptoToken." +
                            " Available aliases: " + availableKeyPairAliases.toString());
                } else {
                    getLogger().info(" Setting nextKeyPairAlias to \"" + nextKeyPairAlias + "\".");
                    internalKeyBinding.setNextKeyPairAlias(nextKeyPairAlias);
                    modified = true;
                }
            }
        }
        // Perform trust changes
        final List<InternalKeyBindingTrustEntry> internalKeyBindingTrustEntries = internalKeyBinding.getTrustedCertificateReferences();
        for (final InternalKeyBindingTrustEntry internalKeyBindingTrustEntry : removeTrustList) {
            if (!internalKeyBindingTrustEntries.remove(internalKeyBindingTrustEntry)) {
                getLogger().info(" Unable to remove non-existing trustEntry: " + internalKeyBindingTrustEntry.toString());
            } else {
                getLogger().info(" Removed trustEntry: " + internalKeyBindingTrustEntry.toString());
                modified = true;
            }
        }
        for (final InternalKeyBindingTrustEntry internalKeyBindingTrustEntry : addTrustList) {
            if (internalKeyBindingTrustEntries.contains(internalKeyBindingTrustEntry)) {
                getLogger().info(" Unable to add existing trustEntry: " + internalKeyBindingTrustEntry.toString());
            } else {
                internalKeyBindingTrustEntries.add(internalKeyBindingTrustEntry);
                getLogger().info(" Added trustEntry: " + internalKeyBindingTrustEntry.toString());
                modified = true;
            }
        }
        internalKeyBinding.setTrustedCertificateReferences(internalKeyBindingTrustEntries);
        // Perform property changes
        final List<InternalKeyBindingProperty<? extends Serializable>> properties = internalKeyBinding.getCopyOfProperties();
        for (final InternalKeyBindingProperty<? extends Serializable> property : properties) {
            final String name = property.getName();
            if (propertyMap.containsKey(name)) {
                final Class<? extends Serializable> clazz = property.getType();
                final String valueString = propertyMap.get(name);
                propertyMap.remove(name);
                final Serializable value;
                try {
                    if (clazz.equals(String.class)) {
                        value = valueString;
                    } else if (clazz.equals(Integer.class)) {
                        value = Integer.parseInt(valueString);
                    } else if (clazz.equals(Boolean.class)) {
                        // We cannot use Boolean.valueOf(String) if we want to detect bad input
                        if (Boolean.TRUE.toString().equalsIgnoreCase(valueString)) {
                            value = Boolean.TRUE;
                        } else if (Boolean.FALSE.toString().equalsIgnoreCase(valueString)) {
                            value = Boolean.FALSE;
                        } else {
                            value = null;
                        }
                    } else {
                        value = null;
                    }
                    if (value==null) {
                        getLogger().info(" Failed to set " + name + " since " + valueString + " is not of type " + clazz.getSimpleName());
                    } else if (property.isMultiValued() && !Arrays.asList(property.getPossibleValues()).contains(value)) {
                        getLogger().info(" Ignoring " + name + " since " + String.valueOf(value) + " is not one of " + Arrays.asList(property.getPossibleValues()).toString());
                    } else {
                        getLogger().info(" Setting " + name + " to " + String.valueOf(value) + "");
                        internalKeyBinding.setProperty(name, value);
                        modified = true;
                    }
                } catch (Exception e) {
                    getLogger().info(" Failed to set " + name + " since " + valueString + " is not of type " + clazz.getSimpleName());
                }
            }
        }
        if (!propertyMap.keySet().isEmpty()) {
            getLogger().info(" InternalKeyBinding of type " + internalKeyBinding.getImplementationAlias() + " does not support any of the following properties: "
                    + propertyMap.keySet().toString());
            
        }
        // Persist modifications
        if (modified) {
            internalKeyBindingMgmtSession.persistInternalKeyBinding(getAdmin(), internalKeyBinding);
            getLogger().info("InternalKeyBinding with id " + internalKeyBindingId.intValue() + " modified successfully.");
        } else {
            getLogger().info("No changes were made to InternalKeyBinding with id " + internalKeyBindingId.intValue() + ".");
        }
    }

}
