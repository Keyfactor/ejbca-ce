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
package org.ejbca.ui.cli.keybind;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.keybind.InternalKeyBinding;
import org.cesecore.keybind.InternalKeyBindingMgmtSessionRemote;
import org.cesecore.keybind.InternalKeyBindingTrustEntry;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.ui.DynamicUiProperty;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * See getDescription().
 * 
 * @version $Id$
 */
public class InternalKeyBindingModifyCommand extends RudInternalKeyBindingCommand {

    private static final Logger log = Logger.getLogger(InternalKeyBindingModifyCommand.class);

    private static final String NEXTKEYPAIR_KEY = "--nextkeypair";
    private static final String ADDTRUST_KEY = "--addtrust";
    private static final String REMOVETRUST_KEY = "--removetrust";

    private static final String TRUSTARGUMENT_SEPARATOR = ",";

    // TODO: Implement escape characters for the trusts. Both ',' and ';' are valid in CA names. 
    // TODO: Test adding and removing multiple trusts

    {
        registerParameter(new Parameter(NEXTKEYPAIR_KEY, "Alias", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                "Use of setting the name of the next key pair"));
        registerParameter(new Parameter(
                ADDTRUST_KEY,
                "TrustEntry",
                MandatoryMode.OPTIONAL,
                StandaloneMode.FORBID,
                ParameterMode.ARGUMENT,
                "Adds trust entries to the given keybinding. Trust entries can be of the form <CAName[;CertificateSerialNumber]> where the serialnumber is in hex and optional. "
                        + "Multiple trust entries can be added by separating them with a ',' i.e. <CA1[;CertificateSerialNumber],CA2[;CertificateSerialNumber]>"));
        registerParameter(new Parameter(
                REMOVETRUST_KEY,
                "TrustEntry",
                MandatoryMode.OPTIONAL,
                StandaloneMode.FORBID,
                ParameterMode.ARGUMENT,
                "Removes trust entries to the given keybinding. Trust entries can be of the form <CAName[;CertificateSerialNumber]> where the serialnumber is in hex and optional. "
                        + "Multiple trust entries can be added by separating them with a ',' i.e. <CA1[;CertificateSerialNumber],CA2[;CertificateSerialNumber]>"));
        //Register type specific properties dynamically
        Map<String, Map<String, DynamicUiProperty<? extends Serializable>>> typesAndProperties = EjbRemoteHelper.INSTANCE.getRemoteSession(
                InternalKeyBindingMgmtSessionRemote.class).getAvailableTypesAndProperties();
        for (Entry<String, Map<String, DynamicUiProperty<? extends Serializable>>> entry : typesAndProperties.entrySet()) {
            for (DynamicUiProperty<? extends Serializable> property : entry.getValue().values()) {
                if (isParameterRegistered("-"+property.getName())) {
                    //Different properties could contain the same keyword. Simply use the same one. 
                    continue;
                }
                Parameter parameter = new Parameter("-"+property.getName(), "", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.ARGUMENT, "");
                parameter.setAllowList(false);
                registerParameter(parameter);
            }
        }
    }

    @Override
    public String getMainCommand() {
        return "modify";
    }

    @Override
    public CommandResult executeCommand(Integer internalKeyBindingId, ParameterContainer parameters) throws AuthorizationDeniedException, Exception {
        final InternalKeyBindingMgmtSessionRemote internalKeyBindingMgmtSession = EjbRemoteHelper.INSTANCE
                .getRemoteSession(InternalKeyBindingMgmtSessionRemote.class);
        final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
        final InternalKeyBinding internalKeyBinding = internalKeyBindingMgmtSession
                .getInternalKeyBinding(getAdmin(), internalKeyBindingId.intValue());

        // Extract properties      
        final Map<String, String> propertyMap = new HashMap<String, String>();
        //Get dynamically loaded properties
        Map<String, Map<String, DynamicUiProperty<? extends Serializable>>> typesAndProperties = EjbRemoteHelper.INSTANCE.getRemoteSession(
                InternalKeyBindingMgmtSessionRemote.class).getAvailableTypesAndProperties();
        for (String propertyName : typesAndProperties.get(internalKeyBinding.getImplementationAlias()).keySet()) {
            if (parameters.containsKey("-"+propertyName)) {
                propertyMap.put(propertyName, parameters.get("-"+propertyName));
            }
        }
        // Extract remove trust entries
        final List<InternalKeyBindingTrustEntry> removeTrustList = new ArrayList<InternalKeyBindingTrustEntry>();
        final String removeTrustArguments = parameters.get(REMOVETRUST_KEY);
        if (removeTrustArguments != null) {
            for (String trustArgument : removeTrustArguments.split(TRUSTARGUMENT_SEPARATOR)) {
                String value;
                String key;
                int indexOfEqualsSign = trustArgument.indexOf(';');
                if (indexOfEqualsSign == -1) {
                    value = null;
                    key = trustArgument;
                } else {
                    key = trustArgument.substring(0, indexOfEqualsSign);
                    if (trustArgument.length() == indexOfEqualsSign) {
                        value = null;
                    } else {
                        value = trustArgument.substring(indexOfEqualsSign + 1);
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
        }
     // Extract add trust entries
        final List<InternalKeyBindingTrustEntry> addTrustList = new ArrayList<InternalKeyBindingTrustEntry>();
        final String addTrustArguments = parameters.get(ADDTRUST_KEY);
        if (addTrustArguments != null) {
            for (String trustArgument : addTrustArguments.split(TRUSTARGUMENT_SEPARATOR)) {
                String value;
                String key;
                int indexOfEqualsSign = trustArgument.indexOf(';');
                if (indexOfEqualsSign == -1) {
                    value = null;
                    key = trustArgument;
                } else {
                    key = trustArgument.substring(0, indexOfEqualsSign);
                    if (trustArgument.length() == indexOfEqualsSign) {
                        value = null;
                    } else {
                        value = trustArgument.substring(indexOfEqualsSign + 1);
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
        }
        // Extract nextKeyPair
        final String nextKeyPairAlias = parameters.get(NEXTKEYPAIR_KEY);
        boolean modified = false;
        // Perform nextKeyPair changes
        if (nextKeyPairAlias != null) {
            if ("null".equals(nextKeyPairAlias)) {
                if (internalKeyBinding.getNextKeyPairAlias() == null) {
                    getLogger().info(" No nextKeyPairAlias mapping was currently set.");
                } else {
                    getLogger().info(" Removing nextKeyPairAlias mapping.");
                    internalKeyBinding.setNextKeyPairAlias(null);
                    modified = true;
                }
            } else {
                final List<String> availableKeyPairAliases = EjbRemoteHelper.INSTANCE.getRemoteSession(CryptoTokenManagementSessionRemote.class)
                        .getKeyPairAliases(getAdmin(), internalKeyBinding.getCryptoTokenId());
                if (internalKeyBinding.getKeyPairAlias().equals(nextKeyPairAlias)) {
                    getLogger().info(
                            " Ignoring --nextkeypair with value " + nextKeyPairAlias + ". The value is already used as the current keyPairAlias.");
                } else if (!availableKeyPairAliases.contains(nextKeyPairAlias)) {
                    getLogger().info(
                            " Ignoring --nextkeypair with value " + nextKeyPairAlias + ". The alias is not present in the bound CryptoToken."
                                    + " Available aliases: " + availableKeyPairAliases.toString());
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
        Map<String, Serializable> validatedProperties = validateProperties(internalKeyBinding.getImplementationAlias(), propertyMap);
        if (validatedProperties == null) {
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        for (Entry<String, Serializable> entry : validatedProperties.entrySet()) {
            DynamicUiProperty<? extends Serializable> oldProperty = internalKeyBinding.getProperty(entry.getKey());
            if (!oldProperty.getValue().equals(entry.getValue())) {
                internalKeyBinding.setProperty(entry.getKey(), entry.getValue());
                getLogger().info(" Setting " + entry.getKey() + " to " + String.valueOf(entry.getValue()) + "");
                modified = true;
            }

        }
        // Persist modifications
        if (modified) {
            internalKeyBindingMgmtSession.persistInternalKeyBinding(getAdmin(), internalKeyBinding);
            getLogger().info("InternalKeyBinding with id " + internalKeyBindingId.intValue() + " modified successfully.");
            return CommandResult.SUCCESS;
        } else {
            getLogger().error("No changes were made to InternalKeyBinding with id " + internalKeyBindingId.intValue() + ".");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
    }

    @Override
    public String getCommandDescription() {
        return "Modify an existing InternalKeyBinding.";
    }

    @Override
    public String getFullHelpText() {
        StringBuilder sb = new StringBuilder();
        sb.append(getCommandDescription() + "\n\nOptional Type specific properties are listed below and are written as -propertyname=value, e.g. \"-nonexistingisgood=true\". \n");
        sb.append(showTypesProperties() + "\n");
        return sb.toString();
    }

    protected Logger getLogger() {
        return log;
    }
}
