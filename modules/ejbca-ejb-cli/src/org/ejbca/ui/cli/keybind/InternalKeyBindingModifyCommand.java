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
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.stream.Collectors;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.keybind.InternalKeyBinding;
import org.cesecore.keybind.InternalKeyBindingMgmtSessionRemote;
import org.cesecore.keybind.InternalKeyBindingTrustEntry;
import org.cesecore.keybind.impl.OcspKeyBinding;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.SimpleTime;
import org.cesecore.util.ui.DynamicUiProperty;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;
import org.ejbca.util.cert.OID;

import com.keyfactor.util.StringTools;

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
    private static final String ADD_SIGN_ON_BEHALF_CA = "--addsignonbehalf";
    private static final String REMOVE_SIGN_ON_BEHALF_CA = "--removesignonbehalf";
    private static final String OCSP_EXTENSIONS = "--ocsp-extensions";
    private static final String ARCHIVE_CUTOFF = "--archive-cutoff";
    private static final String ETSI_ARCHIVE_CUTOFF = "--etsi-archive-cutoff";

    private static final String SEPARATOR = ",";

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
        registerParameter(new Parameter(
                ADD_SIGN_ON_BEHALF_CA,
                "SignOnBehalfEntry",
                MandatoryMode.OPTIONAL,
                StandaloneMode.FORBID,
                ParameterMode.ARGUMENT,
                "Adds CAs to a list for which OCSP responses will be signed by the given OCSP keybinding. Trust entries can be of the form <CAName>. "
                        + "Multiple entries can be added by separating them with a ',' i.e. <CA1,CA2>"));
        registerParameter(new Parameter(
                REMOVE_SIGN_ON_BEHALF_CA,
                "SignOnBehalfEntry",
                MandatoryMode.OPTIONAL,
                StandaloneMode.FORBID,
                ParameterMode.ARGUMENT,
                "Removes CAs from a list for which OCSP responses will be signed by the given OCSP keybinding.  Trust entries can be of the form <CAName>. "
                        + "Multiple entries can be added by separating them with a ',' i.e. <CA1,CA2>"));
        
        registerParameter(new Parameter(
                OCSP_EXTENSIONS,
                "OCSP Extensions",
                MandatoryMode.OPTIONAL,
                StandaloneMode.FORBID,
                ParameterMode.ARGUMENT,
                "Specifies a colon-separated list of OIDs, identifying the OCSP extensions to use for an OCSP key binding. Use empty list \"\" to clear all extensions."));
        registerParameter(new Parameter(ARCHIVE_CUTOFF, "Retention Period", MandatoryMode.OPTIONAL, StandaloneMode.FORBID,
                ParameterMode.ARGUMENT,
                "Enable OCSP archive cutoff (RFC 6960 section 4.4.4.) with the specified retention period. The retention period is a duration, e.g. '10y' (10 years) or '16mo' (16 months)."));
        registerParameter(new Parameter(ETSI_ARCHIVE_CUTOFF, "Enable ETSI Archive Cutoff", MandatoryMode.OPTIONAL, StandaloneMode.FORBID,
                ParameterMode.FLAG,
                "Enable OCSP archive cutoff (RFC 6960 section 4.4.4.), with the archive cutoff date set the to issuer's notBefore date, as mandated by ETSI EN 319 411-2, CSS-6.3.10-08."));
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
        final Collection<String> unboundOnBehalfCas = internalKeyBindingMgmtSession.getAllCaWithoutOcspKeyBinding().values();

        // Ensure archive cutoff with a retention period and ETSI archive cutoff is not being used at the same time
        if (parameters.get(ARCHIVE_CUTOFF) != null && parameters.get(ETSI_ARCHIVE_CUTOFF) != null) {
            getLogger().error(
                    "You cannot use OCSP archive cutoff with a retention period, and OCSP archive cutoff with an ETSI archive cutoff date at the same time.");
            return CommandResult.CLI_FAILURE;
        }
        // Extract properties      
        final Map<String, String> propertyMap = new HashMap<String, String>();
        //Get dynamically loaded properties
        Map<String, Map<String, DynamicUiProperty<? extends Serializable>>> typesAndProperties = EjbRemoteHelper.INSTANCE.getRemoteSession(
                InternalKeyBindingMgmtSessionRemote.class).getAvailableTypesAndProperties();
        for (String propertyName : typesAndProperties.get(internalKeyBinding.getImplementationAlias()).keySet()) {
            if (parameters.containsKey("-"+propertyName)) {
                // Special treatment for case sensitive ResponderID
                if (propertyName.equals("responderidtype")) {
                    final String responderIdType = parameters.get("-"+propertyName).toUpperCase();
                    if (!responderIdType.equals("NAME") && !responderIdType.equals("KEYHASH")) {
                        getLogger().info("Invalid responder id type. Must be either KEYHASH or NAME");
                        return CommandResult.FUNCTIONAL_FAILURE;
                    }
                    propertyMap.put(propertyName, responderIdType);
                } else {
                    propertyMap.put(propertyName, parameters.get("-"+propertyName));
                }

            }
        }
        List<InternalKeyBindingTrustEntry> removeSignOnBehalfList = new ArrayList<InternalKeyBindingTrustEntry>();
        List<InternalKeyBindingTrustEntry> addSignOnBehalfList = new ArrayList<InternalKeyBindingTrustEntry>();
        if(internalKeyBinding.getImplementationAlias().equals(OcspKeyBinding.IMPLEMENTATION_ALIAS)) {
            // Extract remove sign on behalf entries
            final String removeSignOnBehalfArguments = parameters.get(REMOVE_SIGN_ON_BEHALF_CA);
            if (removeSignOnBehalfArguments != null) {
                for (String signOnBehalfEntry : removeSignOnBehalfArguments.split(SEPARATOR)) {
                    final CAInfo caInfo = caSession.getCAInfo(getAdmin(), signOnBehalfEntry);
                    if (caInfo == null) {
                        getLogger().info(" Ignoring sign on behalf entry with unknown CA: " + signOnBehalfEntry);
                    } else {
                        removeSignOnBehalfList.add(new InternalKeyBindingTrustEntry(Integer.valueOf(caInfo.getCAId()), null));
                    }
                }
            }
            // Extract add sign on behalf entries
            final String addSignOnBehalftArguments = parameters.get(ADD_SIGN_ON_BEHALF_CA);
            if (addSignOnBehalftArguments != null) {
                for (String signOnBehalfEntry : addSignOnBehalftArguments.split(SEPARATOR)) {
                    if(!unboundOnBehalfCas.contains(signOnBehalfEntry)) {
                        getLogger().info(" Ignoring sign on behalf entry with already OCSP key bound CA: " + signOnBehalfEntry);
                        continue;
                    }
                    final CAInfo caInfo = caSession.getCAInfo(getAdmin(), signOnBehalfEntry);
                    if (caInfo == null) {
                        getLogger().info(" Ignoring sign on behalf entry with unknown CA: " + signOnBehalfEntry);
                    } else {
                        addSignOnBehalfList.add(new InternalKeyBindingTrustEntry(Integer.valueOf(caInfo.getCAId()), null));
                    }
                }
            }
        }
        // Extract remove trust entries
        final List<InternalKeyBindingTrustEntry> removeTrustList = new ArrayList<InternalKeyBindingTrustEntry>();
        final String removeTrustArguments = parameters.get(REMOVETRUST_KEY);
        if (removeTrustArguments != null) {
            for (String trustArgument : removeTrustArguments.split(SEPARATOR)) {
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
                final CAInfo caInfo = caSession.getCAInfo(getAdmin(), key);
                if (caInfo == null) {
                    getLogger().info(" Ignoring trustEntry with unknown CA: " + key);

                } else {
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
                }
            }
        }
        // Extract add trust entries
        final List<InternalKeyBindingTrustEntry> addTrustList = new ArrayList<InternalKeyBindingTrustEntry>();
        final String addTrustArguments = parameters.get(ADDTRUST_KEY);
        if (addTrustArguments != null) {
            for (String trustArgument : addTrustArguments.split(SEPARATOR)) {
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
                final CAInfo caInfo = caSession.getCAInfo(getAdmin(), key);
                if (caInfo == null) {
                    getLogger().info(" Ignoring trustEntry with unknown CA: " + key);

                } else {
                    if (value == null) {
                        addTrustList.add(new InternalKeyBindingTrustEntry(Integer.valueOf(caInfo.getCAId()), null));
                    } else {
                        try {
                            final BigInteger serialNumber = new BigInteger(StringTools.removeAllWhitespaceAndColon(value), 16);
                            addTrustList.add(new InternalKeyBindingTrustEntry(Integer.valueOf(caInfo.getCAId()), serialNumber));
                        } catch (NumberFormatException e) {
                            getLogger().info(" Ignoring trustEntry with invalid certificate serial number: " + value);
                        }
                    }
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
        // Perform sign on behalf changes
        List<InternalKeyBindingTrustEntry> internalKeyBindingTrustEntries = internalKeyBinding.getSignOcspResponseOnBehalf();
        for (final InternalKeyBindingTrustEntry internalKeyBindingTrustEntry : removeSignOnBehalfList) {
            if (!internalKeyBindingTrustEntries.remove(internalKeyBindingTrustEntry)) {
                getLogger().info(" Unable to remove non-existing sign on behalf entry: " + internalKeyBindingTrustEntry.toString());
            } else {
                getLogger().info(" Removed sign on behalf entry: " + internalKeyBindingTrustEntry.toString());
                modified = true;
            }
        }
        for (final InternalKeyBindingTrustEntry internalKeyBindingTrustEntry : addSignOnBehalfList) {
            if (internalKeyBindingTrustEntries.contains(internalKeyBindingTrustEntry)) {
                getLogger().info(" Unable to add existing sign on behalf entry: " + internalKeyBindingTrustEntry.toString());
            } else {
                internalKeyBindingTrustEntries.add(internalKeyBindingTrustEntry);
                getLogger().info(" Added sign on behalf entry: " + internalKeyBindingTrustEntry.toString());
                modified = true;
            }
        }
        internalKeyBinding.setSignOcspResponseOnBehalf(internalKeyBindingTrustEntries);
        
        // Perform trust changes
        internalKeyBindingTrustEntries = internalKeyBinding.getTrustedCertificateReferences();
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
        // Update OCSP extensions
        if (parameters.get(OCSP_EXTENSIONS) != null) {
            if (internalKeyBinding instanceof OcspKeyBinding) {
                final List<String> ocspExtensions = Arrays.asList(parameters.get(OCSP_EXTENSIONS).split(SEPARATOR))
                        .stream()
                        .map(ocspExtension -> ocspExtension.trim())
                        .filter(ocspExtension -> !StringUtils.isEmpty(ocspExtension))
                        .collect(Collectors.toList());
                for (final String ocspExtension : ocspExtensions) {
                    if (!OID.isValidOid(ocspExtension)) {
                        getLogger().error(ocspExtension + " is not a valid OID.");
                        return CommandResult.CLI_FAILURE;
                    }
                }
                internalKeyBinding.setOcspExtensions(ocspExtensions);
                modified = true;
            } else {
                getLogger().error("OCSP extensions can only be used with OCSP key bindings.");
                return CommandResult.CLI_FAILURE;
            }
        }
        // Set settings for archive cutoff
        if (parameters.get(ARCHIVE_CUTOFF) != null) {
            if (internalKeyBinding instanceof OcspKeyBinding) {
                final SimpleTime retentionPeriod = SimpleTime.getInstance(parameters.get(ARCHIVE_CUTOFF));
                if (retentionPeriod == null) {
                    getLogger().error(parameters.get(ARCHIVE_CUTOFF) + " is not a valid retention period.");
                    return CommandResult.CLI_FAILURE;
                }
                final OcspKeyBinding ocspKeyBinding = (OcspKeyBinding) internalKeyBinding;
                final List<String> ocspExtensions = ocspKeyBinding.getOcspExtensions();
                if (!ocspExtensions.contains(OCSPObjectIdentifiers.id_pkix_ocsp_archive_cutoff.getId())) {
                    ocspExtensions.add(OCSPObjectIdentifiers.id_pkix_ocsp_archive_cutoff.getId());
                    ocspKeyBinding.setOcspExtensions(ocspExtensions);
                }
                ocspKeyBinding.setRetentionPeriod(retentionPeriod);
                ocspKeyBinding.setUseIssuerNotBeforeAsArchiveCutoff(false);
                modified = true;
            } else {
                getLogger().error("Archive Cutoff can only be used with OCSP key bindings.");
                return CommandResult.CLI_FAILURE;
            }
        }
        if (parameters.get(ETSI_ARCHIVE_CUTOFF) != null) {
            if (internalKeyBinding instanceof OcspKeyBinding) {
                final OcspKeyBinding ocspKeyBinding = (OcspKeyBinding) internalKeyBinding;
                final List<String> ocspExtensions = ocspKeyBinding.getOcspExtensions();
                if (!ocspExtensions.contains(OCSPObjectIdentifiers.id_pkix_ocsp_archive_cutoff.getId())) {
                    ocspExtensions.add(OCSPObjectIdentifiers.id_pkix_ocsp_archive_cutoff.getId());
                    ocspKeyBinding.setOcspExtensions(ocspExtensions);
                }
                ocspKeyBinding.setUseIssuerNotBeforeAsArchiveCutoff(true);
                modified = true;
            } else {
                getLogger().error("Archive Cutoff can only be used with OCSP key bindings.");
                return CommandResult.CLI_FAILURE;
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

    @Override
    protected Logger getLogger() {
        return log;
    }
}
