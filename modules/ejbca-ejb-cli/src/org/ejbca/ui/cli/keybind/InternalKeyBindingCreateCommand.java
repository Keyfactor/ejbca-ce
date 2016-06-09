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
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Map.Entry;

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.keybind.InternalKeyBindingFactory;
import org.cesecore.keybind.InternalKeyBindingMgmtSessionRemote;
import org.cesecore.keybind.InternalKeyBindingNameInUseException;
import org.cesecore.keybind.InternalKeyBindingStatus;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.CryptoTokenOfflineException;
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
public class InternalKeyBindingCreateCommand extends BaseInternalKeyBindingCommand {

    private static final Logger log = Logger.getLogger(InternalKeyBindingCreateCommand.class);

    private static final String TYPE_KEY = "--type";
    private static final String STATUS_KEY = "--status";
    private static final String CERTIFICATE_FINGERPRINT_KEY = "--cert";
    private static final String CRYPTO_TOKEN_KEY = "--token";
    private static final String KEYPAIR_ALIAS_KEY = "--alias";
    private static final String SIGNATURE_ALGORITHM_KEY = "--sigalg";

    {
        registerParameter(new Parameter(TYPE_KEY, "Type Name", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Keybinding type."));
        registerParameter(new Parameter(STATUS_KEY, "Status", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Keybinding status."));
        registerParameter(new Parameter(CERTIFICATE_FINGERPRINT_KEY, "Certificate Fingerprint", MandatoryMode.MANDATORY, StandaloneMode.ALLOW,
                ParameterMode.ARGUMENT, "Fingerprint of a certificate from the bound keypair. Set as 'null' to set later."));
        registerParameter(new Parameter(CRYPTO_TOKEN_KEY, "Token Name", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Name of the crypto token where the mapped key pair is stored"));
        registerParameter(new Parameter(KEYPAIR_ALIAS_KEY, "Alias", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "alias of the mapped key pair in the specified CryptoToken."));
        registerParameter(new Parameter(SIGNATURE_ALGORITHM_KEY, "Algorithm", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The signature algorithm that this InternalKeyBinding will use for signatures."));
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
        return "create";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {
        final InternalKeyBindingMgmtSessionRemote internalKeyBindingMgmtSession = EjbRemoteHelper.INSTANCE
                .getRemoteSession(InternalKeyBindingMgmtSessionRemote.class);

        // Start by extracting any property
        final Map<String, String> dataMap = new LinkedHashMap<String, String>();

        // Parse static arguments
        final String name = parameters.get(KEYBINDING_NAME_KEY);
        final String type = parameters.get(TYPE_KEY);
        if (!InternalKeyBindingFactory.INSTANCE.existsTypeAlias(type)) {
            getLogger().error("KeyBinding of type " + type + " does not exist.");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        //Get dynamically loaded properties
        Map<String, Map<String, DynamicUiProperty<? extends Serializable>>> typesAndProperties = EjbRemoteHelper.INSTANCE.getRemoteSession(
                InternalKeyBindingMgmtSessionRemote.class).getAvailableTypesAndProperties();
        for (String propertyName : typesAndProperties.get(type).keySet()) {
            if (parameters.containsKey("-"+propertyName)) {
                dataMap.put(propertyName, parameters.get("-"+propertyName));
            }
        }
        //Validate all properties
        Map<String, Serializable> validatedProperties = validateProperties(type, dataMap);
        if (validatedProperties == null) {
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        final InternalKeyBindingStatus status = InternalKeyBindingStatus.valueOf(parameters.get(STATUS_KEY).toUpperCase());
        final String certificateId = "null".equalsIgnoreCase(parameters.get(CERTIFICATE_FINGERPRINT_KEY)) ? null : parameters
                .get(CERTIFICATE_FINGERPRINT_KEY);
        final Integer cryptoTokenId = EjbRemoteHelper.INSTANCE.getRemoteSession(CryptoTokenManagementSessionRemote.class).getIdFromName(
                parameters.get(CRYPTO_TOKEN_KEY));
        if(cryptoTokenId == null) {
            log.error("ERROR: CryptoToken  " + parameters.get(CRYPTO_TOKEN_KEY) + " was not found.");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        final String keyPairAlias = parameters.get(KEYPAIR_ALIAS_KEY);
        final String signatureAlgorithm = parameters.get(SIGNATURE_ALGORITHM_KEY);
        int internalKeyBindingIdNew;
        try {
            internalKeyBindingIdNew = internalKeyBindingMgmtSession.createInternalKeyBinding(getAuthenticationToken(), type, name, status,
                    certificateId, cryptoTokenId, keyPairAlias, signatureAlgorithm, validatedProperties, null);
        } catch (CryptoTokenOfflineException e) {
            log.error("ERROR: CryptoToken  " + parameters.get(CRYPTO_TOKEN_KEY) + " was offline.");
            return CommandResult.FUNCTIONAL_FAILURE;
        } catch (InternalKeyBindingNameInUseException e) {
            log.error("ERROR: Keybinding of name " + name + " already exists,");
            return CommandResult.FUNCTIONAL_FAILURE;
        } catch (InvalidAlgorithmException e) {
            log.error("ERROR: " + signatureAlgorithm + " was not a valid algorithm.");
            return CommandResult.FUNCTIONAL_FAILURE;
        } catch (AuthorizationDeniedException e) {
            return CommandResult.AUTHORIZATION_FAILURE;
        }
        getLogger().info("InternalKeyBinding with id " + internalKeyBindingIdNew + " created successfully.");
        return CommandResult.SUCCESS;
    }

    @Override
    public String getCommandDescription() {
        return "Creates a new InternalKeyBinding. ";
    }

    @Override
    public String getFullHelpText() {
        StringBuilder sb = new StringBuilder();
        sb.append(getCommandDescription() + "\n\nOptional Type specific properties are listed below and are written as -propertyname=value, e.g. \"-nonexistingisgood=true\". \n");
        sb.append(showTypesProperties() + "\n");
        sb.append(showStatuses() + "\n");
        sb.append(showSigAlgs() + "\n");
        return sb.toString();
    }

    protected Logger getLogger() {
        return log;
    }

}
