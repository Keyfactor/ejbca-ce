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
package org.ejbca.ui.cli.cryptotoken;

import java.io.File;
import java.util.List;
import java.util.Properties;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.keys.token.BaseCryptoToken;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenInfo;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.CryptoTokenNameInUseException;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.PKCS11CryptoToken;
import org.cesecore.keys.token.SoftCryptoToken;
import org.cesecore.keys.token.p11.Pkcs11SlotLabelType;
import org.cesecore.keys.token.p11.exception.NoSuchSlotException;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.StringTools;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.command.EjbcaCliUserCommandBase;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * CryptoToken EJB CLI command. See {@link #getDescription()} implementation.
 * 
 * @version $Id$
 */
public class CryptoTokenCreateCommand extends EjbcaCliUserCommandBase {

    private static final Logger log = Logger.getLogger(CryptoTokenCreateCommand.class);

    private static final String CRYPTOTOKEN_NAME_KEY = "--token";
    private static final String PIN_KEY = "--pin";
    private static final String AUTOACTIVATE_KEY = "--autoactivate";
    private static final String TYPE_KEY = "--type";
    private static final String PRIVATE_KEY_EXPORT_KEY = "--exportkey";
    private static final String USE_EXPLICIT_KEY_PARAMETERS = "--explicitkeyparams";
    private static final String PKCS11_LIB_KEY = "--lib";
    private static final String SLOT_REFERENCE_TYPE_KEY = "--slotlabeltype";
    private static final String SLOT_REFERENCE_KEY = "--slotlabel";
    private static final String PKCS11_ATTR_FILE_KEY = "--attr";
    private static final String PKCS11_SLOTCOLLIDE_IGNORE= "--forceusedslots";

    {
        registerParameter(new Parameter(CRYPTOTOKEN_NAME_KEY, "Token Name", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The name of the crypto token."));
        //Kept as a mandatory parameter for legacy reasons.
        registerParameter(new Parameter(PIN_KEY, "Pin", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Pin code for the crypto token. Set to 'null' to prompt."));
        // TODO: Make this a flag when legacy support isn't necessary
        registerParameter(new Parameter(AUTOACTIVATE_KEY, "true|false", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Set to true|false to allow|disallow whether crypto token should be autoactivated or not."));
        registerParameter(new Parameter(TYPE_KEY, "Type", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT, "Available types: "
                + SoftCryptoToken.class.getSimpleName() + ", " + PKCS11CryptoToken.class.getSimpleName()));
        //Soft params
        registerParameter(new Parameter(PRIVATE_KEY_EXPORT_KEY, "true|false", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "(" + SoftCryptoToken.class.getSimpleName() + ") Set to true|false to allow|disallow private key export."));
        //PKCS#11
        registerParameter(new Parameter(PKCS11_LIB_KEY, "Library Name", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT, "("
                + PKCS11CryptoToken.class.getSimpleName() + ") PKCS#11 library file. Required if type is " + PKCS11CryptoToken.class.getSimpleName()));
        registerParameter(new Parameter(SLOT_REFERENCE_TYPE_KEY, "Slot Reference Type", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW,
                ParameterMode.ARGUMENT, "(" + PKCS11CryptoToken.class.getSimpleName() + ") Slot Reference Type."));
        registerParameter(new Parameter(SLOT_REFERENCE_KEY, "Slot Reference", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "(" + PKCS11CryptoToken.class.getSimpleName() + ") Slot reference."));
        registerParameter(new Parameter(PKCS11_ATTR_FILE_KEY, "Attribute File", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "(" + PKCS11CryptoToken.class.getSimpleName() + ") PKCS#11 Attribute File"));
        registerParameter(new Parameter(PKCS11_SLOTCOLLIDE_IGNORE, "Ignore used P11 slots", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.FLAG, "Ignore warnings, and confirm yes, for P11 slots that are already used."));
        // ePassport CSCA only
        registerParameter(new Parameter(USE_EXPLICIT_KEY_PARAMETERS, "true|false", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Set to true|false to allow|disallow usage of explicit ECC parameters( Only for ICAO CSCA and DS certificates)."));
    }
    
    @Override
    public String[] getCommandPath() {
        return new String[] { "cryptotoken" };
    }

    @Override
    public String getMainCommand() {
        return "create";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {

        final String cryptoTokenName = parameters.get(CRYPTOTOKEN_NAME_KEY);
        final boolean autoActivate = Boolean.valueOf(parameters.get(AUTOACTIVATE_KEY));
        final boolean ignoreslotwarning = (parameters.get(PKCS11_SLOTCOLLIDE_IGNORE) != null);
        final String type = parameters.get(TYPE_KEY);
        final String className;
        final Properties cryptoTokenPropertes = new Properties();
        final CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE
                .getRemoteSession(CryptoTokenManagementSessionRemote.class);
        if (SoftCryptoToken.class.getSimpleName().equals(type)) {
            className = SoftCryptoToken.class.getName();
            cryptoTokenPropertes.setProperty(CryptoToken.ALLOW_EXTRACTABLE_PRIVATE_KEY,
                    Boolean.toString(Boolean.valueOf(parameters.get(PRIVATE_KEY_EXPORT_KEY))));
            cryptoTokenPropertes.setProperty(SoftCryptoToken.NODEFAULTPWD, Boolean.TRUE.toString());
        } else if (PKCS11CryptoToken.class.getSimpleName().equals(type)) {
            className = PKCS11CryptoToken.class.getName();
            // Parse library file
            String pkcs11LibFilename = parameters.get(PKCS11_LIB_KEY);
            if(null == pkcs11LibFilename) {
                getLogger().info("You need to specify a PKCS#11 library file.");
                return CommandResult.CLI_FAILURE;
            }
            if (!new File(pkcs11LibFilename).exists()) {
                getLogger().info("PKCS#11 library file " + pkcs11LibFilename + " does not exist!");
                return CommandResult.CLI_FAILURE;
            }
            cryptoTokenPropertes.setProperty(PKCS11CryptoToken.SHLIB_LABEL_KEY, pkcs11LibFilename);         
            String slotPropertyValue = parameters.get(SLOT_REFERENCE_KEY);
            if(slotPropertyValue == null) {
                getLogger().info("Slot reference key (" + SLOT_REFERENCE_KEY + ") needs to be defined for PKCS#11 tokens.");
                return CommandResult.CLI_FAILURE;
            }
            
            if (!parameters.containsKey(SLOT_REFERENCE_TYPE_KEY)) {
                getLogger().info("Slot reference type (" + SLOT_REFERENCE_TYPE_KEY + ") needs to be defined for PKCS#11 tokens.");
                return CommandResult.CLI_FAILURE;
            }
            Pkcs11SlotLabelType labelType = Pkcs11SlotLabelType.getFromKey(parameters.get(SLOT_REFERENCE_TYPE_KEY));
            if(labelType == null) {
                getLogger().info(parameters.get(SLOT_REFERENCE_TYPE_KEY) + " was not a valid slot reference type.");
                return CommandResult.CLI_FAILURE;
            }
            cryptoTokenPropertes.setProperty(PKCS11CryptoToken.SLOT_LABEL_VALUE, slotPropertyValue);
            //If an index was given, accept just numbers as well
            if (labelType.isEqual(Pkcs11SlotLabelType.SLOT_INDEX)) {
                if (slotPropertyValue.charAt(0) != 'i') {
                    slotPropertyValue = "i" + slotPropertyValue;
                }
            }
            if (!labelType.validate(slotPropertyValue)) {
                getLogger().info("Invalid value " + slotPropertyValue + " given for slot type " + labelType.getDescription());
                return CommandResult.CLI_FAILURE;
            } else {
                cryptoTokenPropertes.setProperty(PKCS11CryptoToken.SLOT_LABEL_TYPE, labelType.getKey());
            }
            // Parse attribute file
            String attributeFileName = parameters.get(PKCS11_ATTR_FILE_KEY);
            if ( (attributeFileName != null) && (!"null".equalsIgnoreCase(attributeFileName)) ) {
                if (!new File(attributeFileName).exists()) {
                    getLogger().info("PKCS#11 attribute file " + attributeFileName + " does not exist!");
                    return CommandResult.CLI_FAILURE;
                }
                cryptoTokenPropertes.setProperty(PKCS11CryptoToken.ATTRIB_LABEL_KEY, attributeFileName);
            }

            // Check if this crypto token is already used
            try {
                List<CryptoTokenInfo> usedBy = cryptoTokenManagementSession.isCryptoTokenSlotUsed(getAuthenticationToken(), cryptoTokenName, className, cryptoTokenPropertes);
                if (!usedBy.isEmpty() && !ignoreslotwarning) {
                    for (CryptoTokenInfo cryptoTokenInfo : usedBy) {
                        String name = cryptoTokenInfo.getName();
                        if (StringUtils.isNumeric(name)) {
                            // if the crypto token name is purely numeric, it is likely to be a database protection token
                            name = name + " (database protection?)";
                        }
                        getLogger().info("The P11 slot is already used by another crypto token: "+name);
                    }
                    getLogger().info("Do you want to continue anyhow? [yes/no]: ");
                    String yes = System.console().readLine();
                    if (!StringUtils.equalsIgnoreCase("yes", yes)) {
                        getLogger().info("Exiting...");
                        return CommandResult.CLI_FAILURE;                    
                    }
                }
            } catch (CryptoTokenNameInUseException | CryptoTokenOfflineException | CryptoTokenAuthenticationFailedException
                    | AuthorizationDeniedException | NoSuchSlotException e) {
                getLogger().info("There is an error creating the Crypto Token: "+e.getMessage());
                getLogger().info("Do you want to continue anyhow? [yes/no]: ");
                String yes = System.console().readLine();
                if (!StringUtils.equalsIgnoreCase("yes", yes)) {
                    getLogger().info("Exiting...");
                    return CommandResult.CLI_FAILURE;                    
                }
            }

        } else {
            getLogger().info("Invalid CryptoToken type: " + type);
            return CommandResult.CLI_FAILURE;
        }
        String useExplicitKeyParameter = parameters.get(USE_EXPLICIT_KEY_PARAMETERS);
        if (useExplicitKeyParameter != null) {
            cryptoTokenPropertes.setProperty(CryptoToken.EXPLICIT_ECC_PUBLICKEY_PARAMETERS,
                    Boolean.toString(Boolean.valueOf(useExplicitKeyParameter)));
        }
        final char[] authenticationCode = getAuthenticationCode(parameters.get(PIN_KEY));
        if (autoActivate) {
            BaseCryptoToken.setAutoActivatePin(cryptoTokenPropertes, new String(authenticationCode), true);
        }
        try {
            final Integer cryptoTokenIdNew = cryptoTokenManagementSession.createCryptoToken(getAuthenticationToken(), cryptoTokenName, className,
                    cryptoTokenPropertes, null, authenticationCode);
            getLogger().info("CryptoToken with id " + cryptoTokenIdNew + " created successfully.");
            return CommandResult.SUCCESS;
        } catch (AuthorizationDeniedException e) {
            getLogger().info(e.getMessage());
            return CommandResult.AUTHORIZATION_FAILURE;
        } catch (CryptoTokenOfflineException e) {
            getLogger().info("CryptoToken is not active. You need to activate the CryptoToken before you can interact with its content.");
        } catch (Exception e) {
            getLogger().info("Operation failed: " + e.getMessage());
        }
        return CommandResult.FUNCTIONAL_FAILURE;
    }

    @Override
    public String getCommandDescription() {
        return "Create a new CryptoToken";
    }

    @Override
    public String getFullHelpText() {
        StringBuilder sb = new StringBuilder();
        sb.append(getCommandDescription() + "\n\n");
        sb.append("Slot Reference Types:\n");
        for (Pkcs11SlotLabelType type : Pkcs11SlotLabelType.values()) {
            sb.append("    " + type.getKey() + " - " + type.getDescription() + "\n");
        }
        return sb.toString();
    }

    @Override
    protected Logger getLogger() {
        return log;
    }
    
    /** @return a decrypted version of the parameter or use input if the parameter equals "null" */
    private char[] getAuthenticationCode(final String commandLineArgument) {
        final char[] authenticationCode;
        if (commandLineArgument == null || "null".equalsIgnoreCase(commandLineArgument)) {
            getLogger().info("Enter CryptoToken password: ");
            getLogger().info("");
            authenticationCode = StringTools.passwordDecryption(String.valueOf(System.console().readPassword()), "CryptoToken pin").toCharArray();
        } else {
            authenticationCode = StringTools.passwordDecryption(commandLineArgument, "CryptoToken pin").toCharArray();

        }
        return authenticationCode;
    }


}
