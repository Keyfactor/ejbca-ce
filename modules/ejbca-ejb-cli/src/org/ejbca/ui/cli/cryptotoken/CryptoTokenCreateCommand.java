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
import org.apache.commons.lang.math.NumberUtils;
import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.keys.token.AzureCryptoToken;
import org.cesecore.keys.token.CryptoTokenConstants;
import org.cesecore.keys.token.CryptoTokenFactory;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.CryptoTokenNameInUseException;
import org.cesecore.keys.token.PKCS11CryptoToken;
import org.cesecore.keys.token.SoftCryptoToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.command.EjbcaCliUserCommandBase;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

import com.keyfactor.util.StringTools;
import com.keyfactor.util.keys.token.BaseCryptoToken;
import com.keyfactor.util.keys.token.CryptoToken;
import com.keyfactor.util.keys.token.CryptoTokenAuthenticationFailedException;
import com.keyfactor.util.keys.token.CryptoTokenOfflineException;
import com.keyfactor.util.keys.token.pkcs11.NoSuchSlotException;
import com.keyfactor.util.keys.token.pkcs11.Pkcs11SlotLabelType;

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
    private static final String AWSKMS_ACCESSKEYID= "--awskmsaccesskeyid";
    private static final String AWSKMS_REGION= "--awskmsregion";
    private static final String AZUREVAULT_TYPE= "--azurevaulttype";
    private static final String AZUREVAULT_USE_KEY_BINDING = "--azurevaultusekeybinding";
    private static final String AZUREVAULT_KEY_BINDING = "--azurevaultkeybinding";
    private static final String AZUREVAULT_NAME= "--azurevaultname";
    private static final String AZUREVAULT_CLIENTID= "--azurevaultclientid";
    private static final String FORTANIX_BASE_ADDRESS = "--fortanixaddr";


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
                + getAvailableTokenTypes()));
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
        registerParameter(new Parameter(AWSKMS_ACCESSKEYID, "Access Key ID", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                "(AWSKMSCryptoToken) Access Key ID for AWS KMS, example AKIA2I6NL4C3YGQJ6YY3"));
        registerParameter(new Parameter(AWSKMS_REGION, "Region", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                "(AWSKMSCryptoToken) AWS KMS region, example us-east-1."));
        registerParameter(new Parameter(AZUREVAULT_NAME, "Name", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                "(AzureCryptoToken)  Key Vault name as chosen when creating the Azure Key Vault, example ejbca-keyvault."));
        registerParameter(new Parameter(AZUREVAULT_TYPE, "Type", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                "(AzureCryptoToken) Key Vault type, Premium or Standard."));
        registerParameter(new Parameter(AZUREVAULT_CLIENTID, "Client ID", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                "(AzureCryptoToken) Key Vault Client ID as noted when creating the App Registration, example 2f6bd1d7-81ee-52cf-b0a4-8dd570196701."));
        registerParameter(new Parameter(AZUREVAULT_USE_KEY_BINDING, "Use Key Binding", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.FLAG,
                "(AzureCryptoToken) Whether or not to use an Internal Key Binding when authenticating to Azure."));
        registerParameter(new Parameter(AZUREVAULT_KEY_BINDING, "Key Binding", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                "(AzureCryptoToken) Internal Key Binding to use when authenticating to Azure."));
        registerParameter(new Parameter(FORTANIX_BASE_ADDRESS, "Base Fortanix Address", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                "(Fortanix) Base address of Fortanix DSM API."));

        // ePassport CSCA only
        registerParameter(new Parameter(USE_EXPLICIT_KEY_PARAMETERS, "true|false", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Set to true|false to allow|disallow usage of explicit ECC parameters( Only for ICAO CSCA and DS certificates)."));
    }
    
    @Override
    public String[] getCommandPath() {
        return new String[] { "cryptotoken" };
    }

    /** Returns a string with a list of the available Crypto Token types, which is shown in the help text. */
    private String getAvailableTokenTypes() {
        final StringBuilder sb = new StringBuilder();
        sb.append(SoftCryptoToken.class.getSimpleName());
        sb.append(", ");
        sb.append(PKCS11CryptoToken.class.getSimpleName());
        sb.append(", ");
        sb.append(AzureCryptoToken.class.getSimpleName());
        try {
            final Class<?> jackJni11Class = Class.forName(CryptoTokenFactory.JACKNJI_NAME);
            sb.append(", ");
            sb.append(jackJni11Class.getSimpleName());
        } catch (ClassNotFoundException e) { /* Ignored */ }
        try {
            final Class<?> awsKmsClass = Class.forName(CryptoTokenFactory.AWSKMS_NAME);
            sb.append(", ");
            sb.append(awsKmsClass.getSimpleName());
        } catch (ClassNotFoundException e) { /* Ignored */ }
        try {
            final Class<?> fortanixClass = Class.forName(CryptoTokenFactory.FORTANIX_NAME);
            sb.append(", ");
            sb.append(fortanixClass.getSimpleName());
        } catch (ClassNotFoundException e) { /* Ignored */ }
        return sb.toString();
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
        } else if (CryptoTokenFactory.AWSKMS_SIMPLE_NAME.equals(type)) {
            className = CryptoTokenFactory.AWSKMS_NAME;
            if (parameters.get(AWSKMS_REGION) == null || parameters.get(AWSKMS_ACCESSKEYID) == null) {
                getLogger().info("You need to specify all parameters for AWS KMS Vault.");
                return CommandResult.CLI_FAILURE;                
            }
            cryptoTokenPropertes.setProperty(CryptoTokenConstants.AWSKMS_REGION, parameters.get(AWSKMS_REGION));
            cryptoTokenPropertes.setProperty(CryptoTokenConstants.AWSKMS_ACCESSKEYID, parameters.get(AWSKMS_ACCESSKEYID));
        } else if (CryptoTokenFactory.FORTANIX_SIMPLE_NAME.equals(type)) {
            className = CryptoTokenFactory.FORTANIX_NAME;
            String baseAddress = parameters.get(FORTANIX_BASE_ADDRESS);
            if (baseAddress == null)
                baseAddress = CryptoTokenConstants.FORTANIX_BASE_ADDRESS_DEFAULT;
            cryptoTokenPropertes.setProperty(CryptoTokenConstants.FORTANIX_BASE_ADDRESS, baseAddress);
        } else if (AzureCryptoToken.class.getSimpleName().equals(type)) {
            className = AzureCryptoToken.class.getName();
            // For an Azure token all three parameters are needed
            if (parameters.get(AZUREVAULT_NAME) == null || parameters.get(AZUREVAULT_TYPE) == null || parameters.get(AZUREVAULT_CLIENTID) == null) {
                getLogger().info("You need to specify all parameters for Azure Key Vault.");
                return CommandResult.CLI_FAILURE;                
            }
            cryptoTokenPropertes.setProperty(AzureCryptoToken.KEY_VAULT_NAME, parameters.get(AZUREVAULT_NAME));
            cryptoTokenPropertes.setProperty(AzureCryptoToken.KEY_VAULT_TYPE, parameters.get(AZUREVAULT_TYPE));
            cryptoTokenPropertes.setProperty(AzureCryptoToken.KEY_VAULT_CLIENTID, parameters.get(AZUREVAULT_CLIENTID));
            cryptoTokenPropertes.setProperty(AzureCryptoToken.KEY_VAULT_USE_KEY_BINDING, parameters.get(AZUREVAULT_USE_KEY_BINDING));
            cryptoTokenPropertes.setProperty(AzureCryptoToken.KEY_VAULT_KEY_BINDING, parameters.get(AZUREVAULT_KEY_BINDING));
        } else if (PKCS11CryptoToken.class.getSimpleName().equals(type) || CryptoTokenFactory.JACKNJI_SIMPLE_NAME.equals(type)) {
            if (PKCS11CryptoToken.class.getSimpleName().equals(type)) {
                className = PKCS11CryptoToken.class.getName();
            } else {
                className = CryptoTokenFactory.JACKNJI_NAME;
            }
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
                List<String> usedBy = cryptoTokenManagementSession.isCryptoTokenSlotUsed(getAuthenticationToken(), cryptoTokenName, className, cryptoTokenPropertes);
                if (!usedBy.isEmpty() && !ignoreslotwarning) {
                    for (String usedByName : usedBy) {
                        String name = usedByName;
                        if (NumberUtils.isNumber(name)) {
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
