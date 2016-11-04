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
package org.ejbca.ui.cli.ca;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.keys.token.CryptoTokenInfo;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * CLI command to change crypto token and CA token properties of a CA.
 * 
 * @version $Id$
 */
public class CaChangeCryptoTokenCommand extends BaseCaAdminCommand {

    private static final Logger log = Logger.getLogger(CaChangeCryptoTokenCommand.class);
    private static final String CA_NAME_KEY = "--caname";
    private static final String CRYPTOTOKEN_NAME_KEY = "--cryptotoken";
    private static final String EXECUTE_KEY = "--execute";
    private static final String CA_TOKEN_PROPERTIES_KEY = "--tokenprop";


    {
        registerParameter(new Parameter(CA_NAME_KEY, "CA Name", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT, "The name of the CA."));
        registerParameter(new Parameter(CRYPTOTOKEN_NAME_KEY, "Crypto token name", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT, "The name of the new crypto token the CA should reference."));
        registerParameter(new Parameter(CA_TOKEN_PROPERTIES_KEY, "Filename", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                "CA Token properties is a file were you define key aliases for the CA, leave out to keep existing properties."));
        registerParameter(Parameter.createFlag(EXECUTE_KEY, "Make the change instead of displaying what would change."));
    }

    /*
     * <pre>
certSignKey fooalias02
crlSignKey fooalias02
keyEncryptKey fooencalias
hardTokenEncrypt fooencalias
defaultKey defaultalias
testKey testalias
previousCertSignKey fooalias01
nextCertSignKey fooalias03
     * </pre>
     */

    @Override
    public String getMainCommand() {
        return "changecatoken";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {
        log.trace(">execute()");
        CryptoProviderTools.installBCProvider(); // need this for CVC certificate
        final String caName = parameters.get(CA_NAME_KEY);
        final String cryptoTokenName = parameters.get(CRYPTOTOKEN_NAME_KEY);
        final boolean force = parameters.containsKey(EXECUTE_KEY);
        Properties caTokenProperties = new Properties();
        String caTokenPropertiesFile = parameters.get(CA_TOKEN_PROPERTIES_KEY);
        if (caTokenPropertiesFile != null) {
            if ((caTokenPropertiesFile != null) && (!caTokenPropertiesFile.equalsIgnoreCase("null"))) {
                File file = new File(caTokenPropertiesFile);
                if (!file.exists()) {
                    getLogger().error("CA Token properties file " + caTokenPropertiesFile + " does not exist.");
                    return CommandResult.FUNCTIONAL_FAILURE;
                } else if (file.isDirectory()) {
                    getLogger().error("CA Token properties file " + caTokenPropertiesFile + " is a directory.");
                    return CommandResult.FUNCTIONAL_FAILURE;
                } else {
                    try (final FileInputStream fis = new FileInputStream(caTokenPropertiesFile)) {
                        caTokenProperties.load(fis);
                    } catch (FileNotFoundException e) {
                        //Can't happen
                        throw new IllegalStateException("Newly referenced file " + caTokenPropertiesFile + " was not found.", e);
                    } catch (IOException e) {
                        throw new IllegalStateException("Unknown exception was caught when reading input stream", e);
                    }
                }
            }
        }

        try {
            final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
            final CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CryptoTokenManagementSessionRemote.class);
            final CAInfo caInfo = caSession.getCAInfo(getAuthenticationToken(), caName);
            final int cryptoTokenId = caInfo.getCAToken().getCryptoTokenId();
            final CryptoTokenInfo cryptoTokenInfo = cryptoTokenManagementSession.getCryptoTokenInfo(getAuthenticationToken(), cryptoTokenId);

            getLogger().info("CA '" + caInfo.getName() + "' references crypto token '" + cryptoTokenInfo.getName() + "'");
            getLogger().info("New crypto token: " + cryptoTokenName);
            getLogger().info("CA token properties: " + caTokenPropertiesFile);
            getLogger().info("");

            
            Integer newId = cryptoTokenManagementSession.getIdFromName(cryptoTokenName);
            if (newId == null) {
                throw new IllegalArgumentException("Crypto Token with name " + cryptoTokenName + " does not exist.");
            }
            if (newId == cryptoTokenId) {
                getLogger().info("Current crypto token and new crypto token are the same, continuing in order to update CA token properties.");
            }
            final CryptoTokenInfo newCryptoTokenInfo = cryptoTokenManagementSession.getCryptoTokenInfo(getAuthenticationToken(), newId);

            getLogger().info((force?"Changing ":"Would change" )+" CA '" + caInfo.getName() + "' that currently references crypto token '" + cryptoTokenInfo.getName() + "' to instead reference '" + newCryptoTokenInfo.getName() + "'.");
            getLogger().info(" CA token properties that will be updated: " + caTokenProperties);

            
            if (force) {
                final CAToken currentCaToken = caInfo.getCAToken();
                currentCaToken.setCryptoTokenId(newId);
                // Set the key options in the CA token properties
                if (caTokenProperties.get(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING) != null) {
                    currentCaToken.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, (String)caTokenProperties.get(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING));                    
                }
                if (caTokenProperties.get(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING) != null) {
                    currentCaToken.setProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, (String)caTokenProperties.get(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING));                    
                }
                if (caTokenProperties.get(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT_STRING) != null) {
                    currentCaToken.setProperty(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT_STRING, (String)caTokenProperties.get(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT_STRING));                    
                }
                if (caTokenProperties.get(CATokenConstants.CAKEYPURPOSE_TESTKEY_STRING) != null) {
                    currentCaToken.setProperty(CATokenConstants.CAKEYPURPOSE_TESTKEY_STRING, (String)caTokenProperties.get(CATokenConstants.CAKEYPURPOSE_TESTKEY_STRING));                    
                }
                if (caTokenProperties.get(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING) != null) {
                    currentCaToken.setProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, (String)caTokenProperties.get(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING));                    
                }
                if (caTokenProperties.get(CATokenConstants.CAKEYPURPOSE_HARDTOKENENCRYPT_STRING) != null) {
                    currentCaToken.setProperty(CATokenConstants.CAKEYPURPOSE_HARDTOKENENCRYPT_STRING, (String)caTokenProperties.get(CATokenConstants.CAKEYPURPOSE_HARDTOKENENCRYPT_STRING));                    
                }
                if (caTokenProperties.get(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING_PREVIOUS) != null) {
                    currentCaToken.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING_PREVIOUS, (String)caTokenProperties.get(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING_PREVIOUS));                    
                }
                if (caTokenProperties.get(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING_NEXT) != null) {
                    currentCaToken.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING_NEXT, (String)caTokenProperties.get(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING_NEXT));                    
                }
                caInfo.setCAToken(currentCaToken);
                caSession.editCA(getAuthenticationToken(), caInfo);
                getLogger().info(" Merged.");
            }
            getLogger().info("");

            if (force) {
                getLogger().info("Modified referenced Crypto Token for CA.");
                final CAInfo caInfoNew = caSession.getCAInfo(getAuthenticationToken(), caName);
                final CAToken newCaToken = caInfoNew.getCAToken();
                final CryptoTokenInfo ctInfo = cryptoTokenManagementSession.getCryptoTokenInfo(getAuthenticationToken(), newCaToken.getCryptoTokenId());

                getLogger().info("CA '" + caInfoNew.getName() + "' now references crypto token '" + ctInfo.getName() + "'");
                getLogger().info("New CA token properties: " + caTokenProperties.toString());
                getLogger().info("");
            } else {
                getLogger().info("Will modify referenced Crypto Token for CA if '" + EXECUTE_KEY + "' option is used.");
            }
            log.trace("<execute()");          
        } catch (AuthorizationDeniedException e) {
            getLogger().error("CLI User was not authorized to modify CA " + caName);
            log.trace("<execute()");
            return CommandResult.AUTHORIZATION_FAILURE;
        } catch (CADoesntExistsException e) {
            getLogger().error("No such CA with by name " + caName);
            getLogger().error(getCaList());
            return CommandResult.FUNCTIONAL_FAILURE;
        } 
        log.trace("<execute()");
        return CommandResult.SUCCESS;
    }

    @Override
    public String getCommandDescription() {
        return "Change Crypto Token and keys for a CA.";
    }

    @Override
    public String getFullHelpText() {
        return getCommandDescription()
                + "\n\n"
                + "The specified CA's Crypto Token will be changed to one passed as parameter, and CA token properties (key labels) updated from the properties file.\n\n"
                + "The default behavior is to only show what would have changed since this command is potentially very dangerous.\n"
                + "Use the " + EXECUTE_KEY + " switch to execute modifications."
                + "\n\n" + getCaList();
    }

    @Override
    protected Logger getLogger() {
        return log;
    }
}
