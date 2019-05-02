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

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Enumeration;

import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.FileTools;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * Imports a keystore and creates a new X509 CA from it
 *
 * @version $Id$
 */
public class CaImportCACommand extends BaseCaAdminCommand {

    private static final Logger log = Logger.getLogger(CaImportCACommand.class);

    private static final String CA_NAME_KEY = "--caname";
    //P12
    private static final String P12_FILE_KEY = "--p12";
    public static final String KEYSTORE_PASSWORD_KEY = "-kspassword";
    private static final String SIGNATURE_ALIAS_KEY = "--signalias";
    private static final String ENCRYPTION_ALIAS_KEY = "--encalias";
    //CACert
    private static final String CA_TOKEN_CLASSPATH_KEY = "--cp";
    private static final String CA_TOKEN_PASSWORD_KEY = "--ctpassword";
    private static final String CA_TOKEN_PROPERTIES_FILE_KEY = "--prop";
    private static final String CA_CERTIFICATE_FILE_KEY = "--cert";

    {
        registerParameter(new Parameter(CA_NAME_KEY, "CA Name", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The name of the CA to import."));
        //P12 arguments        
        registerParameter(new Parameter(P12_FILE_KEY, "File name", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "(PKCS#12) The PKCS#12 file to import from. Mandatory for soft keys."));
        registerParameter(new Parameter(KEYSTORE_PASSWORD_KEY, "Password", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                "(PKCS#12) The keystore password. If not set then it will be prompted for."));
        registerParameter(new Parameter(SIGNATURE_ALIAS_KEY, "Signature Alias", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "(PKCS#12) If left blank, will use the only available alias, or if multiple are available a list will be shown."));
        registerParameter(new Parameter(ENCRYPTION_ALIAS_KEY, "Encryption Alias", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW,
                ParameterMode.ARGUMENT,
                "(PKCS#12) If left blank, will use the only available alias, or if multiple are available a list will be shown. "
                        + "If no encryption alias is given, the encryption keys will be generated."));
        //CA Certificate arguments
        registerParameter(new Parameter(CA_TOKEN_CLASSPATH_KEY, "CA Token Classpath", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW,
                ParameterMode.ARGUMENT, "(PKCS#11) Example: org.cesecore.keys.token.PKCS11CryptoToken for PKCS11 HSMs."));
        registerParameter(new Parameter(CA_TOKEN_PASSWORD_KEY, "CA Token Password", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW,
                ParameterMode.ARGUMENT, "(PKCS#11) Password for the CA Token."));
        registerParameter(new Parameter(CA_TOKEN_PROPERTIES_FILE_KEY, "CA Token Properties File", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW,
                ParameterMode.ARGUMENT,
                "(PKCS#11) A file were you define key name, password and key alias for the HSM. Same as the Hard CA Token Properties in admin GUI."));
        registerParameter(new Parameter(
                CA_CERTIFICATE_FILE_KEY,
                "CA Certificate File",
                MandatoryMode.OPTIONAL,
                StandaloneMode.ALLOW,
                ParameterMode.ARGUMENT,
                "(PKCS#11) A file containing CA-certificates. One or more CA-certificates, with this CA's certificate first, and others following in certificate chain order."));

    }

    @Override
    public String getMainCommand() {
        return "importca";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {
        CryptoProviderTools.installBCProvider();
        String caName = parameters.get(CA_NAME_KEY);
        
        // Import soft keystore
        log.info("Importing soft token.");
        String kspwd = parameters.get(KEYSTORE_PASSWORD_KEY);
        if (kspwd == null) {
            log.info("Enter keystore password: ");
            // Read the password, but mask it so we don't display it on the console
            kspwd = String.valueOf(System.console().readPassword());
        }
        String p12file = parameters.get(P12_FILE_KEY);
        if(p12file == null) {
            log.error("P12 file needs to be specified for soft keys, use "+P12_FILE_KEY+" switch.");
            return CommandResult.CLI_FAILURE;
        }
        String alias = parameters.get(SIGNATURE_ALIAS_KEY);
        String encryptionAlias = parameters.get(ENCRYPTION_ALIAS_KEY);
        // Read old keystore file in the beginning so we know it's good
        byte[] keystorebytes = null;
        try {
            keystorebytes = FileTools.readFiletoBuffer(p12file);
            // Import CA from PKCS12 file
            if (alias == null) {
                // First we must find what aliases there is in the pkcs12-file
                KeyStore ks;
                try {
                    ks = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
                } catch (KeyStoreException e) {
                    throw new IllegalStateException("PKCS12 keystore couldn't be found in BouncyCastle provider.");
                } catch (NoSuchProviderException e) {
                    throw new IllegalStateException("BouncyCastle provider couldn't be found.", e);
                }
                FileInputStream fis = new FileInputStream(p12file);
                try {
                    ks.load(fis, kspwd.toCharArray());
                } catch (NoSuchAlgorithmException e) {
                    log.error("Keystore were created with an unknown algorithm", e);
                    return CommandResult.FUNCTIONAL_FAILURE;
                } catch (CertificateException e) {
                    log.error("Certificates in keystore could not be loaded for unknown reason");
                    return CommandResult.FUNCTIONAL_FAILURE;
                } catch (IOException e) {
                    if (e.getCause() instanceof UnrecoverableKeyException) {
                        log.error("Incorrect password to the PKCS#12 keystore inputed.");
                        return CommandResult.FUNCTIONAL_FAILURE;
                    } else {
                        throw new IllegalStateException("Uknown IOException was caught", e);
                    }
                }
                try {
                    fis.close();
                } catch (IOException e) {
                    throw new IllegalStateException("Uknown IOException was caught", e);
                }
                Enumeration<String> aliases;
                try {
                    aliases = ks.aliases();
                } catch (KeyStoreException e) {
                    throw new IllegalStateException("Keystore was not initialized", e);
                }
                int length = 0;
                while (aliases.hasMoreElements()) {
                    alias = aliases.nextElement();
                    log.info("Keystore contains alias: " + alias);
                    length++;
                }
                if (length > 1) {
                    log.info("Keystore contains more than one alias, alias must be provided as argument.");
                    return CommandResult.FUNCTIONAL_FAILURE;
                } else if (length < 1) {
                    log.info("Keystore does not contain any aliases. It can not be used for a CA.");
                    return CommandResult.FUNCTIONAL_FAILURE;
                }
                // else alias already contains the only alias, so we can use that
            }
        } catch (FileNotFoundException e) {
            log.error("File " + p12file + " not found.");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class).importCAFromKeyStore(getAuthenticationToken(), caName,
                keystorebytes, kspwd, kspwd, alias, encryptionAlias);
        return CommandResult.SUCCESS;
    }

    @Override
    public String getCommandDescription() {
        return "Imports a keystore and creates a new X509 CA from it.";

    }

    @Override
    public String getFullHelpText() {
        return getCommandDescription()
                + " This command imports a CA from a PKCS#12 keystore.\n"
                + "Usageis: \n" 
                + "<CA name> <pkcs12 file> [" + KEYSTORE_PASSWORD_KEY
                + " <password>] [<signature alias>] [<encryption alias>]\n";
    }
    
    @Override
    protected Logger getLogger() {
        return log;
    }
    
    @Override
    protected boolean doPrintSynopsis() {
        //Synopsis turns out kind of weird for this command. 
        return false;
    }
}
