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
import java.security.cert.CertificateException;
import java.util.Enumeration;

import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
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
 * Restore a CA token keystore from a PKCS12 file.
 * 
 * @version $Id$
 */
public class CaRestoreKeyStoreCommand extends BaseCaAdminCommand {

    private static final Logger log = Logger.getLogger(CaInfoCommand.class);

    private static final String CA_NAME_KEY = "--caname";
    private static final String PKCS12_FILE_KEY = "-f";
    private static final String SIG_ALIAS_KEY = "-s";
    private static final String ENC_ALIAS_KEY = "-e";
    private static final String KEYSTORE_PASSWORD_KEY = "-kspassword";

    {
        registerParameter(new Parameter(CA_NAME_KEY, "CA Name", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Name of the CA"));
        registerParameter(new Parameter(PKCS12_FILE_KEY, "Filename", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The PKCS#12 keystore to restore from."));
        registerParameter(new Parameter(SIG_ALIAS_KEY, "Alias", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                "Alias for the Signature key. If left out the existing alias will be used, and if multiple are available a list will be displayed."));
        registerParameter(new Parameter(ENC_ALIAS_KEY, "Alias", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                "Alias for the Encryption key. If left out the existing alias will be used, and if multiple are available a list will be displayed."));
        registerParameter(new Parameter(KEYSTORE_PASSWORD_KEY, "Password", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                "If left out, then password will be prompted for."));
    }

    @Override
    public String getMainCommand() {
        return "restorekeystore";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {
        String kspwd = parameters.get(KEYSTORE_PASSWORD_KEY);
        String caName = parameters.get(CA_NAME_KEY);
        // Import soft keystore
        String p12file = parameters.get(PKCS12_FILE_KEY);
        String alias = parameters.get(SIG_ALIAS_KEY);
        String encryptionAlias = parameters.get(ENC_ALIAS_KEY);
        if (kspwd == null) {
            getLogger().info("Enter keystore password: ");
            // Read the password, but mask it so we don't display it on the console
            kspwd = String.valueOf(System.console().readPassword());
        } else {
            getLogger().info("Keystore password was supplied on the command line.");
        }
        // Read old keystore file in the beginning so we know it's good
        byte[] keystorebytes = null;
        try {
            keystorebytes = FileTools.readFiletoBuffer(p12file);
        } catch (FileNotFoundException e) {
            log.error("File " + p12file + " was not found.");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        // Import CA from PKCS12 file
        if (alias == null) {
            // First we must find what aliases there is in the pkcs12-file
            KeyStore ks;
            try {
                ks = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
            } catch (KeyStoreException e) {
                throw new IllegalStateException("PKCS#12 implementation not found.", e);
            } catch (NoSuchProviderException e) {
                throw new IllegalStateException("BouncyCastle provider not found.", e);
            }
            FileInputStream fis;
            try {
                fis = new FileInputStream(p12file);
            } catch (FileNotFoundException e) {
                log.error("File " + p12file + " was not found.");
                return CommandResult.FUNCTIONAL_FAILURE;
            }
            try {
                ks.load(fis, kspwd.toCharArray());
                fis.close();
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException("Algorithm used to check the integrity of the keystore could npt be found.", e);
            } catch (CertificateException e) {
                throw new IllegalStateException("Certificate could not be loaded from keystore.", e);
            } catch (IOException e) {
                throw new IllegalStateException("Unknown IOException was caught.", e);
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
                getLogger().info("Keystore contains alias: " + alias);
                length++;
            }
            if (length > 1) {
                log.error("Keystore contains more than one alias, alias must be provided as argument.");
                return CommandResult.FUNCTIONAL_FAILURE;
            } else if (length < 1) {
                log.error("Keystore does not contains any aliases. It can not be used for a CA.");
                return CommandResult.FUNCTIONAL_FAILURE;
            }
            // else alias already contains the only alias, so we can use that
        }
        EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class).restoreCAKeyStore(getAuthenticationToken(), caName, keystorebytes,
                kspwd, kspwd, alias, encryptionAlias);
        return CommandResult.SUCCESS;

    }

    @Override
    public String getCommandDescription() {
        return "Restore a CA token keystore from a PKCS12 file.";
    }

    @Override
    public String getFullHelpText() {
        return getCommandDescription();
    }

    @Override
    protected Logger getLogger() {
        return log;
    }

}
