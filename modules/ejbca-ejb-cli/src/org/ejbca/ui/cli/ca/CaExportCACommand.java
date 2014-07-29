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

package org.ejbca.ui.cli.ca;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * Exports CA as a PKCS#12 or PKCS#8 file
 *
 * @version $Id$
 */
public class CaExportCACommand extends BaseCaAdminCommand {

    private static final Logger log = Logger.getLogger(CaExportCACommand.class);

    private static final String CA_NAME_KEY = "--caname";
    private static final String FILE_KEY = "-f";
    private static final String KEYSTORE_PASSWORD_KEY = "-kspassword";
    private static final String SIGNATURE_ALIAS_KEY = "--signalias";
    private static final String ENCRYPTION_ALIAS_KEY = "--encryptalias";
    private static final String SIGNATURE_ALIAS_DEFAULT = "SignatureKeyAlias";
    private static final String ENCRYPTION_ALIAS_DEFAULT = "EncryptionKeyAlias";

    {
        registerParameter(new Parameter(CA_NAME_KEY, "CA Name", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The name of the CA to export."));
        registerParameter(new Parameter(FILE_KEY, "File name", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The destination file."));
        registerParameter(new Parameter(KEYSTORE_PASSWORD_KEY, "Password", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                "They keystore password. If not set then it will be prompted for."));
        registerParameter(new Parameter(SIGNATURE_ALIAS_KEY, "Signature Key Alias", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW,
                ParameterMode.ARGUMENT, "The signature key alias. Will default to " + SIGNATURE_ALIAS_DEFAULT + " if not set."));
        registerParameter(new Parameter(ENCRYPTION_ALIAS_KEY, "Encryption Key Alias", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW,
                ParameterMode.ARGUMENT, "The encryption key alias. Will default to " + ENCRYPTION_ALIAS_DEFAULT + " if not set. "));
    }

    @Override
    public String getMainCommand() {
        return "exportca";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {

        String kspwd = parameters.get(KEYSTORE_PASSWORD_KEY);
        String caName = parameters.get(CA_NAME_KEY);
        String p12file = parameters.get(FILE_KEY);

        String signatureKeyAlias = parameters.get(SIGNATURE_ALIAS_KEY);
        String encryptionKeyAlias = parameters.get(ENCRYPTION_ALIAS_KEY);
        if ((signatureKeyAlias == null && encryptionKeyAlias != null && parameters.isStandalone(ENCRYPTION_ALIAS_KEY))
                || (signatureKeyAlias != null && encryptionKeyAlias == null && parameters.isStandalone(SIGNATURE_ALIAS_KEY))) {
            //only one of the values was set and implicitly, kinda scary. Let's warn about that. 
            log.error("Do not set only one of SignatureKeyAlias or EncryptionKeyAlias implicitely (without a switch).");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        if (signatureKeyAlias == null) {
            log.info("Setting SignatureKeyAlias to " + SIGNATURE_ALIAS_DEFAULT);
            signatureKeyAlias = SIGNATURE_ALIAS_DEFAULT;
        }
        if (encryptionKeyAlias == null) {
            log.info("Setting EncryptionKeyAlias to " + ENCRYPTION_ALIAS_DEFAULT);
            encryptionKeyAlias = ENCRYPTION_ALIAS_DEFAULT;
        }

        if (kspwd == null) {
            log.info("Enter keystore password: ");
            // Read the password, but mask it so we don't display it on the console
            kspwd = String.valueOf(System.console().readPassword());
        } else {
            log.info("Keystore password was supplied on the command line.");
        }
        if (StringUtils.isEmpty(kspwd)) {
            // Can not export CA keystore with empty password. 
            log.error("Export a token without password protection is not allowed.");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        byte[] keyStoreBytes = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class).exportCAKeyStore(getAuthenticationToken(),
                caName, kspwd, kspwd, signatureKeyAlias, encryptionKeyAlias);
        try {            
            FileOutputStream fos = new FileOutputStream(p12file);
            fos.write(keyStoreBytes);
            fos.close();
        } catch (FileNotFoundException e) {
            log.error(e.getMessage());
            return CommandResult.FUNCTIONAL_FAILURE;
        } catch (IOException e) {
            throw new IllegalStateException("Could not write to file for unknown reason", e);
        } 
        return CommandResult.SUCCESS;

    }

    @Override
    public String getCommandDescription() {
        return "Exports CA as a PKCS#12 or PKCS#8 file. ";

    }

    @Override
    public String getFullHelpText() {
        return getCommandDescription()
                + "X.509 CAs are exported as PKCS#12 files while for CVC CAs only the private certificate signing key is exported as a PKCS#8 key. "
                + "You will be prompted for keystore password to protect stored keystore, "
                + "but can optionally specify it on command line using the optional argument '-kspassword <password>'.\n\n"
                + "Do not set only one of SignatureKeyAlias or EncryptionKeyAlias implicitely (without a switch). Either set both, or if only doing one then with a switch. "
                + "Setting only one without a switch may lead to undefined behavior.";
    }
    
    @Override
    protected Logger getLogger() {
        return log;
    }
}
