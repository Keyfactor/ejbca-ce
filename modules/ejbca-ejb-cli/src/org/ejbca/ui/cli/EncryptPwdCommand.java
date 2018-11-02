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

package org.ejbca.ui.cli;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

import org.apache.log4j.Logger;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.StringTools;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.command.EjbcaCommandBase;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * Implements the password encryption mechanism
 *
 * @version $Id$
 */
public class EncryptPwdCommand extends EjbcaCommandBase {

    private static final Logger log = Logger.getLogger(EncryptPwdCommand.class);

    private static final String ENCRYPT_KEY = "--key";

    {
        registerParameter(new Parameter(ENCRYPT_KEY, "Input encryption key", MandatoryMode.OPTIONAL, StandaloneMode.FORBID,
                ParameterMode.FLAG, "Read a custom encryption key instead of using the default value from cesecore.properties."));
    }
    @Override
    public String getMainCommand() {
        return "encryptpwd";
    }

    @Override
    public String getCommandDescription() {
        return "Encrypts a password";
    }

    @Override
    public String getFullHelpText() {
        return "Encrypts a password. This command takes no parameters, but will instead prompt for the password when run.";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {

        final boolean readKey = parameters.get(ENCRYPT_KEY) != null;
        log.info("Please note that this encryption does not provide absolute security. "
                + "If 'password.encryption.key' property haven't been customized it doesn't provide more security than just preventing accidental viewing.");
        char[] encryptionKey = null;
        if (readKey) {
            log.info("Enter encryption key: ");
            encryptionKey = System.console().readPassword();
        }
        log.info("Enter word to encrypt: ");
        String s = String.valueOf(System.console().readPassword());
        CryptoProviderTools.installBCProvider();
        log.info("Encrypting pwd (" + (readKey ? "with custom key" : "with default key") + ")");
        final String enc;

        try {
            if (readKey) {
                enc = StringTools.pbeEncryptStringWithSha256Aes192(s, encryptionKey);
            } else {
                enc = StringTools.pbeEncryptStringWithSha256Aes192(s);
            }
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException
                | InvalidKeySpecException e) {
            log.error(e.getMessage());
            return CommandResult.FUNCTIONAL_FAILURE;
        }

        log.info(enc);

        return CommandResult.SUCCESS;
    }
    
    @Override
    protected Logger getLogger() {
        return log;
    }
}
