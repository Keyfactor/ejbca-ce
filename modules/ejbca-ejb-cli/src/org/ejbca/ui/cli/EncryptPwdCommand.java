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

import org.apache.log4j.Logger;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.StringTools;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.command.EjbcaCommandBase;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;

/**
 * Implements the password encryption mechanism
 *
 * @version $Id$
 */
public class EncryptPwdCommand extends EjbcaCommandBase {

    private static final Logger log = Logger.getLogger(EncryptPwdCommand.class);

    @Override
    public String getMainCommand() {
        return "encryptpwd";
    }

    @Override
    public String getCommandDescription() {
        return "Encrypts a password to avoid accidental reading";
    }

    @Override
    public String getFullHelpText() {
        return "Encrypts a password to avoid accidental reading. This command takes no parameters, but will instead prompt for the password when run.";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {
        try {
            log.info("Please note that this encryption does not provide absolute security, "
                    + "it uses a build in key for encryption to keep the password from at least accidentaly beeing known.");
            log.info("Enter word to encrypt: ");
            String s = String.valueOf(System.console().readPassword());
            CryptoProviderTools.installBCProvider();
            log.info("Encrypting pwd...");
            String enc = StringTools.pbeEncryptStringWithSha256Aes192(s);
            log.info(enc);
        } catch (Exception e) {
            log.error(e.getMessage());
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        return CommandResult.SUCCESS;
    }
    
    @Override
    protected Logger getLogger() {
        return log;
    }
}
