package org.ejbca.ui.cli.cryptotoken;

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

public class CryptoTokenImportKeyPairCommand extends BaseCryptoTokenCommand {
    
    private static final Logger log = Logger.getLogger(CryptoTokenImportKeyPairCommand.class);

    private static final String KEYFILEPATH = "--key-file-path";

    {
        registerParameter(
                new Parameter(KEYFILEPATH, "Key file path", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT, "Path to the directory containing key files."));
    }
    
    @Override
    public String getMainCommand() {
        return "importkeypair";
    }

    @Override
    public String getCommandDescription() {
        return "Imports a key pair from file.";
    }

    @Override
    public CommandResult executeCommand(Integer cryptoTokenId, ParameterContainer parameters)
            throws AuthorizationDeniedException, CryptoTokenOfflineException {
        return null;
    }

    @Override
    protected Logger getLogger() {
        return log;
    }

    @Override
    public String getFullHelpText() {
        return getCommandDescription();
    }

}
