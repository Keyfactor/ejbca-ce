package org.ejbca.ui.cli.cryptotoken;

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;

public class CryptoTokenChangeAuthDataCommand extends BaseCryptoTokenCommand {

    private static final Logger log = Logger.getLogger(CryptoTokenChangeAuthDataCommand.class);
    
    @Override
    public String getMainCommand() {
        return "changeauthdata";
    }

    @Override
    public String getCommandDescription() {
        return "Changes authentication data for a CP5 HSM key.";
    }

    @Override
    public CommandResult executeCommand(Integer cryptoTokenId, ParameterContainer parameters)
            throws AuthorizationDeniedException, CryptoTokenOfflineException {
        // TODO Auto-generated method stub
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
