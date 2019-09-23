package org.ejbca.ui.cli.cryptotoken;

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;

public class CryptoTokenChangeAuthDataCommand extends BaseCryptoTokenCommand {

    @Override
    public String getMainCommand() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public String getCommandDescription() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public CommandResult executeCommand(Integer cryptoTokenId, ParameterContainer parameters)
            throws AuthorizationDeniedException, CryptoTokenOfflineException {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    protected Logger getLogger() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public String getFullHelpText() {
        // TODO Auto-generated method stub
        return null;
    }

}
