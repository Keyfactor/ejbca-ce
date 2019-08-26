package org.ejbca.ui.cli.cryptotoken;

import java.nio.file.Path;
import java.nio.file.Paths;

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * CryptoToken EJB CLI command. See {@link #getDescription()} implementation.
 * 
 * @version $Id$
 */
public class CryptoTokenRestoreKeyCommand extends BaseCryptoTokenCommand {
    
    private static final Logger log = Logger.getLogger(CryptoTokenRestoreKeyCommand.class);
    
    private static final String KEY_PAIR_SPEC_ID_KEY = "--keyspecid";
    private static final String KEY_PAIR_BACKUP_FILE_KEY = "--backupfile";
    
    {
        registerParameter(new Parameter(KEY_PAIR_SPEC_ID_KEY, "Key Specification id", MandatoryMode.MANDATORY, StandaloneMode.ALLOW,
                ParameterMode.ARGUMENT, "Key specification for the key to be restored, can be retrieved using cxitool's ListKeys command."));
        registerParameter(new Parameter(KEY_PAIR_BACKUP_FILE_KEY, "Key backup file", MandatoryMode.MANDATORY, StandaloneMode.ALLOW,
                ParameterMode.ARGUMENT, "The backup file that key will be read from."));
    }

    @Override
    public String getMainCommand() {
        return "restorekey";
    }

    @Override
    public String getCommandDescription() {
        return "Restore the provided key from given file";
    }

    @Override
    public CommandResult executeCommand(Integer cryptoTokenId, ParameterContainer parameters)
            throws AuthorizationDeniedException, CryptoTokenOfflineException {
        final Path backupFilePath = Paths.get(parameters.get(KEY_PAIR_BACKUP_FILE_KEY));
        final int keySpecId = Integer.parseInt(parameters.get(KEY_PAIR_SPEC_ID_KEY));
        
        try {
            final CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE
                    .getRemoteSession(CryptoTokenManagementSessionRemote.class);
            cryptoTokenManagementSession.restoreKey(keySpecId, backupFilePath, cryptoTokenId);
            return CommandResult.SUCCESS;
        } catch (Exception e) {
            getLogger().info("Key resotre operation failed: " + e.getMessage());
            return CommandResult.FUNCTIONAL_FAILURE;
        }
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
