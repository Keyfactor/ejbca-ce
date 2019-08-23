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

public class CryptoTokenBackupKeyCommand extends BaseCryptoTokenCommand {
    
    private static final Logger log = Logger.getLogger(CryptoTokenBackupKeyCommand.class);
    
    private static final String KEY_PAIR_ALIAS_KEY = "--alias";
    private static final String KEY_PAIR_SPEC_ID_KEY = "--keyspecid";
    private static final String KEY_PAIR_BACKUP_FILE_KEY = "--backupfile";

    {
        registerParameter(new Parameter(KEY_PAIR_ALIAS_KEY, "Alias", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Key pair alias"));
        registerParameter(new Parameter(KEY_PAIR_SPEC_ID_KEY, "Key Specification id", MandatoryMode.MANDATORY, StandaloneMode.ALLOW,
                ParameterMode.ARGUMENT, "Key specification for the key to be backed up, can be retrieved using cxitool's ListKeys command."));
        registerParameter(new Parameter(KEY_PAIR_BACKUP_FILE_KEY, "Key backup file", MandatoryMode.MANDATORY, StandaloneMode.ALLOW,
                ParameterMode.ARGUMENT, "The file that key backup will be saved to."));
    }
    
    @Override
    public String getMainCommand() {
        return "backupkey";
    }

    @Override
    public String getCommandDescription() {
        return "Backup the provided key to given file";
    }

    @Override
    public CommandResult executeCommand(Integer cryptoTokenId, ParameterContainer parameters)
            throws AuthorizationDeniedException, CryptoTokenOfflineException {
        final Path backupFilePath = Paths.get(parameters.get(KEY_PAIR_BACKUP_FILE_KEY));
        final int keySpecId = Integer.parseInt(parameters.get(KEY_PAIR_SPEC_ID_KEY));
        
        try {
            final CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE
                    .getRemoteSession(CryptoTokenManagementSessionRemote.class);
            cryptoTokenManagementSession.backupKey(keySpecId, backupFilePath);
            return CommandResult.SUCCESS;
        } catch (Exception e) {
            getLogger().info("CryptoToken activation failed: " + e.getMessage());
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
