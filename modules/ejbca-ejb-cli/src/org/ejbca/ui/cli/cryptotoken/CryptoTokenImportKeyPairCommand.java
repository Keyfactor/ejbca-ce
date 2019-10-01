package org.ejbca.ui.cli.cryptotoken;

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.KeyGenParams;
import org.cesecore.keys.token.KeyGenParams.KeyGenParamsBuilder;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

public class CryptoTokenImportKeyPairCommand extends BaseCryptoTokenCommand {
    
    private static final Logger log = Logger.getLogger(CryptoTokenImportKeyPairCommand.class);

    private static final String KEYFILEPATH = "--key-file-path";
    private static final String KEYALGORITHM = "--key-algorithm";
    private static final String ALIAS = "--alias";
    private static final String KEYSPEC = "--key-spec";

    {
        registerParameter(
                new Parameter(KEYFILEPATH, "Key file path", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT, "Path to the directory containing key files."));
        registerParameter(
                new Parameter(ALIAS, "Alias", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT, "Alias for the key pair which will be created."));
        registerParameter(
                new Parameter(KEYALGORITHM, "Key algorithm", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT, "Algorithm the key is generated with, if not provided RSA will be assumed."));
        registerParameter(
                new Parameter(KEYSPEC, "Key spec", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT, "Key specification for the key pair, if not provided RSA2048 will be assumed."));
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
        final String alias = parameters.get(ALIAS);
        String keySpec = parameters.get(KEYSPEC);
        if (keySpec == null) {
            keySpec = "RSA2048";
        }
        final KeyGenParamsBuilder keyGenParamsBuilder = KeyGenParams.builder(keySpec);
        
        try {
            final CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE
                    .getRemoteSession(CryptoTokenManagementSessionRemote.class);
            cryptoTokenManagementSession.createKeyPair(getAdmin(), cryptoTokenId, alias, keyGenParamsBuilder.build());
            return CommandResult.SUCCESS;
        } catch (Exception e) {
            e.printStackTrace();
            getLogger().error("Changing authentication data for the key  "  + alias + " failed : " + e);
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
