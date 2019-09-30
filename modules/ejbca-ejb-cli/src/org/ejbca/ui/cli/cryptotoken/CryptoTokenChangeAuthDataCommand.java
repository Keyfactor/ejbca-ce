package org.ejbca.ui.cli.cryptotoken;

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

public class CryptoTokenChangeAuthDataCommand extends BaseCryptoTokenCommand {

    private static final Logger log = Logger.getLogger(CryptoTokenChangeAuthDataCommand.class);

    private static final String ALIAS = "--alias";
    private static final String CURRENTKAKTOKENKEYALIAS = "--current-kak-tokenkey-alias";
    private static final String NEWKAKTOKENKEYALIAS = "--new-kak-tokenkey-alias";
    private static final String PADDING_SCHEME = "--padding-scheme";
    private static final String NEW_KAK_TOKEN = "--new-kak-token";
    private static final String CURRENT_KAK_TOKEN = "--current-kak-token";
    
    
    {
        registerParameter(
                new Parameter(ALIAS, "Alias", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT, "HSM Key pair alias"));
        registerParameter(
                new Parameter(CURRENTKAKTOKENKEYALIAS, "Current kak token key alias", MandatoryMode.MANDATORY, StandaloneMode.ALLOW,
                ParameterMode.ARGUMENT, "Alias of the current kak token key."));
        registerParameter(
                new Parameter(NEWKAKTOKENKEYALIAS, "New kak token key alias", MandatoryMode.MANDATORY, StandaloneMode.ALLOW,
                ParameterMode.ARGUMENT, "Alias of the new kak token key."));
        registerParameter(
                new Parameter(PADDING_SCHEME, "Padding Scheme", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Padding scheme used to sign the hash of new kak with, must be same as the old padding scheme."));
        registerParameter(
                new Parameter(NEW_KAK_TOKEN, "New kak token name", MandatoryMode.MANDATORY, StandaloneMode.ALLOW,
                ParameterMode.ARGUMENT, "Token representing the new kak to be used."));
        registerParameter(
                new Parameter(CURRENT_KAK_TOKEN, "Current kak token name", MandatoryMode.MANDATORY, StandaloneMode.ALLOW,
                ParameterMode.ARGUMENT, "Token representing the current kak in use."));
    }

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
        final String alias = parameters.get(ALIAS);
        final String currentKakTokenKeyAlias = parameters.get(CURRENTKAKTOKENKEYALIAS);
        final String newKakTokenKeyAlias = parameters.get(NEWKAKTOKENKEYALIAS);
        
        final String selectedPaddingScheme = parameters.get(PADDING_SCHEME);
        try {
            final CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE
                    .getRemoteSession(CryptoTokenManagementSessionRemote.class);
            final int newKakTokenId = cryptoTokenManagementSession.getIdFromName(parameters.get(NEW_KAK_TOKEN));
            final int currentKakTokenId = cryptoTokenManagementSession.getIdFromName(parameters.get(CURRENT_KAK_TOKEN));

            cryptoTokenManagementSession.changeAuthData(getAdmin(), cryptoTokenId, alias, currentKakTokenId, newKakTokenId, currentKakTokenKeyAlias, newKakTokenKeyAlias, selectedPaddingScheme);
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
