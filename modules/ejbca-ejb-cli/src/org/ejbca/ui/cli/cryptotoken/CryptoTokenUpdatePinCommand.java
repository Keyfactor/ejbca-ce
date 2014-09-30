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

/**
 * CryptoToken EJB CLI command. See {@link #getDescription()} implementation.
 * 
 * @version $Id$
 */
public class CryptoTokenUpdatePinCommand extends BaseCryptoTokenCommand {

    private static final Logger log = Logger.getLogger(CryptoTokenUpdatePinCommand.class);

    private static final String SWITCH_UPDATE_ONLY_KEY = "--update";
    private static final String SWITCH_REMOVE_AUTO_KEY = "--remove";
    private static final String OLD_PIN_KEY = "--oldpin";
    private static final String NEW_PIN_KEY = "--newpin";

    {
        registerParameter(new Parameter(OLD_PIN_KEY, "Pin", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The old pin. Set as \"null\" to prompt"));
        registerParameter(new Parameter(NEW_PIN_KEY, "Pin", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The new pin. Set as \"null\" to prompt"));
        registerParameter(Parameter.createFlag(SWITCH_UPDATE_ONLY_KEY,
                "Set the auto-activation pin and make the token auto-activated if it was so previously."));
        registerParameter(Parameter.createFlag(SWITCH_REMOVE_AUTO_KEY,
                "Will remove any auto-activation pin if present (new pin is not required when this is used)."));
    }

    @Override
    public String getMainCommand() {
        return "setpin";
    }

    @Override
    public CommandResult executeCommand(Integer cryptoTokenId, ParameterContainer parameters) throws AuthorizationDeniedException, CryptoTokenOfflineException {
        final boolean updateOnly = parameters.containsKey(SWITCH_UPDATE_ONLY_KEY);
        final boolean removeAuto = parameters.containsKey(SWITCH_REMOVE_AUTO_KEY);

        final char[] currentAuthenticationCode = getAuthenticationCode(parameters.get(OLD_PIN_KEY));
        final char[] newAuthenticationCode = removeAuto ? null : getAuthenticationCode(parameters.get(NEW_PIN_KEY));
        try {
            final CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE
                    .getRemoteSession(CryptoTokenManagementSessionRemote.class);
            boolean result = cryptoTokenManagementSession.updatePin(getAdmin(), cryptoTokenId.intValue(), currentAuthenticationCode,
                    newAuthenticationCode, updateOnly);
            if (result) {
                getLogger().info("Auto-activation is now in use for this CryptoToken.");
            } else {
                getLogger().info("Auto-activation is now not in use for this CryptoToken.");
            }
            final boolean isActive = cryptoTokenManagementSession.isCryptoTokenStatusActive(getAdmin(), cryptoTokenId.intValue());
            getLogger().info("CryptoToken is " + (isActive ? "active" : "deactivated") + ".");
            return CommandResult.SUCCESS;
        } catch (AuthorizationDeniedException e) {
            getLogger().info(e.getMessage());
            return CommandResult.AUTHORIZATION_FAILURE;
        } catch (Exception e) {
            getLogger().info("CryptoToken activation failed: " + e.getMessage());
        }
        return CommandResult.FUNCTIONAL_FAILURE;
    }

    @Override
    public String getCommandDescription() {
        return "Modifies the current keystore and/or auto-activation pin.";
    }

    @Override
    public String getFullHelpText() {
        return getCommandDescription()
                + " For soft CryptoTokens the underlying keystore's pin will be modified and this requires the current activation PIN."
                + " For PKCS#11 CryptoTokens this will only modify the auto-activation pin and requires the current (auto-activation or) activation PIN.";
    }

    @Override
    protected Logger getLogger() {
        return log;
    }

}
