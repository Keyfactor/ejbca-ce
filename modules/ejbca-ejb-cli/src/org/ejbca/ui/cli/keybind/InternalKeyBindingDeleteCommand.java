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
package org.ejbca.ui.cli.keybind;

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.keybind.InternalKeyBindingMgmtSessionRemote;
import org.cesecore.keybind.InternalKeyBindingNameInUseException;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;

/**
 * See getDescription().
 * 
 * @version $Id$
 */
public class InternalKeyBindingDeleteCommand extends RudInternalKeyBindingCommand {

    private static final Logger log = Logger.getLogger(InternalKeyBindingDeleteCommand.class);

    @Override
    public String getMainCommand() {
        return "delete";
    }

    @Override
    public CommandResult executeCommand(Integer internalKeyBindingId, ParameterContainer parameters) throws AuthorizationDeniedException,
            CryptoTokenOfflineException, InternalKeyBindingNameInUseException, InvalidAlgorithmException {
        final InternalKeyBindingMgmtSessionRemote internalKeyBindingMgmtSession = EjbRemoteHelper.INSTANCE
                .getRemoteSession(InternalKeyBindingMgmtSessionRemote.class);
        if (internalKeyBindingMgmtSession.deleteInternalKeyBinding(getAdmin(), internalKeyBindingId)) {
            getLogger().info("InternalKeyBinding with id " + internalKeyBindingId + " was successfully removed.");
            return CommandResult.SUCCESS;
        } else {
            getLogger().error("InternalKeyBinding with id " + internalKeyBindingId + " could not be removed.");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
    }

    @Override
    public String getCommandDescription() {
        return "Deletes the specified InternalKeyBinding.";
    }

    @Override
    public String getFullHelpText() {
        return getCommandDescription();
    }

    protected Logger getLogger() {
        return log;
    }
}
