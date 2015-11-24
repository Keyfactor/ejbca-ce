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

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.keybind.InternalKeyBindingMgmtSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;

/**
 * RUD (Read, Update, Delete) class for the InternalKeyBinding API access.
 * 
 * @version $Id$
 */
public abstract class RudInternalKeyBindingCommand extends BaseInternalKeyBindingCommand {

    /**
     * Overridable InternalKeyBinding-specific execution methods that will parse and interpret the first parameter
     * (when present) as the name of a InternalKeyBinding and lookup its InternalKeyBindingId.
     */
    public abstract CommandResult executeCommand(Integer internalKeyBindingId, ParameterContainer parameters) throws AuthorizationDeniedException, Exception;

    @Override
    public CommandResult execute(ParameterContainer parameters) {
        Integer internalKeyBindingId = null;
        String internalKeyBindingName = parameters.get(KEYBINDING_NAME_KEY);
        if (internalKeyBindingName!=null) {
            internalKeyBindingName = internalKeyBindingName.trim();
        }
        internalKeyBindingId = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalKeyBindingMgmtSessionRemote.class).getIdFromName(
                internalKeyBindingName);
        if (internalKeyBindingId == null) {
            getLogger().info("Unknown InternalKeyBinding: " + internalKeyBindingName);
            return CommandResult.FUNCTIONAL_FAILURE;
        }

        try {
            return executeCommand(internalKeyBindingId, parameters);
        } catch (AuthorizationDeniedException e) {
            getLogger().info(e.getMessage());
            return CommandResult.AUTHORIZATION_FAILURE;
        } catch (Exception e) {
            getLogger().info("Operation failed: " + e.getMessage());
            throw new IllegalStateException(e);
        }
    }

    /** @return the EJB CLI admin */
    protected AuthenticationToken getAdmin() {
        return getAuthenticationToken();
    }

}
