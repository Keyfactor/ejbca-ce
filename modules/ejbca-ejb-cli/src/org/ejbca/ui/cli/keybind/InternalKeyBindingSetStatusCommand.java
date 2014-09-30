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
import org.cesecore.keybind.InternalKeyBindingMgmtSessionRemote;
import org.cesecore.keybind.InternalKeyBindingStatus;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * See getDescription().
 * 
 * @version $Id$
 */
public class InternalKeyBindingSetStatusCommand extends RudInternalKeyBindingCommand {

    private static final Logger log = Logger.getLogger(InternalKeyBindingModifyCommand.class);

    private static final String VALUE_KEY = "-v";

    {
        StringBuilder values = new StringBuilder();
        for (final InternalKeyBindingStatus status : InternalKeyBindingStatus.values()) {
            values.append((values.length() > 0 ? " | " : "") + status);
        }
        registerParameter(new Parameter(VALUE_KEY, "Value", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "One of the following: " + values.toString()));
    }

    @Override
    public String getMainCommand() {
        return "setstatus";
    }

    @Override
    public CommandResult executeCommand(Integer internalKeyBindingId, ParameterContainer parameters) throws AuthorizationDeniedException {
        final String keybindingName = parameters.get(KEYBINDING_NAME_KEY);
        final InternalKeyBindingMgmtSessionRemote internalKeyBindingMgmtSession = EjbRemoteHelper.INSTANCE
                .getRemoteSession(InternalKeyBindingMgmtSessionRemote.class);
        final InternalKeyBindingStatus status = InternalKeyBindingStatus.valueOf(parameters.get(VALUE_KEY).toUpperCase());
        final boolean modified = internalKeyBindingMgmtSession.setStatus(getAdmin(), internalKeyBindingId, status);
        if (modified) {
            getLogger().info("Status for \"" + keybindingName + "\" was updated.");
            return CommandResult.SUCCESS;
        } else {
            getLogger().error("Status for \"" + keybindingName + "\" was already " + status.name());
            return CommandResult.FUNCTIONAL_FAILURE;
        }
    }

    @Override
    public String getCommandDescription() {
        return "Modifies the status.";
    }

    @Override
    public String getFullHelpText() {
        StringBuilder sb = new StringBuilder();
        sb.append(getCommandDescription() + "\n");
        return sb.toString();
    }

    protected Logger getLogger() {
        return log;
    }
}
