/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
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

import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.core.ejb.keybind.InternalKeyBindingMgmtSessionRemote;
import org.ejbca.core.ejb.keybind.InternalKeyBindingStatus;

/**
 * See getDescription().
 * 
 * @version $Id$
 */
public class InternalKeyBindingSetStatusCommand extends BaseInternalKeyBindingCommand {

    @Override
    public String getSubCommand() {
        return "setstatus";
    }

    @Override
    public String getDescription() {
        return "Modifies the status.";
    }

    @Override
    public void executeCommand(Integer internalKeyBindingId, String[] args) throws AuthorizationDeniedException, Exception {
        if (args.length < 3) {
            getLogger().info("Description: " + getDescription());
            String values = "";
            for (final InternalKeyBindingStatus status : InternalKeyBindingStatus.values()) {
                values += status + " | ";
            }
            values = values.substring(0, values.length()-3);
            getLogger().info("Usage: " + getCommand() + " <name> <"+values+">");
            return;
        }
        final InternalKeyBindingMgmtSessionRemote internalKeyBindingMgmtSession = ejb.getRemoteSession(InternalKeyBindingMgmtSessionRemote.class);
        final InternalKeyBindingStatus status = InternalKeyBindingStatus.valueOf(args[2].toUpperCase());
        final boolean modified = internalKeyBindingMgmtSession.setStatus(getAdmin(), internalKeyBindingId, status);
        if (modified) {
            getLogger().info("Status for \"" + args[1]+ "\" was updated.");
        } else {
            getLogger().info("Status for \"" + args[1]+ "\" was already " + status.name());
        }
    }
}
