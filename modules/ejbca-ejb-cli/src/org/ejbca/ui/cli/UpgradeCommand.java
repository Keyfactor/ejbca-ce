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

package org.ejbca.ui.cli;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

import org.apache.log4j.Logger;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.upgrade.UpgradeSessionRemote;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.command.EjbcaCommandBase;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;

/**
 * Runs the post-upgrade from the CLI
 * 
 * @version $Id$
 */
public class UpgradeCommand extends EjbcaCommandBase {

    private static final Logger log = Logger.getLogger(UpgradeCommand.class);


    @Override
    public String getMainCommand() {
        return "upgrade";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {
        // Upgrade the database
        Future<Boolean> result = EjbRemoteHelper.INSTANCE.getRemoteSession(UpgradeSessionRemote.class).startPostUpgrade();
        try {
            if (result.get()) {
                log.info("Post Upgrade completed.");
            } else {
                log.error("Post Upgrade not performed, see server log for details.");
                return CommandResult.FUNCTIONAL_FAILURE;
            }
        } catch (InterruptedException e) {
            result.cancel(true);
            log.error("Post Upgrade was interrupted, see server log for details.");
            return CommandResult.FUNCTIONAL_FAILURE;
        } catch (ExecutionException e) {
            log.error("Post Upgrade failed, see server log for details.");
            result.cancel(true);
        }
        return CommandResult.SUCCESS;

    }

    @Override
    public String getCommandDescription() {
        return "Post upgrade command. Use 'ant upgrade' instead of running this directly.";
    }

    @Override
    public String getFullHelpText() {
        return getCommandDescription();
    }
    
    @Override
    protected Logger getLogger() {
        return log;
    }
}
