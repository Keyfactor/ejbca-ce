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

package org.ejbca.ui.cli.log;

import java.rmi.RemoteException;

import javax.ejb.EJB;

import org.ejbca.core.ejb.log.ProtectedLogSessionRemote;
import org.ejbca.core.model.log.ProtectedLogConstants;
import org.ejbca.core.model.log.ProtectedLogEventIdentifier;
import org.ejbca.ui.cli.ErrorAdminCommandException;

/**
 * Verify log
 * 
 * @version $Id$
 */
public class LogVerifyProtectedLogCommand extends BaseLogAdminCommand  {

    @EJB
    private ProtectedLogSessionRemote protectedLogSession;
    
	public String getMainCommand() { return MAINCOMMAND; }
	public String getSubCommand() { return "verifyprotected"; }
	public String getDescription() { return "Verify log (ProtectedLog)"; }

    public void execute(String[] args) throws ErrorAdminCommandException {
		if (args.length < 2) {
			getLogger().info("Description: " + getDescription());
			getLogger().info("Usage: " + getCommand() + " <freezeThreshold>");
			getLogger().info("Verify protected log. freezeThreshold is the oldest allowed log event for any node in seconds.");
			return;
		}
		long freezeThreshold = Long.parseLong(args[1]) * 1000;
		getLogger().info("Starting verification..");
        try {
			ProtectedLogEventIdentifier protectedLogEventIdentifier = protectedLogSession.verifyEntireLog(ProtectedLogConstants.ACTION_NONE, freezeThreshold);
			if (protectedLogEventIdentifier == null) {
				getLogger().info("Log verification OK!");
		        return;
			}
			getLogger().error("Failed to verify nodeGUID=" + protectedLogEventIdentifier.getNodeGUID() + " counter=" + protectedLogEventIdentifier.getCounter() + "");
		} catch (Exception e) {
			e.printStackTrace();
		}
		getLogger().error("Log verification FAILED!");
	}
}
