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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.SecureRandom;

import org.ejbca.core.ejb.log.ProtectedLogSessionRemote;
import org.ejbca.ui.cli.ErrorAdminCommandException;

/**
 * Reset list of non-deleted exports
 * 
 * @version $Id$
 */
public class LogResetExportProtectedLogCommand extends BaseLogAdminCommand {

    private ProtectedLogSessionRemote protectedLogSession = ejb.getProtectedLogSession();
    
	public String getMainCommand() { return MAINCOMMAND; }
	public String getSubCommand() { return "resetexports"; }
	public String getDescription() { return "Reset list of non-deleted exports (ProtectedLog)"; }

    public void execute(String[] args) throws ErrorAdminCommandException {
		// 4 chars should be enough to make the user think at least once..
        String randomString = ""+(new SecureRandom().nextInt(9000)+1000);
        getLogger().info("You are about to roll back the list of exports to the last non-deleted export.");
        getLogger().info("The next time the export service runs it will try to export all events since that time. ");
        getLogger().info("This might put a big load on your system for some time. Confirm the export-reset by entering \""+randomString+"\": ");
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        try {
           if (!randomString.equals(br.readLine().trim())) {
        	   getLogger().error("Not correct. Exiting.");
        	   return;
           }
        } catch (IOException e) {
        	getLogger().error(e.getMessage());
           return;
        }
        getLogger().info("Forcing the protected log to a consistent state..");
        try {
			if (protectedLogSession.removeAllExports(false)) {
				getLogger().info("SUCCESS!");
			} else {
				getLogger().error("FAILED!");
			}
		} catch (Exception e) {
			getLogger().error("", e);
		}
	}
}
