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

import javax.ejb.EJB;

import org.ejbca.core.ejb.log.ProtectedLogSessionRemote;
import org.ejbca.ui.cli.ErrorAdminCommandException;

/**
 * Reset log to a consistent state
 * 
 * @version $Id$
 */
public class LogResetProtectedLogCommand extends BaseLogAdminCommand  {
	
    @EJB
    private ProtectedLogSessionRemote protectedLogSession;
    
	public String getMainCommand() { return MAINCOMMAND; }
	public String getSubCommand() { return "resetprotected"; }
	public String getDescription() { return "Reset log to a consistent state (ProtectedLog)"; }

    public void execute(String[] args) throws ErrorAdminCommandException {
		if (args.length < 2) {
    		getLogger().info("Description: " + getDescription());
    		getLogger().info("Usage: " + getCommand() + " <export | noexport>");
    		getLogger().info("This command tries to set the log to a consistent state, by removing almost all log posts. Use with care.");
    		return;
		}
		boolean export = "export".equalsIgnoreCase(args[1]);
		// 4 chars should be enough to make the user think at least once..
        String randomString = ""+(new SecureRandom().nextInt(9000)+1000);
        getLogger().info("YOU ARE ABOUT TO DELETE THE PROTECTED LOG!");
        getLogger().info("This should only be used for recovery when everything else fails.");
        getLogger().info("Confirm the delete by entering \""+randomString+"\": ");
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
        getLogger().info("Forcing the protected log to a consistent state...");
        try {
			if (protectedLogSession.resetEntireLog(export)) {
				getLogger().info("SUCCESS!");
			} else {
				getLogger().error("FAILED!");
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
