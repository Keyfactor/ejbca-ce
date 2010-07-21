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
import java.rmi.RemoteException;
import java.security.SecureRandom;

import javax.ejb.EJB;

import org.ejbca.core.ejb.log.ProtectedLogSessionRemote;
import org.ejbca.ui.cli.ErrorAdminCommandException;

/**
 * Signs unsigned log-chains
 * 
 * @version $Id$
 */
public class LogAcceptProtectedLogCommand extends BaseLogAdminCommand  {
	
    @EJB
    private ProtectedLogSessionRemote protectedLogSession;
    
	public String getMainCommand() { return MAINCOMMAND; }
	public String getSubCommand() { return "accept"; }
	public String getDescription() { return "Signs unsigned log-chains (ProtectedLog)"; }

    public void execute(String[] args) throws ErrorAdminCommandException {
    	if (args.length < 2) {
    		getLogger().info("Description: " + getDescription());
    		getLogger().info("Usage: " + getCommand() + " [nodeGUID | all | frozen]");
    		getLogger().info(" all:    Signs unsigned log-chains. This should only be used when log protection is first enabled.");
    		getLogger().info(" frozen: Frozen nodes will be signed instead.");
    		getLogger().info(" specifying a nodeGUID can be used if you have a specific failing nodeGUID that you want to link in.");
			return;
		}
		boolean all = !"frozen".equalsIgnoreCase(args[1]);
		Integer nodeGUID = 0;
		try {
			nodeGUID = Integer.valueOf(args[1]);			
		} catch (NumberFormatException e) {
			// ignore this will simply leave nodeGUID as 0, meaning that we did not give anodeGUID as parameter. 
		}
		// 4 chars should be enough to make the user think at least once..
        String randomString = ""+(new SecureRandom().nextInt(9000)+1000);
        getLogger().info("YOU ARE ABOUT TO SIGN UNVERIFIABLE LOG EVENTS IN THE PROTECTED LOG!");
        getLogger().info("This should only be used when log protection is first enabled or when recovering from a crash.");
        getLogger().info("Confirm this by entering \""+randomString+"\": ");
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        try {
           if (!randomString.equals(br.readLine().trim())) {
        	   getLogger().error("Not correct. Exiting.");
        	   return;
           }
        } catch (IOException e) {
        	getLogger().info("IO error: "+e.getMessage());
           return;
        }
        try {
        	if (nodeGUID.intValue() == 0) {
        		getLogger().info("Signing "+(all? "all":"frozen")+"...");
        		if (protectedLogSession.signAllUnsignedChains(all)) {
        			getLogger().info("SUCCESS!");
        		} else {
        			getLogger().error("FAILED!");
        		}
        	} else {
        		getLogger().info("Signing "+nodeGUID+"...");
        		if (protectedLogSession.signUnsignedChainUsingSingleSignerNode(nodeGUID)) {
        			getLogger().info("SUCCESS!");
        		} else {
        			getLogger().error("FAILED!");
        		}        		
        	}
        } catch (Exception e) {
        	getLogger().error("",e);
        }
	}
}
