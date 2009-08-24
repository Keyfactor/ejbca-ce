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

package org.ejbca.ui.cli;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.rmi.RemoteException;
import java.security.SecureRandom;

/**
 * 
 * @version $Id$
 *
 */
public class LogAcceptProtectedLogCommand extends BaseLogAdminCommand  {
	
	public static final String COMMAND_NAME = "accept";

	private static final SecureRandom seeder = new SecureRandom();

	public LogAcceptProtectedLogCommand(String[] args) {
        super(args);
	}

	public void execute() throws IllegalAdminCommandException,	ErrorAdminCommandException {
		if (args.length < 2) {
			String msg = "Usage: LOG accept [nodeGUID | all | frozen]\n" +
			"all: This command signes unsigned log-chains. This should only be used when log protection is first enabled.\n"+
			"\"frozen\" mean that frozen nodes will be signed instead.\n"+
			"specifying a nodeGUID can be used if you have a specific failing nodeGUID that you want to link in.\n";
			throw new IllegalAdminCommandException(msg);
		}
		boolean all = "frozen".equalsIgnoreCase(args[1]);
		Integer nodeGUID = 0;
		try {
			nodeGUID = Integer.valueOf(args[1]);			
		} catch (NumberFormatException e) {
			// ignore this will simply leave nodeGUID as 0, meaning that we did not give anodeGUID as parameter. 
		}
		// 4 chars should be enough to make the user think at least once..
        String randomString = ""+(seeder.nextInt(9000)+1000);
        getOutputStream().print("\nYOU ARE ABOUT TO SIGN UNVERIFIABLE LOG EVENTS IN THE PROTECTED LOG!\n\n"+
        							"This should only be used when log protection is first enabled or when recovering from a crash.\n"+
        							"Confirm this by entering \""+randomString+"\": ");
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        try {
           if (!randomString.equals(br.readLine().trim())) {
        	   getOutputStream().println("\nNot correct. Exiting.\n");
        	   return;
           }
        } catch (IOException e) {
        	getOutputStream().println("IO error: "+e.getMessage());
           return;
        }
        try {
        	if (nodeGUID.intValue() == 0) {
        		getOutputStream().print("\nSigning "+(all? "all":"frozen")+"...\n");
        		if (getProtectedLogSession().signAllUnsignedChains(all)) {
        			getOutputStream().print("SUCCESS!\n");
        		} else {
        			getOutputStream().print("FAILED!\n");
        		}
        	} else {
        		getOutputStream().print("\nSigning "+nodeGUID+"...\n");
        		if (getProtectedLogSession().signUnsignedChain(null, nodeGUID)) {
        			getOutputStream().print("SUCCESS!\n");
        		} else {
        			getOutputStream().print("FAILED!\n");
        		}        		
        	}
        } catch (RemoteException e) {
        	e.printStackTrace();
        } catch (Exception e) {
        	e.printStackTrace();
        }
	}
}
