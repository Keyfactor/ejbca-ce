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

public class LogAcceptProtectedLogCommand extends BaseLogAdminCommand  {
	
	public static final String COMMAND_NAME = "accept";

	private static final SecureRandom seeder = new SecureRandom();

	public LogAcceptProtectedLogCommand(String[] args) {
        super(args);
	}

	public void execute() throws IllegalAdminCommandException,	ErrorAdminCommandException {
		if (args.length < 2) {
			String msg = "Usage: LOG accept [all | frozen]\n" +
			"This command signes all unsigned log-chains. This should only be used when log protection is first enabled.\n"+
			"\"frozen\" mean that frozen nodes will be signed instead.\n";
			throw new IllegalAdminCommandException(msg);
		}
		boolean all = "frozen".equalsIgnoreCase(args[1]);
		// 4 chars should be enough to make the user think at least once..
        String randomString = ""+(seeder.nextInt(9000)+1000);
        System.out.print("\nYOU ARE ABOUT TO SIGN UNVERIFIABLE LOG EVENTS IN THE PROTECTED LOG!\n\n"+
        							"This should only be used when log protection is first enabled or when recovering from a crash.\n"+
        							"Confirm this by entering \""+randomString+"\": ");
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        try {
           if (!randomString.equals(br.readLine().trim())) {
               System.out.println("\nNot correct. Exiting.\n");
        	   return;
           }
        } catch (IOException e) {
           System.out.println("IO error: "+e.getMessage());
           return;
        }
        System.out.print("\nSigning...\n");
        try {
			if (getProtectedLogSession().signAllUnsignedChains(all)) {
		        System.out.print("SUCCESS!\n");
			} else {
		        System.out.print("FAILED!\n");
			}
		} catch (RemoteException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
