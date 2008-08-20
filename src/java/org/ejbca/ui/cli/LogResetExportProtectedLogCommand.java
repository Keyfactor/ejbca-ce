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
public class LogResetExportProtectedLogCommand extends BaseLogAdminCommand {

	private static final SecureRandom seeder = new SecureRandom();
	
	public static final String COMMAND_NAME = "resetexports";
	
	public LogResetExportProtectedLogCommand(String[] args) {
        super(args);
	}
	
	public void execute() throws IllegalAdminCommandException,	ErrorAdminCommandException {
		// 4 chars should be enough to make the user think at least once..
        String randomString = ""+(seeder.nextInt(9000)+1000);
        getOutputStream().print("\nYou are about to roll back the list of exports to the last non-deleted export.\n\n"+
        							"The next time the export service runs it will try to export all events since that time. "+
        							"This might put a big load on your system for some time.\n"+
        							"Confirm the export-reset by entering \""+randomString+"\": ");
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
        getOutputStream().print("\nForcing the protected log to a consistent state...\n");
        try {
			if (getProtectedLogSession().removeAllExports(false)) {
				getOutputStream().print("SUCCESS!\n");
			} else {
				getOutputStream().print("FAILED!\n");
			}
		} catch (RemoteException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
