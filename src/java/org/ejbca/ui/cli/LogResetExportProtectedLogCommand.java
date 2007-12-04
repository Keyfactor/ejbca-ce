package org.ejbca.ui.cli;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.rmi.RemoteException;
import java.security.SecureRandom;
import java.util.Properties;

public class LogResetExportProtectedLogCommand extends BaseLogAdminCommand  {

	private static final SecureRandom seeder = new SecureRandom();
	
	public LogResetExportProtectedLogCommand(String[] args) {
        super(args);
	}

	public void execute() throws IllegalAdminCommandException,	ErrorAdminCommandException {
		// 4 chars should be enough to make the user think at least once..
        String randomString = ""+(seeder.nextInt(9000)+1000);
        System.out.print("\nYou are about to roll back the list of exports to the last non-deleted export.\n\n"+
        							"The next time the export serive runs it will try to export all events since that time. "+
        							"This might put a big load on your system for some time.\n"+
        							"Confirm the export-reset by entering \""+randomString+"\": ");
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
        System.out.print("\nForcing the protected log to a consistent state...\n");
        try {
			if (getProtectedLogSession().removeAllExports(false)) {
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
