package org.ejbca.ui.cli;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.rmi.RemoteException;
import java.security.SecureRandom;
import java.util.Properties;

public class LogAcceptProtectedLogCommand extends BaseLogAdminCommand  {
	
	private static final SecureRandom seeder = new SecureRandom();

	public LogAcceptProtectedLogCommand(String[] args) {
        super(args);
	}

	public void execute() throws IllegalAdminCommandException,	ErrorAdminCommandException {
		if (args.length < 2) {
			String msg = "Usage: LOG accept <protected log properties-file> [frozen]\n" +
			"This command signes all unsigned log-chains. This should only be used when log protection is first enabled.\n"+
			"\"frozen\" mean that frozen nodes will be signed instead.\n";
			throw new IllegalAdminCommandException(msg);
		}
		Properties properties = new Properties();
		try {
			properties.load(new FileInputStream(args[1]));
		} catch (FileNotFoundException e1) {
	        System.out.print("Connot find "+args[1]+"\n");
	        return;
		} catch (IOException e1) {
	        System.out.print("Connot load "+args[1]+"\n");
	        return;
		}
		boolean all = (args.length == 3 && "frozen".equalsIgnoreCase(args[2]));
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
			if (getProtectedLogSession().signAllUnsignedChains(properties, all)) {
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
