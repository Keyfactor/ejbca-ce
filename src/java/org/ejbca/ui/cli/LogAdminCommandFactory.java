package org.ejbca.ui.cli;

import java.lang.reflect.Constructor;

public class LogAdminCommandFactory {

    private LogAdminCommandFactory() {
    }

	private static final Class[] commandClasses = { LogVerifyProtectedLogCommand.class, LogAcceptProtectedLogCommand.class, LogResetExportProtectedLogCommand.class,
			LogResetProtectedLogCommand.class};
	
	private static final String[] commandNames = { LogVerifyProtectedLogCommand.COMMAND_NAME, LogAcceptProtectedLogCommand.COMMAND_NAME,
			LogResetExportProtectedLogCommand.COMMAND_NAME, LogResetProtectedLogCommand.COMMAND_NAME};
	
    public static IAdminCommand getCommand(String[] args) {
        if (args.length >= 1) {
        	for (int i=0; i<commandClasses.length; i++) {
        		if (commandNames[i].equalsIgnoreCase(args[0])) {
        			Class[] paramTypes = new Class[] {String[].class};
        			Constructor constructor;
        			try {
        				constructor = commandClasses[i].getConstructor(paramTypes);
		                Object[] params = new Object[1];
	                    params[0] = args;
        				return (IAdminCommand) constructor.newInstance(params);
        			} catch (Exception e) {
        				throw new RuntimeException(e);
        			}
        		}
        	}
        }
        return null;
    } // getCommand

    public static String getAvailableCommands() {
    	String availableCommands = "";
    	for (int i=0; i<commandNames.length; i++) {
    		availableCommands += commandNames[i] + (commandNames.length -1 != i ? " | " : "");
    	}
    	return availableCommands;
    }
}
