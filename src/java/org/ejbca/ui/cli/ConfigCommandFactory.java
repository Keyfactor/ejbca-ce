package org.ejbca.ui.cli;

public class ConfigCommandFactory {

    /**
     * Cannot create an instance of this class, only use static methods.
     */
    private ConfigCommandFactory() { }
    
    /**
     * Returns an Admin Command object based on contents in args[0].
     *
     * @param args array of arguments typically passed from main().
     *
     * @return Command object or null if args[0] does not specify a valid command.
     */
    public static IAdminCommand getCommand(String[] args) {
        if (args.length < 1) {
            return null;
        }
        if (args[0].equalsIgnoreCase("dump")) {
        	return new ConfigDumpCommand(args);
        }
        return null;
    }
}
