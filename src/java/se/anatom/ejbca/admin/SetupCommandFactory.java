package se.anatom.ejbca.admin;

/**
 * Factory for General Setup Commands.
 *
 * @version $Id: SetupCommandFactory.java,v 1.1 2004-01-31 14:24:58 herrvendil Exp $
 */
public class SetupCommandFactory {
    /**
     * Cannot create an instance of this class, only use static methods.
     */
    private SetupCommandFactory() {
    }

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

        if (args[0].equals("setbaseurl")) {
            return new SetupSetBaseURLCommand(args);
        }  else {
            return null;
        }
    }

    // getCommand
}


// CaAdminCommandFactory
