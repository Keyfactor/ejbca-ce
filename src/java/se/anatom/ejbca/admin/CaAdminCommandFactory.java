package se.anatom.ejbca.admin;

/**
 * Factory for CA Admin Commands.
 *
 * @version $Id: CaAdminCommandFactory.java,v 1.3 2003-06-26 11:43:22 anatom Exp $
 */
public class CaAdminCommandFactory {
    /**
     * Cannot create an instance of this class, only use static methods.
     */
    private CaAdminCommandFactory() {
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

        if (args[0].equals("makeroot")) {
            return new CaMakeRootCommand(args);
        } else if (args[0].equals("getrootcert")) {
            return new CaGetRootCertCommand(args);
        } else if (args[0].equals("listexpired")) {
            return new CaListExpiredCommand(args);
        } else if (args[0].equals("info")) {
            return new CaInfoCommand(args);
        } else if (args[0].equals("init")) {
            return new CaInitCommand(args);
        } else if (args[0].equals("makereq")) {
            return new CaMakeReqCommand(args);
        } else if (args[0].equals("recrep")) {
            return new CaRecRepCommand(args);
        } else if (args[0].equals("processreq")) {
            return new CaProcessReqCommand(args);
        } else if (args[0].equals("createcrl")) {
            return new CaCreateCrlCommand(args);
        } else if (args[0].equals("getcrl")) {
            return new CaGetCrlCommand(args);
        } else if (args[0].equals("rolloverroot")) {
            return new CaRolloverRootCommand(args);
        } else if (args[0].equals("rolloversub")) {
            return new CaRolloverSubCommand(args);
        } else {
            return null;
        }
    }
     // getCommand
}
 // CaAdminCommandFactory
