
package se.anatom.ejbca.admin;

/** Factory for CA Admin Commands.
 *
 * @version $Id: CaAdminCommandFactory.java,v 1.1 2002-04-07 09:55:29 anatom Exp $
 */
public class CaAdminCommandFactory {

    /** Cannot create an instance of this class, only use static methods. */
    private CaAdminCommandFactory() {
    }

    /** Returns an Admin Command object based on contents in args[0].
     *
     *@param args array of arguments typically passed from main().
     *@return Command object or null if args[0] does not specify a valid command.
     */
    public static IAdminCommand getCommand(String[] args) {
        if (args.length < 1)
            return null;
        if (args[0].equals("makeroot"))
            return new CaMakeRootCommand(args);
        else if (args[0].equals("getrootcert"))
            return new CaGetRootCertCommand(args);
        else if (args[0].equals("listexpired"))
            return new CaListExpiredCommand(args);
        else if (args[0].equals("info"))
            return new CaInfoCommand(args);
        else 
            return null;
    } // getCommand
} // CaAdminCommandFactory
