
package se.anatom.ejbca.admin;

/** Factory for RA Admin Commands.
 *
 * @version $Id: RaAdminCommandFactory.java,v 1.1 2002-04-13 19:00:56 anatom Exp $
 */
public class RaAdminCommandFactory {

    /** Cannot create an instance of this class, only use static methods. */
    private RaAdminCommandFactory() {
    }

    /** Returns an Admin Command object based on contents in args[0].
     *
     *@param args array of arguments typically passed from main().
     *@return Command object or null if args[0] does not specify a valid command.
     */
    public static IAdminCommand getCommand(String[] args) {
        if (args.length < 1)
            return null;
        if (args[0].equals("adduser"))
            return null;
            //return new RaAddUserCommand(args);
        else if (args[0].equals("deluser"))
            return null;
            //return new RaDelUserCommand(args);
        else 
            return null;
    } // getCommand
} // RaAdminCommandFactory
