
package se.anatom.ejbca.admin;

/** Factory for RA Admin Commands.
 *
 * @version $Id: RaAdminCommandFactory.java,v 1.5 2003-02-12 13:21:41 herrvendil Exp $
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
            return new RaAddUserCommand(args);
        else if (args[0].equals("deluser"))
            return new RaDelUserCommand(args);
        else if (args[0].equals("setpwd"))
            return new RaSetPwdCommand(args);
        else if (args[0].equals("setclearpwd"))
            return new RaSetClearPwdCommand(args);
        else if (args[0].equals("setuserstatus"))
            return new RaSetUserStatusCommand(args);
        else if (args[0].equals("finduser"))
            return new RaFindUserCommand(args);
        else if (args[0].equals("listnewusers"))
            return new RaListNewUsersCommand(args);
        else if (args[0].equals("listusers"))
            return new RaListUsersCommand(args);
        else if (args[0].equals("revokeuser"))
            return new RaRevokeUserCommand(args);
        else if (args[0].equals("startservice"))
            return new RaStartServiceCommand(args);
        else if (args[0].equals("keyrecover"))
            return new RaKeyRecoverCommand(args);
        else if (args[0].equals("keyrecovernewest"))
            return new RaKeyRecoverNewestCommand(args);        
        else
            return null;
    } // getCommand
} // RaAdminCommandFactory
