
package se.anatom.ejbca.admin;

import java.io.*;
import se.anatom.ejbca.ra.authorization.AuthorizationDeniedException;

/** Deletes a user from the database.
 *
 * @version $Id: RaDelUserCommand.java,v 1.2 2002-08-27 12:41:06 herrvendil Exp $
 */
public class RaDelUserCommand extends BaseRaAdminCommand {

    /** Creates a new instance of RaDelUserCommand */
    public RaDelUserCommand(String[] args) {
        super(args);
    }
    
    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
        try {
            if (args.length < 2) {
                System.out.println("Usage: RA deluser <username>");
                return;
            }
            String username = args[1];
            System.out.print("Have you revoked the user [y/N]? ");
            int inp = System.in.read();
            if ( (inp == 121) || (inp==89) ) {
              try{
                getAdminSession().deleteUser(username);
                System.out.println("Deleted user "+username);
              }catch(AuthorizationDeniedException e){
               System.out.println("Error : Not authorized to remove user."); 
              }  
            } else {
                System.out.println("Delete aborted!");
                System.out.println("Please run 'ra revokeuser "+username+"'.");
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    } // execute
    
}
