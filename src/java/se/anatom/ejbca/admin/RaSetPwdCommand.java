
package se.anatom.ejbca.admin;

import java.io.*;
import se.anatom.ejbca.ra.authorization.AuthorizationDeniedException;
import se.anatom.ejbca.ra.raadmin.UserDoesntFullfillEndEntityProfile;

/** Set the (hashed) password for a user in the database.
 *
 * @version $Id: RaSetPwdCommand.java,v 1.4 2002-10-24 20:00:28 herrvendil Exp $
 */
public class RaSetPwdCommand extends BaseRaAdminCommand {

    /** Creates a new instance of RaSetPwdCommand */
    public RaSetPwdCommand(String[] args) {
        super(args);
    }

    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
        try {
            if (args.length < 3) {
                System.out.println("Usage: RA setpwd <username> <password>");
                return;
            }
            String username = args[1];
            String password = args[2];
            System.out.println("Setting password (hashed only) "+password+" for user "+username);
            try{
              getAdminSession().setPassword(username, password);
            }catch(AuthorizationDeniedException e){
               System.out.println("Error : Not authorized to change userdata."); 
            }catch(UserDoesntFullfillEndEntityProfile e){
                System.out.println("Error : Given userdata doesn't fullfill profile.");                
            }   
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    } // execute
    
}
