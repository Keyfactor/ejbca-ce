
package se.anatom.ejbca.admin;

import java.io.*;
import se.anatom.ejbca.ra.authorization.AuthorizationDeniedException;
import se.anatom.ejbca.ra.raadmin.UserDoesntFullfillProfile;

/** Set the clear text password for a user in the database. 
 * Clear text passwords are used for batch generation of keystores (pkcs12/pem).
 *
 * @version $Id: RaSetClearPwdCommand.java,v 1.2 2002-08-27 12:41:06 herrvendil Exp $
 */
public class RaSetClearPwdCommand extends BaseRaAdminCommand {

    /** Creates a new instance of RaSetClearPwdCommand */
    public RaSetClearPwdCommand(String[] args) {
        super(args);
    }

    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
        try {
            if (args.length < 3) {
                System.out.println("Usage: RA setclearpwd <username> <password>");
                return;
            }
            String username = args[1];
            String password = args[2];
            System.out.println("Setting clear text password "+password+" for user "+username);
            try{
              getAdminSession().setClearTextPassword(username, password);
            }catch(AuthorizationDeniedException e){
               System.out.println("Error : Not authorized to change userdata."); 
            }catch(UserDoesntFullfillProfile e){
                System.out.println("Error : Given userdata doesn't fullfill profile.");                
            }     
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    } // execute
    
}
