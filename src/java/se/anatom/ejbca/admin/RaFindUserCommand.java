
package se.anatom.ejbca.admin;

import se.anatom.ejbca.ra.UserAdminData;
import se.anatom.ejbca.ra.authorization.AuthorizationDeniedException;

/** Find details of a user in the database.
 *
 * @version $Id: RaFindUserCommand.java,v 1.4 2003-01-12 17:16:31 anatom Exp $
 */
public class RaFindUserCommand extends BaseRaAdminCommand {

    /** Creates a new instance of RaFindUserCommand */
    public RaFindUserCommand(String[] args) {
        super(args);
    }

    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
        try {
            if (args.length < 2) {
                System.out.println("Usage: RA finduser <username>");
                return;
            }
            String username = args[1];
            try{
              UserAdminData data = getAdminSession().findUser(administrator, username);
              if (data != null) {
                System.out.println("Found user:");
                System.out.println("username="+data.getUsername());
                System.out.println("dn=\""+data.getDN()+"\"");
                System.out.println("email="+data.getEmail());
                System.out.println("status="+data.getStatus());
                System.out.println("type="+data.getType());
                System.out.println("password="+data.getPassword());
              } else {
                System.out.println("User '"+username+"' does not exist.");
              }
            }catch(AuthorizationDeniedException e){
               System.out.println("Error : Not authorized to view user."); 
            }  
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    } // execute
    
}
