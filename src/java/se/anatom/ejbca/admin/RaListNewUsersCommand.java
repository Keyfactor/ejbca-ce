
package se.anatom.ejbca.admin;

import java.io.*;
import java.util.Collection;
import java.util.Iterator;

import se.anatom.ejbca.ra.UserAdminData;
import se.anatom.ejbca.ra.UserDataLocal;
import se.anatom.ejbca.ra.authorization.AuthorizationDeniedException;

/** List users with status NEW in the database.
 *
 * @see se.anatom.ejbca.ra.UserDataLocal
 * @version $Id: RaListNewUsersCommand.java,v 1.4 2002-11-17 14:01:38 herrvendil Exp $
 */
public class RaListNewUsersCommand extends BaseRaAdminCommand {

    /** Creates a new instance of RaListNewUsersCommand */
    public RaListNewUsersCommand(String[] args) {
        super(args);
    }

    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
        try {
            Collection coll = getAdminSession().findAllUsersByStatus(administrator, UserDataLocal.STATUS_NEW);
            Iterator iter = coll.iterator();
            while (iter.hasNext()) {
                UserAdminData data = (UserAdminData)iter.next();
                System.out.println("New user: "+data.getUsername()+", \""+data.getDN()+"\", "+data.getEmail()+", "+data.getStatus()+", "+data.getType());
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    } // execute
    
}
