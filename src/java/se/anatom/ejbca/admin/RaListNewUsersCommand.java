
package se.anatom.ejbca.admin;

import java.io.*;
import java.util.Collection;
import java.util.Iterator;

import se.anatom.ejbca.ra.UserAdminData;
import se.anatom.ejbca.ra.UserDataLocal;

/** List users with status NEW in the database.
 *
 * @see se.anatom.ejbca.ra.UserDataLocal
 * @version $Id: RaListNewUsersCommand.java,v 1.2 2002-07-05 23:43:18 herrvendil Exp $
 */
public class RaListNewUsersCommand extends BaseRaAdminCommand {

    /** Creates a new instance of RaListNewUsersCommand */
    public RaListNewUsersCommand(String[] args) {
        super(args);
    }

    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
        try {
            Collection coll = getAdminSession().findAllUsersByStatus(UserDataLocal.STATUS_NEW);
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
