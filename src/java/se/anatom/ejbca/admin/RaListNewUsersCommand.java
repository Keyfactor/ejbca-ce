
package se.anatom.ejbca.admin;

import java.io.*;
import java.util.Collection;
import java.util.Iterator;

import se.anatom.ejbca.ra.UserAdminData;
import se.anatom.ejbca.ra.UserData;

/** List users with status NEW in the database.
 *
 * @see se.anatom.ejbca.ra.UserData
 * @version $Id: RaListNewUsersCommand.java,v 1.1 2002-04-14 08:49:31 anatom Exp $
 */
public class RaListNewUsersCommand extends BaseRaAdminCommand {

    /** Creates a new instance of RaListNewUsersCommand */
    public RaListNewUsersCommand(String[] args) {
        super(args);
    }

    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
        try {
            Collection coll = getAdminSession().findAllUsersByStatus(UserData.STATUS_NEW);
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
