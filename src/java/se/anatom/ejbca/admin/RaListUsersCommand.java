
package se.anatom.ejbca.admin;

import java.util.Collection;
import java.util.Iterator;

import se.anatom.ejbca.ra.UserAdminData;

/** List users with specified status in the database.
 *
 * @see se.anatom.ejbca.ra.UserDataLocal
 * @version $Id: RaListUsersCommand.java,v 1.6 2003-01-19 09:40:13 herrvendil Exp $
 */
public class RaListUsersCommand extends BaseRaAdminCommand {

    /** Creates a new instance of RaListUsersCommand */
    public RaListUsersCommand(String[] args) {
        super(args);
    }

    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
        try {
            if (args.length < 2) {
                System.out.println("Usage: RA listusers <status>");
                System.out.println("Status: NEW=10; FAILED=11; INITIALIZED=20; INPROCESS=30; GENERATED=40; HISTORICAL=50");
                return;
            }
            int status = Integer.parseInt(args[1]);
            Collection coll = getAdminSession().findAllUsersByStatus(administrator, status);
            Iterator iter = coll.iterator();
            while (iter.hasNext()) {
                UserAdminData data = (UserAdminData)iter.next();
                System.out.println("User: "+data.getUsername()+", \""+data.getDN()+"\", \"" +data.getSubjectAltName()+ "\", " +data.getEmail()+", "+data.getStatus()+", "+data.getType() + ", " +data.getTokenType());
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    } // execute

}
