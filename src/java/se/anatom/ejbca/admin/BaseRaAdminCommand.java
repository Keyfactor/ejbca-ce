
package se.anatom.ejbca.admin;

import javax.naming.*;
import javax.ejb.CreateException;
import java.rmi.RemoteException;

import se.anatom.ejbca.ra.IUserAdminSessionHome;
import se.anatom.ejbca.ra.IUserAdminSession;

/** Base for RA commands, contains comom functions for RA operations
 *
 * @version $Id: BaseRaAdminCommand.java,v 1.2 2002-04-14 08:49:31 anatom Exp $
 */
public abstract class BaseRaAdminCommand extends BaseAdminCommand {

    /** UserAdminSession handle, not static since different object should go to different session beans concurrently */
    private IUserAdminSession cacheAdmin;
    /** Handle to AdminSessionHome */
    private static IUserAdminSessionHome cacheHome;
    
    /** Creates a new instance of BaseRaAdminCommand */
    public BaseRaAdminCommand(String[] args) {
        super(args);
        
    }    
    
    /** Gets user admin session
     *@return InitialContext
     */
    protected IUserAdminSession getAdminSession() throws CreateException, NamingException, RemoteException {
        debug(">getAdminSession()");
        try {
            if( cacheAdmin == null ) {
                if (cacheHome == null) {
                    Context jndiContext = getInitialContext();
                    Object obj1 = jndiContext.lookup("UserAdminSession");
                    cacheHome = (IUserAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, IUserAdminSessionHome.class);
                }
                cacheAdmin = cacheHome.create();
            }
            debug("<getAdminSession()");
            return  cacheAdmin;
        } catch (NamingException e ) {
            error("Can't get Admin session", e);
            throw e;
        }
    } // getAdminSession
}
