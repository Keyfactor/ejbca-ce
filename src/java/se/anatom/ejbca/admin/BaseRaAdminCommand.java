package se.anatom.ejbca.admin;

import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.ra.IUserAdminSessionHome;
import se.anatom.ejbca.ra.IUserAdminSessionRemote;

import java.rmi.RemoteException;

import javax.ejb.CreateException;

import javax.naming.*;


/**
 * Base for RA commands, contains comom functions for RA operations
 *
 * @version $Id: BaseRaAdminCommand.java,v 1.7 2003-06-26 11:43:22 anatom Exp $
 */
public abstract class BaseRaAdminCommand extends BaseAdminCommand {
    /**
     * UserAdminSession handle, not static since different object should go to different session
     * beans concurrently
     */
    private IUserAdminSessionRemote cacheAdmin;

    /** Handle to AdminSessionHome */
    private static IUserAdminSessionHome cacheHome;
    protected Admin administrator = null;

    /**
     * Creates a new instance of BaseRaAdminCommand
     *
     * @param args command line arguments
     */
    public BaseRaAdminCommand(String[] args) {
        super(args);
    }

    /**
     * Gets user admin session
     *
     * @return InitialContext
     */
    protected IUserAdminSessionRemote getAdminSession()
        throws CreateException, NamingException, RemoteException {
        debug(">getAdminSession()");
        administrator = new Admin(Admin.TYPE_RACOMMANDLINE_USER);

        try {
            if (cacheAdmin == null) {
                if (cacheHome == null) {
                    Context jndiContext = getInitialContext();
                    Object obj1 = jndiContext.lookup("UserAdminSession");
                    cacheHome = (IUserAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1,
                            IUserAdminSessionHome.class);
                }

                cacheAdmin = cacheHome.create();
            }

            debug("<getAdminSession()");

            return cacheAdmin;
        } catch (NamingException e) {
            error("Can't get Admin session", e);
            throw e;
        }
    }

    // getAdminSession
}
