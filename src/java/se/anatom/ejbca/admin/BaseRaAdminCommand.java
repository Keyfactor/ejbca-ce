package se.anatom.ejbca.admin;

import java.rmi.RemoteException;

import javax.ejb.CreateException;
import javax.naming.*;

import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.ra.IUserAdminSessionHome;
import se.anatom.ejbca.ra.IUserAdminSessionRemote;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionHome;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote;
import se.anatom.ejbca.log.Admin;



/**
 * Base for RA commands, contains comom functions for RA operations
 *
 * @version $Id: BaseRaAdminCommand.java,v 1.9 2003-09-03 14:32:02 herrvendil Exp $
 */
public abstract class BaseRaAdminCommand extends BaseAdminCommand {
    /**
     * UserAdminSession handle, not static since different object should go to different session
     * beans concurrently
     */
    private IUserAdminSessionRemote cacheAdmin;

    /** Handle to AdminSessionHome */
    private static IUserAdminSessionHome cacheHome;

    /** RaAdminSession handle, not static since different object should go to different session beans concurrently */
    private IRaAdminSessionRemote raadminsession;
    /** Handle to RaAdminSessionHome */
    private static IRaAdminSessionHome raadminHomesession;    
    
    protected Admin administrator = null;

    /**
     * Creates a new instance of BaseRaAdminCommand
     *
     * @param args command line arguments
     */
    public BaseRaAdminCommand(String[] args) {
        super(args);
        administrator = new Admin(Admin.TYPE_RACOMMANDLINE_USER);
    }    
    
    /** Gets user admin session
     *@return InitialContext
     */
    protected IUserAdminSessionRemote getAdminSession()
        throws CreateException, NamingException, RemoteException {
        debug(">getAdminSession()");
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
    } // getAdminSession
    
    /** Gets ra admin session
     *@return InitialContext
     */
    protected IRaAdminSessionRemote getRaAdminSession() throws CreateException, NamingException, RemoteException {
        debug(">getRaAdminSession()");
        administrator = new Admin(Admin.TYPE_RACOMMANDLINE_USER);
        try {
            if( raadminsession == null ) {
                if (raadminHomesession == null) {
                    Context jndiContext = getInitialContext();
                    Object obj1 = jndiContext.lookup("RaAdminSession");
                    raadminHomesession = (IRaAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, IRaAdminSessionHome.class);
                }
                raadminsession = raadminHomesession.create();
            }
            debug("<getRaAdminSession()");
            return  raadminsession;
        } catch (NamingException e ) {
            error("Can't get RaAdmin session", e);
            throw e;
        }
    } // getRaAdminSession    

}
