package se.anatom.ejbca.webdist.webconfiguration;

import java.rmi.RemoteException;

import javax.naming.*;

import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.ra.GlobalConfiguration;
import se.anatom.ejbca.ra.IUserAdminSessionRemote;


/**
 * A class handling the saving and loading of global configuration data. By default all data are
 * saved to a database.
 *
 * @author Philip Vendil
 * @version $Id: GlobalConfigurationDataHandler.java,v 1.15 2003-07-24 08:43:33 anatom Exp $
 */
public class GlobalConfigurationDataHandler {
    /**
     * Creates a new instance of GlobalConfigurationDataHandler
     *
     * @param adminsession DOCUMENT ME!
     * @param administrator DOCUMENT ME!
     */
    public GlobalConfigurationDataHandler(IUserAdminSessionRemote adminsession, Admin administrator) {
        this.adminsession = adminsession;
        this.administrator = administrator;
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     * @throws NamingException DOCUMENT ME!
     */
    public GlobalConfiguration loadGlobalConfiguration()
        throws RemoteException, NamingException {
        GlobalConfiguration ret = null;

        ret = adminsession.loadGlobalConfiguration(administrator);

        InitialContext ictx = new InitialContext();
        Context myenv = (Context) ictx.lookup("java:comp/env");
        ret.initialize((String) myenv.lookup("BASEURL"), (String) myenv.lookup("ADMINDIRECTORY"),
            (String) myenv.lookup("AVAILABLELANGUAGES"), (String) myenv.lookup("AVAILABLETHEMES"),
            (String) myenv.lookup("PUBLICPORT"), (String) myenv.lookup("PRIVATEPORT"),
            (String) myenv.lookup("PUBLICPROTOCOL"), (String) myenv.lookup("PRIVATEPROTOCOL"));

        return ret;
    }

    /**
     * DOCUMENT ME!
     *
     * @param gc DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     */
    public void saveGlobalConfiguration(GlobalConfiguration gc)
        throws RemoteException {
        adminsession.saveGlobalConfiguration(administrator, gc);
    }

    // private IRaAdminSessionHome  raadminsessionhome;
    private IUserAdminSessionRemote adminsession;
    private Admin administrator;
}
