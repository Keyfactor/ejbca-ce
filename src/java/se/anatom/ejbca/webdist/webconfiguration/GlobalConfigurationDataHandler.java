package se.anatom.ejbca.webdist.webconfiguration;

import java.beans.*;
import javax.naming.*;
import javax.ejb.CreateException;
import javax.ejb.FinderException;
import java.rmi.RemoteException;

import se.anatom.ejbca.ra.raadmin.IRaAdminSessionHome;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote;

/**
 * A class handling the saving and loading of global configuration data.
 * By default all data are saved to a database.
 *
 * @author  Philip Vendil
 * @version $Id: GlobalConfigurationDataHandler.java,v 1.7 2002-07-16 12:26:40 anatom Exp $
 */
public class GlobalConfigurationDataHandler {

    /** Creates a new instance of GlobalConfigurationDataHandler */
    public GlobalConfigurationDataHandler() throws RemoteException, NamingException, CreateException{

       InitialContext jndicontext = new InitialContext();
       IRaAdminSessionHome raadminsessionhome = (IRaAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(jndicontext.lookup("RaAdminSession"),
                                                                                 IRaAdminSessionHome.class);
       raadminsession = raadminsessionhome.create();

    }

    public GlobalConfiguration loadGlobalConfiguration() throws RemoteException, NamingException{
        GlobalConfiguration ret = null;

        ret = raadminsession.loadGlobalConfiguration();
        if(ret == null){
           ret = new GlobalConfiguration();
        }
        return ret;
    }

    public void saveGlobalConfiguration(GlobalConfiguration gc) throws RemoteException {
       raadminsession.saveGlobalConfiguration( gc);
    }

   // private IRaAdminSessionHome  raadminsessionhome;
    private IRaAdminSessionRemote raadminsession;
}
