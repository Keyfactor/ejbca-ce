package se.anatom.ejbca.webdist.webconfiguration;

import java.beans.*;
import javax.naming.*;
import javax.ejb.CreateException;
import javax.ejb.FinderException;
import java.rmi.RemoteException;
import java.io.IOException;

import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.ra.IUserAdminSessionHome;
import se.anatom.ejbca.ra.IUserAdminSessionRemote;
import se.anatom.ejbca.ra.GlobalConfiguration;

/**
 * A class handling the saving and loading of global configuration data.
 * By default all data are saved to a database.
 *
 * @author  Philip Vendil
 * @version $Id: GlobalConfigurationDataHandler.java,v 1.10 2002-09-12 18:14:15 herrvendil Exp $
 */
public class GlobalConfigurationDataHandler {

    /** Creates a new instance of GlobalConfigurationDataHandler */
    public GlobalConfigurationDataHandler(Admin administrator) throws IOException,  NamingException,
                                                   FinderException, CreateException{
      // Get the UserSdminSession instance.
      InitialContext jndicontext = new InitialContext();
      Object obj1 = jndicontext.lookup("UserAdminSession");
      IUserAdminSessionHome adminsessionhome = (IUserAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, IUserAdminSessionHome.class);
      adminsession = adminsessionhome.create(administrator);

      this.administrator = administrator;
    }

    public GlobalConfiguration loadGlobalConfiguration() throws RemoteException, NamingException{
        GlobalConfiguration ret = null;

        ret = adminsession.loadGlobalConfiguration();
        if(!ret.isInitialized()){
           InitialContext ictx = new InitialContext();
           Context myenv = (Context) ictx.lookup("java:comp/env");      
           ret.initialize((String) myenv.lookup("BASEURL"), (String) myenv.lookup("RAADMINDIRECTORY"),
                          (String) myenv.lookup("AVAILABLELANGUAGES"), (String) myenv.lookup("AVAILABLETHEMES"));
           saveGlobalConfiguration(ret);
        }
        return ret;
    }

    public void saveGlobalConfiguration(GlobalConfiguration gc) throws RemoteException {
       adminsession.saveGlobalConfiguration( gc);
    }

   // private IRaAdminSessionHome  raadminsessionhome;
    private IUserAdminSessionRemote adminsession;
    private Admin administrator;
}
