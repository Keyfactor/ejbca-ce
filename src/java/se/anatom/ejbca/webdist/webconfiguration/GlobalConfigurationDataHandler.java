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
 * @version $Id: GlobalConfigurationDataHandler.java,v 1.11 2002-10-24 20:14:00 herrvendil Exp $
 */
public class GlobalConfigurationDataHandler {

    /** Creates a new instance of GlobalConfigurationDataHandler */
    public GlobalConfigurationDataHandler(IUserAdminSessionRemote adminsession, Admin administrator ){
      this.adminsession = adminsession;
      this.administrator = administrator;
    }

    public GlobalConfiguration loadGlobalConfiguration() throws RemoteException, NamingException{
        GlobalConfiguration ret = null;

        ret = adminsession.loadGlobalConfiguration();
        InitialContext ictx = new InitialContext();
        Context myenv = (Context) ictx.lookup("java:comp/env");      
        ret.initialize((String) myenv.lookup("BASEURL"), (String) myenv.lookup("ADMINDIRECTORY"),
                        (String) myenv.lookup("AVAILABLELANGUAGES"), (String) myenv.lookup("AVAILABLETHEMES"), 
                        (String) myenv.lookup("PUBLICPORT"),(String) myenv.lookup("PRIVATEPORT"),
                        (String) myenv.lookup("PUBLICPROTOCOL"),(String) myenv.lookup("PRIVATEPROTOCOL"));
        return ret;
    }

    public void saveGlobalConfiguration(GlobalConfiguration gc) throws RemoteException {
       adminsession.saveGlobalConfiguration( gc);
    }

   // private IRaAdminSessionHome  raadminsessionhome;
    private IUserAdminSessionRemote adminsession;
    private Admin administrator;
}
