/*
 * GlobalConfigurationDataHandler.java
 *
 * Created on den 29 mars 2002, 13:16
 */

package se.anatom.ejbca.webdist.webconfiguration;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.FileNotFoundException;
import java.beans.*;
import javax.naming.*;
import javax.ejb.CreateException;
import javax.ejb.FinderException;
import java.util.Properties;
import java.rmi.RemoteException;

import se.anatom.ejbca.ra.raadmin.IRaAdminSessionHome;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote;

import java.math.BigInteger;

/**
 * A class handling the saving and loading of global configuration data.
 * By default all data are saved to a database.
 *
 * @author  Philip Vendil
 * @version $Id: GlobalConfigurationDataHandler.java,v 1.6 2002-06-27 12:14:03 anatom Exp $
 */
public class GlobalConfigurationDataHandler {

    /** Creates a new instance of GlobalConfigurationDataHandler */
    public GlobalConfigurationDataHandler() throws IOException, FileNotFoundException, NamingException,
                                                   FinderException, CreateException{

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
