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
import se.anatom.ejbca.ra.raadmin.IRaAdminSession;

/**
 * A class handling the saving and loading of global configuration data.
 * By default all data are saved to a database.
 * 
 * @author  Philip Vendil
 */
public class GlobalConfigurationDataHandler {
    
    /** Creates a new instance of GlobalConfigurationDataHandler */
    public GlobalConfigurationDataHandler() throws IOException, FileNotFoundException, NamingException, CreateException,
                                                   FinderException{
        InitialContext jndicontext = new InitialContext();
        
        Object obj1 = jndicontext.lookup("RaAdminSession");
        IRaAdminSessionHome raadminsessionhome = (IRaAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, 
                                                                                 IRaAdminSessionHome.class);
        raadminsession = raadminsessionhome.create(); 
    }
    
    public GlobalConfiguration loadGlobalConfiguration() throws RemoteException, NamingException {
        GlobalConfiguration ret;
     
        ret = raadminsession.loadGlobalConfiguration();  
        if(ret == null){
           System.out.println("HERE"); 
           ret = new GlobalConfiguration();    
           System.out.println("HEREEND"); 
        }
        return ret;
    }
    
    public void saveGlobalConfiguration(GlobalConfiguration gc) throws RemoteException {
       raadminsession.saveGlobalConfiguration(gc);      
    }
 
    private IRaAdminSession raadminsession;
}
