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
 */
public class GlobalConfigurationDataHandler {
    
    /** Creates a new instance of GlobalConfigurationDataHandler */
    public GlobalConfigurationDataHandler() throws IOException, FileNotFoundException, NamingException,
                                                   FinderException, CreateException{
                                       
      //  Properties jndienv = new Properties(); 
      // jndienv.load(this.getClass().getResourceAsStream("/WEB-INF/jndi.properties"));   
      //  jndicontext = new InitialContext(jndienv); 
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
