/*
 * UsersPreferences.java
 *
 * Created on den 28 mars 2002, 16:18
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
import java.math.BigInteger;

import se.anatom.ejbca.ra.raadmin.IRaAdminSessionHome;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote;

/**
 * A class handling the storage of user preferences. Currently all user preferences are
 * save to a database.
 *
 * @author  Philip Vendil
 */
public class UsersPreferenceDataHandler {
    
    /** Creates a new instance of UsersPreferences */
    public UsersPreferenceDataHandler()throws IOException, FileNotFoundException, NamingException, CreateException,
                                                   FinderException{
        Properties jndienv = new Properties();
        jndienv.load(this.getClass().getResourceAsStream("/WEB-INF/jndi.properties"));     
        InitialContext jndicontext = new InitialContext(jndienv);
        
        Object obj1 = jndicontext.lookup("RaAdminSession");
        IRaAdminSessionHome raadminsessionhome = (IRaAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, 
                                                                                 IRaAdminSessionHome.class);
        raadminsession = raadminsessionhome.create(); 
    }
    
    /** Retrieves the user from the database or null if the user doesn't exists. */
    public UserPreference getUserPreference(BigInteger certificateserialnumber) {
      UserPreference returnvalue=null;  
      try{
         returnvalue = raadminsession.getUserPreference(certificateserialnumber);
      }catch(Exception e) {
         returnvalue=null;
      }
      return returnvalue;  
    }
    
    /** Adds a user preference to the database */
    public void addUserPreference(BigInteger certificateserialnumber, UserPreference userpreference) 
                                  throws UserExistsException, RemoteException {
      if(!raadminsession.addUserPreference(certificateserialnumber, userpreference))
        throw new UserExistsException("User already exists in the database.");   
    }
    
    /** Changes the user preference for the given user. */
    public void changeUserPreference(BigInteger certificateserialnumber, UserPreference userpreference) 
                              throws UserDoesntExistException, RemoteException{                          
      if(!raadminsession.changeUserPreference(certificateserialnumber, userpreference))
        throw new UserDoesntExistException("User doesn't exists in the database.");                 
                                  
    }
    
    /** Checks if user preference exists in database. */
    public boolean existsUserPreference(BigInteger certificateserialnumber) throws RemoteException{
      return raadminsession.existsUserPreference(certificateserialnumber);
        
    }
   
    private IRaAdminSessionRemote raadminsession;    
}
