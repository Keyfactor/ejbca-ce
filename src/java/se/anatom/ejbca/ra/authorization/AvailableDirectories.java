/*
 * AvailableDirectories.java
 *
 * Created on den 16 mars 2002, 16:35
 */

package se.anatom.ejbca.ra.authorization;

import java.util.Vector;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import javax.naming.*;
import javax.ejb.CreateException;
import javax.ejb.FinderException;
import java.rmi.RemoteException;

import se.anatom.ejbca.ra.GlobalConfiguration;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionHome;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote;


/**
 * 
 *
 * @author  Philip Vendil
 */
public class AvailableDirectories {
        
    /** Creates a new instance of AvailableDirectories */
    public AvailableDirectories(GlobalConfiguration globalconfiguration) throws NamingException, CreateException, RemoteException {   
      this.profileendings=globalconfiguration.getProfileEndings();
      this.profileprefix= globalconfiguration.getProfilePrefix();
      this.usestrongauthentication = globalconfiguration.getUseStrongAuthorization();

      InitialContext jndicontext = new InitialContext();     
      Object objl = jndicontext.lookup("RaAdminSession");
      IRaAdminSessionHome raadminsessionhome = (IRaAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(objl, 
                                                                       IRaAdminSessionHome.class);
      raadminsession = raadminsessionhome.create();
      
      objl = jndicontext.lookup("AuthorizationSession");
      IAuthorizationSessionHome authorizationsessionhome = (IAuthorizationSessionHome) javax.rmi.PortableRemoteObject.narrow(objl, 
                                                                       IAuthorizationSessionHome.class);
      authorizationsession = authorizationsessionhome.create();
      authorizationsession.init(globalconfiguration);
 
    }
    // Public methods 
    /** Returns all the directories and subdirectories from the given subdirectory */
    public String[] getDirectories()  {
      Vector directories = new Vector();
      String[] dummy = {};
      
      insertAvailableRules(directories);
      if(usestrongauthentication) 
        insertAvailableProfileRules(directories);
      
      Collections.sort(directories);
      return (String[]) directories.toArray(dummy);  
    }
    
    // Private methods
    private void insertAvailableRules(Vector directories) {
      try{  
        directories.addAll(authorizationsession.getAvailableAccessRules());  
      }catch(RemoteException e){}
    }
    
    private void insertAvailableProfileRules(Vector directories){
      try{  
        Collection profilenames = raadminsession.getProfileNames();
        if(profilenames != null){
          Iterator i = profilenames.iterator();
      
          while(i.hasNext()){
            String name = (String) i.next();
            int id = raadminsession.getProfileId(name);
            directories.addElement(profileprefix + id);
            for(int j=0;j < profileendings.length; j++){     
              directories.addElement(profileprefix + id +profileendings[j]);             
            }        
          }
        }
      }catch(RemoteException e){}  
    }
    // Private fields
    private String[] profileendings;
    private String profileprefix;
    private IRaAdminSessionRemote raadminsession;
    private IAuthorizationSessionRemote authorizationsession;
    private boolean usestrongauthentication;
}
